"""Authorization model. One place defines who may read what.

Principals are strings: ``user:<id>``, ``role:<id>``, ``tenant:<id>``.
A document is readable by a user iff, in the same tenant, the document is tenant-wide or the user
holds at least one principal in the document's ACL (the owner always has ``user:<owner>`` there).

``authorize_document`` is the policy, evaluated against the authoritative ``document_acl`` table.
The retrieval pre-filter uses the denormalised ``chunk_acl`` table for speed; the service re-checks
every retrieved chunk with this policy before it can reach a prompt (defence in depth).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    id: str
    tenant_id: str
    email: str
    roles: frozenset[str]  # role names
    principals: frozenset[str]
    is_admin: bool


def load_user(conn: sqlite3.Connection, user_id: str, admin_role_name: str) -> User | None:
    """Load a user *fresh from the database*. Returns None if the user or tenant is inactive.

    Roles are never taken from the token, so removing a role or deactivating a user takes
    effect on the very next request.
    """
    row = conn.execute(
        "SELECT u.id, u.tenant_id, u.email FROM users u JOIN tenants t ON t.id = u.tenant_id "
        "WHERE u.id=? AND u.active=1 AND t.active=1",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    roles = conn.execute(
        "SELECT r.id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
        "WHERE ur.user_id=? AND r.tenant_id=?",
        (user_id, row["tenant_id"]),
    ).fetchall()
    principals = {f"user:{user_id}", f"tenant:{row['tenant_id']}"} | {
        f"role:{r['id']}" for r in roles
    }
    names = frozenset(r["name"] for r in roles)
    return User(
        id=row["id"],
        tenant_id=row["tenant_id"],
        email=row["email"],
        roles=names,
        principals=frozenset(principals),
        is_admin=admin_role_name in names,
    )


def authorize_document(conn: sqlite3.Connection, user: User, document_id: str) -> bool:
    doc = conn.execute(
        "SELECT tenant_id, visibility FROM documents WHERE id=?", (document_id,)
    ).fetchone()
    if doc is None or doc["tenant_id"] != user.tenant_id:
        return False
    if doc["visibility"] == "tenant":
        return True
    acl = {
        r["principal"]
        for r in conn.execute(
            "SELECT principal FROM document_acl WHERE document_id=?", (document_id,)
        )
    }
    return bool(acl & user.principals)
