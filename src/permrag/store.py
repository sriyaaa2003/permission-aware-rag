"""Tenant, user, role and document management. Every mutation is one transaction that also
rewrites the retrieval ACL, bumps the tenant's data version and appends an audit event."""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from dataclasses import dataclass

from .audit import AuditLog
from .chunking import chunk_text
from .db import transaction
from .embeddings import Embedder, to_blob


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


def _id() -> str:
    return uuid.uuid4().hex


def _bump(conn: sqlite3.Connection, tenant_id: str) -> None:
    conn.execute("UPDATE tenants SET data_version = data_version + 1 WHERE id=?", (tenant_id,))


# ----- tenants, users, roles ----------------------------------------------------------------------
def create_tenant(conn: sqlite3.Connection, audit: AuditLog, name: str) -> str:
    tid = _id()
    try:
        with transaction(conn):
            conn.execute(
                "INSERT INTO tenants(id, name, created_at) VALUES (?,?,?)", (tid, name, time.time())
            )
            audit.append(conn, tid, None, "tenant.create", {"name": name})
    except sqlite3.IntegrityError as exc:
        raise ConflictError(f"tenant {name!r} already exists") from exc
    return tid


def create_role(
    conn: sqlite3.Connection, audit: AuditLog, tenant_id: str, name: str, actor: str | None
) -> str:
    rid = _id()
    try:
        with transaction(conn):
            conn.execute(
                "INSERT INTO roles(id, tenant_id, name) VALUES (?,?,?)", (rid, tenant_id, name)
            )
            audit.append(conn, tenant_id, actor, "role.create", {"role": name, "role_id": rid})
    except sqlite3.IntegrityError as exc:
        raise ConflictError(f"role {name!r} already exists") from exc
    return rid


def create_user(
    conn: sqlite3.Connection,
    audit: AuditLog,
    tenant_id: str,
    email: str,
    roles: list[str],
    actor: str | None,
) -> str:
    uid = _id()
    try:
        with transaction(conn):
            conn.execute(
                "INSERT INTO users(id, tenant_id, email, created_at) VALUES (?,?,?,?)",
                (uid, tenant_id, email, time.time()),
            )
            _set_roles(conn, tenant_id, uid, roles)
            audit.append(conn, tenant_id, actor, "user.create", {"user_id": uid, "roles": roles})
    except sqlite3.IntegrityError as exc:
        raise ConflictError(f"user {email!r} already exists") from exc
    return uid


def _role_ids(conn: sqlite3.Connection, tenant_id: str, names: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for n in names:
        row = conn.execute(
            "SELECT id FROM roles WHERE tenant_id=? AND name=?", (tenant_id, n)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"role {n!r} does not exist in this tenant")
        out[n] = row["id"]
    return out


def _set_roles(conn: sqlite3.Connection, tenant_id: str, user_id: str, roles: list[str]) -> None:
    ids = _role_ids(conn, tenant_id, roles)
    conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
    conn.executemany(
        "INSERT INTO user_roles(user_id, role_id) VALUES (?,?)",
        [(user_id, r) for r in ids.values()],
    )


def set_user_roles(
    conn: sqlite3.Connection,
    audit: AuditLog,
    tenant_id: str,
    user_id: str,
    roles: list[str],
    actor: str | None,
) -> None:
    with transaction(conn):
        if not conn.execute(
            "SELECT 1 FROM users WHERE id=? AND tenant_id=?", (user_id, tenant_id)
        ).fetchone():
            raise NotFoundError("user not found")
        _set_roles(conn, tenant_id, user_id, roles)
        audit.append(conn, tenant_id, actor, "user.roles_set", {"user_id": user_id, "roles": roles})


def deactivate_user(
    conn: sqlite3.Connection, audit: AuditLog, tenant_id: str, user_id: str, actor: str | None
) -> None:
    with transaction(conn):
        cur = conn.execute(
            "UPDATE users SET active=0 WHERE id=? AND tenant_id=?", (user_id, tenant_id)
        )
        if cur.rowcount == 0:
            raise NotFoundError("user not found")
        audit.append(conn, tenant_id, actor, "user.deactivate", {"user_id": user_id})


# ----- documents --------------------------------------------------------------------------------
@dataclass(frozen=True)
class DocumentSpec:
    external_id: str
    title: str
    text: str
    visibility: str  # "tenant" | "restricted"
    allowed_roles: list[str]
    allowed_users: list[str]


def _acl_principals(
    conn: sqlite3.Connection,
    tenant_id: str,
    spec_roles: list[str],
    spec_users: list[str],
    owner: str | None,
) -> set[str]:
    principals = {f"role:{rid}" for rid in _role_ids(conn, tenant_id, spec_roles).values()}
    for uid in spec_users:
        if not conn.execute(
            "SELECT 1 FROM users WHERE id=? AND tenant_id=?", (uid, tenant_id)
        ).fetchone():
            raise NotFoundError(f"user {uid!r} does not exist in this tenant")
        principals.add(f"user:{uid}")
    if owner:
        principals.add(f"user:{owner}")
    return principals


def _rewrite_chunk_acl(
    conn: sqlite3.Connection, tenant_id: str, document_id: str, visibility: str
) -> None:
    conn.execute(
        "DELETE FROM chunk_acl WHERE chunk_id IN (SELECT id FROM chunks WHERE document_id=?)",
        (document_id,),
    )
    if visibility == "tenant":
        conn.execute(
            "INSERT INTO chunk_acl(chunk_id, tenant_id, principal) "
            "SELECT id, ?, ? FROM chunks WHERE document_id=?",
            (tenant_id, f"tenant:{tenant_id}", document_id),
        )
    else:
        conn.execute(
            "INSERT INTO chunk_acl(chunk_id, tenant_id, principal) "
            "SELECT c.id, ?, a.principal FROM chunks c JOIN document_acl a "
            "ON a.document_id = c.document_id WHERE c.document_id=?",
            (tenant_id, document_id),
        )


def upsert_document(
    conn: sqlite3.Connection,
    audit: AuditLog,
    embedder: Embedder,
    tenant_id: str,
    actor: str,
    spec: DocumentSpec,
    *,
    chunk_chars: int,
    overlap: int,
) -> str:
    """Idempotent create/replace. Returns 'created' | 'updated' | 'unchanged'."""
    if spec.visibility not in ("tenant", "restricted"):
        raise ValueError("visibility must be 'tenant' or 'restricted'")
    pieces = chunk_text(spec.text, chunk_chars, overlap)
    if not pieces:
        raise ValueError("document has no content")
    vectors = embedder.embed(pieces)  # slow; done before taking the write lock
    content_hash = hashlib.sha256(spec.text.encode()).hexdigest()
    now = time.time()

    with transaction(conn):
        existing = conn.execute(
            "SELECT id, content_hash, visibility, owner_user_id FROM documents "
            "WHERE tenant_id=? AND external_id=?",
            (tenant_id, spec.external_id),
        ).fetchone()
        owner = existing["owner_user_id"] if existing and existing["owner_user_id"] else actor
        principals = _acl_principals(conn, tenant_id, spec.allowed_roles, spec.allowed_users, owner)

        if existing:
            doc_id = existing["id"]
            old_acl = {
                r["principal"]
                for r in conn.execute(
                    "SELECT principal FROM document_acl WHERE document_id=?", (doc_id,)
                )
            }
            same = (
                existing["content_hash"] == content_hash
                and existing["visibility"] == spec.visibility
                and old_acl == principals
            )
            if same:
                return "unchanged"
            conn.execute(
                "UPDATE documents SET title=?, content_hash=?, visibility=?, updated_at=? WHERE id=?",
                (spec.title, content_hash, spec.visibility, now, doc_id),
            )
            result = "updated"
        else:
            doc_id = _id()
            conn.execute(
                "INSERT INTO documents(id, tenant_id, external_id, title, content_hash, "
                "owner_user_id, visibility, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    doc_id,
                    tenant_id,
                    spec.external_id,
                    spec.title,
                    content_hash,
                    owner,
                    spec.visibility,
                    now,
                    now,
                ),
            )
            result = "created"

        conn.execute("DELETE FROM document_acl WHERE document_id=?", (doc_id,))
        conn.executemany(
            "INSERT INTO document_acl(document_id, principal) VALUES (?,?)",
            [(doc_id, p) for p in sorted(principals)],
        )
        if result == "created" or (existing and existing["content_hash"] != content_hash):
            conn.execute("DELETE FROM chunks WHERE document_id=?", (doc_id,))  # cascades chunk_acl
            conn.executemany(
                "INSERT INTO chunks(document_id, tenant_id, ordinal, text, embedding) "
                "VALUES (?,?,?,?,?)",
                [
                    (doc_id, tenant_id, i, t, to_blob(v))
                    for i, (t, v) in enumerate(zip(pieces, vectors, strict=True))
                ],
            )
        _rewrite_chunk_acl(conn, tenant_id, doc_id, spec.visibility)
        _bump(conn, tenant_id)
        audit.append(
            conn,
            tenant_id,
            actor,
            f"document.{result}",
            {
                "document_id": doc_id,
                "external_id": spec.external_id,
                "visibility": spec.visibility,
                "acl": sorted(principals),
            },
        )
    return result


def delete_document(
    conn: sqlite3.Connection, audit: AuditLog, tenant_id: str, actor: str, external_id: str
) -> None:
    with transaction(conn):
        row = conn.execute(
            "SELECT id FROM documents WHERE tenant_id=? AND external_id=?", (tenant_id, external_id)
        ).fetchone()
        if row is None:
            raise NotFoundError("document not found")
        conn.execute("DELETE FROM documents WHERE id=?", (row["id"],))  # cascades to chunks + ACLs
        _bump(conn, tenant_id)
        audit.append(
            conn,
            tenant_id,
            actor,
            "document.delete",
            {"document_id": row["id"], "external_id": external_id},
        )
