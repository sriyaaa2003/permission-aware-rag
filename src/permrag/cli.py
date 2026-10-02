"""Operator CLI: ``permrag <command>``. Tenant creation is a platform-operator action and is not
exposed over HTTP; everything inside a tenant is managed by that tenant's admins via the API."""

from __future__ import annotations

import argparse
import logging
import sys

from . import store
from .audit import AuditLog
from .auth import mint_token
from .config import Settings, get_settings
from .db import Database


def _audit(settings: Settings) -> AuditLog:
    if settings.audit_hmac_key is None:
        raise SystemExit("PR_AUDIT_HMAC_KEY must be set")
    return AuditLog(settings.audit_hmac_key.get_secret_value().encode())


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("permrag.api.app:create_app", factory=True, host=args.host, port=args.port)
    return 0


def _cmd_create_tenant(args: argparse.Namespace) -> int:
    s = get_settings()
    db, audit = Database(s.db_path), _audit(s)
    tid = store.create_tenant(db.conn, audit, args.name)
    store.create_role(db.conn, audit, tid, s.admin_role_name, None)
    uid = store.create_user(db.conn, audit, tid, args.admin_email, [s.admin_role_name], None)
    print(f"tenant_id={tid}\nadmin_user_id={uid}")
    return 0


def _cmd_token(args: argparse.Namespace) -> int:
    s = get_settings()
    db = Database(s.db_path)
    row = db.conn.execute("SELECT tenant_id FROM users WHERE id=?", (args.user_id,)).fetchone()
    if row is None:
        raise SystemExit("unknown user id")
    print(mint_token(s, args.user_id, row["tenant_id"], args.ttl))
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    s = get_settings()
    db, audit = Database(s.db_path), _audit(s)
    tenants = (
        [args.tenant]
        if args.tenant
        else [r["id"] for r in db.conn.execute("SELECT id FROM tenants")] + ["_system"]
    )
    bad = 0
    for t in tenants:
        r = audit.verify(db.conn, t)
        print(
            f"{t}: {'OK' if r.ok else 'BROKEN at seq ' + str(r.first_bad_seq)} ({r.checked} rows)"
        )
        bad += not r.ok
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=get_settings().log_level)
    p = argparse.ArgumentParser(prog="permrag")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=_cmd_serve)

    t = sub.add_parser("create-tenant", help="create a tenant with its admin role and first admin")
    t.add_argument("name")
    t.add_argument("--admin-email", required=True)
    t.set_defaults(func=_cmd_create_tenant)

    k = sub.add_parser("token", help="mint a development token (HS* only)")
    k.add_argument("user_id")
    k.add_argument("--ttl", type=int, default=3600)
    k.set_defaults(func=_cmd_token)

    v = sub.add_parser("verify-audit", help="verify the audit chain (all tenants by default)")
    v.add_argument("--tenant")
    v.set_defaults(func=_cmd_verify_audit)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
