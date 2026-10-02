"""Tamper-evident audit log: a per-tenant HMAC chain.

Each row stores ``hmac = HMAC(key, prev_hmac || canonical(row fields))``. Editing, deleting or
reordering any row breaks the chain from that point on, and an attacker with database write access
but without the HMAC key (kept outside the database) cannot recompute it. The log is append-only
by construction: this module only ever INSERTs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

GENESIS = "0" * 64
SYSTEM_TENANT = "_system"


def _canonical(tenant_id: str, ts: float, actor: str | None, action: str, detail: str) -> bytes:
    return json.dumps([tenant_id, ts, actor, action, detail], separators=(",", ":")).encode()


def _mac(key: bytes, prev: str, payload: bytes) -> str:
    return hmac.new(key, prev.encode() + payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


class AuditLog:
    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("audit HMAC key must not be empty")
        self._key = key

    def append(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        actor: str | None,
        action: str,
        detail: dict[str, Any],
    ) -> int:
        """Append one event. Must be called with an open transaction or autocommit connection;
        the read of the previous hmac and the insert are done under BEGIN IMMEDIATE so two
        writers cannot fork the chain."""
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)
        own_tx = not conn.in_transaction
        if own_tx:
            conn.execute("BEGIN IMMEDIATE")
        try:
            last = conn.execute(
                "SELECT hmac FROM audit_log WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            prev = last["hmac"] if last else GENESIS
            ts = time.time()
            mac = _mac(self._key, prev, _canonical(tenant_id, ts, actor, action, detail_json))
            cur = conn.execute(
                "INSERT INTO audit_log(tenant_id, ts, actor, action, detail, prev_hmac, hmac) "
                "VALUES (?,?,?,?,?,?,?)",
                (tenant_id, ts, actor, action, detail_json, prev, mac),
            )
            seq = int(cur.lastrowid or 0)
        except BaseException:
            if own_tx:
                conn.execute("ROLLBACK")
            raise
        if own_tx:
            conn.execute("COMMIT")
        return seq

    def verify(self, conn: sqlite3.Connection, tenant_id: str) -> VerifyResult:
        prev = GENESIS
        checked = 0
        for r in conn.execute(
            "SELECT seq, ts, actor, action, detail, prev_hmac, hmac FROM audit_log "
            "WHERE tenant_id=? ORDER BY seq",
            (tenant_id,),
        ):
            expected = _mac(
                self._key,
                prev,
                _canonical(tenant_id, r["ts"], r["actor"], r["action"], r["detail"]),
            )
            if r["prev_hmac"] != prev:
                return VerifyResult(False, checked, r["seq"], "chain link broken (row removed?)")
            if not hmac.compare_digest(r["hmac"], expected):
                return VerifyResult(False, checked, r["seq"], "row content does not match its MAC")
            prev = r["hmac"]
            checked += 1
        return VerifyResult(True, checked)

    @staticmethod
    def read(
        conn: sqlite3.Connection, tenant_id: str, *, after_seq: int = 0, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT seq, ts, actor, action, detail FROM audit_log "
            "WHERE tenant_id=? AND seq>? ORDER BY seq LIMIT ?",
            (tenant_id, after_seq, limit),
        ).fetchall()
        return [
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "actor": r["actor"],
                "action": r["action"],
                "detail": json.loads(r["detail"]),
            }
            for r in rows
        ]
