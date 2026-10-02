"""Tenant-scoped vector index with *pre-filtering*.

Ranking only ever sees chunks the caller is allowed to read. Filtering after ranking ("retrieve
top-k, then drop what the user cannot see") is deliberately not done: it leaks through result
counts and returns too few results. Permission is always read fresh from ``chunk_acl``; the cached
matrix only supplies vectors, so a stale cache can never grant access.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

import numpy as np

from .db import Database
from .embeddings import from_blob


@dataclass(frozen=True)
class Hit:
    chunk_id: int
    score: float


@dataclass
class _TenantMatrix:
    version: int
    row_of: dict[int, int]
    mat: np.ndarray


class TenantIndex:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.Lock()
        self._cache: dict[str, _TenantMatrix] = {}

    def _matrix(self, tenant_id: str) -> _TenantMatrix | None:
        row = self._db.conn.execute(
            "SELECT data_version v FROM tenants WHERE id=?", (tenant_id,)
        ).fetchone()
        if row is None:
            return None
        version = int(row["v"])
        with self._lock:
            cached = self._cache.get(tenant_id)
            if cached and cached.version == version:
                return cached
        rows = self._db.conn.execute(
            "SELECT id, embedding FROM chunks WHERE tenant_id=? ORDER BY id", (tenant_id,)
        ).fetchall()
        mat = (
            np.stack([from_blob(r["embedding"]) for r in rows])
            if rows
            else np.zeros((0, 0), dtype=np.float32)
        )
        built = _TenantMatrix(version, {int(r["id"]): i for i, r in enumerate(rows)}, mat)
        with self._lock:
            self._cache[tenant_id] = built
        return built

    def allowed_chunk_ids(self, tenant_id: str, principals: frozenset[str]) -> list[int]:
        if not principals:
            return []
        marks = ",".join("?" * len(principals))
        rows = self._db.conn.execute(
            f"SELECT DISTINCT chunk_id FROM chunk_acl WHERE tenant_id=? AND principal IN ({marks})",
            (tenant_id, *sorted(principals)),
        ).fetchall()
        return [int(r["chunk_id"]) for r in rows]

    def search(
        self, tenant_id: str, principals: frozenset[str], query_vec: np.ndarray, k: int
    ) -> tuple[list[Hit], int]:
        """Return (top-k hits among permitted chunks, number of permitted chunks)."""
        allowed = self.allowed_chunk_ids(tenant_id, principals)
        m = self._matrix(tenant_id)
        if m is None or not allowed:
            return [], len(allowed)
        ids = [cid for cid in allowed if cid in m.row_of]
        if not ids:
            return [], len(allowed)
        rows = np.fromiter((m.row_of[c] for c in ids), dtype=np.int64, count=len(ids))
        scores = m.mat[rows] @ query_vec
        k = min(k, len(ids))
        top = np.argpartition(-scores, k - 1)[:k]
        top = top[np.argsort(-scores[top])]
        return [Hit(ids[i], float(scores[i])) for i in top], len(allowed)
