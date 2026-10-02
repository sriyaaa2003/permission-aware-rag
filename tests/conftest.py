"""Test doubles live here only. Production code never imports from tests."""

from __future__ import annotations

import hashlib
import re

import numpy as np
import pytest

from permrag import store
from permrag.audit import AuditLog
from permrag.auth import mint_token
from permrag.config import Settings
from permrag.db import Database
from permrag.embeddings import normalise
from permrag.llm import LLMResult
from permrag.service import RagService

KEY = b"test-audit-hmac-key"


class HashEmbedder:
    """Deterministic bag-of-words embedder. Test-only."""

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), 512), dtype=np.float32)
        for i, t in enumerate(texts):
            for w in re.findall(r"[a-z0-9']+", t.lower()):
                out[i, int(hashlib.md5(w.encode()).hexdigest(), 16) % 512] += 1.0  # noqa: S324
        return normalise(out)


class FakeLLM:
    """Records every prompt it receives; replies with a scripted answer."""

    def __init__(self, reply: str = "Answer based on the passage [1].") -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def generate(self, system: str, user: str, *, max_tokens: int, temperature: float) -> LLMResult:
        self.prompts.append(user)
        return LLMResult(self.reply, 100, 10, 1.0)


@pytest.fixture
def settings(tmp_path):
    return Settings(
        db_path=str(tmp_path / "t.db"),
        jwt_key="jwt-secret-for-tests-0123456789abcdef",
        audit_hmac_key=KEY.decode(),
        chunk_chars=400,
        chunk_overlap_chars=20,
        llm_model_id="fake-model",
    )


@pytest.fixture
def db(settings):
    return Database(settings.db_path)


@pytest.fixture
def audit():
    return AuditLog(KEY)


@pytest.fixture
def llm():
    return FakeLLM()


@pytest.fixture
def svc(db, settings, audit, llm):
    return RagService(db, HashEmbedder(), settings, audit, llm)


class World:
    """A small two-tenant world built through the real store functions."""

    def __init__(self, db, audit, svc, settings):
        self.db, self.audit, self.svc, self.settings = db, audit, svc, settings
        c = db.conn
        self.t1 = store.create_tenant(c, audit, "acme")
        self.t2 = store.create_tenant(c, audit, "globex")
        for t in (self.t1, self.t2):
            store.create_role(c, audit, t, "admin", None)
            store.create_role(c, audit, t, "finance", None)
            store.create_role(c, audit, t, "eng", None)
        self.admin1 = store.create_user(c, audit, self.t1, "admin@acme", ["admin"], None)
        self.fin1 = store.create_user(c, audit, self.t1, "fin@acme", ["finance"], None)
        self.eng1 = store.create_user(c, audit, self.t1, "eng@acme", ["eng"], None)
        self.admin2 = store.create_user(c, audit, self.t2, "admin@globex", ["admin"], None)

    def put(self, tenant, actor, ext, text, visibility="restricted", roles=(), users=()):
        return store.upsert_document(
            self.db.conn,
            self.audit,
            self.svc.embedder,
            tenant,
            actor,
            store.DocumentSpec(ext, ext, text, visibility, list(roles), list(users)),
            chunk_chars=self.settings.chunk_chars,
            overlap=self.settings.chunk_overlap_chars,
        )

    def user(self, uid):
        from permrag.access import load_user

        return load_user(self.db.conn, uid, "admin")

    def token(self, uid, tid):
        return mint_token(self.settings, uid, tid)


@pytest.fixture
def world(db, audit, svc, settings):
    return World(db, audit, svc, settings)
