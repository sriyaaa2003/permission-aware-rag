"""HTTP API. Handlers authenticate, validate and delegate; policy lives in access/service/store."""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .. import store
from ..access import User, load_user
from ..audit import SYSTEM_TENANT, AuditLog
from ..auth import AuthError, verify_token
from ..config import Settings, get_settings
from ..db import Database
from ..embeddings import Embedder, FastEmbedEmbedder
from ..llm import build_provider
from ..service import RagService, ServiceError

log = logging.getLogger("permrag")


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    top_k: int | None = Field(default=None, ge=1)


class DocumentBody(BaseModel):
    title: str = Field(default="", max_length=500)
    text: str = Field(min_length=1)
    visibility: str = Field(default="restricted", pattern="^(tenant|restricted)$")
    allowed_roles: list[str] = []
    allowed_users: list[str] = []


class RoleBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class UserBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    roles: list[str] = []


class RolesBody(BaseModel):
    roles: list[str]


class _RateLimiter:
    """Sliding-window limiter per user id (in-process; use the gateway for multi-instance)."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        if self.per_minute <= 0:
            return
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                raise HTTPException(429, "rate limit exceeded")
            q.append(now)


def build_service(settings: Settings, embedder: Embedder | None = None) -> RagService:
    if settings.audit_hmac_key is None:
        raise RuntimeError("PR_AUDIT_HMAC_KEY must be set")
    db = Database(settings.db_path)
    llm = None
    if settings.llm_provider and settings.llm_model_id:
        llm = build_provider(
            settings.llm_provider,
            settings.llm_model_id,
            base_url=settings.llm_base_url,
            api_key_env=settings.llm_api_key_env,
            timeout=settings.llm_timeout_seconds,
        )
    audit = AuditLog(settings.audit_hmac_key.get_secret_value().encode())
    return RagService(
        db, embedder or FastEmbedEmbedder(settings.embedding_model), settings, audit, llm
    )


def create_app(
    settings: Settings | None = None,
    *,
    service: RagService | None = None,
    rate_limit_per_minute: int | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    svc = service or build_service(settings)
    db, audit = svc.db, svc.audit
    limiter = _RateLimiter(
        settings.rate_limit_per_minute if rate_limit_per_minute is None else rate_limit_per_minute
    )
    app = FastAPI(title="permrag", version="0.1.0")

    def current_user(authorization: Annotated[str | None, Header()] = None) -> User:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        try:
            claims = verify_token(authorization[7:].strip(), settings)
        except AuthError as exc:
            raise HTTPException(401, str(exc)) from exc
        user = load_user(db.conn, claims.user_id, settings.admin_role_name)
        if user is None or user.tenant_id != claims.tenant_id:
            audit.append(
                db.conn,
                SYSTEM_TENANT,
                None,
                "auth.denied",
                {"sub": claims.user_id, "claimed_tenant": claims.tenant_id},
            )
            raise HTTPException(401, "unknown or inactive user")
        limiter.check(user.id)
        return user

    def admin_user(user: Annotated[User, Depends(current_user)]) -> User:
        if not user.is_admin:
            audit.append(db.conn, user.tenant_id, user.id, "auth.forbidden", {"needed": "admin"})
            raise HTTPException(403, "admin role required")
        return user

    caller = Annotated[User, Depends(current_user)]
    admin = Annotated[User, Depends(admin_user)]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ----- retrieval ------------------------------------------------------------------------
    @app.post("/v1/search")
    def search(body: SearchRequest, user: caller) -> dict[str, Any]:
        res = svc.search_and_audit(user, body.query, body.top_k)
        return {
            "results": [
                {
                    "document": c.external_id,
                    "title": c.title,
                    "chunk_id": c.chunk_id,
                    "score": c.score,
                    "text": c.text,
                }
                for c in res.chunks
            ]
        }

    @app.post("/v1/query")
    def query(body: SearchRequest, user: caller) -> dict[str, Any]:
        try:
            r = svc.answer(user, body.query, body.top_k)
        except ServiceError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        return {
            "answer": r.answer,
            "abstained": r.abstained,
            "citations": r.citations,
            "model": r.model,
            "usage": r.usage,
        }

    @app.get("/v1/documents")
    def list_documents(user: caller) -> list[dict[str, Any]]:
        marks = ",".join("?" * len(user.principals))
        rows = db.conn.execute(
            "SELECT DISTINCT d.external_id, d.title, d.visibility, d.updated_at FROM documents d "
            "LEFT JOIN document_acl a ON a.document_id = d.id "
            f"WHERE d.tenant_id=? AND (d.visibility='tenant' OR a.principal IN ({marks})) "
            "ORDER BY d.external_id",
            (user.tenant_id, *sorted(user.principals)),
        ).fetchall()
        return [dict(r) for r in rows]

    # ----- document administration ---------------------------------------------------------------
    @app.put("/v1/documents/{external_id:path}")
    def put_document(external_id: str, body: DocumentBody, user: admin) -> dict[str, str]:
        if len(body.text) > settings.max_document_chars:
            raise HTTPException(413, "document too large")
        try:
            result = store.upsert_document(
                db.conn,
                audit,
                svc.embedder,
                user.tenant_id,
                user.id,
                store.DocumentSpec(
                    external_id,
                    body.title,
                    body.text,
                    body.visibility,
                    body.allowed_roles,
                    body.allowed_users,
                ),
                chunk_chars=settings.chunk_chars,
                overlap=settings.chunk_overlap_chars,
            )
        except store.NotFoundError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"external_id": external_id, "result": result}

    @app.delete("/v1/documents/{external_id:path}")
    def delete_document(external_id: str, user: admin) -> dict[str, str]:
        try:
            store.delete_document(db.conn, audit, user.tenant_id, user.id, external_id)
        except store.NotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"deleted": external_id}

    @app.get("/v1/admin/documents")
    def admin_documents(user: admin) -> list[dict[str, Any]]:
        """Metadata only. Being an admin does not grant the right to read document content."""
        rows = db.conn.execute(
            "SELECT d.external_id, d.title, d.visibility, d.owner_user_id, "
            "(SELECT group_concat(principal) FROM document_acl WHERE document_id=d.id) AS acl "
            "FROM documents d WHERE d.tenant_id=? ORDER BY d.external_id",
            (user.tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ----- identity administration -----------------------------------------------------------------
    @app.post("/v1/admin/roles", status_code=201)
    def create_role(body: RoleBody, user: admin) -> dict[str, str]:
        try:
            rid = store.create_role(db.conn, audit, user.tenant_id, body.name, user.id)
        except store.ConflictError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"id": rid, "name": body.name}

    @app.post("/v1/admin/users", status_code=201)
    def create_user(body: UserBody, user: admin) -> dict[str, str]:
        try:
            uid = store.create_user(db.conn, audit, user.tenant_id, body.email, body.roles, user.id)
        except store.ConflictError as exc:
            raise HTTPException(409, str(exc)) from exc
        except store.NotFoundError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": uid, "email": body.email}

    @app.put("/v1/admin/users/{user_id}/roles")
    def set_roles(user_id: str, body: RolesBody, user: admin) -> dict[str, Any]:
        try:
            store.set_user_roles(db.conn, audit, user.tenant_id, user_id, body.roles, user.id)
        except store.NotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"user_id": user_id, "roles": body.roles}

    @app.delete("/v1/admin/users/{user_id}")
    def deactivate(user_id: str, user: admin) -> dict[str, str]:
        try:
            store.deactivate_user(db.conn, audit, user.tenant_id, user_id, user.id)
        except store.NotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"deactivated": user_id}

    # ----- audit -----------------------------------------------------------------------------
    @app.get("/v1/audit")
    def read_audit(
        user: admin,
        after_seq: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, Any]]:
        return audit.read(db.conn, user.tenant_id, after_seq=after_seq, limit=limit)

    @app.get("/v1/audit/verify")
    def verify_audit(user: admin) -> dict[str, Any]:
        r = audit.verify(db.conn, user.tenant_id)
        return {
            "ok": r.ok,
            "checked": r.checked,
            "first_bad_seq": r.first_bad_seq,
            "reason": r.reason,
        }

    return app
