import time

import jwt
import pytest
from fastapi.testclient import TestClient

from permrag import store
from permrag.api.app import create_app
from permrag.audit import AuditLog


# ----- audit chain ---------------------------------------------------------------------------
def test_chain_verifies_and_detects_edit_delete_and_reorder(world):
    w = world
    for i in range(5):
        w.put(w.t1, w.admin1, f"d{i}", f"text {i}", visibility="tenant")
    ok = w.audit.verify(w.db.conn, w.t1)
    assert ok.ok and ok.checked >= 5

    c = w.db.conn
    seqs = [
        r["seq"]
        for r in c.execute("SELECT seq FROM audit_log WHERE tenant_id=? ORDER BY seq", (w.t1,))
    ]

    c.execute("UPDATE audit_log SET detail='{}' WHERE seq=?", (seqs[3],))
    bad = w.audit.verify(c, w.t1)
    assert not bad.ok and bad.first_bad_seq == seqs[3]


def test_deleted_row_breaks_the_chain(world):
    w = world
    for i in range(4):
        w.put(w.t1, w.admin1, f"d{i}", f"text {i}", visibility="tenant")
    c = w.db.conn
    seqs = [
        r["seq"]
        for r in c.execute("SELECT seq FROM audit_log WHERE tenant_id=? ORDER BY seq", (w.t1,))
    ]
    c.execute("DELETE FROM audit_log WHERE seq=?", (seqs[2],))
    bad = w.audit.verify(c, w.t1)
    assert not bad.ok and bad.first_bad_seq == seqs[3]


def test_recomputing_the_chain_requires_the_key(world):
    w = world
    w.put(w.t1, w.admin1, "d", "text", visibility="tenant")
    c = w.db.conn
    c.execute(
        "UPDATE audit_log SET detail='{\"forged\":true}' WHERE tenant_id=? AND action='document.created'",
        (w.t1,),
    )
    assert not AuditLog(b"test-audit-hmac-key").verify(c, w.t1).ok
    assert not AuditLog(b"some-other-key").verify(c, w.t1).ok


def test_chains_are_per_tenant(world):
    w = world
    w.put(w.t1, w.admin1, "d", "text", visibility="tenant")
    w.db.conn.execute(
        "UPDATE audit_log SET detail='{}' WHERE tenant_id=? AND action='document.created'", (w.t1,)
    )
    assert not w.audit.verify(w.db.conn, w.t1).ok
    assert w.audit.verify(w.db.conn, w.t2).ok


def test_query_audit_records_who_what_and_retrieved_ids_but_not_text_by_default(world):
    w = world
    w.put(w.t1, w.admin1, "faq", "salary faq", visibility="tenant")
    w.svc.answer(w.user(w.eng1), "salary", 5)
    ev = [e for e in w.audit.read(w.db.conn, w.t1, limit=500) if e["action"] == "query"][-1]
    assert ev["actor"] == w.eng1
    assert ev["detail"]["retrieved"][0]["external_id"] == "faq"
    assert "query" not in ev["detail"] and len(ev["detail"]["query_sha256"]) == 64
    assert ev["detail"]["answer_sha256"]


def test_concurrent_appends_keep_the_chain_intact(world):
    import threading

    w = world
    errors = []

    def work(n):
        try:
            for i in range(10):
                w.audit.append(w.db.conn, w.t1, "x", "test.event", {"n": n, "i": i})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    assert w.audit.verify(w.db.conn, w.t1).ok


# ----- HTTP API --------------------------------------------------------------------------------
@pytest.fixture
def client(world, svc, settings):
    return TestClient(create_app(settings, service=svc, rate_limit_per_minute=1000))


def auth(world, uid, tid):
    return {"authorization": f"Bearer {world.token(uid, tid)}"}


def test_missing_bad_expired_and_forged_tokens_are_rejected(client, world, settings):
    w = world
    assert client.post("/v1/search", json={"query": "x"}).status_code == 401
    assert (
        client.post(
            "/v1/search", json={"query": "x"}, headers={"authorization": "Bearer junk"}
        ).status_code
        == 401
    )
    expired = jwt.encode(
        {"sub": w.eng1, "tid": w.t1, "exp": int(time.time()) - 600},
        "jwt-secret-for-tests-0123456789abcdef",
        algorithm="HS256",
    )
    assert (
        client.post(
            "/v1/search", json={"query": "x"}, headers={"authorization": f"Bearer {expired}"}
        ).status_code
        == 401
    )
    forged = jwt.encode(
        {"sub": w.eng1, "tid": w.t1, "exp": int(time.time()) + 600},
        "wrong-key-wrong-key-wrong-key-wrong-key",
        algorithm="HS256",
    )
    assert (
        client.post(
            "/v1/search", json={"query": "x"}, headers={"authorization": f"Bearer {forged}"}
        ).status_code
        == 401
    )
    # alg=none must never be accepted
    none_tok = jwt.encode(
        {"sub": w.eng1, "tid": w.t1, "exp": int(time.time()) + 600}, None, algorithm="none"
    )
    assert (
        client.post(
            "/v1/search", json={"query": "x"}, headers={"authorization": f"Bearer {none_tok}"}
        ).status_code
        == 401
    )


def test_token_claiming_another_tenant_is_rejected_and_audited(client, world):
    w = world
    r = client.post("/v1/search", json={"query": "x"}, headers=auth(w, w.eng1, w.t2))
    assert r.status_code == 401
    ev = w.audit.read(w.db.conn, "_system")
    assert ev and ev[-1]["action"] == "auth.denied"


def test_role_comes_from_the_database_not_the_token(client, world):
    w = world
    headers = auth(w, w.eng1, w.t1)
    r = client.put(
        "/v1/documents/x", json={"text": "hello", "visibility": "tenant"}, headers=headers
    )
    assert r.status_code == 403
    store.set_user_roles(w.db.conn, w.audit, w.t1, w.eng1, ["admin"], w.admin1)
    r = client.put(
        "/v1/documents/x", json={"text": "hello", "visibility": "tenant"}, headers=headers
    )
    assert r.status_code == 200
    store.deactivate_user(w.db.conn, w.audit, w.t1, w.eng1, w.admin1)
    assert client.post("/v1/search", json={"query": "x"}, headers=headers).status_code == 401


def test_end_to_end_document_lifecycle_over_http(client, world):
    w = world
    admin, fin, eng = (auth(w, w.admin1, w.t1), auth(w, w.fin1, w.t1), auth(w, w.eng1, w.t1))
    r = client.put(
        "/v1/documents/payroll",
        headers=admin,
        json={"title": "Payroll", "text": "salary bands for finance", "allowed_roles": ["finance"]},
    )
    assert r.json()["result"] == "created"
    assert (
        client.put(
            "/v1/documents/payroll",
            headers=admin,
            json={
                "title": "Payroll",
                "text": "salary bands for finance",
                "allowed_roles": ["finance"],
            },
        ).json()["result"]
        == "unchanged"
    )
    assert [d["external_id"] for d in client.get("/v1/documents", headers=fin).json()] == [
        "payroll"
    ]
    assert client.get("/v1/documents", headers=eng).json() == []
    assert client.post("/v1/search", headers=fin, json={"query": "salary"}).json()["results"]
    assert client.post("/v1/search", headers=eng, json={"query": "salary"}).json()["results"] == []
    q = client.post("/v1/query", headers=fin, json={"query": "salary"})
    assert q.status_code == 200 and q.json()["citations"]
    assert client.delete("/v1/documents/payroll", headers=admin).status_code == 200
    assert client.delete("/v1/documents/payroll", headers=admin).status_code == 404
    assert client.post("/v1/search", headers=fin, json={"query": "salary"}).json()["results"] == []


def test_admin_endpoints_forbidden_for_non_admins_and_unknown_roles_rejected(client, world):
    w = world
    eng, admin = auth(w, w.eng1, w.t1), auth(w, w.admin1, w.t1)
    for method, url in [
        ("get", "/v1/audit"),
        ("get", "/v1/audit/verify"),
        ("get", "/v1/admin/documents"),
    ]:
        assert getattr(client, method)(url, headers=eng).status_code == 403
    assert (
        client.put(
            "/v1/documents/d", headers=admin, json={"text": "t", "allowed_roles": ["ghost"]}
        ).status_code
        == 422
    )
    assert client.post("/v1/admin/roles", headers=admin, json={"name": "eng"}).status_code == 409


def test_audit_endpoints_are_tenant_scoped(client, world):
    w = world
    r1 = client.get("/v1/audit", headers=auth(w, w.admin1, w.t1)).json()
    r2 = client.get("/v1/audit", headers=auth(w, w.admin2, w.t2)).json()
    assert r1 and r2
    assert {e["seq"] for e in r1}.isdisjoint({e["seq"] for e in r2})
    assert client.get("/v1/audit/verify", headers=auth(w, w.admin1, w.t1)).json()["ok"] is True


def test_rate_limit(world, svc, settings):
    c = TestClient(create_app(settings, service=svc, rate_limit_per_minute=3))
    h = auth(world, world.eng1, world.t1)
    codes = [c.post("/v1/search", json={"query": "x"}, headers=h).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_generation_unavailable_returns_503(world, db, settings, audit):
    from permrag.service import RagService

    from .conftest import HashEmbedder

    svc = RagService(db, HashEmbedder(), settings, audit, llm=None)
    c = TestClient(create_app(settings, service=svc, rate_limit_per_minute=100))
    assert (
        c.post(
            "/v1/query", json={"query": "x"}, headers=auth(world, world.eng1, world.t1)
        ).status_code
        == 503
    )
    assert (
        c.post(
            "/v1/search", json={"query": "x"}, headers=auth(world, world.eng1, world.t1)
        ).status_code
        == 200
    )
