"""Randomised check of the central guarantee: retrieval returns exactly the documents the caller is
authorized to read, no more (leakage) and no fewer (over-filtering). The oracle is computed from the
generated world description in plain Python, independently of the SQL and index code."""

import random

import pytest

from permrag import store
from permrag.audit import AuditLog
from permrag.config import Settings
from permrag.db import Database
from permrag.service import RagService

from .conftest import KEY, FakeLLM, HashEmbedder

WORDS = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu".split()


def build_world(tmp_path, seed):
    rng = random.Random(seed)
    settings = Settings(
        db_path=str(tmp_path / f"w{seed}.db"),
        jwt_key="k" * 32,
        audit_hmac_key=KEY.decode(),
        chunk_chars=400,
        chunk_overlap_chars=20,
    )
    db, audit = Database(settings.db_path), AuditLog(KEY)
    llm = FakeLLM()
    svc = RagService(db, HashEmbedder(), settings, audit, llm)
    c = db.conn

    users: dict[str, dict] = {}  # id -> {tenant, roles:set(names)}
    roles_by_tenant: dict[str, list[str]] = {}
    tenants = []
    for ti in range(rng.randint(2, 3)):
        tid = store.create_tenant(c, audit, f"t{ti}")
        tenants.append(tid)
        names = [f"r{i}" for i in range(rng.randint(2, 4))] + ["admin"]
        roles_by_tenant[tid] = names
        for n in names:
            store.create_role(c, audit, tid, n, None)
        for ui in range(rng.randint(2, 4)):
            my_roles = rng.sample(names, rng.randint(0, 2))
            uid = store.create_user(c, audit, tid, f"u{ti}{ui}@x", my_roles, None)
            users[uid] = {"tenant": tid, "roles": set(my_roles)}

    docs = []  # oracle records
    for di in range(rng.randint(8, 20)):
        tid = rng.choice(tenants)
        tenant_users = [u for u, v in users.items() if v["tenant"] == tid]
        owner = rng.choice(tenant_users)
        vis = rng.choice(["tenant", "restricted", "restricted"])
        allowed_roles = (
            rng.sample(roles_by_tenant[tid], rng.randint(0, 2)) if vis == "restricted" else []
        )
        allowed_users = rng.sample(tenant_users, rng.randint(0, 2)) if vis == "restricted" else []
        marker = f"MARK{di}x"
        text = f"{marker} " + " ".join(rng.choices(WORDS, k=rng.randint(3, 8)))
        store.upsert_document(
            c,
            audit,
            svc.embedder,
            tid,
            owner,
            store.DocumentSpec(f"d{di}", f"d{di}", text, vis, allowed_roles, allowed_users),
            chunk_chars=400,
            overlap=20,
        )
        docs.append(
            {
                "ext": f"d{di}",
                "tenant": tid,
                "owner": owner,
                "vis": vis,
                "roles": set(allowed_roles),
                "users": set(allowed_users),
                "marker": marker,
            }
        )
    return svc, llm, users, docs


def oracle(user_id, users, docs):
    u = users[user_id]
    out = set()
    for d in docs:
        if d["tenant"] != u["tenant"]:
            continue
        if (
            d["vis"] == "tenant"
            or user_id == d["owner"]
            or user_id in d["users"]
            or (u["roles"] & d["roles"])
        ):
            out.add(d["ext"])
    return out


@pytest.mark.parametrize("seed", range(40))
def test_retrieval_equals_authorization_oracle(tmp_path, seed):
    from permrag.access import load_user

    svc, llm, users, docs = build_world(tmp_path, seed)
    rng = random.Random(seed + 1000)
    for uid in users:
        user = load_user(svc.db.conn, uid, "admin")
        expected = oracle(uid, users, docs)
        query = " ".join(rng.choices(WORDS, k=3))
        res = svc.search(user, query, top_k=20)  # k >= number of docs: completeness is checkable
        got = {c.external_id for c in res.chunks}
        assert got == expected, (
            f"seed={seed} user={uid} leak={got - expected} missing={expected - got}"
        )
        assert res.violations == 0  # the pre-filter alone was already correct
        # the generated prompt must also contain nothing outside the permitted set
        if expected:
            svc.answer(user, query, top_k=20)
            prompt = llm.prompts[-1]
            forbidden = {d["marker"] for d in docs if d["ext"] not in expected}
            assert not any(m in prompt for m in forbidden)


@pytest.mark.parametrize("seed", range(10))
def test_random_mutations_keep_retrieval_consistent(tmp_path, seed):
    """Role changes, ACL edits and deletions interleaved with searches never leave stale access."""
    from permrag.access import load_user

    svc, _, users, docs = build_world(tmp_path, seed)
    rng = random.Random(seed)
    c, audit = svc.db.conn, svc.audit
    for _ in range(15):
        d = rng.choice(docs)
        tenant_users = [u for u, v in users.items() if v["tenant"] == d["tenant"]]
        action = rng.choice(["acl", "role", "delete", "noop"])
        if action == "acl" and d in docs:
            roles = rng.sample(
                [
                    r["name"]
                    for r in c.execute("SELECT name FROM roles WHERE tenant_id=?", (d["tenant"],))
                ],
                1,
            )
            store.upsert_document(
                c,
                audit,
                svc.embedder,
                d["tenant"],
                d["owner"],
                store.DocumentSpec(
                    d["ext"], d["ext"], f"{d['marker']} edited alpha", "restricted", roles, []
                ),
                chunk_chars=400,
                overlap=20,
            )
            d.update(vis="restricted", roles=set(roles), users=set())
        elif action == "role":
            uid = rng.choice(tenant_users)
            names = [
                r["name"]
                for r in c.execute("SELECT name FROM roles WHERE tenant_id=?", (d["tenant"],))
            ]
            new = set(rng.sample(names, rng.randint(0, 2)))
            store.set_user_roles(c, audit, d["tenant"], uid, sorted(new), None)
            users[uid]["roles"] = new
        elif action == "delete":
            store.delete_document(c, audit, d["tenant"], d["owner"], d["ext"])
            docs.remove(d)
            if not docs:
                break
        for uid in users:
            res = svc.search(load_user(c, uid, "admin"), "alpha beta gamma", top_k=50)
            assert {x.external_id for x in res.chunks} == oracle(uid, users, docs)
