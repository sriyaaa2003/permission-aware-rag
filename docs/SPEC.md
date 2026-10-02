# permrag: technical specification

Items marked **REQUIRES USER DECISION** need an input that cannot be derived from the requirements.

## 1. Purpose and boundaries

**Does:** multi-tenant retrieval and grounded answering where every returned or prompted chunk is one the
caller may read; immediate effect of permission changes; a tamper-evident record of access.

**Does not:** act as an identity provider (it verifies tokens issued elsewhere); provide per-section ACLs,
groups, deny rules or attribute-based policies; cache answers across users; run tools or agents; guarantee
factual correctness.

**Actors:** *platform operator* (CLI: creates tenants, mints dev tokens, verifies audit), *tenant admin*
(role `admin`: manages roles, users, documents, reads audit), *user* (searches, asks), *identity provider*
(external), *LLM provider* (external, optional).

## 2. Requirements

| # | Requirement | Priority | Verified by |
|---|---|---|---|
| S1 | A user never receives, and the model never sees, text from a document they cannot read | must | `test_fuzz_isolation`, `test_access_control` |
| S2 | Tenants are fully isolated | must | fuzz (2–3 tenants per world), cross-tenant tests |
| S3 | Permission changes (role, ACL, visibility, delete, deactivate) apply on the next request | must | `test_access_control` and mutation fuzz |
| S4 | Authorization is applied before ranking (no post-filter result leaks) | must | `test_prefilter_returns_full_k_...` |
| S5 | A second, independent check runs before prompt assembly | must | `test_defence_in_depth_...` |
| S6 | Every query/search is audited; the audit log is tamper-evident | must | `test_audit_api` |
| S7 | Forged, expired, unsigned or wrong-tenant tokens are rejected | must | `test_audit_api` |
| S8 | Admin actions require the admin role, read from the DB | must | `test_audit_api` |
| S9 | Generation output validated against the supplied passages | must | `test_access_control` |
| F1 | Idempotent document upsert (content, visibility, ACL); delete removes all derived data | must | `test_access_control` |
| F2 | Retrieval works without an LLM (`/v1/search`) | should | `test_audit_api` |
| N1 | No secret stored in the database | must | design |
| N2 | Typed, linted, tested | must | CI |

## 3. Architecture

Modular monolith. `api/app.py` (authentication, authorization of the *action*, validation) → `service.py`
(search/answer, defence in depth, audit) → `index.py` (pre-filtered ranking), `access.py` (policy),
`store.py` (transactional mutations), `audit.py` (HMAC chain), `auth.py` (token verification), `llm.py`.

### Request path (query)

1. **Identity.** Verify the token (explicit algorithm list; `exp`, `sub`, `tid` required; issuer if set).
2. **Fresh user load.** `users` ⨝ `tenants` with `active=1`; roles read from the DB. The token's `tid` must equal
   the user's real tenant; otherwise 401 and an `auth.denied` audit event in the `_system` chain.
3. **Principals.** `user:<id>`, `tenant:<tid>`, `role:<role id>` for each role.
4. **Pre-filter.** `SELECT DISTINCT chunk_id FROM chunk_acl WHERE tenant_id=? AND principal IN (…)`.
5. **Rank.** Cosine similarity over the permitted rows of the tenant's matrix. The matrix is cached per tenant
   and keyed on `tenants.data_version`; it supplies vectors only. **Permission is always read fresh**, so a
   stale cache can omit new chunks but can never grant access.
6. **Re-check.** For each hit, `authorize_document()` evaluates the authoritative `document_acl` and the
   tenant. Failure → dropped, `security.violation` audited, request continues with the rest.
7. **Prompt.** Passages are HTML-escaped and wrapped in `<passage id="n">`; no tools are provided.
8. **Validate.** Citations must be within the supplied passage ids; otherwise 502.
9. **Audit.** One event with the query hash, permitted-candidate count, retrieved ids and scores, answer hash.

## 4. Data model (migrations in `src/permrag/migrations`)

`tenants(id, active, data_version)` · `users(tenant_id, email, active)` · `roles(tenant_id, name)` ·
`user_roles` · `documents(tenant_id, external_id, visibility, owner_user_id, content_hash)` ·
`document_acl(document_id, principal)` **authoritative** · `chunks(tenant_id, text, embedding)` ·
`chunk_acl(chunk_id, tenant_id, principal)` **derived**, indexed on `(tenant_id, principal, chunk_id)` ·
`audit_log(seq, tenant_id, ts, actor, action, detail, prev_hmac, hmac)`.

Every mutation (`store.py`) is one `BEGIN IMMEDIATE` transaction that changes the data, rewrites
`chunk_acl`, bumps `data_version` and appends the audit event, so a crash cannot leave an ACL half-applied
or a change unaudited.

## 5. Policy

A user may read a document iff the document is in their tenant and either `visibility = 'tenant'` or the
document's ACL contains one of the user's principals. The owner is added to the ACL on creation. Admin does not imply
read. ACL entries must reference existing roles/users **in the same tenant** (validated on write).

## 6. API

See the README table. Conventions: bearer auth; JSON; idempotent `PUT` for documents; `DELETE` of a missing
document is 404; admin routes 403 for non-admins; rate limit per user (default 60/min, configurable).

## 7. Audit log

Per-tenant chain: `hmac_n = HMAC(key, hmac_{n-1} ‖ canonical([tenant, ts, actor, action, detail]))`, genesis
`0…0`. `append` reads the previous MAC and inserts under one write lock (`BEGIN IMMEDIATE`) so concurrent writers
cannot fork the chain (tested with 4 threads). `verify` recomputes and reports the first bad `seq`. Events:
`tenant.create`, `role.create`, `user.create|roles_set|deactivate`, `document.created|updated|delete`, `search`,
`query`, `security.violation`, `auth.forbidden`; `auth.denied` goes to the `_system` chain.
Query text is stored only when `PR_AUDIT_LOG_QUERY_TEXT=true`.

## 8. Configuration

| Item | Where | Redeploy |
|---|---|---|
| Keys (JWT, audit HMAC), algorithm, issuer, admin role name | environment | restart |
| Retrieval limits, chunking, rate limit, LLM provider/model/key-variable name | environment | restart |
| Roles, users, documents, ACLs | database via admin API | no |

REQUIRES USER DECISION: whether a database-backed runtime config (as in the sibling `ragcache`) is wanted
here; environment-only was chosen to keep the trust surface small.

## 9. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Cross-tenant read | tenant in every SQL predicate and ACL principal; same-tenant ACL validation | a bug in policy code: covered by fuzz and re-check |
| Post-filter leakage (counts, short results) | pre-filter | none by design |
| Stale permissions | roles from DB each request; no answer cache | tokens remain valid until `exp` for *identity*, not for roles |
| Forged tokens, `alg=none`, key confusion | explicit algorithm list, required claims, key length check (≥ 32 B for HS*) | key compromise |
| Cross-tenant token reuse | `tid` must equal DB tenant; audited | none |
| Prompt injection | escaping, no tools, only permitted text, citation validation | misleading but permitted content |
| Audit tampering | HMAC chain, key outside DB | tail truncation (export the head MAC) |
| Admin abuse | admin ≠ read; all admin actions audited | an admin can grant themselves a role (audited) |
| Enumeration of hidden documents | counts of *permitted* candidates only; hidden docs never ranked | timing differences |
| Brute force / abuse | per-user rate limit | in-process only |

## 10. Failure matrix

| Component | Failure | Behaviour |
|---|---|---|
| Token verification | bad/expired token | 401, no data access |
| Database | locked | 30 s busy timeout, then 500; no partial writes (transactions) |
| Pre-filter bug | unauthorized chunk ranked | dropped by re-check, `security.violation` audited |
| LLM | error/timeout | 502 `the language model is unavailable`; event audited with error |
| LLM | uncited or out-of-range citation | 502, answer not returned |
| No permitted context | nothing retrieved | abstain without calling the LLM |
| Restart | in-memory matrices lost | rebuilt lazily; permissions unaffected (they are in SQL) |
| Concurrent mutations | ACL change during query | permission read fresh; worst case one more/less chunk for that instant |
| Audit write fails | exception | the surrounding mutation rolls back (same transaction) |
| Corrupt audit row | manual edit | `verify` reports first bad seq |

## 11. Testing

Unit/integration (access control, store, audit, API), **fuzz isolation** (40 randomised worlds × all users
against an independent oracle, plus 10 mutation sequences), concurrency (audit chain). Test doubles
(hashing embedder, fake LLM) live only in `tests/`. **Not covered:** live LLM, JWKS/RS256 paths, load tests,
multi-process behaviour, independent security review.

## 12. Deployment

Single container with a volume for the SQLite file; secrets via environment/secret manager; TLS and
additional rate limiting at the gateway. REQUIRES USER DECISION: identity provider and token format
(issuer, `sub`/`tid` claim mapping, algorithm), hosting target.

## 13. Architecture decision records

**ADR-1 Pre-filter on a denormalised ACL table.** Alternatives: post-filter (leaks, short results), per-user
index copies (storage), filter in the vector DB (needs a different store). Chosen: SQL pre-filter over `chunk_acl`
with exact ranking; the seam (`TenantIndex`) maps directly onto payload-filtered vector DBs.

**ADR-2 Defence in depth.** A second policy evaluation against the authoritative table before the prompt.
Cost: one lookup per distinct document; benefit: a pre-filter bug becomes an alert rather than a breach.

**ADR-3 Roles from the database.** Alternatives: roles as token claims. Chosen so revocation is immediate.

**ADR-4 No answer cache.** A shared cache keyed on query similarity can return user A's answer to user B.

**ADR-5 HMAC chain with external key.** Alternatives: plain hash chain (recomputable by a DB writer),
external append-only store (infrastructure). Chosen for tamper evidence without new infrastructure.

**ADR-6 Roles, not groups.** Simplest model that expresses the requirement; groups add membership
resolution and nesting semantics. Extension point: more principal types in `access.load_user`.

**ADR-7 Admin cannot read by default.** Least privilege; auditable self-grant.

## 14. Definition of done and status

Implemented and tested: S1–S9, F1–F2, N1–N2. **Not implemented/verified:** JWKS, groups/deny rules, tail-truncation
protection, live LLM test, load test, external security review.
