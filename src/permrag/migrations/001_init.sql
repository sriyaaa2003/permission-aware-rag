CREATE TABLE tenants (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    active       INTEGER NOT NULL DEFAULT 1,
    data_version INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL
);

CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    UNIQUE (tenant_id, email)
);

CREATE TABLE roles (
    id        TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE documents (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id   TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    content_hash  TEXT NOT NULL,
    owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    visibility    TEXT NOT NULL CHECK (visibility IN ('tenant', 'restricted')),
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    UNIQUE (tenant_id, external_id)
);

-- Authoritative ACL. principal is 'role:<role id>' or 'user:<user id>'.
CREATE TABLE document_acl (
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    principal   TEXT NOT NULL,
    PRIMARY KEY (document_id, principal)
);

CREATE TABLE chunks (
    id          INTEGER PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    text        TEXT NOT NULL,
    embedding   BLOB NOT NULL,
    UNIQUE (document_id, ordinal)
);
CREATE INDEX idx_chunks_tenant ON chunks(tenant_id);

-- Denormalised copy of the ACL, one row per (chunk, principal), used to pre-filter retrieval.
-- 'tenant:<tenant id>' is written for tenant-wide documents. Always rewritten with the document ACL
-- in the same transaction as the change.
CREATE TABLE chunk_acl (
    chunk_id  INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    PRIMARY KEY (chunk_id, principal)
);
CREATE INDEX idx_chunk_acl_lookup ON chunk_acl(tenant_id, principal, chunk_id);

CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    ts         REAL NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hmac  TEXT NOT NULL,
    hmac       TEXT NOT NULL
);
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id, seq);
