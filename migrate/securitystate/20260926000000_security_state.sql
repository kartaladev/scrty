-- +goose Up
-- Security state only: no identity tables, and no foreign keys to them.
-- User references are opaque consumer-owned text compared byte for byte.

-- +goose StatementBegin
CREATE TABLE sessions (
    id                  uuid PRIMARY KEY,
    -- SHA-256 of the session identifier. The identifier is a bearer credential
    -- and is never stored.
    id_digest           bytea NOT NULL UNIQUE,
    user_id             text NOT NULL,
    created_at          timestamptz NOT NULL,
    last_accessed_at    timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    first_factor        text NOT NULL DEFAULT '',
    mfa_state           smallint NOT NULL DEFAULT 0,
    mfa_satisfied_at    timestamptz NULL,
    password_change_pending boolean NOT NULL DEFAULT false,
    -- Absent federation values are '' rather than NULL so every adapter scans
    -- plain strings; deletions guard with <> '' so '' never matches.
    external_provider   text NOT NULL DEFAULT '',
    external_issuer     text NOT NULL DEFAULT '',
    external_session_id text NOT NULL DEFAULT '',
    -- base64url envelope, '' = none.
    external_id_token   text NOT NULL DEFAULT '',
    data                jsonb NOT NULL DEFAULT '{}',
    -- The absolute deadline held before an enrolment mark; NULL = not marked.
    enrolment_origin_deadline timestamptz NULL,
    enrolment_generation      uuid NULL
);
-- +goose StatementEnd
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX sessions_external_session ON sessions (external_issuer, external_session_id) WHERE external_session_id <> '';
CREATE INDEX sessions_user_issuer ON sessions (user_id, external_issuer) WHERE external_issuer <> '';
CREATE INDEX sessions_user ON sessions (user_id);
-- Two single-column expiry indexes, not one composite: expiry deletion matches
-- idle_expires_at <= $1 OR absolute_expires_at <= $1, and a composite index
-- cannot seek on its second column.
CREATE INDEX sessions_idle_expiry ON sessions (idle_expires_at);
CREATE INDEX sessions_absolute_expiry ON sessions (absolute_expires_at);

CREATE TABLE signing_keys (
    id          uuid PRIMARY KEY,
    kid         text NOT NULL UNIQUE,
    alg         text NOT NULL,
    private_key bytea NOT NULL, -- envelope over PKCS8 DER
    public_jwk  bytea NOT NULL, -- published, not sealed
    created_at  timestamptz NOT NULL
);

CREATE TABLE login_attempts (
    id           uuid PRIMARY KEY,
    username     text NOT NULL,
    attempted_at timestamptz NOT NULL
);
CREATE INDEX login_attempts_username ON login_attempts (username, attempted_at);
-- Deletion scans by time alone and cannot range-scan the composite index:
-- do not consolidate these two indexes.
CREATE INDEX login_attempts_time ON login_attempts (attempted_at);

CREATE TABLE mfa_enrolments (
    id           uuid PRIMARY KEY,
    user_id      text NOT NULL UNIQUE,
    secret       text NOT NULL, -- base64url envelope
    -- Nullable guard: NULL = pending. A NOT NULL default would make
    -- "IS NULL" unsatisfiable and break confirm-once.
    confirmed_at timestamptz NULL,
    last_step    bigint NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL,
    -- Enrolment path. NULL generation = none, and matches no conditional write.
    generation          uuid NULL,
    device_proven_at    timestamptz NULL,
    email_code          text NULL, -- base64url envelope, NULL = none
    email_code_until    timestamptz NULL,
    email_code_attempts integer NOT NULL DEFAULT 0
);

CREATE TABLE api_keys (
    id            uuid PRIMARY KEY,
    user_id       text NOT NULL,
    name          text NOT NULL,
    scopes        jsonb NOT NULL DEFAULT '[]',
    secret_digest bytea NOT NULL,
    expires_at    timestamptz NULL,
    revoked_at    timestamptz NULL, -- nullable guard, first revocation kept
    last_used_at  timestamptz NULL,
    created_at    timestamptz NOT NULL
);
CREATE INDEX api_keys_user ON api_keys (user_id);

CREATE TABLE one_time_tokens (
    id           uuid PRIMARY KEY,
    purpose      text NOT NULL,
    subject      text NOT NULL,
    secret_hash  bytea NOT NULL,
    -- NULL = unbound. Absent is not empty: the contract tells the two apart,
    -- so an unbound token round-trips as NULL, never as an empty value.
    binding_hash bytea NULL,
    issued_at    timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    -- Nullable guard with no default: single use is "consumed_at IS NULL".
    consumed_at  timestamptz NULL
);
CREATE INDEX one_time_tokens_subject ON one_time_tokens (purpose, subject);
CREATE INDEX one_time_tokens_expiry ON one_time_tokens (purpose, expires_at);

CREATE TABLE oidc_links (
    id         uuid PRIMARY KEY,
    provider   text NOT NULL,
    issuer     text NOT NULL,
    subject    text NOT NULL,
    user_id    text NOT NULL,
    username   text NOT NULL DEFAULT '', -- operators only, never a lookup key
    email      text NOT NULL DEFAULT '', -- operators only, never a lookup key
    created_at timestamptz NOT NULL,
    UNIQUE (provider, issuer, subject)
);
CREATE INDEX oidc_links_user ON oidc_links (user_id);

CREATE TABLE oidc_flows (
    id           uuid PRIMARY KEY,
    handle       text NOT NULL UNIQUE,
    provider     text NOT NULL,
    state        text NOT NULL,
    nonce        text NOT NULL,
    verifier     text NOT NULL,
    next         text NOT NULL DEFAULT '', -- untrusted, stored verbatim
    expires_at   timestamptz NOT NULL,
    completed_at timestamptz NULL -- nullable guard with no default
);
CREATE INDEX oidc_flows_expiry ON oidc_flows (expires_at);

CREATE TABLE oidc_handoffs (
    id          uuid PRIMARY KEY,
    token_id    text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    user_id     text NOT NULL,
    provider    text NOT NULL DEFAULT '',
    issuer      text NOT NULL DEFAULT '',
    session_id  text NOT NULL DEFAULT '',
    id_token    text NOT NULL DEFAULT '',
    next        text NOT NULL DEFAULT '', -- untrusted, re-resolved at redemption
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL,
    consumed_at timestamptz NULL -- nullable guard with no default
);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs (expires_at);

-- +goose Down
-- Reverse creation order; IF EXISTS so teardown completes after a test drops a table.
DROP TABLE IF EXISTS oidc_handoffs;
DROP TABLE IF EXISTS oidc_flows;
DROP TABLE IF EXISTS oidc_links;
DROP TABLE IF EXISTS one_time_tokens;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_enrolments;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS sessions;
