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
    -- Also the confinement marker of a session an account recovery produced.
    enrolment_origin_deadline timestamptz NULL,
    enrolment_generation      uuid NULL,
    -- Account recovery. NULL = never recovered.
    recovered_at        timestamptz NULL,
    -- Set once, at creation, when a second factor was met at the first factor
    -- (a passkey with user verification). Never written by an update.
    mfa_at_first_factor boolean NOT NULL DEFAULT false,
    -- What the identity provider asserted for the login that created a federated
    -- session: amr is a JSON array of strings, in the order asserted ('[]' =
    -- none); acr is '' when none. Stored unsealed.
    federated_amr       jsonb NOT NULL DEFAULT '[]',
    federated_acr       text NOT NULL DEFAULT ''
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

-- One row per identifier: its consecutive failures since they were last
-- cleared or restarted. NULL held_at = not held; a NOT NULL default would hold
-- every new streak.
CREATE TABLE login_failure_streaks (
    id                uuid PRIMARY KEY,
    username          text NOT NULL UNIQUE,
    failures          integer NOT NULL,
    newest_failure_at timestamptz NOT NULL,
    held_at           timestamptz NULL
);
-- The purge deletes inactive streaks that are not held, by time alone.
CREATE INDEX login_failure_streaks_inactive ON login_failure_streaks (newest_failure_at) WHERE held_at IS NULL;

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
    email_code_attempts integer NOT NULL DEFAULT 0,
    -- TOTP verification attempts charged in the window ending at
    -- verify_window_until. NULL = no window open.
    verify_attempts     integer NOT NULL DEFAULT 0,
    verify_window_until timestamptz NULL
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
    -- The provider's asserted amr (JSON array of strings, '[]' = none) and acr
    -- ('' = none), carried to the session redemption creates. Stored unsealed.
    amr         jsonb NOT NULL DEFAULT '[]',
    acr         text NOT NULL DEFAULT '',
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL,
    consumed_at timestamptz NULL -- nullable guard with no default
);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs (expires_at);

-- Account recovery: saved recovery codes and recovery records.
CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    text NOT NULL,
    code_hash  bytea NOT NULL,
    created_at timestamptz NOT NULL,
    -- Nullable guard with no default: single use is "spent_at IS NULL".
    spent_at   timestamptz NULL,
    UNIQUE (user_id, code_hash)
);

CREATE TABLE account_recoveries (
    id           uuid PRIMARY KEY,
    user_id      text NOT NULL,
    started_at   timestamptz NOT NULL,
    not_before   timestamptz NOT NULL,
    -- Nullable guards with no default: neither completed nor cancelled is
    -- "completed_at IS NULL AND cancelled_at IS NULL".
    completed_at timestamptz NULL,
    cancelled_at timestamptz NULL,
    -- Newline-joined "kind:id" authenticator refs; a kind and an id never
    -- contain a newline.
    proven       text NOT NULL,
    reported     text NOT NULL,
    saved_spent  boolean NOT NULL DEFAULT false
);
CREATE INDEX account_recoveries_user ON account_recoveries (user_id);

-- Passkeys: credentials and the per-user WebAuthn user handle.
CREATE TABLE passkey_credentials (
    id                    uuid PRIMARY KEY,
    user_id               text NOT NULL,
    credential_id         bytea NOT NULL,
    public_key            bytea NOT NULL,
    sign_count            bigint NOT NULL,
    backup_eligible       boolean NOT NULL,
    backup_state          boolean NOT NULL,
    transports            text NOT NULL,
    aaguid                bytea NULL,
    attestation_format    text NULL,
    attestation_statement bytea NULL,
    name                  text NOT NULL,
    created_at            timestamptz NOT NULL,
    last_used_at          timestamptz NULL,
    state                 smallint NOT NULL,
    pending               smallint NOT NULL,
    email_code            text NULL,
    email_code_expires_at timestamptz NULL,
    email_code_attempts   smallint NOT NULL DEFAULT 0,
    CONSTRAINT passkey_credentials_credential_id_key UNIQUE (credential_id)
);
CREATE INDEX passkey_credentials_user_id_idx ON passkey_credentials (user_id);

CREATE TABLE passkey_user_handles (
    id      uuid PRIMARY KEY,
    user_id text NOT NULL UNIQUE,
    handle  bytea NOT NULL UNIQUE
);

-- Shared rate-limit buckets: one row per namespace and key. No index on a
-- column that changes, so updates stay HOT; logged, so a failover keeps limits.
CREATE TABLE rate_limit_buckets (
    namespace         text          NOT NULL,
    key               text          NOT NULL,
    stamps            timestamptz[] NOT NULL,
    newest_at         timestamptz   NOT NULL,
    longest_window_us bigint        NOT NULL,
    PRIMARY KEY (namespace, key)
) WITH (fillfactor = 70);

-- +goose Down
-- Reverse creation order; IF EXISTS so teardown completes after a test drops a table.
DROP TABLE IF EXISTS rate_limit_buckets;
DROP TABLE IF EXISTS passkey_user_handles;
DROP TABLE IF EXISTS passkey_credentials;
DROP TABLE IF EXISTS account_recoveries;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS oidc_handoffs;
DROP TABLE IF EXISTS oidc_flows;
DROP TABLE IF EXISTS oidc_links;
DROP TABLE IF EXISTS one_time_tokens;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_enrolments;
DROP TABLE IF EXISTS login_failure_streaks;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS sessions;
