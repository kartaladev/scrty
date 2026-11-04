-- +goose Up
-- The OpenID Provider's tables. As in the rest of this set, there is no foreign key,
-- user references are opaque text, and an absent optional text is '' rather than NULL.
-- A list is a JSON array of strings, and a map a JSON object, as sessions.federated_amr
-- and sessions.data are.
--
-- No credential is held in clear: a code, handle, flow secret, browser-session secret,
-- refresh token, opaque access token or client secret appears here only as its SHA-256
-- digest, and a code's secret not at all, as it lives in one_time_tokens.
--
-- No lookup index here is partial, unlike the sessions table's upstream indexes. A
-- predicate such as external_session_id <> '' cannot be proven from a parameter, so a
-- generic prepared plan could not use the index. op_refresh_tokens alone keeps them, as
-- it is the sessions table's shape.

-- One row per client. A registered client's secret is never a column: secrets holds a
-- JSON array of at most two objects, each a digest and a deadline. Durations are
-- nanoseconds, which a time.Duration reads back exactly. jwks is the consumer's bytes,
-- unchanged, and NULL when there are none.
CREATE TABLE op_clients (
    id                         uuid PRIMARY KEY,
    client_id                  text NOT NULL UNIQUE,
    name                       text NOT NULL DEFAULT '',
    client_type                smallint NOT NULL,
    application_type           smallint NOT NULL DEFAULT 0,
    auth_method                text NOT NULL,
    pkce                       smallint NOT NULL DEFAULT 0,
    jwks                       bytea NULL,
    jwks_uri                   text NOT NULL DEFAULT '',
    redirect_uris              jsonb NOT NULL DEFAULT '[]',
    post_logout_redirect_uris  jsonb NOT NULL DEFAULT '[]',
    back_channel_logout_uri    text NOT NULL DEFAULT '',
    scopes                     jsonb NOT NULL DEFAULT '[]',
    resources                  jsonb NOT NULL DEFAULT '[]',
    default_audience           jsonb NOT NULL DEFAULT '[]',
    resource_identifier        text NOT NULL DEFAULT '',
    grant_types                jsonb NOT NULL DEFAULT '[]',
    first_party                boolean NOT NULL DEFAULT false,
    offline_access             smallint NOT NULL DEFAULT 0,
    id_token_alg               text NOT NULL DEFAULT '',
    id_token_lifetime_ns       bigint NOT NULL DEFAULT 0,
    access_token_lifetime_ns   bigint NOT NULL DEFAULT 0,
    opaque_access_tokens       boolean NOT NULL DEFAULT false,
    require_binding            smallint NOT NULL DEFAULT 0,
    refresh_grace_ns           bigint NOT NULL DEFAULT 0,
    grant_idle_timeout_ns      bigint NOT NULL DEFAULT 0,
    grant_absolute_lifetime_ns bigint NOT NULL DEFAULT 0,
    disable_rotation           boolean NOT NULL DEFAULT false,
    end_grants_with_sign_in    boolean NOT NULL DEFAULT false,
    keep_public_web_grants_past_sign_in boolean NOT NULL DEFAULT false,
    metadata                   jsonb NOT NULL DEFAULT '{}',
    secrets                    jsonb NOT NULL DEFAULT '[]'
);

-- A parked request. handle_digest is the record's key, and its uniqueness is what
-- refuses a second record for one handle. sign_in is the sign-in that answered the
-- login stage, as one JSON object, and NULL before that: nothing selects by it.
CREATE TABLE op_pending_requests (
    id                    uuid PRIMARY KEY,
    handle_digest         bytea NOT NULL UNIQUE,
    flow_digest           bytea NOT NULL,
    client_id             text NOT NULL,
    redirect_uri          text NOT NULL DEFAULT '',
    scopes                jsonb NOT NULL DEFAULT '[]',
    resources             jsonb NOT NULL DEFAULT '[]',
    state                 text NOT NULL DEFAULT '',
    nonce                 text NOT NULL DEFAULT '',
    challenge             text NOT NULL DEFAULT '',
    prompt                jsonb NOT NULL DEFAULT '[]',
    max_age               bigint NULL,
    id_token_hint_subject text NOT NULL DEFAULT '',
    dpop_jkt              text NOT NULL DEFAULT '',
    login_hint            text NOT NULL DEFAULT '',
    ui_locales            jsonb NOT NULL DEFAULT '[]',
    claims_locales        jsonb NOT NULL DEFAULT '[]',
    acr_values            jsonb NOT NULL DEFAULT '[]',
    parked_at             timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    stage                 smallint NOT NULL,
    sign_in               jsonb NULL
);
CREATE INDEX op_pending_requests_expiry ON op_pending_requests (expires_at);

-- A browser that signed in. digest is the record's key. The sign-in's fields are
-- columns, because a sign-in's end selects by them. The two expiry indexes are
-- single-column for the reason the sessions table's are.
CREATE TABLE op_browser_sessions (
    id                          uuid PRIMARY KEY,
    digest                      bytea NOT NULL UNIQUE,
    user_ref                    text NOT NULL,
    sign_in_family              uuid NOT NULL,
    authenticated_at            timestamptz NOT NULL,
    amr                         jsonb NOT NULL DEFAULT '[]',
    acr                         text NOT NULL DEFAULT '',
    sign_in_absolute_expires_at timestamptz NOT NULL,
    external_issuer             text NOT NULL DEFAULT '',
    external_session_id         text NOT NULL DEFAULT '',
    idle_expires_at             timestamptz NOT NULL,
    absolute_expires_at         timestamptz NOT NULL
);
-- Its user_ref leads, so it also serves a selector naming the user alone.
CREATE INDEX op_browser_sessions_user_issuer ON op_browser_sessions (user_ref, external_issuer);
CREATE INDEX op_browser_sessions_sign_in ON op_browser_sessions (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX op_browser_sessions_external_session ON op_browser_sessions (external_issuer, external_session_id);
CREATE INDEX op_browser_sessions_idle_expiry ON op_browser_sessions (idle_expires_at);
CREATE INDEX op_browser_sessions_absolute_expiry ON op_browser_sessions (absolute_expires_at);

-- The request data of an authorization code, keyed by its one_time_tokens row's
-- identifier. A code's spend is decided in that table, so there is no spent column: a
-- held code is any row here. The sign-in's fields are columns, as above.
CREATE TABLE op_authorization_codes (
    token_id                    uuid PRIMARY KEY,
    client_id                   text NOT NULL,
    redirect_uri                text NOT NULL DEFAULT '',
    challenge                   text NOT NULL DEFAULT '',
    nonce                       text NOT NULL DEFAULT '',
    dpop_jkt                    text NOT NULL DEFAULT '',
    scopes                      jsonb NOT NULL DEFAULT '[]',
    resources                   jsonb NOT NULL DEFAULT '[]',
    user_ref                    text NOT NULL,
    sign_in_family              uuid NOT NULL,
    authenticated_at            timestamptz NOT NULL,
    amr                         jsonb NOT NULL DEFAULT '[]',
    acr                         text NOT NULL DEFAULT '',
    sign_in_absolute_expires_at timestamptz NOT NULL,
    external_issuer             text NOT NULL DEFAULT '',
    external_session_id         text NOT NULL DEFAULT '',
    grant_family                uuid NOT NULL,
    offline                     boolean NOT NULL DEFAULT false,
    ends_with_sign_in           boolean NOT NULL DEFAULT false,
    expires_at                  timestamptz NOT NULL
);
-- Their user_ref leads, so either also serves a selector naming the user alone.
CREATE INDEX op_authorization_codes_user_client ON op_authorization_codes (user_ref, client_id);
CREATE INDEX op_authorization_codes_user_issuer ON op_authorization_codes (user_ref, external_issuer);
CREATE INDEX op_authorization_codes_sign_in ON op_authorization_codes (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX op_authorization_codes_external_session ON op_authorization_codes (external_issuer, external_session_id);
CREATE INDEX op_authorization_codes_expiry ON op_authorization_codes (expires_at);

-- One consent per user and client, which also serves a listing by user.
CREATE TABLE op_consents (
    id            uuid PRIMARY KEY,
    user_ref      text NOT NULL,
    client_id     text NOT NULL,
    scopes        jsonb NOT NULL DEFAULT '[]',
    offline       boolean NOT NULL DEFAULT false,
    last_given_at timestamptz NOT NULL,
    UNIQUE (user_ref, client_id)
);

-- A grant, or a revocation recorded before its grant was stored, which holds only
-- family, the revocation's columns and perhaps the sign-in-ended mark. Every other
-- column therefore has a value meaning unset, and invents none: a time or an identifier
-- is NULL, and holds_lineage is false, as a Grant's godoc and the memory store's
-- tombstone have it: an adapter writes it explicitly, true, when it stores a grant.
-- NULL created_at is what tells a tombstone from a stored grant, so an adapter writes a
-- stored grant's created_at even when it is the zero time, and never NULL. Selecting
-- by "every family but one" must read NULL as different (IS DISTINCT FROM).
CREATE TABLE op_grants (
    family              uuid PRIMARY KEY,
    user_ref            text NOT NULL DEFAULT '',
    client_id           text NOT NULL DEFAULT '',
    scopes              jsonb NOT NULL DEFAULT '[]',
    resources           jsonb NOT NULL DEFAULT '[]',
    auth_time           timestamptz NULL,
    amr                 jsonb NOT NULL DEFAULT '[]',
    acr                 text NOT NULL DEFAULT '',
    key_binding         text NOT NULL DEFAULT '',
    cert_binding        text NOT NULL DEFAULT '',
    code_id             uuid NULL,
    sign_in_family      uuid NULL,
    external_issuer     text NOT NULL DEFAULT '',
    external_session_id text NOT NULL DEFAULT '',
    offline             boolean NOT NULL DEFAULT false,
    ends_with_sign_in   boolean NOT NULL DEFAULT false,
    holds_lineage       boolean NOT NULL DEFAULT false,
    created_at          timestamptz NULL,
    expires_at          timestamptz NULL,
    revoked             boolean NOT NULL DEFAULT false,
    revoked_at          timestamptz NULL,
    revoke_cause        text NOT NULL DEFAULT '',
    sign_in_ended_at    timestamptz NULL
);
CREATE INDEX op_grants_user ON op_grants (user_ref);
CREATE INDEX op_grants_user_client ON op_grants (user_ref, client_id);
CREATE INDEX op_grants_user_issuer ON op_grants (user_ref, external_issuer);
CREATE INDEX op_grants_sign_in ON op_grants (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX op_grants_external_session ON op_grants (external_issuer, external_session_id);
-- The sweep's two conditions.
CREATE INDEX op_grants_expiry ON op_grants (expires_at);
CREATE INDEX op_grants_revoked ON op_grants (revoked_at);

-- Refresh-token lineages, which a session store runs over unchanged but for the table's
-- name. Its columns and indexes are the sessions table's, in the same order, and a later
-- migration changing sessions must change this table too. It is never a table a sign-in
-- is read from. external_id_token and csrf_token are sealed, as on sessions.
CREATE TABLE op_refresh_tokens (
    id                  uuid PRIMARY KEY,
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
    external_provider   text NOT NULL DEFAULT '',
    external_issuer     text NOT NULL DEFAULT '',
    external_session_id text NOT NULL DEFAULT '',
    external_id_token   text NOT NULL DEFAULT '',
    data                jsonb NOT NULL DEFAULT '{}',
    enrolment_origin_deadline timestamptz NULL,
    enrolment_generation      uuid NULL,
    recovered_at        timestamptz NULL,
    mfa_at_first_factor boolean NOT NULL DEFAULT false,
    federated_amr       jsonb NOT NULL DEFAULT '[]',
    federated_acr       text NOT NULL DEFAULT '',
    family_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    family_created_at   timestamptz NOT NULL DEFAULT now(),
    authenticated_at    timestamptz NOT NULL DEFAULT now(),
    superseded_at       timestamptz NULL,
    accept_until        timestamptz NULL,
    successor_digest    bytea NULL,
    first_presented_at  timestamptz NULL,
    retain_until        timestamptz NULL,
    rotated_strictly    boolean NOT NULL DEFAULT false,
    client_ip           text,
    user_agent          text,
    binding_kind        text,
    binding_thumbprint  text,
    csrf_token          text
);
CREATE INDEX op_refresh_tokens_external_session ON op_refresh_tokens (external_issuer, external_session_id) WHERE external_session_id <> '';
CREATE INDEX op_refresh_tokens_user_issuer ON op_refresh_tokens (user_id, external_issuer) WHERE external_issuer <> '';
CREATE INDEX op_refresh_tokens_user ON op_refresh_tokens (user_id);
CREATE INDEX op_refresh_tokens_idle_expiry ON op_refresh_tokens (idle_expires_at);
CREATE INDEX op_refresh_tokens_absolute_expiry ON op_refresh_tokens (absolute_expires_at);
CREATE INDEX op_refresh_tokens_family ON op_refresh_tokens (family_id);

-- An opaque access token. id is what the token carries in clear, and digest is compared
-- by the provider, so it is not a lookup key. A revoked grant ends a token without this
-- row changing, so nothing reads this table by grant.
CREATE TABLE op_access_tokens (
    id           uuid PRIMARY KEY,
    digest       bytea NOT NULL,
    grant_family uuid NOT NULL,
    client_id    text NOT NULL,
    user_ref     text NOT NULL,
    scopes       jsonb NOT NULL DEFAULT '[]',
    audience     jsonb NOT NULL DEFAULT '[]',
    confirmation jsonb NOT NULL DEFAULT '{}',
    issued_at    timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked      boolean NOT NULL DEFAULT false
);
CREATE INDEX op_access_tokens_expiry ON op_access_tokens (expires_at);

-- The client assertions already accepted. The uniqueness of a client and identifier
-- together is the conditional write that decides a replay. An identifier is no
-- credential: it is worthless without the assertion's signature.
CREATE TABLE op_client_assertions (
    id         uuid PRIMARY KEY,
    client_id  text NOT NULL,
    jti        text NOT NULL,
    held_until timestamptz NOT NULL,
    UNIQUE (client_id, jti)
);
CREATE INDEX op_client_assertions_expiry ON op_client_assertions (held_until);

-- +goose Down
-- Reverse creation order; IF EXISTS so teardown completes after a test drops a table.
DROP TABLE IF EXISTS op_client_assertions;
DROP TABLE IF EXISTS op_access_tokens;
DROP TABLE IF EXISTS op_refresh_tokens;
DROP TABLE IF EXISTS op_grants;
DROP TABLE IF EXISTS op_consents;
DROP TABLE IF EXISTS op_authorization_codes;
DROP TABLE IF EXISTS op_browser_sessions;
DROP TABLE IF EXISTS op_pending_requests;
DROP TABLE IF EXISTS op_clients;
