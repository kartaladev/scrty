-- +goose Up
-- The security-state schema, created directly under the scrty_ prefix. Security state
-- only: no identity tables, and no foreign key to them or between these tables. User
-- references are opaque consumer-owned text compared byte for byte, and an absent
-- optional text is '' rather than NULL so every adapter scans plain strings.
--
-- Every CREATE carries no IF NOT EXISTS: a relation of the same name already present is
-- refused, never adopted, and the migration's transaction leaves nothing behind.
-- scrty_rate_limit_buckets is created last.

-- +goose StatementBegin
CREATE TABLE scrty_sessions (
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
    -- Deletions guard with <> '' so '' never matches.
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
    federated_acr       text NOT NULL DEFAULT '',
    -- A session family is the chain of sessions one login produces by renewal.
    -- An insert that names neither column gets a family of its own.
    family_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    family_created_at   timestamptz NOT NULL DEFAULT now(),
    -- When the user last proved who they are: the later of the sign-in and the
    -- second factor.
    authenticated_at    timestamptz NOT NULL DEFAULT now(),
    -- Supersession state of a renewed session; NULL = never superseded.
    superseded_at       timestamptz NULL,
    accept_until        timestamptz NULL,
    -- SHA-256 of the successor's identifier, never the identifier itself.
    successor_digest    bytea NULL,
    first_presented_at  timestamptz NULL,
    -- How long a superseded session is kept for reuse detection, apart from its
    -- own deadlines; NULL = none, and the row is judged by its own deadlines.
    retain_until        timestamptz NULL,
    -- Whether the latest supersession was a strict rotation, one that gave the
    -- superseded session no grace window. Written only by the supersession.
    rotated_strictly    boolean NOT NULL DEFAULT false,
    -- The sign-in state fixed when a sign-in is built, carried by every session
    -- of its family and written only by the insert of a session:
    --   client_ip, user_agent    the sign-in metadata, recorded only when the
    --                            consumer turns it on, since both are personal
    --                            data;
    --   binding_kind,            the key the sign-in is bound to: 'jkt' for a DPoP
    --   binding_thumbprint       key, 'x5t#S256' for a client certificate, and the
    --                            key's base64url thumbprint;
    --   csrf_token               the session's CSRF token, sealed and bound to the
    --                            session's own identifier, as external_id_token is.
    -- Every one is nullable with no default. No index: a user's sign-ins are
    -- listed through scrty_sessions_user.
    client_ip           text,
    user_agent          text,
    binding_kind        text,
    binding_thumbprint  text,
    csrf_token          text,
    -- The role the session's user switched to, by name. NULL = none selected:
    -- the primary grant stays active until a switch is made.
    selected_role       text NULL
);
-- +goose StatementEnd
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX scrty_sessions_external_session ON scrty_sessions (external_issuer, external_session_id) WHERE external_session_id <> '';
CREATE INDEX scrty_sessions_user_issuer ON scrty_sessions (user_id, external_issuer) WHERE external_issuer <> '';
CREATE INDEX scrty_sessions_user ON scrty_sessions (user_id);
-- Two single-column expiry indexes, not one composite: expiry deletion matches
-- idle_expires_at <= $1 OR absolute_expires_at <= $1, and a composite index
-- cannot seek on its second column.
CREATE INDEX scrty_sessions_idle_expiry ON scrty_sessions (idle_expires_at);
CREATE INDEX scrty_sessions_absolute_expiry ON scrty_sessions (absolute_expires_at);
CREATE INDEX scrty_sessions_family ON scrty_sessions (family_id);

CREATE TABLE scrty_signing_keys (
    id          uuid PRIMARY KEY,
    kid         text NOT NULL UNIQUE,
    alg         text NOT NULL,
    private_key bytea NOT NULL, -- envelope over PKCS8 DER
    public_jwk  bytea NOT NULL, -- published, not sealed
    created_at  timestamptz NOT NULL
);

CREATE TABLE scrty_login_attempts (
    id           uuid PRIMARY KEY,
    username     text NOT NULL,
    attempted_at timestamptz NOT NULL
);
CREATE INDEX scrty_login_attempts_username ON scrty_login_attempts (username, attempted_at);
-- Deletion scans by time alone and cannot range-scan the composite index:
-- do not consolidate these two indexes.
CREATE INDEX scrty_login_attempts_time ON scrty_login_attempts (attempted_at);

-- One row per identifier: its consecutive failures since they were last
-- cleared or restarted. NULL held_at = not held; a NOT NULL default would hold
-- every new streak.
CREATE TABLE scrty_login_failure_streaks (
    id                uuid PRIMARY KEY,
    username          text NOT NULL UNIQUE,
    failures          integer NOT NULL,
    newest_failure_at timestamptz NOT NULL,
    held_at           timestamptz NULL
);
-- The purge deletes inactive streaks that are not held, by time alone.
CREATE INDEX scrty_login_failure_streaks_inactive ON scrty_login_failure_streaks (newest_failure_at) WHERE held_at IS NULL;

CREATE TABLE scrty_mfa_enrolments (
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

CREATE TABLE scrty_api_keys (
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
CREATE INDEX scrty_api_keys_user ON scrty_api_keys (user_id);

CREATE TABLE scrty_one_time_tokens (
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
CREATE INDEX scrty_one_time_tokens_subject ON scrty_one_time_tokens (purpose, subject);
CREATE INDEX scrty_one_time_tokens_expiry ON scrty_one_time_tokens (purpose, expires_at);

CREATE TABLE scrty_oidc_links (
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
CREATE INDEX scrty_oidc_links_user ON scrty_oidc_links (user_id);

CREATE TABLE scrty_oidc_flows (
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
CREATE INDEX scrty_oidc_flows_expiry ON scrty_oidc_flows (expires_at);

CREATE TABLE scrty_oidc_handoffs (
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
CREATE INDEX scrty_oidc_handoffs_expiry ON scrty_oidc_handoffs (expires_at);

-- Account recovery: saved recovery codes and recovery records.
CREATE TABLE scrty_recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    text NOT NULL,
    code_hash  bytea NOT NULL,
    created_at timestamptz NOT NULL,
    -- Nullable guard with no default: single use is "spent_at IS NULL".
    spent_at   timestamptz NULL,
    UNIQUE (user_id, code_hash)
);

CREATE TABLE scrty_account_recoveries (
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
CREATE INDEX scrty_account_recoveries_user ON scrty_account_recoveries (user_id);

-- Passkeys: credentials and the per-user WebAuthn user handle.
CREATE TABLE scrty_passkey_credentials (
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
    CONSTRAINT scrty_passkey_credentials_credential_id_key UNIQUE (credential_id)
);
CREATE INDEX scrty_passkey_credentials_user_id_idx ON scrty_passkey_credentials (user_id);

CREATE TABLE scrty_passkey_user_handles (
    id      uuid PRIMARY KEY,
    user_id text NOT NULL UNIQUE,
    handle  bytea NOT NULL UNIQUE
);

-- The OpenID Provider's tables. A list is a JSON array of strings, and a map a JSON
-- object, as scrty_sessions.federated_amr and scrty_sessions.data are.
--
-- No credential is held in clear: a code, handle, flow secret, browser-session secret,
-- refresh token, opaque access token or client secret appears here only as its SHA-256
-- digest, and a code's secret not at all, as it lives in scrty_one_time_tokens.
--
-- No lookup index here is partial, unlike the sessions table's upstream indexes. A
-- predicate such as external_session_id <> '' cannot be proven from a parameter, so a
-- generic prepared plan could not use the index. scrty_op_refresh_tokens alone keeps
-- them, as it is the sessions table's shape.

-- One row per client. A registered client's secret is never a column: secrets holds a
-- JSON array of at most two objects, each a digest and a deadline. Durations are
-- nanoseconds, which a time.Duration reads back exactly. jwks is the consumer's bytes,
-- unchanged, and NULL when there are none. device_complete_uri is whether the client's
-- device authorization response carries verification_uri_complete, and
-- device_grants_outlive_sign_in whether its device grants outlive their sign-in.
CREATE TABLE scrty_op_clients (
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
    secrets                    jsonb NOT NULL DEFAULT '[]',
    device_complete_uri        boolean NOT NULL DEFAULT false,
    device_grants_outlive_sign_in boolean NOT NULL DEFAULT false
);

-- A parked request. handle_digest is the record's key, and its uniqueness is what
-- refuses a second record for one handle. sign_in is the sign-in that answered the
-- login stage, as one JSON object, and NULL before that: nothing selects by it.
-- device_authorization_id and device_user_code are the device authorization a request
-- was parked for, and its user code as shown, which is bound to the one browser that
-- claimed it and yields no token.
CREATE TABLE scrty_op_pending_requests (
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
    sign_in               jsonb NULL,
    device_authorization_id uuid NULL,
    device_user_code      text NOT NULL DEFAULT ''
);
CREATE INDEX scrty_op_pending_requests_expiry ON scrty_op_pending_requests (expires_at);

-- A browser that signed in. digest is the record's key. The sign-in's fields are
-- columns, because a sign-in's end selects by them. The two expiry indexes are
-- single-column for the reason the sessions table's are.
CREATE TABLE scrty_op_browser_sessions (
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
CREATE INDEX scrty_op_browser_sessions_user_issuer ON scrty_op_browser_sessions (user_ref, external_issuer);
CREATE INDEX scrty_op_browser_sessions_sign_in ON scrty_op_browser_sessions (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX scrty_op_browser_sessions_external_session ON scrty_op_browser_sessions (external_issuer, external_session_id);
CREATE INDEX scrty_op_browser_sessions_idle_expiry ON scrty_op_browser_sessions (idle_expires_at);
CREATE INDEX scrty_op_browser_sessions_absolute_expiry ON scrty_op_browser_sessions (absolute_expires_at);

-- The request data of an authorization code, keyed by its scrty_one_time_tokens row's
-- identifier. A code's spend is decided in that table, so there is no spent column: a
-- held code is any row here. The sign-in's fields are columns, as above.
CREATE TABLE scrty_op_authorization_codes (
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
CREATE INDEX scrty_op_authorization_codes_user_client ON scrty_op_authorization_codes (user_ref, client_id);
CREATE INDEX scrty_op_authorization_codes_user_issuer ON scrty_op_authorization_codes (user_ref, external_issuer);
CREATE INDEX scrty_op_authorization_codes_sign_in ON scrty_op_authorization_codes (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX scrty_op_authorization_codes_external_session ON scrty_op_authorization_codes (external_issuer, external_session_id);
CREATE INDEX scrty_op_authorization_codes_expiry ON scrty_op_authorization_codes (expires_at);

-- One consent per user and client, which also serves a listing by user.
CREATE TABLE scrty_op_consents (
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
--
-- origin is what created a grant: 0 an authorization code, 1 a device authorization.
-- survives_sign_in_end keeps a device grant without offline_access past its sign-in's
-- end, and is false for every code grant.
CREATE TABLE scrty_op_grants (
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
    sign_in_ended_at    timestamptz NULL,
    origin              smallint NOT NULL DEFAULT 0,
    survives_sign_in_end boolean NOT NULL DEFAULT false
);
CREATE INDEX scrty_op_grants_user ON scrty_op_grants (user_ref);
CREATE INDEX scrty_op_grants_user_client ON scrty_op_grants (user_ref, client_id);
CREATE INDEX scrty_op_grants_user_issuer ON scrty_op_grants (user_ref, external_issuer);
CREATE INDEX scrty_op_grants_sign_in ON scrty_op_grants (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX scrty_op_grants_external_session ON scrty_op_grants (external_issuer, external_session_id);
-- The sweep's two conditions.
CREATE INDEX scrty_op_grants_expiry ON scrty_op_grants (expires_at);
CREATE INDEX scrty_op_grants_revoked ON scrty_op_grants (revoked_at);

-- Refresh-token lineages, which a session store runs over unchanged but for the table's
-- name. Its columns and indexes are scrty_sessions', in the same order, and a later
-- migration changing scrty_sessions must change this table too. It is never a table a
-- sign-in is read from. external_id_token and csrf_token are sealed, as on
-- scrty_sessions.
CREATE TABLE scrty_op_refresh_tokens (
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
    csrf_token          text,
    selected_role       text NULL
);
CREATE INDEX scrty_op_refresh_tokens_external_session ON scrty_op_refresh_tokens (external_issuer, external_session_id) WHERE external_session_id <> '';
CREATE INDEX scrty_op_refresh_tokens_user_issuer ON scrty_op_refresh_tokens (user_id, external_issuer) WHERE external_issuer <> '';
CREATE INDEX scrty_op_refresh_tokens_user ON scrty_op_refresh_tokens (user_id);
CREATE INDEX scrty_op_refresh_tokens_idle_expiry ON scrty_op_refresh_tokens (idle_expires_at);
CREATE INDEX scrty_op_refresh_tokens_absolute_expiry ON scrty_op_refresh_tokens (absolute_expires_at);
CREATE INDEX scrty_op_refresh_tokens_family ON scrty_op_refresh_tokens (family_id);

-- An opaque access token. id is what the token carries in clear, and digest is compared
-- by the provider, so it is not a lookup key. A revoked grant ends a token without this
-- row changing, so nothing reads this table by grant.
CREATE TABLE scrty_op_access_tokens (
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
CREATE INDEX scrty_op_access_tokens_expiry ON scrty_op_access_tokens (expires_at);

-- The client assertions already accepted. The uniqueness of a client and identifier
-- together is the conditional write that decides a replay. An identifier is no
-- credential: it is worthless without the assertion's signature.
CREATE TABLE scrty_op_client_assertions (
    id         uuid PRIMARY KEY,
    client_id  text NOT NULL,
    jti        text NOT NULL,
    held_until timestamptz NOT NULL,
    UNIQUE (client_id, jti)
);
CREATE INDEX scrty_op_client_assertions_expiry ON scrty_op_client_assertions (held_until);

-- One row per device authorization (RFC 8628). No code is held in clear: the device
-- code, the user code and the claiming browser's flow secret appear only as digests, the
-- user code's keyed. device_code_digest is the record's lookup key and stays for the
-- record's life, so a replay of a spent code is still detected. user_code_digest is
-- unique among the rows that hold one: a create releases an expired holder's, setting it
-- NULL, in the transaction that inserts the new row, and the unique index is what
-- decides two creates of one code. A plain unique index, not a partial one, as NULLs
-- never conflict and a generic prepared plan can use it. Durations are nanoseconds, as
-- on scrty_op_clients.
--
-- poll_count is the version a poll's conditional write compares, never a time, as a
-- time read back here has lost its nanoseconds.
--
-- The approval's columns are unset until the user approves. sign_in holds the approving
-- sign-in whole, and is NULL until then. sign_in_family, external_issuer and
-- external_session_id copy the fields of it a sign-in's end selects by, and user_ref is
-- the approving user, so a sign-in's end or a consent revocation reaches an approval the
-- device has not exchanged yet, through the same indexes scrty_op_authorization_codes
-- has.
CREATE TABLE scrty_op_device_authorizations (
    id                   uuid PRIMARY KEY,
    device_code_digest   bytea NOT NULL UNIQUE,
    user_code_digest     bytea NULL UNIQUE,
    claim_flow_digest    bytea NULL,
    client_id            text NOT NULL,
    scopes               jsonb NOT NULL DEFAULT '[]',
    resources            jsonb NOT NULL DEFAULT '[]',
    issued_at            timestamptz NOT NULL,
    expires_at           timestamptz NOT NULL,
    last_polled_at       timestamptz NULL,
    interval_ns          bigint NOT NULL DEFAULT 0,
    poll_count           integer NOT NULL DEFAULT 0,
    state                smallint NOT NULL,
    user_ref             text NOT NULL DEFAULT '',
    granted_scopes       jsonb NOT NULL DEFAULT '[]',
    sign_in              jsonb NULL,
    sign_in_family       uuid NULL,
    external_issuer      text NOT NULL DEFAULT '',
    external_session_id  text NOT NULL DEFAULT '',
    grant_family         uuid NULL,
    offline              boolean NOT NULL DEFAULT false,
    ends_with_sign_in    boolean NOT NULL DEFAULT false,
    survives_sign_in_end boolean NOT NULL DEFAULT false
);
CREATE INDEX scrty_op_device_authorizations_expiry ON scrty_op_device_authorizations (expires_at);
-- Their user_ref leads, so either also serves a selector naming the user alone.
CREATE INDEX scrty_op_device_authorizations_user_client ON scrty_op_device_authorizations (user_ref, client_id);
CREATE INDEX scrty_op_device_authorizations_user_issuer ON scrty_op_device_authorizations (user_ref, external_issuer);
CREATE INDEX scrty_op_device_authorizations_sign_in ON scrty_op_device_authorizations (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX scrty_op_device_authorizations_external_session ON scrty_op_device_authorizations (external_issuer, external_session_id);

-- Shared rate-limit buckets: one row per namespace and key. No index on a
-- column that changes, so updates stay HOT; logged, so a failover keeps limits.
-- A fill factor of 70 leaves each page room for HOT updates, and autovacuum
-- runs once 1% of this small, constantly updated and pruned table is dead.
-- An operator may change any of them with ALTER TABLE ... SET.
CREATE TABLE scrty_rate_limit_buckets (
    namespace         text          NOT NULL,
    key               text          NOT NULL,
    stamps            timestamptz[] NOT NULL,
    newest_at         timestamptz   NOT NULL,
    longest_window_us bigint        NOT NULL,
    PRIMARY KEY (namespace, key)
) WITH (fillfactor = 70,
        -- Keeps a bucket's stamp array in-line up to a full page, so a row of up
        -- to 400 stamps is never moved to TOAST and an update stays HOT. Without
        -- it, rows above about 2 kB are TOASTed: slower, never wrong. A row past
        -- the threshold also stops getting HOT updates.
        toast_tuple_target = 8160,
        autovacuum_vacuum_scale_factor = 0.01,
        autovacuum_vacuum_insert_scale_factor = 0.01);

-- +goose Down
-- Drops everything Up created, in reverse creation order, with every row in it.
-- IF EXISTS, so a rollback still completes after a table was dropped by hand.
-- lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock each DROP takes, so a
-- long transaction on a table fails the rollback within the bound instead of queueing
-- every query behind it. Each statement is one line.
SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS scrty_rate_limit_buckets;
DROP TABLE IF EXISTS scrty_op_device_authorizations;
DROP TABLE IF EXISTS scrty_op_client_assertions;
DROP TABLE IF EXISTS scrty_op_access_tokens;
DROP TABLE IF EXISTS scrty_op_refresh_tokens;
DROP TABLE IF EXISTS scrty_op_grants;
DROP TABLE IF EXISTS scrty_op_consents;
DROP TABLE IF EXISTS scrty_op_authorization_codes;
DROP TABLE IF EXISTS scrty_op_browser_sessions;
DROP TABLE IF EXISTS scrty_op_pending_requests;
DROP TABLE IF EXISTS scrty_op_clients;
DROP TABLE IF EXISTS scrty_passkey_user_handles;
DROP TABLE IF EXISTS scrty_passkey_credentials;
DROP TABLE IF EXISTS scrty_account_recoveries;
DROP TABLE IF EXISTS scrty_recovery_codes;
DROP TABLE IF EXISTS scrty_oidc_handoffs;
DROP TABLE IF EXISTS scrty_oidc_flows;
DROP TABLE IF EXISTS scrty_oidc_links;
DROP TABLE IF EXISTS scrty_one_time_tokens;
DROP TABLE IF EXISTS scrty_api_keys;
DROP TABLE IF EXISTS scrty_mfa_enrolments;
DROP TABLE IF EXISTS scrty_login_failure_streaks;
DROP TABLE IF EXISTS scrty_login_attempts;
DROP TABLE IF EXISTS scrty_signing_keys;
DROP TABLE IF EXISTS scrty_sessions;
