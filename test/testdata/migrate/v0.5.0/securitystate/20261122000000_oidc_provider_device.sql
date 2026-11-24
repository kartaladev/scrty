-- +goose Up
-- The OpenID Provider's device authorization grant (RFC 8628). Additions only: one new
-- table, and columns whose defaults give every existing row the meaning it had. As in
-- the rest of this set, there is no foreign key, user references are opaque text, an
-- absent optional text is '' and an absent time or identifier is NULL.

-- One row per device authorization. No code is held in clear: the device code, the user
-- code and the claiming browser's flow secret appear only as digests, the user code's
-- keyed. device_code_digest is the record's lookup key and stays for the record's life,
-- so a replay of a spent code is still detected. user_code_digest is unique among the
-- rows that hold one: a create releases an expired holder's, setting it NULL, in the
-- transaction that inserts the new row, and the unique index is what decides two
-- creates of one code. A plain unique index, not a partial one, as NULLs never conflict
-- and a generic prepared plan can use it. Durations are nanoseconds, as on op_clients.
--
-- poll_count is the version a poll's conditional write compares, never a time, as a
-- time read back here has lost its nanoseconds.
--
-- The approval's columns are unset until the user approves. sign_in holds the approving
-- sign-in whole, and is NULL until then. sign_in_family, external_issuer and
-- external_session_id copy the fields of it a sign-in's end selects by, and user_ref is
-- the approving user, so a sign-in's end or a consent revocation reaches an approval the
-- device has not exchanged yet, through the same indexes op_authorization_codes has.
CREATE TABLE op_device_authorizations (
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
CREATE INDEX op_device_authorizations_expiry ON op_device_authorizations (expires_at);
-- Their user_ref leads, so either also serves a selector naming the user alone.
CREATE INDEX op_device_authorizations_user_client ON op_device_authorizations (user_ref, client_id);
CREATE INDEX op_device_authorizations_user_issuer ON op_device_authorizations (user_ref, external_issuer);
CREATE INDEX op_device_authorizations_sign_in ON op_device_authorizations (sign_in_family);
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX op_device_authorizations_external_session ON op_device_authorizations (external_issuer, external_session_id);

-- A client's two device settings: whether its device authorization response carries
-- verification_uri_complete, and whether its device grants outlive their sign-in. Both
-- off, as every existing client had them.
ALTER TABLE op_clients
    ADD COLUMN device_complete_uri boolean NOT NULL DEFAULT false,
    ADD COLUMN device_grants_outlive_sign_in boolean NOT NULL DEFAULT false;

-- What created a grant: 0 an authorization code, 1 a device authorization. Every grant
-- stored before is a code's. survives_sign_in_end keeps a device grant without
-- offline_access past its sign-in's end; false for every code grant, so the rule that
-- ends a grant with its sign-in reads every existing row as it did.
ALTER TABLE op_grants
    ADD COLUMN origin smallint NOT NULL DEFAULT 0,
    ADD COLUMN survives_sign_in_end boolean NOT NULL DEFAULT false;

-- The device authorization a request was parked for, and its user code as shown, which
-- is bound to the one browser that claimed it and yields no token. None for every
-- existing request.
ALTER TABLE op_pending_requests
    ADD COLUMN device_authorization_id uuid NULL,
    ADD COLUMN device_user_code text NOT NULL DEFAULT '';

-- +goose Down
-- Exactly what Up added, in reverse; IF EXISTS so teardown completes after a test drops a
-- table. Each statement is one line, as the set's lifecycle test runs them.
ALTER TABLE IF EXISTS op_pending_requests DROP COLUMN IF EXISTS device_user_code, DROP COLUMN IF EXISTS device_authorization_id;
ALTER TABLE IF EXISTS op_grants DROP COLUMN IF EXISTS survives_sign_in_end, DROP COLUMN IF EXISTS origin;
ALTER TABLE IF EXISTS op_clients DROP COLUMN IF EXISTS device_grants_outlive_sign_in, DROP COLUMN IF EXISTS device_complete_uri;
DROP TABLE IF EXISTS op_device_authorizations;
