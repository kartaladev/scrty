-- +goose Up
-- Test-only fixture: adds a NOT NULL column with a default to every
-- security-state table, applied over rows the test seeded first, to prove a
-- migration like this applies to a populated table rather than only an empty
-- one.
ALTER TABLE sessions ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE signing_keys ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE login_attempts ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE mfa_enrolments ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE api_keys ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE one_time_tokens ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE oidc_links ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE oidc_flows ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE oidc_handoffs ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE oidc_handoffs DROP COLUMN probe_flag;
ALTER TABLE oidc_flows DROP COLUMN probe_flag;
ALTER TABLE oidc_links DROP COLUMN probe_flag;
ALTER TABLE one_time_tokens DROP COLUMN probe_flag;
ALTER TABLE api_keys DROP COLUMN probe_flag;
ALTER TABLE mfa_enrolments DROP COLUMN probe_flag;
ALTER TABLE login_attempts DROP COLUMN probe_flag;
ALTER TABLE signing_keys DROP COLUMN probe_flag;
ALTER TABLE sessions DROP COLUMN probe_flag;
