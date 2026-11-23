-- +goose Up
-- Test-only fixture: adds a NOT NULL column with a default to every
-- security-state table, applied over rows the test seeded first, to prove a
-- migration like this applies to a populated table rather than only an empty
-- one.
ALTER TABLE scrty_sessions ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_signing_keys ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_login_attempts ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_mfa_enrolments ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_api_keys ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_one_time_tokens ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_oidc_links ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_oidc_flows ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;
ALTER TABLE scrty_oidc_handoffs ADD COLUMN probe_flag boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE scrty_oidc_handoffs DROP COLUMN probe_flag;
ALTER TABLE scrty_oidc_flows DROP COLUMN probe_flag;
ALTER TABLE scrty_oidc_links DROP COLUMN probe_flag;
ALTER TABLE scrty_one_time_tokens DROP COLUMN probe_flag;
ALTER TABLE scrty_api_keys DROP COLUMN probe_flag;
ALTER TABLE scrty_mfa_enrolments DROP COLUMN probe_flag;
ALTER TABLE scrty_login_attempts DROP COLUMN probe_flag;
ALTER TABLE scrty_signing_keys DROP COLUMN probe_flag;
ALTER TABLE scrty_sessions DROP COLUMN probe_flag;
