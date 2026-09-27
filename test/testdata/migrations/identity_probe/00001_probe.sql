-- +goose Up
-- Stands in for an unrelated identity migration set, to prove the
-- security-state set's version table is untouched by another set's rollback.
CREATE TABLE identity_probe_users (id uuid PRIMARY KEY);

-- +goose Down
DROP TABLE IF EXISTS identity_probe_users;
