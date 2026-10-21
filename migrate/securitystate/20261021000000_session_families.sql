-- +goose Up
-- A session family is the chain of sessions one login produces by renewal.
-- Existing sessions each become a family of one: family_id is the row's own id
-- and family_created_at its created_at.
ALTER TABLE sessions ADD COLUMN family_id uuid;
ALTER TABLE sessions ADD COLUMN family_created_at timestamptz;
UPDATE sessions SET family_id = id, family_created_at = created_at;
ALTER TABLE sessions ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN family_created_at SET NOT NULL;
-- Supersession state of a renewed session; NULL = never superseded.
ALTER TABLE sessions ADD COLUMN superseded_at timestamptz NULL;
ALTER TABLE sessions ADD COLUMN accept_until timestamptz NULL;
-- SHA-256 of the successor's identifier, never the identifier itself.
ALTER TABLE sessions ADD COLUMN successor_digest bytea NULL;
ALTER TABLE sessions ADD COLUMN first_presented_at timestamptz NULL;
CREATE INDEX sessions_family ON sessions (family_id);

-- +goose Down
-- IF EXISTS so teardown completes after a test drops the table.
DROP INDEX IF EXISTS sessions_family;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS first_presented_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS successor_digest;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS accept_until;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS superseded_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS family_created_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS family_id;
