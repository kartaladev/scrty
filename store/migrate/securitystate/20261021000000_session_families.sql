-- +goose Up
-- A session family is the chain of sessions one login produces by renewal.
-- Existing sessions each become a family of one: family_id is the row's own id
-- and family_created_at its created_at.
ALTER TABLE sessions ADD COLUMN family_id uuid;
ALTER TABLE sessions ADD COLUMN family_created_at timestamptz;
UPDATE sessions SET family_id = id, family_created_at = created_at;
ALTER TABLE sessions ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN family_created_at SET NOT NULL;
-- An insert that names neither column (a writer from before this migration,
-- during a rolling upgrade) gets a family of its own.
ALTER TABLE sessions ALTER COLUMN family_id SET DEFAULT gen_random_uuid();
ALTER TABLE sessions ALTER COLUMN family_created_at SET DEFAULT now();
-- When the user last proved who they are: the later of the sign-in and the
-- second factor. Existing rows take it from what they already record.
ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz;
UPDATE sessions SET authenticated_at = greatest(created_at, coalesce(mfa_satisfied_at, created_at));
ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET DEFAULT now();
-- Supersession state of a renewed session; NULL = never superseded.
ALTER TABLE sessions ADD COLUMN superseded_at timestamptz NULL;
ALTER TABLE sessions ADD COLUMN accept_until timestamptz NULL;
-- SHA-256 of the successor's identifier, never the identifier itself.
ALTER TABLE sessions ADD COLUMN successor_digest bytea NULL;
ALTER TABLE sessions ADD COLUMN first_presented_at timestamptz NULL;
-- How long a superseded session is kept for reuse detection, apart from its
-- own deadlines; NULL = none, and the row is judged by its own deadlines.
ALTER TABLE sessions ADD COLUMN retain_until timestamptz NULL;
CREATE INDEX sessions_family ON sessions (family_id);

-- +goose Down
-- IF EXISTS so teardown completes after a test drops the table.
DROP INDEX IF EXISTS sessions_family;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS retain_until;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS first_presented_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS successor_digest;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS accept_until;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS superseded_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS authenticated_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS family_created_at;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS family_id;
