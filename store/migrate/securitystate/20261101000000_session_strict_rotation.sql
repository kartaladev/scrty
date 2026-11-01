-- +goose Up
-- Whether the latest supersession of a session was a strict rotation, one that
-- gave the superseded session no grace window. Written only by the
-- supersession; existing rows were rotated before the mark existed and read
-- back unmarked, and an insert that does not name the column (a writer from
-- before this migration, during a rolling upgrade) is unmarked too.
ALTER TABLE sessions ADD COLUMN rotated_strictly boolean NOT NULL DEFAULT false;

-- +goose Down
-- IF EXISTS so teardown completes after a test drops the table.
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS rotated_strictly;
