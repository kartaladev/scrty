-- +goose Up
-- Whether the browser cookie a sign-in handed out persists across browser restarts,
-- on the sessions table and on the refresh-token lineage table that mirrors it, so a
-- session store's statements run over both unchanged. The mark is written once, by the
-- insert that creates a session or its successor, and never by an update.
--
-- The column is nullable with no default, so adding it rewrites no row and reads no
-- table. A row written before this migration holds NULL, which the stores read as
-- unset: a session cookie, the fail-closed reading.
--
-- lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock each ALTER takes, so a long
-- transaction on a table fails the migration within the bound instead of queueing every
-- query behind it. The migration runs in one transaction, so a failure leaves nothing.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scrty_sessions ADD COLUMN persistent_cookie boolean NULL;
ALTER TABLE scrty_op_refresh_tokens ADD COLUMN persistent_cookie boolean NULL;

-- +goose Down
-- Drops exactly the column Up added, with the values in it, and nothing else. lock_timeout
-- bounds each ALTER, as in Up.
SET LOCAL lock_timeout = '5s';

ALTER TABLE IF EXISTS scrty_op_refresh_tokens DROP COLUMN IF EXISTS persistent_cookie;
ALTER TABLE IF EXISTS scrty_sessions DROP COLUMN IF EXISTS persistent_cookie;
