-- +goose Up
-- The role a session's user switched to, by name. NULL means none was selected, and is what
-- every existing session holds: the primary grant stays active until a switch is made. The
-- refresh-token lineage table is the sessions table under another name, and the session
-- statements run over both, so it gains the same column and the two keep the same columns.
-- Each column is nullable with no default, so the statements change no row and apply to a
-- populated table. lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock they take, so a
-- long transaction on a table fails the upgrade within the bound instead of queueing every
-- query behind it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scrty_sessions ADD COLUMN selected_role text NULL;
ALTER TABLE scrty_op_refresh_tokens ADD COLUMN selected_role text NULL;

-- +goose Down
-- Exactly what Up added, in reverse. IF EXISTS, so a rollback still completes after a column
-- was dropped by hand. A selection stored in a column is lost with it. lock_timeout bounds the
-- wait for the ACCESS EXCLUSIVE lock the statements take, as it does for Up.
SET LOCAL lock_timeout = '5s';

ALTER TABLE IF EXISTS scrty_op_refresh_tokens DROP COLUMN IF EXISTS selected_role;
ALTER TABLE IF EXISTS scrty_sessions DROP COLUMN IF EXISTS selected_role;
