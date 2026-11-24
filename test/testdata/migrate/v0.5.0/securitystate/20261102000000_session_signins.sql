-- +goose Up
-- The sign-in state fixed when a sign-in is built, carried by every session of
-- its family and written only by the insert of a session (a sign-in or a
-- supersession's successor), never by a save:
--   client_ip, user_agent    the sign-in metadata, recorded only when the
--                            consumer turns it on, since both are personal
--                            data;
--   binding_kind,            the key the sign-in is bound to: 'jkt' for a DPoP
--   binding_thumbprint       key, 'x5t#S256' for a client certificate, and the
--                            key's base64url thumbprint;
--   csrf_token               the session's CSRF token, sealed and bound to the
--                            session's own identifier, as external_id_token is.
-- Every column is nullable with no default, so existing rows read back with no
-- metadata, unbound and with no token, and an insert from a writer that does
-- not name them (one from before this migration, during a rolling upgrade)
-- still succeeds. No index: a user's sign-ins are listed through sessions_user.
ALTER TABLE sessions ADD COLUMN client_ip text;
ALTER TABLE sessions ADD COLUMN user_agent text;
ALTER TABLE sessions ADD COLUMN binding_kind text;
ALTER TABLE sessions ADD COLUMN binding_thumbprint text;
ALTER TABLE sessions ADD COLUMN csrf_token text;

-- +goose Down
-- IF EXISTS so teardown completes after a test drops the table.
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS csrf_token;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS binding_thumbprint;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS binding_kind;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS user_agent;
ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS client_ip;
