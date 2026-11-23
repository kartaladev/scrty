-- +goose Up
-- Adds what the administration services keep: a user's email, its verification time, a soft
-- deletion time and a version; a role's display name, description, labels and version; a
-- privilege's scope; and the profile attribute table. Every added relation carries the scrty_
-- prefix, and no column, constraint or index of an earlier migration changes.
--
-- The migration applies in one transaction, so it must never opt out of goose's own. The column
-- statements carry no IF NOT EXISTS: a database where the application already added an email
-- column to scrty_users is not at the state this migration expects, so the upgrade fails at
-- that statement and, with nothing committed, leaves no column, table or index behind. Rename
-- or drop the application's column, then apply again.
--
-- Existing rows read back as before: no email, not deleted, version 1, an empty role display
-- name, description and labels, and privilege scope 'all'. Every new column is nullable or
-- carries a default, so the statements apply to a populated table and a release that does not
-- know the columns keeps working. lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock
-- the statements take, so a long transaction on a table fails the upgrade within the bound
-- instead of queueing every query behind it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scrty_roles ADD COLUMN display_name text NOT NULL DEFAULT '';
ALTER TABLE scrty_roles ADD COLUMN description text NOT NULL DEFAULT '';
ALTER TABLE scrty_roles ADD COLUMN labels text[] NOT NULL DEFAULT '{}';
ALTER TABLE scrty_roles ADD COLUMN version bigint NOT NULL DEFAULT 1;

-- 'all' is the scope every grant had before the column existed.
ALTER TABLE scrty_resource_privileges ADD COLUMN scope text NOT NULL DEFAULT 'all';

ALTER TABLE scrty_users ADD COLUMN email text NULL;
ALTER TABLE scrty_users ADD COLUMN email_verified_at timestamptz NULL;
ALTER TABLE scrty_users ADD COLUMN deleted_at timestamptz NULL;
ALTER TABLE scrty_users ADD COLUMN version bigint NOT NULL DEFAULT 1;

-- Unique among live users, ignoring case. A deleted user has no email (it is cleared on
-- deletion), and a NULL email is never indexed.
CREATE UNIQUE INDEX scrty_users_email_live ON scrty_users (lower(email))
    WHERE deleted_at IS NULL AND email IS NOT NULL;
-- Serves the list order, (lower(username), id), and its cursor.
CREATE INDEX scrty_users_username_lower ON scrty_users (lower(username), id);
-- Serves the check that a role is still assigned before it is deleted.
CREATE INDEX scrty_assigned_roles_role_name ON scrty_assigned_roles (role_name);

-- Nothing constrains user_id to the users table: identity tables reference each other by value, so a
-- dangling reference loads as absent and never as an error.
CREATE TABLE scrty_user_attributes (
    user_id uuid NOT NULL,
    name    text NOT NULL,
    value   text NOT NULL,
    PRIMARY KEY (user_id, name)
);
-- Exact-match search by attribute name and value.
CREATE INDEX scrty_user_attributes_name_value ON scrty_user_attributes (name, value);

-- +goose Down
-- Exactly what Up added, in reverse. IF EXISTS on every statement, so a rollback still
-- completes after a relation was dropped by hand. Dropping a column drops the index over it.
-- A user's email, version and deleted state, and a role's display name, description, labels
-- and version, are lost with their columns: back the data up before rolling back.
DROP TABLE IF EXISTS scrty_user_attributes;
DROP INDEX IF EXISTS scrty_assigned_roles_role_name;
DROP INDEX IF EXISTS scrty_users_username_lower;
DROP INDEX IF EXISTS scrty_users_email_live;
ALTER TABLE IF EXISTS scrty_resource_privileges DROP COLUMN IF EXISTS scope;
ALTER TABLE IF EXISTS scrty_roles DROP COLUMN IF EXISTS version;
ALTER TABLE IF EXISTS scrty_roles DROP COLUMN IF EXISTS labels;
ALTER TABLE IF EXISTS scrty_roles DROP COLUMN IF EXISTS description;
ALTER TABLE IF EXISTS scrty_roles DROP COLUMN IF EXISTS display_name;
ALTER TABLE IF EXISTS scrty_users DROP COLUMN IF EXISTS version;
ALTER TABLE IF EXISTS scrty_users DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE IF EXISTS scrty_users DROP COLUMN IF EXISTS email_verified_at;
ALTER TABLE IF EXISTS scrty_users DROP COLUMN IF EXISTS email;
