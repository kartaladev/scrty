-- +goose Up
-- Gives every identity table, index and the sequence behind password_history.seq the scrty_
-- prefix, so scrty's relations cannot collide with an application's own tables in a shared
-- schema. This migration changes catalog names only: no row, column, constraint definition or
-- data type changes. An index that backs a primary key or a unique constraint carries that
-- constraint's name with it, so the constraint is renamed by its index and never by a
-- statement of its own. The sequence is renamed explicitly: renaming its table leaves its name
-- as it was, and it stays linked to the column it fills, so history order carries on. The
-- version table (goose_identity) keeps its name.
--
-- The statements are explicit and carry no IF EXISTS: a relation missing here is a database
-- that is not at the version this migration expects, and the upgrade must fail, not skip it.
-- lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock a rename takes, so a long
-- transaction on a table fails the upgrade within the bound instead of queueing every query
-- behind it; the migration is transactional, so a failure renames nothing.
--
-- Stop every application instance running a release that names the old tables before
-- applying this, and start the instances that name the new tables afterwards: a statement
-- against a name that no longer exists fails, it is not redirected.
SET LOCAL lock_timeout = '5s';

ALTER TABLE assigned_roles RENAME TO scrty_assigned_roles;
ALTER TABLE groups RENAME TO scrty_groups;
ALTER TABLE organizations RENAME TO scrty_organizations;
ALTER TABLE password_history RENAME TO scrty_password_history;
ALTER TABLE resource_privileges RENAME TO scrty_resource_privileges;
ALTER TABLE roles RENAME TO scrty_roles;
ALTER TABLE users RENAME TO scrty_users;
ALTER INDEX assigned_roles_pkey RENAME TO scrty_assigned_roles_pkey;
ALTER INDEX assigned_roles_user_id RENAME TO scrty_assigned_roles_user_id;
ALTER INDEX groups_pkey RENAME TO scrty_groups_pkey;
ALTER INDEX organizations_pkey RENAME TO scrty_organizations_pkey;
ALTER INDEX password_history_pkey RENAME TO scrty_password_history_pkey;
ALTER INDEX password_history_user_seq RENAME TO scrty_password_history_user_seq;
ALTER INDEX resource_privileges_pkey RENAME TO scrty_resource_privileges_pkey;
ALTER INDEX resource_privileges_role_name RENAME TO scrty_resource_privileges_role_name;
ALTER INDEX roles_name_key RENAME TO scrty_roles_name_key;
ALTER INDEX roles_pkey RENAME TO scrty_roles_pkey;
ALTER INDEX users_pkey RENAME TO scrty_users_pkey;
ALTER INDEX users_username_key RENAME TO scrty_users_username_key;
ALTER SEQUENCE password_history_seq_seq RENAME TO scrty_password_history_seq_seq;

-- +goose Down
-- Exactly what Up renamed, in reverse. IF EXISTS on every statement, so a rollback still
-- completes after a relation was dropped by hand.
ALTER SEQUENCE IF EXISTS scrty_password_history_seq_seq RENAME TO password_history_seq_seq;
ALTER INDEX IF EXISTS scrty_users_username_key RENAME TO users_username_key;
ALTER INDEX IF EXISTS scrty_users_pkey RENAME TO users_pkey;
ALTER INDEX IF EXISTS scrty_roles_pkey RENAME TO roles_pkey;
ALTER INDEX IF EXISTS scrty_roles_name_key RENAME TO roles_name_key;
ALTER INDEX IF EXISTS scrty_resource_privileges_role_name RENAME TO resource_privileges_role_name;
ALTER INDEX IF EXISTS scrty_resource_privileges_pkey RENAME TO resource_privileges_pkey;
ALTER INDEX IF EXISTS scrty_password_history_user_seq RENAME TO password_history_user_seq;
ALTER INDEX IF EXISTS scrty_password_history_pkey RENAME TO password_history_pkey;
ALTER INDEX IF EXISTS scrty_organizations_pkey RENAME TO organizations_pkey;
ALTER INDEX IF EXISTS scrty_groups_pkey RENAME TO groups_pkey;
ALTER INDEX IF EXISTS scrty_assigned_roles_user_id RENAME TO assigned_roles_user_id;
ALTER INDEX IF EXISTS scrty_assigned_roles_pkey RENAME TO assigned_roles_pkey;
ALTER TABLE IF EXISTS scrty_users RENAME TO users;
ALTER TABLE IF EXISTS scrty_roles RENAME TO roles;
ALTER TABLE IF EXISTS scrty_resource_privileges RENAME TO resource_privileges;
ALTER TABLE IF EXISTS scrty_password_history RENAME TO password_history;
ALTER TABLE IF EXISTS scrty_organizations RENAME TO organizations;
ALTER TABLE IF EXISTS scrty_groups RENAME TO groups;
ALTER TABLE IF EXISTS scrty_assigned_roles RENAME TO assigned_roles;
