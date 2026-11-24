-- +goose Up
-- The identity and administration schema, created directly under the scrty_ prefix.
-- Identity only: no security-state tables, and no cross-table constraint linking to or
-- from them or between these tables. A dangling or absent organization, group or role
-- reference loads as absent, never an error. See the schema-migrations spec.
--
-- Every CREATE carries no IF NOT EXISTS: a relation of the same name already present is
-- refused, never adopted, and the migration's transaction leaves nothing behind.
-- scrty_password_history is created last.

CREATE TABLE scrty_groups (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    internal   boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE scrty_organizations (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    -- Dangling or NULL: an organization without a group loads with Group ==
    -- nil, never an error.
    group_id   uuid NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE scrty_roles (
    id           uuid PRIMARY KEY,
    -- Not the only source of a grant's role name: just-in-time provisioning
    -- assigns claim-derived names that may not be in this catalogue.
    name         text NOT NULL UNIQUE,
    super_role   boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    display_name text NOT NULL DEFAULT '',
    description  text NOT NULL DEFAULT '',
    labels       text[] NOT NULL DEFAULT '{}',
    version      bigint NOT NULL DEFAULT 1
);

CREATE TABLE scrty_users (
    id                  uuid PRIMARY KEY,
    name                text NOT NULL DEFAULT '',
    username            text NOT NULL UNIQUE,
    -- Never NULL: a user with no credential yet stores an empty hash.
    password            bytea NOT NULL,
    active              boolean NOT NULL DEFAULT true,
    -- The primary role name, written by provisioning and by a role rebuild,
    -- never independently of the grants in assigned_roles.
    role                text NOT NULL DEFAULT '',
    organization_id     uuid NULL,
    -- Written only when a caller names it; NULL means never recorded.
    password_changed_at timestamptz NULL,
    -- NOT NULL DEFAULT false: losing an enrolment row must not clear the
    -- requirement, and a NULL would scan as "not required" and fail open.
    mfa_required        boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    -- NULL means no email recorded; a deleted user's email is cleared.
    email               text NULL,
    email_verified_at   timestamptz NULL,
    -- Soft deletion time; NULL means live.
    deleted_at          timestamptz NULL,
    version             bigint NOT NULL DEFAULT 1
);
-- Unique among live users, ignoring case. A deleted user has no email, and a NULL
-- email is never indexed.
CREATE UNIQUE INDEX scrty_users_email_live ON scrty_users (lower(email))
    WHERE deleted_at IS NULL AND email IS NOT NULL;
-- Serves the list order, (lower(username), id), and its cursor.
CREATE INDEX scrty_users_username_lower ON scrty_users (lower(username), id);

CREATE TABLE scrty_assigned_roles (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL,
    role_name    text NOT NULL,
    -- Explicit order, not identifier order: the identifier generator is
    -- replaceable and need not sort in creation order, so this column alone
    -- decides which duplicate grant survives an update's collapse.
    position     integer NOT NULL,
    is_primary   boolean NOT NULL DEFAULT false,
    super_role   boolean NOT NULL DEFAULT false,
    start_date   timestamptz NULL,
    valid_until  timestamptz NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL
);
CREATE INDEX scrty_assigned_roles_user_id ON scrty_assigned_roles (user_id);
-- Serves the check that a role is still assigned before it is deleted.
CREATE INDEX scrty_assigned_roles_role_name ON scrty_assigned_roles (role_name);

CREATE TABLE scrty_resource_privileges (
    id             uuid PRIMARY KEY,
    role_name      text NOT NULL,
    resource_group text NOT NULL,
    resource       text NOT NULL,
    privilege      text NOT NULL,
    granted        boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    -- 'all' is the scope a grant written without one has.
    scope          text NOT NULL DEFAULT 'all'
);
CREATE INDEX scrty_resource_privileges_role_name ON scrty_resource_privileges (role_name);

-- Nothing constrains user_id to the users table: identity tables reference each other by
-- value, so a dangling reference loads as absent and never as an error.
CREATE TABLE scrty_user_attributes (
    user_id uuid NOT NULL,
    name    text NOT NULL,
    value   text NOT NULL,
    PRIMARY KEY (user_id, name)
);
-- Exact-match search by attribute name and value.
CREATE INDEX scrty_user_attributes_name_value ON scrty_user_attributes (name, value);

CREATE TABLE scrty_password_history (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL,
    -- Same type and handling as scrty_users.password: never logged, never in
    -- error text, and never returned except through the history read.
    password   bytea NOT NULL,
    -- Order by seq, not by id or retired_at: the identifier generator is
    -- replaceable, and two retirements can tie on their timestamp. ALWAYS, so a
    -- caller cannot write the order.
    seq        bigint GENERATED ALWAYS AS IDENTITY,
    retired_at timestamptz NOT NULL
);
CREATE INDEX scrty_password_history_user_seq ON scrty_password_history (user_id, seq DESC);

-- +goose Down
-- Drops everything Up created, in reverse creation order, with every row in it. IF
-- EXISTS, so a rollback still completes after a table was dropped by hand. Dropping
-- scrty_password_history drops the sequence behind its seq column. lock_timeout bounds
-- the wait for the ACCESS EXCLUSIVE lock each DROP takes, so a long transaction on a
-- table fails the rollback within the bound instead of queueing every query behind it.
SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS scrty_password_history;
DROP TABLE IF EXISTS scrty_user_attributes;
DROP TABLE IF EXISTS scrty_resource_privileges;
DROP TABLE IF EXISTS scrty_assigned_roles;
DROP TABLE IF EXISTS scrty_users;
DROP TABLE IF EXISTS scrty_roles;
DROP TABLE IF EXISTS scrty_organizations;
DROP TABLE IF EXISTS scrty_groups;
