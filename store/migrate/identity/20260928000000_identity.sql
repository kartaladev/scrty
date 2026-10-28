-- +goose Up
-- Identity only: no security-state tables, and no cross-table constraint
-- linking to or from them. A dangling or absent organization, group or role
-- reference loads as absent, never an error. See the schema-migrations spec.

CREATE TABLE groups (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    internal   boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE organizations (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    -- Dangling or NULL: an organization without a group loads with Group ==
    -- nil, never an error.
    group_id   uuid NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE roles (
    id         uuid PRIMARY KEY,
    -- Not the only source of a grant's role name: just-in-time provisioning
    -- assigns claim-derived names that may not be in this catalogue.
    name       text NOT NULL UNIQUE,
    super_role boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE users (
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
    -- Written only when a caller names it; NULL means never recorded. A
    -- password written without naming this leaves the stored value as it
    -- was, which is right for a password mirrored from an identity
    -- provider and wrong for a local change.
    password_changed_at timestamptz NULL,
    -- NOT NULL DEFAULT false: losing an enrolment row must not clear the
    -- requirement, a NULL would scan as "not required" and fail open, and
    -- the default lets the column be added to a populated table.
    mfa_required        boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL
);

CREATE TABLE assigned_roles (
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
CREATE INDEX assigned_roles_user_id ON assigned_roles (user_id);

CREATE TABLE resource_privileges (
    id             uuid PRIMARY KEY,
    role_name      text NOT NULL,
    resource_group text NOT NULL,
    resource       text NOT NULL,
    privilege      text NOT NULL,
    granted        boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);
CREATE INDEX resource_privileges_role_name ON resource_privileges (role_name);

CREATE TABLE password_history (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL,
    -- Same type and handling as users.password: never logged, never in
    -- error text, and never returned except through the history read.
    password   bytea NOT NULL,
    -- Order by seq, not by id or retired_at: the identifier generator is
    -- replaceable, and two retirements can tie on their timestamp.
    seq        bigint GENERATED ALWAYS AS IDENTITY,
    retired_at timestamptz NOT NULL
);
CREATE INDEX password_history_user_seq ON password_history (user_id, seq DESC);

-- +goose Down
-- Reverse creation order; IF EXISTS so teardown completes after a test drops
-- a table. Touches nothing outside this set.
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS resource_privileges;
DROP TABLE IF EXISTS assigned_roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS groups;
