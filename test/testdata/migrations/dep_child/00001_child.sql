-- +goose Up
-- References dep_parent, so this set's rollback must run before dep_parent's:
-- rolling back dep_parent first would fail with a foreign key violation while
-- this table still exists.
CREATE TABLE dep_child (id uuid PRIMARY KEY REFERENCES dep_parent (id));

-- +goose Down
DROP TABLE dep_child;
