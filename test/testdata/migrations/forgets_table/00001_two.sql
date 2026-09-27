-- +goose Up
CREATE TABLE probe_a (id uuid PRIMARY KEY);
CREATE TABLE probe_b (id uuid PRIMARY KEY);

-- +goose Down
-- Deliberately drops only probe_a: the helper's leftover-table finalizer must
-- name probe_b.
DROP TABLE probe_a;
