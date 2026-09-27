-- +goose Up
CREATE TABLE probe_a (id uuid PRIMARY KEY);

-- +goose Down
DROP TABLE probe_a;
