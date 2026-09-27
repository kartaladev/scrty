-- +goose Up
CREATE TABLE dep_parent (id uuid PRIMARY KEY);

-- +goose Down
DROP TABLE dep_parent;
