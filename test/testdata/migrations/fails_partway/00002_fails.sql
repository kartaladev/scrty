-- +goose Up
CREATE TABLE half_a (id uuid PRIMARY KEY);
SELECT 1/0;

-- +goose Down
DROP TABLE IF EXISTS half_a;
