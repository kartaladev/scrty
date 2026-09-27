-- +goose Up
CREATE TABLE ok_table (id uuid PRIMARY KEY);

-- +goose Down
DROP TABLE IF EXISTS ok_table;
