-- +goose Up
CREATE TABLE goose_like_but_real (id uuid PRIMARY KEY);

-- +goose Down
-- Deliberately does not drop goose_like_but_real: it must survive rollback,
-- proving the leftover-table check names a table merely shaped like a goose
-- version table rather than exempting it by name pattern.
SELECT 1;
