-- +goose Up
-- Deliberately invalid SQL ("TBLE" is not a keyword): Up must fail, and
-- postgresSetUp must record that failure rather than panic or abort the test
-- binary.
CREATE TBLE this_is_not_valid_sql (id uuid PRIMARY KEY);

-- +goose Down
SELECT 1;
