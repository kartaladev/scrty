-- +goose Up
-- How a sign-in was proved, on every provider record that keeps a sign-in in columns:
-- whether the library verified a second factor in it, and, for a federated sign-in, the
-- provider's configured name and the amr and acr its ID token asserted. The upstream
-- issuer already has its column. Pending requests and device authorizations keep their
-- sign-in as a jsonb document, which gains the same fields and needs no column.
--
-- The columns are nullable with no default, so adding them rewrites no row and reads no
-- table. A row written before this migration holds NULL in each, which the stores read
-- as no marker and no evidence: the fail-closed reading.
--
-- lock_timeout bounds the wait for the ACCESS EXCLUSIVE lock each ALTER takes, so a long
-- transaction on a table fails the migration within the bound instead of queueing every
-- query behind it. The migration runs in one transaction, so a failure leaves nothing.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scrty_op_grants ADD COLUMN second_factor_verified boolean NULL, ADD COLUMN external_provider text NULL, ADD COLUMN external_amr jsonb NULL, ADD COLUMN external_acr text NULL;
ALTER TABLE scrty_op_authorization_codes ADD COLUMN second_factor_verified boolean NULL, ADD COLUMN external_provider text NULL, ADD COLUMN external_amr jsonb NULL, ADD COLUMN external_acr text NULL;
ALTER TABLE scrty_op_browser_sessions ADD COLUMN second_factor_verified boolean NULL, ADD COLUMN external_provider text NULL, ADD COLUMN external_amr jsonb NULL, ADD COLUMN external_acr text NULL;

-- +goose Down
-- Drops exactly the columns Up added, with the values in them, and nothing else. A
-- sign-in document of a pending request or device authorization keeps the fields, which
-- a store of the earlier schema ignores. lock_timeout bounds each ALTER, as in Up.
SET LOCAL lock_timeout = '5s';

ALTER TABLE IF EXISTS scrty_op_browser_sessions DROP COLUMN IF EXISTS second_factor_verified, DROP COLUMN IF EXISTS external_provider, DROP COLUMN IF EXISTS external_amr, DROP COLUMN IF EXISTS external_acr;
ALTER TABLE IF EXISTS scrty_op_authorization_codes DROP COLUMN IF EXISTS second_factor_verified, DROP COLUMN IF EXISTS external_provider, DROP COLUMN IF EXISTS external_amr, DROP COLUMN IF EXISTS external_acr;
ALTER TABLE IF EXISTS scrty_op_grants DROP COLUMN IF EXISTS second_factor_verified, DROP COLUMN IF EXISTS external_provider, DROP COLUMN IF EXISTS external_amr, DROP COLUMN IF EXISTS external_acr;
