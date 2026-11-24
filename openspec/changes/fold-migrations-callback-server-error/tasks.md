# Tasks

## 1. Security-state baseline

- [ ] 1.1 Copy the eight v0.5.0 security-state files, unchanged, to `test/testdata/migrate/v0.5.0/securitystate/` and verify `diff -r` against `git show v0.5.0:store/migrate/securitystate/...` shows no difference
- [ ] 1.2 Write the equivalence test (D4): apply the frozen chain in one schema and the embedded set in another, compare columns (attnum order, type, nullability, default), index names and definitions, sequences, constraint definitions and table storage parameters; run it on PostgreSQL 15 and 18 and see it fail because the embedded set's schema differs (red)
- [ ] 1.3 Write the failing tests for the baseline's behaviour: one migration recorded, applies beside the consumer's own `sessions` and `users` tables, refuses an earlier history in `goose_security_state` with the "earlier release" error and leaves nothing, fails atomically when `scrty_sessions` already exists, applies with the old name chosen as version table; see each fail for the intended reason
- [ ] 1.4 Replace the set with `20261126000000_security_state.sql` (D1) and its guard (D3), remove the eight earlier files, and change `SecurityStateVersionTable` to `scrty_state_migrate` with its godoc (D2); verify 1.2 and 1.3 pass
- [ ] 1.5 Remove or rewrite every test that walks the earlier security-state chain or its rename (`test/migrate_securitystate_test.go`, `test/schema_inventory_test.go`, `test/prefix_schema_test.go`, `test/crossbackend/populated_test.go`, `test/migrate_rollback_bound_test.go`, `store/migrate/migrate_test.go`), keeping the fresh-schema, rollback, re-apply, goose-direct and consumer-schema scenarios against the baseline; verify the scoped run of `store/migrate`, `test`, `test/crossbackend` and every package applying the set passes
- [ ] 1.6 Update the godoc that names removed versions (`store/sqlstore`, `store/pgxstore`, `store/gormstore` `oidcprovider_device.go`) and verify `go vet` and `gofmt -l` are clean for those packages

## 2. Identity baseline

- [ ] 2.1 Copy the three v0.5.0 identity files, unchanged, to `test/testdata/migrate/v0.5.0/identity/` and verify `diff -r` against the v0.5.0 tag shows no difference
- [ ] 2.2 Extend the equivalence test to the identity set and see it fail (red)
- [ ] 2.3 Write the failing identity baseline tests: one migration recorded, applies beside the consumer's own `users` table with rows, refuses an earlier history in `goose_identity`, fails atomically when `scrty_users` already exists, live emails unique ignoring case and free again after deletion; see each fail for the intended reason
- [ ] 2.4 Replace the identity set with `20261126000000_identity.sql` (D1, D3), remove the three earlier files, and change `IdentityVersionTable` to `scrty_identity_migrate` with its godoc (D2); verify 2.2 and 2.3 pass
- [ ] 2.5 Remove or rewrite every test that walks the earlier identity chain, its rename or the separate administration migration (`test/migrate_identity_test.go`, `test/identity_prefix_test.go`, `store/migrate/migrate_test.go`), keeping the independence, rollback and consumer-named version table scenarios; verify the scoped run of `store/migrate`, `test`, `test/crossbackend` and every package applying the identity set passes

## 3. Callback server_error

- [ ] 3.1 Write the failing tests in `httpsec` for a parked login under completion: a hook `Apply` failure and a hook decide failure that is neither refusal nor outage each answer 303 to `<login URL>?req=<handle>&error=server_error` with the request still parked; the same under `WithOIDCFailToClient` answers the client with `error=server_error`, `state` and `iss`; see them fail on the plain error (red)
- [ ] 3.2 Make `callbackCode` answer `server_error` for every failure after the flow is spent that maps to no other code (D5), and revise its godoc; verify 3.1 passes
- [ ] 3.3 Verify, with tests, that an invalid state, an unspent flow, an unreadable error, a hung-up caller and a non-parked login keep their plain answer, and that no login-failure event is emitted for a `server_error` answer; run the scoped `httpsec` suite and its dependents

## 4. Documentation

- [ ] 4.1 Add this change's entries to `CHANGELOG.md` under `Unreleased`: the baselines, the new version tables, the refusal of earlier databases with the statements to drop them, and the callback's `server_error`; update `README.md` wherever it names the version tables or the upgrade path; verify with `git diff`

## 5. Final gate

- [ ] 5.1 Run `make check` and `make spec-check` once after the last code edit and read the output
- [ ] 5.2 Run the whole-branch review against every requirement of this change's specs, and fix findings before re-running 5.1

## Workflow follow-up

- Open the pull request. The change ships in v0.6.0, whose release preparation (`RELEASING.md` steps 1-2) runs once every v0.6.0 change has merged; the maintainer tags.
- Archive the change after merge.
- Message the CRM rewrite coordinator with the v0.6.0 tag and this change's changelog lines.
