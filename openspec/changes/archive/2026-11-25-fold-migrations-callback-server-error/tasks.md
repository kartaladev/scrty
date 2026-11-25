# Tasks

## 1. Security-state baseline

- [x] 1.1 Copy the eight v0.5.0 security-state files, unchanged, to `test/testdata/migrate/v0.5.0/securitystate/`. Verify: each file is byte-identical to `git show v0.5.0:<path>`.
- [x] 1.2 Write the equivalence test (D4). It compares:
  - columns in attnum order, with type, nullability, default and identity;
  - table persistence and storage parameters;
  - index names and definitions;
  - sequences with their parameters;
  - constraint definitions.

  Show it red by mutation: drop a column in a scratch copy of the frozen fixture, see the diff, restore. Verify: it passes against the unchanged chain on PostgreSQL 15 and 18.
- [x] 1.3 Write the failing baseline tests:
  - exactly one migration is recorded, in `scrty_state_migrate`;
  - the set applies beside the consumer's own `sessions` and `users` tables and leaves their rows;
  - with `scrty_rate_limit_buckets`, the last relation, pre-created, applying fails, no earlier relation exists, and no version is recorded;
  - a consumer-named version table records the version.

  See each fail for the intended reason.
- [x] 1.4 Replace the set with `20261126000000_security_state.sql` (D1: chain column order, identity, persistence, storage parameters, and a down section bounded by `lock_timeout`). Remove the eight earlier files. Change `SecurityStateVersionTable` to `scrty_state_migrate`, with its godoc (D2). Verify: 1.2 and 1.3 pass.
- [x] 1.5 Remove or rewrite every test that walks the earlier security-state chain or its rename. Keep the test packages compiling for task 2, which still uses the identity chain. Keep, against the baseline:
  - the fresh-schema, rollback-to-zero, "table already dropped", re-apply, goose-direct, consumer-schema and 63-byte scenarios;
  - `TestMigrationRollback_LockBound`;
  - the synthetic populated-migration test;
  - the twenty-five-table count.

  Update `store/migrate/migrate_test.go` and `store/gormstore/models_test.go`. Verify: the scoped run in `plans.md` (Lane M) passes.
- [x] 1.6 Update the comments and godoc that name removed migrations (`store/{sqlstore,pgxstore,gormstore}/oidcprovider_device.go`, `store/{sqlstore,pgxstore}/limiter_factory.go`). Verify: `go vet` and `gofmt -l` are clean in the root module and in `store/pgxstore` and `store/gormstore`.

## 2. Identity baseline

- [x] 2.1 Copy the three v0.5.0 identity files, unchanged, to `test/testdata/migrate/v0.5.0/identity/`. Verify: each file is byte-identical to `git show v0.5.0:<path>`.
- [x] 2.2 Extend the equivalence test to the identity set, including `scrty_password_history.seq`'s `GENERATED ALWAYS` identity. Show it red by mutation. Verify: it passes against the unchanged chain.
- [x] 2.3 Write the failing identity baseline tests:
  - exactly one migration is recorded, in `scrty_identity_migrate`;
  - the set applies beside the consumer's own `users` table and leaves its rows;
  - with `scrty_password_history`, the last relation, pre-created, applying fails and no earlier relation or version remains;
  - live emails are unique ignoring case, and free again after deletion;
  - a privilege row inserted without a scope loads with scope `all`.

  See each fail for the intended reason.
- [x] 2.4 Replace the identity set with `20261126000000_identity.sql` (D1). Remove the three earlier files. Change `IdentityVersionTable` to `scrty_identity_migrate`, with its godoc (D2). Extend the no-transaction-annotation check to the identity set. Verify: 2.2 and 2.3 pass.
- [x] 2.5 Remove or rewrite every test that walks the earlier identity chain, its rename or the separate administration migration. Keep the independence, rollback, consumer-named version table and lock-bound scenarios. Update the identity godoc in `store/{sqlstore,pgxstore,gormstore}/identity.go`. Verify: the scoped run (Lane M) passes.

## 3. Callback server_error

- [x] 3.1 Write the failing tests in `httpsec` for a parked login under completion:
  - a hook `Apply` failure answers 303 to `<login URL>?req=<handle>&error=server_error`, with the request still parked;
  - so does a hook decide failure that is neither a refusal nor an outage;
  - under `WithOIDCFailToClient`, the same failures answer the client with `error=server_error`, `state` and `iss`.

  See them fail on the plain error.
- [x] 3.2 Make `callbackCode` list its exclusions (unspent flow, invalid state, hung-up caller, `ErrOIDCReauthenticate`, `oidc.ErrUnknownProvider`) and answer `server_error` by default (D5), and revise its godoc. Verify: 3.1 passes, and `TestParkedFailureCode`'s re-authentication and unknown-provider cases still expect no code.
- [x] 3.3 Write the failing test that a `server_error` answer writes one error-level record naming the cause's type, with no handle, state, redirect target or error text, and that a refusal writes none. Then add the record (D7). Verify: the test passes.
- [x] 3.4 Verify with tests that these keep their plain answer: an invalid state, an unspent flow, an unreadable error, a hung-up caller, a non-parked login, and a consumer manager failing without the unspent marker. Verify too that a `server_error` answer emits no login-failure event. Then run Lane C's scoped commands.

## 4. Documentation

- [x] 4.1 Add this change's entries to `CHANGELOG.md` under `Unreleased`:
  - the baselines and the new version tables;
  - that earlier databases must be recreated, with the drop statements (every `scrty_%` relation and the `goose_*` and `scrty_*_migrate` version tables);
  - that going back to v0.5.0 is not supported;
  - that one `goose down` drops a whole set;
  - the recommendation of `goose.WithSessionLocker`;
  - the callback's `server_error` and its error record.

  Update `README.md` where it names the version tables, a removed migration, the fresh-install steps or the rename's limits. Verify with `git diff`.

## 5. Final gate

- [x] 5.1 Run `make check` and `make spec-check` once after the last code edit, and read the output.
- [x] 5.2 Run the whole-branch review against every requirement of this change's specs. Fix the findings, then re-run 5.1.

## Workflow follow-up

- Update the pull request. The change ships in v0.6.0, whose release preparation (`RELEASING.md` steps 1–2) runs once every v0.6.0 change has merged. The maintainer tags.
- Archive the change after merge.
- Message the CRM rewrite coordinator with the v0.6.0 tag and this change's changelog lines.
