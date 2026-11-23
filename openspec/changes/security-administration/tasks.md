# Tasks

Every task is test-first: write the failing test, run it with a focused `go test -run`, see it fail
for the intended reason (not a compile error), then implement, then refactor. Tests follow the
`table-test`, `use-mockgen` and `use-testcontainers` skills. "Verify" names the command that must pass
when the task is done. Scoped runs cover the changed packages and their transitive dependents
(`test-scope.md`); the full suite runs once, in group 14.

The whole change lands in one pull request, opened after group 14's final gate (design D1).

## 1. Identity model

- [x] 1.1 `identity.Scope`, `ScopeAll`, `ScopeOwn`, and `Privilege.Scope`, with the empty scope read
  as `all` by a helper `Privilege.EffectiveScope()` (spec identity-model "Scope preserved"). Red: a
  table test of `EffectiveScope` for empty, `all`, `own` and `team`, against a stub that returns the
  stored value, fails on the empty case. Verify: `go test -race -count=1 ./identity/`.
- [x] 1.2 `Details.Email`, `Details.EmailVerifiedAt` and `Details.EmailVerified()` (spec "Unverified
  email"). Red: `EmailVerified` reports true for a zero time. Verify: `go test -race -count=1 ./identity/`.
- [x] 1.3 `identity.EmailLoader` port with godoc stating the contract (spec "Email loader contract");
  regenerate the mocks that consumers of `identity` use. Verify: `go vet ./identity/` and
  `go generate ./...` leaves no diff after a second run.
- [x] 1.4 `identity.PrincipalFromDetailsAt(details, at)` keeps only grants valid at `at` and makes the first
  kept primary grant active, or none (spec "Expired primary grant", "Grant not yet started",
  "Boundary"; design D17, F18). Red: a table test with an expired primary grant expects no active
  role and gets `sales`. Verify: `go test -race -count=1 ./identity/`.

## 2. Authorization core

- [x] 2.1 Denial reasons `ErrNoSubject`, `ErrNoActiveRole`, `ErrNotGranted`, `ErrWrongScope`,
  `ErrNotOwner`, each wrapped with `ErrAccessDenied` by the privilege and ownership authorizers and
  the requirements (spec "Denials say why"; design D8). Red: `errors.Is(err, ErrNoActiveRole)` is
  false for a subject without a role. Verify: `go test -race -count=1 ./authorize/`.
- [x] 2.2 Scope in the privilege authorizer: `PrivilegeAttributes.Accept`, empty meaning `all` only;
  an own-only grant fails a plain check with `ErrWrongScope`; an undefined scope covers nothing
  (spec MODIFIED "Privilege checks match…", "A grant carries a scope"; design D4, F12, F13). Red: the
  own-only scenario is allowed. Verify: `go test -race -count=1 ./authorize/`.
- [x] 2.3 `authorize.AllOf` (spec MODIFIED "Requirements distinguish…": all-of across resources,
  empty, absent member; design D6). Red: the across-resources case is allowed. Verify:
  `go test -race -count=1 ./authorize/`.
- [x] 2.4 `HasPrivilegeAnyScope`, which reports the strongest scope held through the context, and
  `HasPrivilegeFor` with `OwnershipAttributes`, which calls the ownership check only for `own` (spec
  "A check can accept any scope…", "A check for one record…"; design D4). Red: the all-scope record
  check calls the ownership mock, which `gomock` rejects. Verify: `go test -race -count=1 ./authorize/`.
- [x] 2.5 The request memo: `authorize.WithRequestMemo`, one load per role, `ErrPrivilegesNotFound`
  remembered, other errors not, a bound of 32 roles (spec "…loaded at most once per request", "A
  consumer can install a memo outside the chain"; design D5, F14, F15, F17). Red: ten checks call the
  loader mock ten times. Add a barrier test of eight concurrent checks expecting one load. Verify:
  `go test -race -count=1 ./authorize/`.
- [x] 2.6 The bulk check `HeldPrivileges` and `PrivilegeInspector`, through `FirstOf`, with
  `ErrInspectionUnsupported` for an authorizer without it (spec "One call reports…"; design D7, F32).
  Red: the allowed-actions scenario reports `update` as not held. Verify:
  `go test -race -count=1 ./authorize/`.
- [x] 2.7 `authorize.Catalogue`: construction refusals, default scopes, `Allows`, and a defensive copy
  (spec resource-catalogue, all requirements; design D9, F30). Red: a duplicate `view`/`VIEW` is
  accepted. Verify: `go test -race -count=1 ./authorize/`.
- [x] 2.8 Godoc for every new exported name, naming its default and override, and an `Example` for the
  any-scope list filter and the bulk check. Verify: `go test -run Example -count=1 ./authorize/` and
  `go doc -all ./authorize | grep -c HeldPrivileges`.

## 3. Chain and adapters

- [x] 3.1 `httpsec.Guards.Require(authorize.Requirement)`, refusing an absent requirement when built
  (spec http-security-chain "The net/http guard accepts any requirement"; design D6). Red: an all-of
  guarded route runs its handler for a principal missing one member. Verify: scoped `httpsec` run
  from `plans.md`.
- [x] 3.2 The same guard in `ginsec` and `fibersec`, with a test that runs one composed requirement
  through net/http, gin and fiber and compares status and error (spec framework-adapters "Adapter guards
  accept any requirement"). Red: the fiber case is missing. Verify: `go test -race -count=1
  ./httpsec/ginsec/... ./httpsec/fibersec/...` from their module directories.
- [x] 3.3 The chain attaches a fresh memo per authenticated request, with `WithoutPrivilegeMemo`
  (spec "Every request carries its own privilege memo by default"; design F16). Red: a counting role
  loader sees ten loads for one request. Verify: scoped `httpsec` run.
- [x] 3.4 The chain builds the principal with `identity.PrincipalFromDetailsAt` at its clock (spec "The
  principal holds only the role grants valid…"; design D17, F18). Red: a request with an expired
  primary grant passes a privilege guard. Verify: scoped `httpsec` run, then the `test` module's
  adapter integration suites.

## 4. Migrations

- [x] 4.1 Identity migration `<ts>_scrty_administration.sql` after `20261124000000_scrty_prefix`: user
  email, verification, deletion and version columns; role display name, description, labels and
  version; privilege scope (default `all`); `scrty_user_attributes`; the partial unique email index;
  the down section in reverse (spec schema-migrations "The identity set adds…", "…rolls back exactly
  what it added"; design D11 to D15). Red: a catalog test in `test/` expects the new columns and
  table and fails. Verify: the identity migration tests on PostgreSQL 15 and 18.
- [x] 4.2 Atomic-failure migration test: add a consumer `email` column to `scrty_users`, then apply;
  the migration fails and the catalog shows nothing added (spec "Consumer already added an email
  column"; design F22).
  Verify: the focused test.
- [x] 4.3 Populated-database test: users, roles and privileges written before the migration read back
  with no email, version 1 and scope `all` (spec "Apply to a populated database"). Verify: the focused
  test.
- [x] 4.4 Security-state migration `<ts>_scrty_selected_role.sql` adding the nullable
  `scrty_sessions.selected_role`, with its down section and an existing-sessions test (spec "The
  security-state set adds the selected-role column"). Verify: the security-state migration tests.

## 5. SQL identity stores: runtime reads

- [x] 5.1 `internal/pgschema` statements and `sqlstore`/`pgxstore`: load privileges with scope;
  load email and verification; filter deleted users from every loader and from the MFA lookup (spec
  default-identity-store MODIFIED "Loading a user…", "The store never returns a deleted user…",
  "Privilege scopes are stored…"), and the identity port's `Update` increases `version` (design
  D11). Red: new cases in the identity conformance suite (`test/identity`)
  fail on scope and on a deleted user. Verify: the identity conformance suite for `sqlstore` and
  `pgxstore`.
- [x] 5.2 `LoadByEmail` in both SQL stores: lower-cased match, live and verified only, unrepresentable
  input as not found (spec "The store loads a user by verified email", identity-model "Email loader
  contract"). Red: new conformance cases. Verify: as 5.1.
- [x] 5.3 Provisioning and username-naming updates take the advisory lock and refuse a username equal
  to another live user's email; the email given to `Provision` is still not stored (spec "Provisioning
  refuses a username that is another user's email"; design D12, F5, F31). Red: the conformance case
  provisions `carol@example.com` successfully; add a barrier test for the racing pair. Verify: as 5.1.

## 6. Gorm identity store: runtime reads

- [x] 6.1 The same as 5.1 to 5.3 in `gormstore`, with the models gaining the new columns and the
  attribute model. Red: the same conformance cases fail for gorm. Verify: the identity conformance
  suite for `gormstore`.

## 7. Administration services

- [x] 7.1 Package `admin`: ports, record types, errors (`ErrNotFound`, `ErrAlreadyExists` with the
  field, `ErrStillAssigned`, `ErrStaleUpdate`, `ErrUnknownPrivilege`, `ErrInvalidInput`,
  `ErrNoActor`), `WithSystemActor`, and mocks for every port (spec "Administration errors carry one
  reason each", "Every administrative call names its actor"; design D2, D3, F25, F29). Red: a table test that
  `ErrAlreadyExists` for the email does not contain the address. Verify: `go test -race -count=1 ./admin/`.
- [x] 7.2 `admin.NewUsers`: list bounds and cursor, get, create, update, deactivate, reactivate,
  delete, against the store mock (spec user requirements; design D15, D16, F23, F24). Red: an
  oversized page reaches the store. Verify: `go test -race -count=1 ./admin/`.
- [x] 7.3 Password set and reset through the policy, the reuse guard, the encoder, the history and the
  clock, in one store call (spec "Passwords are set through…"). Red: a reused password reaches the
  store. Verify: `go test -race -count=1 ./admin/`.
- [x] 7.4 `admin.NewImporter`: canonical identifier, recognised hash, outcome reporting, no event for
  `Unchanged` (spec "Import writes given values…", "Import never takes over…"; design D14, F8, F9).
  Red: an unrecognised hash reaches the store. Verify: `go test -race -count=1 ./admin/`.
- [x] 7.5 `admin.NewRoles`, `admin.NewGrants` (catalogue required, every grant checked) and
  `admin.NewAssignments` (end after start) (spec role, grant and assignment requirements; design D9,
  D10, F11, F30). Red: a grant naming `purge` reaches the store. Verify: `go test -race -count=1 ./admin/`.
- [x] 7.6 Events: `event.Event` gains `Actor`, `Target`, `Changed`; each service emits the OWASP name
  after a successful store call, and none for a refusal, failure or no-op; new names are listed by
  `event.Names` (spec security-events "Administration changes are reported…", "An administration event
  names…"; design D19). Red: a deactivation of an inactive user emits `user_archived`. Verify:
  `go test -race -count=1 ./admin/ ./event/`.
- [x] 7.7 The audit port: before and after records without a hash field; a failing or panicking sink
  is logged without values and the call still succeeds (spec "Before and after values go only to an
  optional audit port"; design F26). Red: a panicking sink fails the call. Verify:
  `go test -race -count=1 ./admin/`.
- [x] 7.8 Godoc for the package, each service and option (default and override), and one `Example`
  per service. Verify: `go test -run Example -count=1 ./admin/`.

## 8. SQL stores: administration ports

- [ ] 8.1 The administration conformance suite in `test/admin` covering versions, row-lock
  serialisation with barrier tests, uniqueness of username and email, soft deletion, attributes,
  paging, import idempotence, forced role delete and the primary-grant hand-over (spec
  default-identity-store "The administration conformance suite tests any implementation"; design F1
  to F4, F10, F28, F33). Red: run against a stub that returns `ErrNotFound`; every case fails. Verify:
  the suite compiles and its cases fail against the stub.
- [ ] 8.2 `sqlstore` and `pgxstore` user and import ports through shared `pgschema` statements
  (design D11 to D16). Red: the user and import cases of 8.1. Verify: the administration suite's user
  and import cases for both stores.
- [ ] 8.3 `sqlstore` and `pgxstore` role, grant and assignment ports, grant replacement in one
  transaction (design D10, D11, F2, F3). Red: the role, grant and assignment cases of 8.1, including a
  failure injected between delete and insert. Verify: the full administration suite for both stores.

## 9. Gorm store: administration ports

- [ ] 9.1 `gormstore` implements every administration port. Red: the administration suite for gorm.
  Verify: the full administration suite for `gormstore` on PostgreSQL 15 and 18.

## 10. Administration end to end

- [ ] 10.1 A `test` module scenario over the real chain and store: create a role with a catalogue,
  grant `view` all and `update` own, assign it, log in, check allowed actions with the bulk check,
  update an own record, refuse another's record with `ErrNotOwner`, deactivate the user and see the
  next request refused (design F10, F13). Verify: the focused test in `test/`.
- [ ] 10.2 Import scenario: import a user with a bcrypt hash, log in with the password, re-import
  with equal values and see `Unchanged` and no event. Verify: the focused test in `test/`.

## 11. Login by email

- [ ] 11.1 `authenticate.WithEmailLogin` and the identifier resolution step: construction refuses a
  loader without `EmailLoader`; username first, then verified email; the conflict refusal with decoy
  work and `scrty_identifier_conflict` (spec authentication, all four requirements; design D18, F6,
  F21). Red: the email-login scenario returns the uniform failure. Verify: `go test -race -count=1
  ./authenticate/...`.
- [ ] 11.2 The chain's login and basic endpoints resolve before the pre-authentication phase and pass
  the resolved details to the provider, so lockout keys on the account and the user is loaded once
  (spec security-policy, both requirements; design F20). Red: three failures by username and two by
  email do not lock. Verify: scoped `httpsec` run.
- [ ] 11.3 Timing parity test: unknown email, unverified email and unknown username spend the same
  password work, counted through a counting encoder (spec "Email login reveals nothing…"). Verify:
  the focused test.
- [ ] 11.4 Godoc and an `Example` for email login, naming the default (off). Verify:
  `go test -run Example -count=1 ./authenticate/`.

## 12. Switching the active role

- [x] 12.1 `session.Session.SelectedRole`, a store method that writes only that field, kept by every
  rotation, in the memory store and the three durable stores (spec sessions, both requirements). Red:
  the session conformance suite's new cases fail. Verify: the session conformance suites.
- [ ] 12.2 `httpsec.WithActiveRoleSwitching` and `Chain.SwitchActiveRole`, with `ErrRoleNotHeld` for a role
  not held and a not-enabled error when off; the `scrty_active_role_switched` event (spec "Switching
  the active role is opt-in"; design D20). Red: switching to `audit` leaves `sales` active. Verify:
  scoped `httpsec` run.
- [ ] 12.3 The selected role is applied per request only while held and valid, and ignored when
  switching is off (spec "A selected role applies only while it is still held"; design F19). Red: a
  removed `audit` grant stays active. Verify: scoped `httpsec` run and the adapter integration suites.

## 13. Documentation and release notes

- [ ] 13.1 README: the administration services, the catalogue, scopes, the memo, email login and role
  switching, each with its default and override. Verify: every code block in the new sections compiles
  as an `Example` or is copied from one.
- [ ] 13.2 CHANGELOG under Unreleased: Added entries, the three behaviour changes under Changed marked
  breaking, the two migrations, and the note on a consumer-added `email` column. Verify: `make spec-check` and a read of
  the entry against proposal.md's behaviour changes.

## 14. Final gate

- [ ] 14.1 Whole-branch review against every spec requirement this change covers, by a fresh reviewer
  that did not write the code, findings fixed in fresh dispatches. Verify: the review reports no open
  finding.
- [ ] 14.2 Full suite after the last code edit: `make check` and `make spec-check`, and the test leg on
  PostgreSQL 15. Verify: each exits 0, with the output read by the main session.

## Workflow follow-up

- Archive the change after the final gate and the review.
- The maintainer tags v0.3.0 once this change's pull request has merged.
