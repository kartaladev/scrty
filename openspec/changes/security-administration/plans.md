# Security Administration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ready-to-use security administration (users, roles, grants, assignments, import), scoped
grants with a resource catalogue, a per-request privilege memo, `AllOf` and any-requirement guards,
a bulk check, login by email, and an optional active-role switch, all shipping in v0.3.0.

**Architecture:** The runtime pieces live in `identity` and `authorize` and are wired by the
`httpsec` chain and its gin and fiber adapters. A new `admin` package holds services over store
ports. The three identity stores implement those ports, proven by one conformance suite in the
`test` module. Two migrations add the columns and tables.

**Tech Stack:** Go 1.27, database/sql + pgx v5 + gorm over PostgreSQL 15 and 18, goose migrations,
uber-go/mock (`mockgen --typed`), testcontainers through `test.RunTestPostgres`, gin, fiber v3.

**Spec:** `openspec/changes/security-administration/` — `proposal.md`, `design.md` (decisions D1 to
D20, failure modes F1 to F33), `specs/*/spec.md`, `tasks.md`. Step numbers below are `tasks.md`
numbers.

## Global Constraints

- No new module dependency. No exported signature changes; everything is added beside what exists.
- Every new relation and index carries the `scrty_` prefix. Version tables stay `goose_identity` and
  `goose_security_state`. Migrations sort after `20261124000000_scrty_prefix` and have a Down section.
- Default page size 50, maximum 500; attribute names 1 to 64 bytes, values up to 1024 bytes, at most
  64 per user; memo bound 32 roles.
- Scope values: `"all"`, `"own"`; the empty scope reads as `"all"`.
- Event names: `user_created`, `user_updated`, `user_archived`, `user_deleted`,
  `authn_password_change`, `privilege_permissions_changed`, `authz_change`, `authz_admin`,
  `scrty_user_reactivated`, `scrty_user_imported`, `scrty_identifier_conflict`,
  `scrty_active_role_switched`.
- Error text never contains a username, email, attribute value or password hash.
- Tests: `table-test` skill (assert closures, `t.Context()`), `use-mockgen` (mocks in `_test.go`
  files of the consuming package), `use-testcontainers` (`test.RunTestPostgres`; no fakes).
- The `test` module is imported by no other module, including from `_test.go` files.
- Never cite the predecessor in code, comments, godoc or commits (`legacy-reference.md`).

## Review Focus

1. **A consumer `RoleLoader` that returns privileges with no scope**, such as an existing in-house
   loader, must keep authorizing exactly as before. Pinned in Task 2.2 by `TestPrivilege_EmptyScopeReadsAsAll`.
2. **A handler that checks `HasPrivilege` on a list route while the caller holds only `own`** must be
   denied, not shown every row. Pinned in Task 10.1 step "own-only list".
3. **An administrator's tab left open for an hour, then saved**, must get `ErrStaleUpdate`, not
   overwrite a colleague's change. Pinned in Task 8.1 `StaleAfterLoginUpdate`: a login-time
   `Update` moves the version too (D11).
4. **An import run twice concurrently for the same new identifier** must create one user and report
   `Created` once and `Unchanged` or `Updated` for the other, never a constraint error. Pinned in
   Task 8.1 `ImportRace`.
5. **A user whose primary grant expired but who holds another valid grant** is authenticated with no
   active role, and must not be logged out. Pinned in Task 3.4 `TestResolve_ExpiredPrimaryKeepsSession`.

---

## Lanes, ownership and order

Each dispatch is a fresh agent. Every prompt carries the binding rules (`golang-tdd.md`,
`library-design.md`, `defect-claims.md`, `defensive-coding.md`), the skills to read (`table-test`,
`use-mockgen`, `use-testcontainers`), the failure modes listed for its tasks, the files it owns and
the ones it must not touch, the full red-green order, its scoped commands, and the report format
(files changed, tests added, red output seen, final output, anything unfinished). No agent edits
`openspec/`, and none runs `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.

| Dispatch | Tasks | Owns | Model (reason) | Starts after |
|---|---|---|---|---|
| A1 | 1.1–1.4 | `identity/` | Sonnet: types and a pure mapping the plan fixes | — |
| M1 | 4.1–4.4 | `store/migrate/`, `test/migrate_*_test.go` | Sonnet: SQL the design fixes | — (parallel with A1) |
| A2 | 2.1–2.4, 2.7 | `authorize/` | Opus: refusal logic written for the first time | A1 |
| A3 | 2.5, 2.6, 2.8 | `authorize/` | Opus: concurrency (memo, single load per role) | A2 |
| A4 | 3.1, 3.3, 3.4 | `httpsec/*.go` (not sub-modules) | Sonnet: plumbing with fixed signatures | A3 |
| A5 | 3.2 | `httpsec/ginsec/`, `httpsec/fibersec/`, `test/httpsec_{gin,fiber,nethttp}_test.go` | Sonnet | A3 (parallel with A4) |
| S1 | 5.1–5.3 | `internal/pgschema/identity*.go`, `store/sqlstore/identity*.go`, `store/pgxstore/identity*.go`, `test/identity/`, `test/sqlstore/identity_test.go`, `test/pgxstore/identity_test.go` | Opus: advisory lock and race tests | A1, M1 |
| S2 | 6.1 | `store/gormstore/`, `test/gormstore/identity_test.go` | Sonnet: mirrors S1 against its suite | S1 |
| C1 | 7.1–7.3 | `admin/` | Sonnet: services over mocked ports | A2 |
| C2 | 7.4–7.8 | `admin/`, `event/` | Opus: takeover refusal; `event.Event` is shared | C1 |
| D1 | 8.1 | `test/admin/` | Opus: barrier tests of locks and versions | C2 |
| D2 | 8.2, 8.3 | `internal/pgschema/admin*.go`, `store/sqlstore/admin*.go`, `store/pgxstore/admin*.go`, `test/sqlstore/admin_test.go`, `test/pgxstore/admin_test.go` | Opus: conditional writes under row locks | D1, S2 |
| D3 | 9.1 | `store/gormstore/admin*.go`, `test/gormstore/admin_test.go` | Sonnet | D2 |
| E1 | 10.1, 10.2 | `test/admin_e2e_test.go` | Sonnet | D3, A4 |
| F1 | 11.1–11.4 | `authenticate/`, `httpsec/login.go`, `httpsec/basic.go` and their tests | Opus: security-critical login path | A4, S2 |
| G1 | 12.1–12.3 | `session/`, `store/*/session*.go`, `internal/pgschema/sessions.go`, `httpsec/resolve.go`, `httpsec/role_switch.go`, `test/storetest/session_suite.go` | Opus: several packages | F1, M1 |
| H1 | 13.1 | `*_example_test.go` named in 13.1 | Sonnet | G1 |
| main | 13.2, 14.x | `CHANGELOG.md`, `README.md` prose | the main session | H1 |

A2 and A3 both own `authorize/` and run in order. So do A4, F1 and G1 for `httpsec/`. Ownership
follows callers: S1 owns `test/identity/` because the conformance cases and the store code move
together.

**Scoped commands.** Find dependents of a changed package with the toolchain, in the root module
and in each workspace module that imports it:

```sh
dependents() { # $1 = import path suffix, e.g. authorize
  for m in . httpsec/fibersec httpsec/ginsec httpsec/prblmsec store/gormstore store/pgxstore \
           ratelimit/redisstore expiry/sweep authenticate/passkey/webauthn test; do
    (cd "$m" && go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
      | awk -v p="github.com/kartaladev/scrty/$1" '{for(i=2;i<=NF;i++) if($i==p){print $1; break}}')
  done
}
```

Each task's verification runs `go test -race -count=1` over the changed packages plus `dependents`,
then `go vet` and `gofmt -l` over the changed packages. `identity` and `authorize` changes reach most
of the tree. That is still the scoped run for them: a dependent is never skipped because it is slow.

---

### Task 1 (tasks 1.1–1.4): identity model

**Files:**
- Modify: `identity/principal.go`, `identity/ports.go`
- Test: `identity/principal_test.go`, `identity/ports_test.go`

**Interfaces:**
- Produces:
  - `type Scope string`; `const ScopeAll Scope = "all"`; `const ScopeOwn Scope = "own"`
  - `Privilege.Scope Scope`; `func (p Privilege) EffectiveScope() Scope`, where empty maps to `ScopeAll`
  - `Details.Email string`; `Details.EmailVerifiedAt time.Time`; `func (d *Details) EmailVerified() bool`, false for nil or zero
  - `type EmailLoader interface { LoadByEmail(ctx context.Context, email string) (*Details, error) }`
  - `func (r *AssignedRole) ValidAt(at time.Time) bool`: start zero or `!start.After(at)`, and end zero or `end.After(at)`
  - `func PrincipalFromDetailsAt(details *Details, at time.Time) *Principal`

- [ ] **Step 1 (1.1, 1.2): failing tests.** `TestPrivilege_EffectiveScope` with rows
  `{"", all}`, `{"all", all}`, `{"own", own}`, `{"team", team}`, and `TestDetails_EmailVerified` with
  rows nil, zero time, set time. Before implementing, add the fields and stub methods that return the
  zero value. Run `go test -run 'TestPrivilege_EffectiveScope|TestDetails_EmailVerified' -count=1 ./identity/`.
  Expected: FAIL on the `""` row and the set-time row.
- [ ] **Step 2: implement** the two methods. Re-run: PASS.
- [ ] **Step 3 (1.3): add `EmailLoader`** with godoc carrying the contract in spec identity-model
  "Email loader contract", and no mock yet: Task 15 adds the directive in `authenticate`, which
  consumes it. Verify `go vet ./identity/`.
- [ ] **Step 4 (1.4): failing test** `TestPrincipalFromDetailsAt` as a table:
  - expired primary `sales` plus valid `audit`: `ActiveRole == nil`, and `Roles` holds only `audit`;
  - future start: grant dropped;
  - `ValidUntil == at`: dropped;
  - primary grant with no start and no end date: kept and active at any time.

  Stub `PrincipalFromDetailsAt` to call `PrincipalFromDetails`. Expected: FAIL on the first row.
- [ ] **Step 5: implement** by filtering a copy of the grants with `ValidAt` and reusing
  `PrincipalFromDetails`'s mapping. Run the identity scoped command. Expected: PASS.
- [ ] **Step 6: commit** `feat(identity): grant scopes, email fields, point-in-time principal`.

### Task 2 (tasks 2.1–2.4, 2.7): scopes, reasons, AllOf, record check, catalogue

**Files:**
- Modify: `authorize/privilege.go`, `authorize/requirements.go`, `authorize/ownership.go`,
  `authorize/authorize.go` (errors)
- Create: `authorize/scope.go`, `authorize/catalogue.go`
- Test: `authorize/privilege_test.go`, `authorize/requirements_test.go`, `authorize/scope_test.go`,
  `authorize/catalogue_test.go`

**Interfaces:**
- Consumes: Task 1's `identity.Scope` and `Privilege.EffectiveScope`.
- Produces:
  - Sentinels `ErrNoSubject`, `ErrNoActiveRole`, `ErrNotGranted`, `ErrWrongScope`, `ErrNotOwner`. Every
    denial is built as `fmt.Errorf("%w: %w: …", ErrAccessDenied, reason)`.
  - `PrivilegeAttributes.Accept []identity.Scope`; empty means `{ScopeAll}`.
  - `func strongestHeld(entry *identity.ResourcePrivileges, name string, accept []identity.Scope, same func(a, b string) bool) (identity.Scope, bool)`,
    unexported and shared with Task 3. The order is `all` before `own`; an undefined scope is never held.
  - `func AllOf(requirements ...Requirement) Requirement`
  - `func HasPrivilegeAnyScope(group, resource string, required ...string) Requirement`, with Accept `{all, own}`
  - `func HasPrivilegeFor(group, resource string, owned OwnershipAttributes, required ...string) Requirement`
  - `func CheckAnyScope(ctx context.Context, group, resource, privilege string) (identity.Scope, error)`
  - `type CataloguePrivilege struct{ Name, DisplayName string; Scopes []identity.Scope }`
  - `type CatalogueResource struct{ Group, Name, DisplayName string; Privileges []CataloguePrivilege }`
  - `func NewCatalogue(resources ...CatalogueResource) (*Catalogue, error)`;
    `func (c *Catalogue) Resources() []CatalogueResource`, a deep copy;
    `func (c *Catalogue) Allows(group, resource, privilege string, scope identity.Scope) bool`

- [ ] **Step 1 (2.1): failing test** `TestPrivilege_DenialReasons`, a table of no subject, no active
  role, a role without the privilege, and own-only under a plain check. Each row asserts
  `errors.Is(err, ErrAccessDenied)` and exactly one reason via an `assert` closure over all five.
  Run focused. Expected: FAIL, because the reason sentinels do not match.
- [ ] **Step 2: implement** the sentinels and wrap them at each denial site in `privilege.go`,
  `requirements.go` and `ownership.go`. PASS.
- [ ] **Step 3 (2.2): failing tests** `TestPrivilege_OwnOnlyFailsPlainCheck` (expects `ErrWrongScope`),
  `TestPrivilege_EmptyScopeReadsAsAll` (Review Focus 1: a loader returning `Scope: ""` allows) and
  `TestPrivilege_UndefinedScopeCoversNothing` (`team` with Accept `{all, own}` denies). Expected:
  FAIL on the first. The empty-scope test may pass before implementing. If it does, invert
  `EffectiveScope` temporarily and confirm it fails.
- [ ] **Step 4: implement** `Accept` and `strongestHeld` in `satisfied`/`grants`. The existing
  privilege tests must stay green.
- [ ] **Step 5 (2.3): failing test** `TestAllOf`, a table of across-resources (denied with the second
  member's error, `errors.Is` on the member's sentinel), empty, absent member, all pass, and outage
  passed through unchanged. Stub `AllOf` to return `PermitAll()`. FAIL. Implement. PASS.
- [ ] **Step 6 (2.4): failing tests** `TestHasPrivilegeAnyScope_ReportsStrongest` (super role gives
  `all`; own-only gives `own`, through `CheckAnyScope`) and `TestHasPrivilegeFor`, a table with a typed
  `OwnershipAttributes` mock:
  - `all` grant: the ownership mock expects no call;
  - `own` and owner: allow;
  - `own` and not the owner: `ErrNotOwner`;
  - resolver error: wrapped, not `ErrAccessDenied`.

  FAIL. Implement by delegating to the context's authorizer with Accept, then to the ownership
  authorizer when the scope held is `own`. PASS.
- [ ] **Step 7 (2.7): failing test** `TestNewCatalogue`, a table of blank names, duplicate
  `view`/`VIEW`, duplicate resource, empty `Scopes` (defaults to both), `Scopes: {"team"}` (error),
  `Allows` with case-folded names, unknown resource, and caller slice mutation after construction.
  FAIL. Implement with the package's default name comparison. PASS.
- [ ] **Step 8: verify** with the `authorize` scoped command, `go vet ./authorize/` and `gofmt -l authorize`.
- [ ] **Step 9: commit** `feat(authorize): grant scopes, denial reasons, AllOf, record check, catalogue`.

### Task 3 (tasks 2.5, 2.6, 2.8): memo and bulk check

**Files:**
- Create: `authorize/memo.go`, `authorize/inspect.go`, `authorize/example_memo_test.go`
- Modify: `authorize/privilege.go` (load through the memo), `authorize/authorize.go` (`FirstOf` forwards inspection)
- Test: `authorize/memo_test.go`, `authorize/inspect_test.go`

**Interfaces:**
- Consumes: Task 2's `strongestHeld`.
- Produces:
  - `func WithRequestMemo(ctx context.Context) context.Context`
  - `type Holding struct{ Privilege string; Held bool; Scope identity.Scope }`; `type Holdings []Holding`;
    `func (h Holdings) Lookup(name string) (Holding, bool)`
  - `type PrivilegeInspector interface { InspectPrivileges(ctx context.Context, group, resource string, names []string) (Holdings, error) }`
  - `func HeldPrivileges(ctx context.Context, group, resource string, names ...string) (Holdings, error)`
  - `ErrInspectionUnsupported`

- [ ] **Step 1 (2.5): failing tests:**
  - `TestMemo_TenChecksOneLoad`: the typed `RoleLoader` mock with `.Times(1)`;
  - `TestMemo_ConcurrentChecksOneLoad`: 8 goroutines released together by a closed channel, the mock
    blocking until all have called;
  - `TestMemo_ErrorNotRemembered`: a first error, then success, `.Times(2)`;
  - `TestMemo_NotFoundRemembered`;
  - `TestMemo_BoundOf32`: 33 roles, the 33rd loaded on each check;
  - `TestMemo_AbsentMeansNoMemo`.

  Run with `-race`. Expected: FAIL on loader call counts.
- [ ] **Step 2: implement** a memo of `sync.Mutex` plus `map[string]*memoEntry`, where an entry holds a
  `done chan struct{}`, the result and the error. The first caller loads and the rest wait on `done`
  or `ctx.Done()`. On a non-not-found error the entry is deleted before `done` closes. Past 32 entries,
  load without storing. A waiter whose context ends returns `ctx.Err()` wrapped. PASS under `-race`.
- [ ] **Step 3 (2.6): failing tests** `TestHeldPrivileges` table:
  - view all / update own / delete not held, one load;
  - no active role gives all not held, no load, nil error;
  - super role gives all `all`;
  - empty names gives `ErrInvalidAttributes`;
  - loader outage: error matches, nothing held;
  - an authorizer without the inspector gives `ErrInspectionUnsupported`;
  - `FirstOf(ownership, privilege)` forwards.

  FAIL. Implement. PASS.
- [ ] **Step 4 (2.8): godoc and examples.** `ExampleHeldPrivileges` and `ExampleCheckAnyScope`, the
  latter filtering a list when the scope is `own`. Verify `go test -run Example -count=1 ./authorize/`.
- [ ] **Step 5: verify** with the `authorize` scoped command. **Commit** `feat(authorize): per-request privilege memo and bulk check`.

### Task 4 (tasks 3.1, 3.3, 3.4): chain

**Files:**
- Modify: `httpsec/guards.go`, `httpsec/options.go`, `httpsec/resolve.go`
- Test: `httpsec/guards_test.go`, `httpsec/memo_test.go`, `httpsec/resolve_test.go`

**Interfaces:**
- Consumes: `authorize.AllOf`, `authorize.WithRequestMemo`, `identity.PrincipalFromDetailsAt`.
- Produces:
  - `func (g *Guards) Require(req authorize.Requirement) (func(http.Handler) http.Handler, error)`;
    a nil `req` gives an error matching `ErrConfig`
  - `func WithoutPrivilegeMemo() Option`

- [ ] **Step 1 (3.1): failing test** `TestGuards_Require`, a table of all-of across resources (403 and
  `ErrAccessDenied` through the chain's error path), anonymous (`ErrAuthenticationRequired`), outage
  (dependency failure, not denial), and nil requirement (build error). FAIL. Implement with the
  existing `guard(judgement)` helper. PASS.
- [ ] **Step 2 (3.3): failing test** `TestChain_PrivilegeMemoPerRequest`: a counting loader, a route
  guard plus a handler that calls `authorize.HeldPrivileges` for nine names gives 1 load. A second
  request gives 1 more. With `WithoutPrivilegeMemo()`, 10 loads. FAIL. Implement by attaching the memo
  where the chain publishes the principal. PASS.
- [ ] **Step 3 (3.4): failing tests:**
  - `TestResolve_ExpiredPrimaryNoActiveRole`: a fake clock, an expired primary grant, and a privilege
    guard that refuses with `ErrNoActiveRole`;
  - `TestResolve_ExpiredPrimaryKeepsSession` (Review Focus 5): the same request passes `Authenticated()`
    and the session is not revoked.

  FAIL. Implement by calling `PrincipalFromDetailsAt` with the chain clock at the reload in `resolve.go`. PASS.
- [ ] **Step 4: verify** with the scoped `httpsec` dependents command, including `test/`'s
  `httpsec_*_test.go`. **Commit** `feat(httpsec): any-requirement guard, per-request memo, dated grants`.

### Task 5 (task 3.2): gin and fiber guards

**Files:** Modify `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go`. Test: their
`guards_test.go`, plus `TestGuards_RequireParity` in `test/httpsec_nethttp_test.go`.

**Interfaces:** Produces `func (g *Guards) Require(req authorize.Requirement) (gin.HandlerFunc, error)`
and `func (g *Guards) Require(req authorize.Requirement) (fiber.Handler, error)`.

- [ ] **Step 1: failing tests** `TestGuards_Require` in each adapter, the same table as Task 4 step 1,
  and `TestGuards_RequireParity` in `test/`, which runs one composed requirement through all three
  and compares status and `errors.Is`. FAIL. Implement. PASS.
- [ ] **Step 2: verify** with `go test -race -count=1 ./...` in `httpsec/ginsec`, `httpsec/fibersec`,
  and `go test -race -count=1 -run 'TestGuards' ./` in `test`. **Commit** `feat(ginsec,fibersec): guard for any requirement`.

### Task 6 (tasks 4.1–4.4): migrations

**Files:**
- Create: `store/migrate/identity/<UTC timestamp after 20261124000000>_scrty_administration.sql`,
  `store/migrate/securitystate/<same rule>_scrty_selected_role.sql`
- Test: `test/migrate_identity_test.go`, `test/migrate_securitystate_test.go`

**Interfaces:** Produces these columns, which every later store task reads:
- `scrty_users`: `email text NULL`, `email_verified_at timestamptz NULL`, `deleted_at timestamptz NULL`,
  `version bigint NOT NULL DEFAULT 1`
- `scrty_roles`: `display_name text NOT NULL DEFAULT ''`, `description text NOT NULL DEFAULT ''`,
  `labels text[] NOT NULL DEFAULT '{}'`, `version bigint NOT NULL DEFAULT 1`
- `scrty_resource_privileges`: `scope text NOT NULL DEFAULT 'all'`
- `scrty_user_attributes(user_id uuid NOT NULL, name text NOT NULL, value text NOT NULL, PRIMARY KEY (user_id, name))`,
  with index `scrty_user_attributes_name_value (name, value)`
- `scrty_users_email_live` UNIQUE on `(lower(email)) WHERE deleted_at IS NULL AND email IS NOT NULL`
- `scrty_users_username_lower` on `(lower(username), id)`, for list order
- `scrty_assigned_roles_role_name` on `(role_name)`, for the still-assigned check
- `scrty_sessions.selected_role text NULL`

- [ ] **Step 1 (4.1): failing catalog test** `TestIdentityMigration_Administration`. Apply up to the
  latest version on `test.RunTestPostgres` and assert every column, default, index and prefix above.
  FAIL, because the columns are absent. Write the migration. PASS on PostgreSQL 15 and 18 via
  `SCRTY_TEST_POSTGRES_IMAGE`.
- [ ] **Step 2 (4.1): rollback test** `TestIdentityMigration_AdministrationDown`: down by one leaves
  the pre-migration catalog and the seeded users' other columns. PASS.
- [ ] **Step 3 (4.2): test** `TestIdentityMigration_FailsAtomically`. Apply up to the prefix, add a
  consumer column `scrty_users.email text`, apply. Expect an error, and a catalog with none of the
  migration's other columns, the attribute table or its indexes. If it passes before the migration is
  wrapped in one transaction, add `-- +goose NO TRANSACTION` temporarily and confirm it fails.
- [ ] **Step 4 (4.3): populated test** `TestIdentityMigration_AdministrationPopulated`: existing rows
  read version 1, no email, scope `all`.
- [ ] **Step 5 (4.4): security-state** `TestSecurityStateMigration_SelectedRole`, up and down, with
  existing sessions unchanged.
- [ ] **Step 6: verify** with `go test -race -count=1 -run 'Migration' ./` in `test`. **Commit** `feat(migrate): administration columns and selected role`.

### Task 7 (tasks 5.1–5.3): SQL identity stores, runtime reads

**Files:**
- Modify: `internal/pgschema/identity.go`, `store/sqlstore/identity.go`, `store/pgxstore/identity.go`,
  `test/identity/conformance.go` (new cases), `test/identity/` fixture hooks
- Test: `test/sqlstore/identity_test.go`, `test/pgxstore/identity_test.go`

**Interfaces:** Produces `(*IdentityStore).LoadByEmail(ctx, email string) (*identity.Details, error)`
in `sqlstore` and `pgxstore`, and a fixture hook `SeedEmail(t, username, email string, verified time.Time)`
plus `SoftDelete(t, username string)` in `test/identity.Fixture`.

- [ ] **Step 1 (5.1): failing conformance cases:**
  - `RoleLoader/Scope`: an `own` grant round-trips;
  - `RoleLoader/LegacyRowIsAll`;
  - `UserLoader/DeletedIsNotFound`, by username and by reference;
  - `MFALookup/DeletedAsUnknown`;
  - `UserLoader/EmailFields`;
  - `Provisioner/UpdateBumpsVersion` (design D11; Review Focus 3).

  Run `go test -run 'TestIdentityConformance' -count=1 ./sqlstore/ ./pgxstore/` in `test`. FAIL.
  Implement. PASS.
- [ ] **Step 2 (5.2): failing cases** `EmailLoader/CaseInsensitive`, `EmailLoader/UnverifiedNotFound`,
  `EmailLoader/DeletedNotFound` and `EmailLoader/Unrepresentable` (a `\x00` byte gives not found).
  FAIL. Implement with `WHERE lower(email) = lower($1) AND email_verified_at IS NOT NULL AND deleted_at IS NULL`. PASS.
- [ ] **Step 3 (5.3): failing cases:**
  - `Provisioner/UsernameIsAnotherEmail`;
  - `Provisioner/EmailNotStored`;
  - `Provisioner/RacingUsernameAndEmail`, a barrier test where 8 goroutines alternate between
    provisioning `x@example.com` and setting that email on another user through `SeedEmail` under the
    same lock helper, and at most one pair forms.

  FAIL. Implement `pg_advisory_xact_lock(hashtextextended(lower($1), 0))` for each identifier value,
  taken in sorted order to avoid deadlock, then check, inside the provision and update transactions.
  PASS under `-race`.
- [ ] **Step 4: verify** that the scoped run covers `internal/pgschema`, `store/sqlstore`,
  `store/pgxstore` and their dependents, plus the `test` identity suites on PostgreSQL 15 and 18.
  **Commit** `feat(store): scope, email and soft deletion in the SQL identity stores`.

### Task 8 (task 6.1): gorm identity store, runtime reads

**Files:** Modify `store/gormstore/models.go`, `store/gormstore/identity.go`,
`store/gormstore/identity_tx.go`. Test: `test/gormstore/identity_test.go`.

- [ ] **Step 1:** run Task 7's new cases against gorm: FAIL. Implement the same queries and lock,
  through `db.Exec` for the advisory lock. PASS on PostgreSQL 15 and 18. **Commit** `feat(gormstore): scope, email and soft deletion`.

### Task 9 (tasks 7.1–7.3): admin package, users

**Files:**
- Create: `admin/doc.go`, `admin/errors.go`, `admin/actor.go`, `admin/ports.go`, `admin/records.go`,
  `admin/users.go`, `admin/users_options.go`, `admin/cursor.go`
- Test: `admin/errors_test.go`, `admin/actor_test.go`, `admin/users_test.go`, `admin/cursor_test.go`,
  and mocks `admin/*_mock_test.go`

**Interfaces:**
- Consumes: `identity.Details`, `authenticate/password` encoder, policy and reuse guard, `pkg/clock`.
- Produces:
  - Errors `ErrNotFound`, `ErrAlreadyExists`, `ErrStillAssigned`, `ErrStaleUpdate`,
    `ErrUnknownPrivilege`, `ErrInvalidInput`, `ErrNoActor`, and `type AlreadyExistsError struct{ Field string }` matching
    `ErrAlreadyExists`, with `Field` one of `"username"`, `"email"`, `"role"`.
  - `func WithSystemActor(ctx context.Context, name string) context.Context`;
    `func ActorFrom(ctx context.Context) (string, error)`, which gives the principal's ID, else
    `"system:" + name`, else `ErrNoActor`.
  - Records: `type User struct{ ID identity.UserID; Username, Name, Email string; EmailVerifiedAt time.Time; Active bool; Attributes map[string]string; Roles []*identity.AssignedRole; Organization *identity.Organization; Version int64; CreatedAt, UpdatedAt time.Time }`.
    It has no password field.
  - `type UserFilter struct{ Search string; Active *bool; Role string; Attribute *AttributeMatch; PageSize int; Cursor string }`;
    `type AttributeMatch struct{ Name, Value string }`; `type UserPage struct{ Users []User; Next string }`
  - `type UserChange struct` with optional pointer fields `Name, Email *string`, `EmailVerifiedAt *time.Time`,
    `Attributes map[string]string` (nil means unchanged), `Organization **identity.Organization`.
  - Port `UserStore`: `ListUsers(ctx, UserQuery) ([]User, error)`, `GetUser(ctx, id) (User, error)`,
    `CreateUser(ctx, NewUser) (User, error)`, `UpdateUser(ctx, id, version int64, UserChange) (User, error)`,
    `SetActive(ctx, id, version int64, active bool) (User, bool, error)`, where the bool reports
    whether anything changed, `DeleteUser(ctx, id, version int64) error`,
    `SetPassword(ctx, id, version int64, hash []byte, at time.Time) (User, error)`.
    `UserQuery` is `UserFilter` with the cursor decoded into `AfterUsername, AfterID` and the bounded
    `Limit`. `SetPassword` records history and the change time in one transaction.
  - `func NewUsers(store UserStore, opts ...UsersOption) (*Users, error)`; options `WithPageSize(def, max int)`,
    `WithAttributeLimits(nameBytes, valueBytes, count int)`, `WithPasswordEncoder(password.Encoder)`
    (default: `password.NewArgon2idEncoder()`), `WithPasswordPolicy(*password.Policy)` (default
    `password.NewPolicy()`), `WithClock(clock.Clock)`, `WithEventSink(event.Sink)`, `WithAudit(AuditSink)`
    (Task 10), `WithLogger(*slog.Logger)`.
  - Methods: `List(ctx, UserFilter) (UserPage, error)`, `Get(ctx, id)`, `Create(ctx, NewUser) (User, error)`,
    `Update(ctx, id, version, UserChange) (User, error)`, `Deactivate(ctx, id, version)`,
    `Reactivate(ctx, id, version)`, `Delete(ctx, id, version) error`,
    `SetPassword(ctx, id, version int64, plain []byte) (User, error)`.

- [ ] **Step 1 (7.1): failing tests** `TestAlreadyExistsError_NoIdentifierInText`, `TestActorFrom`
  (principal, system, neither) and `TestUsers_RefusesWithoutActor` (the store mock expects no call).
  FAIL. Implement. PASS.
- [ ] **Step 2 (7.2): failing table** `TestUsers_List`:
  - page 0 gives limit 50;
  - 501 gives `ErrInvalidInput` with no store call;
  - -1 gives `ErrInvalidInput`;
  - `WithPageSize(50, 1000)` and 800 gives limit 800;
  - `WithPageSize(600, 500)` fails construction;
  - a malformed cursor gives `ErrInvalidInput`;
  - a returned full page sets `Next`.

  Also `TestCursor_RoundTrip`, and table tests for create, update, deactivate and the rest against
  mocks. Covers F23 and F24. FAIL. Implement. The cursor is base64url of a version byte plus
  length-prefixed lower(username) and id, decoded strictly. PASS.
- [ ] **Step 3 (7.3): failing tests** `TestUsers_SetPasswordReuseRefused` (no store call) and
  `TestUsers_SetPasswordRecordsChange` (the hash passed verifies with the encoder; `at` equals the fake
  clock). FAIL. Implement. PASS.
- [ ] **Step 4: verify** `go test -race -count=1 ./admin/`, `go vet ./admin/`. **Commit** `feat(admin): user administration service`.

### Task 10 (tasks 7.4–7.8): import, roles, grants, assignments, events, audit

**Files:**
- Create: `admin/importer.go`, `admin/roles.go`, `admin/grants.go`, `admin/assignments.go`,
  `admin/audit.go`, `admin/events.go`, `admin/example_test.go`
- Modify: `event/event.go`
- Test: one `_test.go` per created file, `event/event_test.go`

**Interfaces:**
- Consumes: Task 2's `*authorize.Catalogue`, Task 9's actor and errors.
- Produces:
  - `type ImportedUser struct{ ID identity.UserID; Username, Name, Email string; EmailVerifiedAt time.Time; PasswordHash []byte; Active bool; CreatedAt, UpdatedAt time.Time; Roles []string; Attributes map[string]string }`
  - `type ImportOutcome uint8`, with `ImportCreated`, `ImportUpdated` and `ImportUnchanged`
  - Port `ImportStore{ ImportUser(ctx, ImportedUser) (ImportOutcome, error) }`
  - `func NewImporter(store ImportStore, recognizer password.Recognizer, opts ...ImporterOption) (*Importer, error)`
  - `type Role struct{ Name, DisplayName, Description string; Labels []string; SuperRole bool; Version int64; Assigned int }`
  - Port `RoleStore{ ListRoles(ctx, label string) ([]Role, error); GetRole(ctx, name) (Role, error); CreateRole(ctx, Role) (Role, error); UpdateRole(ctx, name string, version int64, RoleChange) (Role, error); DeleteRole(ctx, name string, version int64, force bool) error }`
  - `type Grant struct{ Group, Resource, Privilege string; Granted bool; Scope identity.Scope }`
  - Port `GrantStore{ GetGrants(ctx, role string) ([]Grant, int64, error); ReplaceGrants(ctx, role string, version int64, resources []ResourceGrants) (int64, error) }`,
    where `ResourceGrants{ Group, Resource string; Grants []Grant }`
  - Port `AssignmentStore{ ListAssignments(ctx, id) ([]*identity.AssignedRole, int64, error); AddAssignment(ctx, id, version, Assignment) (int64, error); RemoveAssignment(ctx, id, version, grantID string) (int64, error); SetPrimary(ctx, id, version, grantID string) (int64, error) }`,
    where `Assignment{ Role string; Primary bool; Start, End time.Time }`
  - `NewRoles(store RoleStore, ...)`, `NewGrants(store GrantStore, cat *authorize.Catalogue, ...)` (a
    nil catalogue gives an `ErrConfig`-matching error), `NewAssignments(store AssignmentStore, ...)`
  - `event.Event` gains `Actor string`, `Target string`, `Changed []string`; constants for the
    administration event names in Global Constraints; `event.Names()` lists them.
  - `type Change struct{ Actor, Action, Target string; Before, After any }`. `Before` and `After` are
    `User`, `Role` or `[]Grant` values, so no hash field exists. `type AuditSink func(ctx context.Context, c Change) error`.

- [ ] **Step 1 (7.4): failing table** `TestImporter`:
  - a non-canonical id gives `ErrInvalidInput`;
  - an unrecognised hash gives `ErrInvalidInput` with no store call;
  - `ImportUnchanged` emits no event;
  - `ImportCreated` emits `scrty_user_imported`;
  - the store's `AlreadyExistsError` passes through.

  FAIL. Implement. PASS.
- [ ] **Step 2 (7.5): failing tables** `TestRoles` (duplicate, still-assigned passed through, label
  filter), `TestGrants` (nil catalogue fails construction; `purge` and `create`+`own` give
  `ErrUnknownPrivilege` with no store call) and `TestAssignments` (end not after start gives
  `ErrInvalidInput`). FAIL. Implement. PASS.
- [ ] **Step 3 (7.6): failing tests** `TestEvents_OneAfterCommit` (each mutating call emits its name
  with `Actor`, `Target`, `Changed` and no value; `Changed` for an email change is `["email"]`, and the
  event does not contain the address), `TestEvents_NoneOnRefusalOrNoop` (deactivating an inactive user)
  and `event` `TestNames_IncludesAdministration`. FAIL. Implement. PASS.
- [ ] **Step 4 (7.7): failing tests** `TestAudit_BeforeAfterWithoutHash` (a reflective walk over
  `Change` finds no `[]byte` field) and `TestAudit_SinkFailureLogged` (error and panic: the call still
  succeeds, and the log record holds the action and target only). FAIL. Implement, recovering the
  panic. PASS.
- [ ] **Step 5 (7.8): examples** `ExampleUsers`, `ExampleImporter`, `ExampleGrants` (with a
  catalogue) and `ExampleAssignments`, plus godoc naming each default. Verify
  `go test -run Example -count=1 ./admin/`.
- [ ] **Step 6: verify** `admin` and `event` scoped. **Commit** `feat(admin): import, roles, grants, assignments, events, audit`.

### Task 11 (task 8.1): administration conformance suite

**Files:** Create `test/admin/conformance.go`, `test/admin/fixture.go`, `test/admin/conformance_test.go`.

**Interfaces:** Produces `type Fixture interface{ Users() admin.UserStore; Importer() admin.ImportStore; Roles() admin.RoleStore; Grants() admin.GrantStore; Assignments() admin.AssignmentStore; Loader() identity.UserLoader }`,
`type Factory func(t *testing.T) Fixture`, `func RunConformanceSuite(t *testing.T, newFixture Factory)`.

- [ ] **Step 1: write the cases**, one `t.Run` each:
  - `StaleUpdate`;
  - `StaleAfterLoginUpdate` (Review Focus 3);
  - `ConcurrentGrantReplace`, a barrier test that expects one success and one `ErrStaleUpdate`;
  - `ReplaceGrantsAtomic`, which cancels the context between resources and expects grants unchanged
    (F3, F33);
  - `CreateRace` (8 creators, one success);
  - `UsernameEmailRace`;
  - `ImportRace` (Review Focus 4);
  - `ImportIdempotent`, where `updated_at` is unchanged;
  - `ImportTakeoverRefused`;
  - `SoftDelete`: username kept, email released, attributes and history gone, loaders not found;
  - `DeleteTwice`;
  - `ForcedRoleDelete`, where the primary is handed over (F28);
  - `AttributesRoundTrip` and `AttributeSearch`;
  - `ListPagingStable` (120 users, 3 pages);
  - `SearchLiteral` (`a_b`);
  - `RemovePrimaryHandsOver`;
  - `AssignUnknownRole`.

  Run `conformance_test.go` against a stub fixture whose ports return `admin.ErrNotFound`. Expected:
  every case FAILS with assertion messages, not compile errors. Leave the stub test behind a build tag
  `admin_stub` so the default run does not carry it.
- [ ] **Step 2: commit** `test(admin): administration conformance suite`.

### Task 12 (tasks 8.2, 8.3): SQL stores, administration ports

**Files:** Create `internal/pgschema/admin.go`, `store/sqlstore/admin_users.go`,
`store/sqlstore/admin_roles.go`, and the same two in `store/pgxstore/`. Test:
`test/sqlstore/admin_test.go`, `test/pgxstore/admin_test.go`.

- [ ] **Step 1 (8.2):** wire the suite for both stores, then run the user and import cases: FAIL.
  Implement each write as `BEGIN; SELECT … FOR UPDATE` on the row; compare `version`; write;
  `version = version + 1`; `COMMIT`. Take the advisory locks of Task 7 for username and email values.
  Map unique violations on `scrty_users_email_live` and the username constraint to
  `AlreadyExistsError`. Import takes a `FOR UPDATE` on the id. A miss inserts with `ON CONFLICT (id) DO NOTHING`
  and re-reads, so the race becomes `Unchanged` or `Updated`. A field-by-field comparison skips the
  write. PASS.
- [ ] **Step 2 (8.3):** role, grant and assignment cases: FAIL. Implement grant replacement as one
  transaction that locks the role row, checks the version, deletes the named resources' rows and
  inserts the new ones. A forced delete removes grants and assignments and promotes the lowest
  `position` remaining grant per affected user, updating `scrty_users.role`. PASS on 15 and 18.
- [ ] **Step 3: verify** scoped and **commit** `feat(store): administration ports in sqlstore and pgxstore`.

### Task 13 (task 9.1): gorm, administration ports

- [ ] **Step 1:** wire the suite for gorm: FAIL. Implement with `Clauses(clause.Locking{Strength: "UPDATE"})`
  and the same semantics. PASS on 15 and 18. **Commit** `feat(gormstore): administration ports`.

### Task 14 (tasks 10.1, 10.2): end to end

**Files:** Create `test/admin_e2e_test.go`.

- [ ] **Step 1: write** `TestAdministration_EndToEnd` over `test.RunTestPostgres`, pgxstore and the
  net/http chain:
  - catalogue `crm/lead` with `view` and `update`;
  - role `partner`: `view` all, `update` own;
  - assign it and log in;
  - `HeldPrivileges` gives view all and update own;
  - **own-only list** (Review Focus 2): a route guarded by `HasPrivilege(view)` passes, and one guarded
    by `HasPrivilege(update)` is refused with `ErrWrongScope`;
  - `HasPrivilegeFor(update)` passes on an owned lead and refuses another with `ErrNotOwner`;
  - deactivate, then the next request gets 401.

  Write `TestAdministration_ImportBcrypt`: import with a bcrypt hash, log in with
  `password.NewBcryptEncoder()` recognised, re-import, `ImportUnchanged` and no event. Both should pass
  on first run, since they integrate finished work. If one passes trivially, break a link (drop the
  grant) and confirm it fails. **Commit** `test: administration end to end`.

### Task 15 (tasks 11.1–11.4): login by email

**Files:**
- Modify: `authenticate/password.go`, `httpsec/login.go`, `httpsec/basic.go`
- Create: `authenticate/password_email.go`, `authenticate/example_email_login_test.go`
- Test: `authenticate/password_email_test.go`, `httpsec/login_email_test.go`

**Interfaces:**
- Consumes: `identity.EmailLoader`.
- Produces:
  - `func WithEmailLogin() PasswordOption`
  - `type ResolvedIdentifier struct{ Key string; Details *identity.Details }`. `Key` is the username
    when resolved, else the typed identifier.
  - `func (a *UsernamePasswordAuthenticator) ResolveIdentifier(ctx context.Context, identifier string) (ResolvedIdentifier, error)`
  - Credentials gain an unexported resolved-details carrier, set through
    `authenticate.WithResolved(ctx, ResolvedIdentifier) context.Context`, which the provider reads
    instead of loading again.

- [ ] **Step 1 (11.1): failing table** `TestPassword_EmailLogin`:
  - off by default (uniform failure);
  - a loader without `EmailLoader` fails construction with `ErrConfig`;
  - email login succeeds;
  - an unverified email gives uniform failure;
  - a conflict gives uniform failure, the decoy verifier called once and the event emitted;
  - an email outage gives the unavailable error.

  Use typed mocks of `identity.UserLoader` and `identity.EmailLoader`. FAIL. Implement. PASS.
- [ ] **Step 2 (11.2): failing tests** `TestLogin_EmailSharesLockout` (threshold 5; 3 failures by
  username and 2 by email lock both) and `TestLogin_HeldAccountByEmail` (no password compared, through
  a counting encoder). Also `TestLogin_ResolvesOnce` (each lookup `.Times(1)`). FAIL. Implement by
  calling `ResolveIdentifier` before `evaluatePhase(PreAuthentication)` in `login.go` and `basic.go`,
  passing `Key` as the identifier and the resolved details on. PASS.
- [ ] **Step 3 (11.3): failing test** `TestPassword_EmailTimingParity`: the counting encoder reports
  equal work for an unknown username, an unknown email and an unverified email. Invert temporarily (skip
  the decoy for an unverified email) and see it fail.
- [ ] **Step 4 (11.4):** `ExampleWithEmailLogin`. **Verify** `authenticate` and `httpsec` scoped.
  **Commit** `feat(authenticate): login by verified email`.

### Task 16 (tasks 12.1–12.3): active-role switch

**Files:**
- Modify: `session/session.go`, `session/store.go`, the memory store, `internal/pgschema/sessions.go`,
  `store/{sqlstore,pgxstore,gormstore}/session.go`, `httpsec/resolve.go`, `httpsec/options.go`
- Create: `httpsec/role_switch.go`
- Test: `test/storetest/session_suite.go` (new cases), `httpsec/role_switch_test.go`

**Interfaces:**
- Produces:
  - `Session.SelectedRole string`
  - optional `session.RoleSelector interface{ SelectRole(ctx context.Context, id string, role string) error }`,
    implemented by every shipped store; a missing session gives `ErrSessionNotFound`
  - `func WithActiveRoleSwitching() Option`. Building the chain with it over a store without
    `RoleSelector` fails with `ErrConfig`.
  - `func (c *Chain) SwitchActiveRole(ctx context.Context, role string) error`
  - `ErrRoleSwitchingDisabled`
  - `ErrRoleNotHeld`, matching `authorize.ErrAccessDenied` and `authorize.ErrNoActiveRole`

- [ ] **Step 1 (12.1): failing cases** `RunSessionStoreSuite/SelectRole`, `…/SelectRoleDeleted` and
  `…/RotationCarriesSelectedRole` for the memory and the three durable stores. FAIL. Implement. PASS.
- [ ] **Step 2 (12.2): failing table** `TestChain_SwitchActiveRole`: switch to `audit`, then the next
  request is active as `audit` and the event is emitted; `admin` not held gives `ErrRoleNotHeld` and the
  session is unchanged; off gives `ErrRoleSwitchingDisabled`; a store without the selector fails
  construction. FAIL. Implement. PASS.
- [ ] **Step 3 (12.3): failing tests** `TestResolve_SelectedRoleRevoked` (F19: primary active after
  removal) and `TestResolve_SelectionIgnoredWhenOff`. FAIL. Implement in `resolve.go` after
  `PrincipalFromDetailsAt`: if switching is on and a kept grant has the selected name, make it active.
  PASS.
- [ ] **Step 4: verify** scoped over `session`, the stores, `httpsec` and the `test` session suites.
  **Commit** `feat(httpsec): optional active-role switch`.

### Task 17 (tasks 13.1, 13.2, 14.1, 14.2): documentation and gate

- [ ] **Step 1 (13.1, H1 dispatch):** README sections for administration, catalogue and scopes, the
  memo, email login and role switching, with code taken from the examples added in Tasks 3, 10 and 15.
  Verify: each snippet matches an `Example` that passes.
- [ ] **Step 2 (13.2, main session):** the CHANGELOG Unreleased entry. Added: every new API. Changed,
  each marked breaking: soft-deleted users not found; dated grants enforced; provisioning refuses a
  username that is another live user's email; and the migrations, with the note that a consumer who
  added an `email` column to `scrty_users` renames or drops it first. Verify `make spec-check`.
- [ ] **Step 3 (14.1):** a fresh Opus reviewer checks the whole branch against every requirement in
  `specs/`, enumerating failure modes first. Findings go to fresh dispatches of the owning lane.
- [ ] **Step 4 (14.2, main session):** `make check`, `make spec-check`, and
  `SCRTY_TEST_POSTGRES_IMAGE=postgres:15-alpine make test`. Each must exit 0, with output read by the
  main session after the last code edit.
