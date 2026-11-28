# Admin User Rename, Paging and Port Fold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** finish the change with one shape for every contract:
- `admin.UserStore` renames through `UpdateUser`, which reports `renamed`; it pages through
  `ListUsers` with `UserQuery.Offset` and counts through `CountUsers`;
- every compatibility-only optional port in the library is folded into its base interface (D15).

**Architecture:**
- **Admin fold:** the optional `UsernameUpdater` and `UserPager` ports already built on this branch
  move into `UserStore`. The SQL stores keep their shared helpers and serve both listing modes from
  one statement.
- **Library fold:** each folded port's methods join the base interface. The type assertions,
  fallbacks, refusals, variant wrappers and conformance skips that existed for the absent case are
  deleted.
- **Lanes:** areas are independent. They run in their own git worktrees and are integrated one by
  one.

**Tech Stack:** Go 1.27, testify, mockgen (`use-mockgen`), testcontainers PostgreSQL 18 and 15
(`use-testcontainers`).

**Spec:** `openspec/changes/admin-user-rename-and-paging/{proposal.md,design.md,specs/**,tasks.md}`.
Every plan task names the `tasks.md` numbers it carries out. This plan adds no scope beyond
`tasks.md`.

## Done before the revision (record)

| tasks.md | Commit | What |
|---|---|---|
| 1.1–1.5 | `04415fe2` | Service rename, routing, events, opt-in revocation and godoc, behind `UsernameUpdater`. |
| 2.1–2.7, 4.1 | `0e8d9fba`, `8c235de8` | Stores apply renames, plus the collision, the race, library stores, load-bearing cases and import after a rename. |
| 3.1 | `3b8874b8` | Opted-in revocation over the real `sqlstore`. |
| 5.1–5.4 | `808724b5` | Service offset, `Count` and godoc, behind `UserPager`. |
| (6.x, before the revision) | `8445f0dd` | The stores' offset and count behind `UserPager`, the shared filter fragment, and the gated cases and defects. |
| 7.1 | `9c74355a` | The changelog `Added` entry. Task 7.2 rewrites it. |

## Global Constraints

- **Test-first** (`golang-tdd.md`):
  - The red step is a behavioural failure seen in a focused run. A compile error is never a red step;
    add a stub so the test compiles first.
  - A fold with no behaviour change is a mechanical change that existing tests cover. Its proof is the
    existing suite staying green, plus deleting the tests of the "absent" path.
- **No compatibility shims.** A folded port gets no type alias, no deprecated wrapper and no
  kept-but-unused method (D15).
- **These stay optional; do not touch them:** `DecoyVerifier`, `IdentifierResolver`, `InputLimiter`,
  `mfa.Enroller`, `mfa.ChallengeMethod`, `oidc.UpstreamBroker`, `UnreportedAttemptRecorder`, the
  policy marker interfaces, `AttemptReaper`, `onetime.Reaper`, `identity.EmailLoader`,
  `logsample.Flusher`, `signingkey.LifetimeReporter`, `token.ConfirmingGenerator`,
  `notify.NonBlocking`, `ratelimit.Verifier` and `clock.Timed`.
- **Mocks:** regenerate with each `//go:generate` the lane touches. Delete the mock file of an
  interface that no longer exists (`use-mockgen`).
- **The toy store** needs `-tags admin_stub`. Its load-bearing run is
  `(cd test && go test -race -count=1 -tags admin_stub -run '^(TestAdminSuiteIsLoadBearing|TestBrokenAdminStore)$' ./admin/)`.
- **Agents:**
  - never edit `openspec/`;
  - never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`;
  - never read or cite `.claude/.legacy/`;
  - commit only in their own worktree, and only when the dispatch says to.
- **Error text** never contains a username, email, attribute value or password hash.

## Review Focus

1. **Wrappers that embed a folded interface now forward the folded methods.** Where a wrapper
   changes rows, as the encrypted session store does, the forwarded method must apply the same
   treatment. Task 3 tests that the encrypted store's `ListByFamily` returns opened sessions, and
   that `oidcprovider`'s embedding wrappers answer a family read through the inner store's
   `ListByFamily`.
2. **One listing statement for both modes must leave cursor paging exactly as it was.** Task 2 pins
   that cursor pages are unchanged (`TestListAdminUsersUnchanged` and the existing listing cases),
   and that offset 0 with a cursor equals the cursor page.
3. **A consumer encoder that recognises nothing makes every login cost the same and fail.** Task 6
   tests it.
4. **`unavailable.Wrap` answers `Policy()` while its backend is down.** It returns the configured
   limit and window, never an error or zero. Task 7 tests it.
5. **`FailureStreak` moves to `policy`, and `Held()` must behave as before on every store.** Task 8
   runs the streak suite on the memory store and the three SQL stores, on PostgreSQL 18 and 15.

---

## Lanes, waves and models

| Lane | Plan task (tasks.md) | Owns | Model (reason) |
|---|---|---|---|
| G1 | 1 (6.1) | `admin/**`, `store/{sqlstore,pgxstore,gormstore}/admin_users.go`, `test/admin/**`, `test/internal/adminfix/**`, `test/identity/inmem.go`, `test/sqlstore/rename_sessions_test.go` | Opus: it changes an interface that three modules compile against. |
| G2 | 2 (6.2, 6.3) | the G1 files, `internal/pgschema/admin*.go`, `test/sqlstore/admin_test.go` | Opus: it merges two SQL statements and must keep cursor paging's behaviour. |
| H1 | 3 (8.1) | `session/**`, `oidcprovider/{lineage,exchange,refresh}.go`, `internal/oplineage/**`, `store/*/session.go`, `httpsec` role-switch files, `test/storetest/session*` | Opus: wrappers, and an encrypted store whose forwarding must open rows. |
| H2 | 4 (8.2) | `authenticate/oidc/**`, `store/*/oidc_link.go`, `test/oidc/**`, `httpsec/oidc_backchannel.go` mocks | Sonnet: the refusal it removes is already decided. |
| H3 | 5 (8.3) | `authenticate/mfa/{store,totp,enroller,doc}.go`, `store/seal/mfa*.go`, `store/*/mfa.go`, `httpsec/mfa_enrol*.go`, `policy/mfa_requirement_enrolment.go`, `authenticate/passkey/mfa_method.go`, `test/storetest/{mfa_suite,deviceproof_suite}.go`, `test/{sqlstore,pgxstore,gormstore}/mfa_test.go` | Opus: several packages, the test module's public API, and an interface other code compiles against. |
| H4 | 6 (8.6) | `authenticate/password/**`, `authenticate/password*.go`, `admin/importer.go` (godoc only), `httpsec/login_rehash_test.go`, `httpsec/reauth_password_test.go` | Sonnet: mechanical embedding plus one behaviour test. |
| H5 | 7 (8.5) | `ratelimit/**`, `internal/unavailable/**`, `internal/pglimiter/**`, `store/*/limiter*.go`, `httpsec/{throttle,oidc_client_auth}.go` and their tests, limiter test doubles across packages | Opus: wrapper typing across modules, and refusal paths in the chain. |
| H6 | 8 (8.7) | `policy/attempt_views.go`, `policy/lockout/**`, `store/*/attempts.go`, `test/storetest/{streak_suite,attempts_suite}.go`, `httpsec` attempt-store doubles | Opus: a public type moves across packages and modules. |
| H7 | 9 (8.4, 8.9) | `authenticate/mfa/{mfa,reset}.go`, `recovery/**`, `authenticate/passkey/recovery_kind*.go`, MFA method stubs in `httpsec` tests | Sonnet: two small mechanical folds in one package family. |
| H8 | 10 (8.8) | `oidcprovider/{store,store_memory,pending,options}.go`, `store/*/oidcprovider_stores.go`, `test/storetest/oidcprovider_pending_suite.go` | Sonnet: mechanical. |
| F | 11 (7.2) | `CHANGELOG.md`, `README.md` | Sonnet: documentation text. |

**Shared files.** Several lanes touch generated mocks in `httpsec` and test doubles in `httpsec`
tests.
- Each lane regenerates only the mocks of its own interfaces and edits only the doubles of its own
  interfaces.
- At integration, any conflict is in regenerated mocks. Resolve it by running `go generate` again.

**Waves.** Each H lane runs in its own git worktree, branched from the tip of
`feat/admin-user-rename-and-paging` at launch. The main session merges the lanes back one at a time
and runs each lane's verification after its merge.
1. G1 in the main tree; H1, H2 and H4 in worktrees.
2. G2 in the main tree; H3, H5 and H6 in worktrees.
3. H7 and H8 in worktrees.
4. Task 12 (8.10 sweep) in the main session, then F, then Task 13 (9.1 and 9.2).

**Reviewers:** Opus for G1, G2, H1, H3, H5 and H6; Sonnet for H2, H4, H7, H8 and F.

### Scoped verification (every lane)

```sh
# every module builds and vets
for m in . store/pgxstore store/gormstore ratelimit/redisstore test httpsec/ginsec httpsec/fibersec; do (cd $m && go build ./... && go vet ./...); done
# the changed packages and their in-module dependents (repeat per module; see test-scope.md)
go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | awk '/github.com\/kartaladev\/scrty\/<changed>( |$)/{print $1}' | xargs go test -race -count=1
# database-backed dependents, on PostgreSQL 18 and 15
(cd test && go test -race -count=1 -p 2 <db packages>)
(cd test && SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine go test -race -count=1 -p 2 <db packages>)
gofmt -l <touched dirs>
```

---

### Task 1 (tasks 6.1): Renames fold into `UserStore.UpdateUser`

**Files:**
- Modify:
  - `admin/ports.go`: change `UserStore.UpdateUser`; delete `UsernameUpdater` and its `//go:generate`.
  - `admin/users.go`: `NewUsers` and `Update`.
  - `admin/users_options.go`, `admin/errors.go`, `admin/records.go`: godoc.
  - `admin/example_test.go`.
  - `store/{sqlstore,pgxstore,gormstore}/admin_users.go`.
  - `test/admin/{toystore_test.go,conformance_users.go,conformance_import.go,conformance_guard_test.go}`.
  - `test/internal/adminfix/{userstore.go,races.go}`.
  - `test/identity/inmem.go`.
- Delete: `admin/usernameupdater_mock_test.go`.
- Test: `admin/rename_test.go` and the `test/admin` conformance cases.

**Interfaces:**
- Produces:

  ```go
  // in admin.UserStore, replacing UpdateUser and UsernameUpdater.UpdateUserRenaming:
  UpdateUser(ctx context.Context, id identity.UserID, version int64, change UserChange) (updated User, renamed bool, err error)
  ```

- `Users.Update` keeps this order:
  1. actor;
  2. id and version;
  3. validation;
  4. the audit "before" record;
  5. `UpdateUser`;
  6. the event and audit;
  7. revocation, when `renamed`.

  It still returns `(User, error)` to its callers.
- `NewUsers` no longer type-asserts the store. `WithSessionRevocation` refuses only a nil or typed-nil
  revoker.

- [ ] **Step 1: Write the failing tests.**
  - In `test/admin/conformance_users.go`, add the case "No username in the update". A change naming
    only `Name` returns `renamed == false` and leaves the username unchanged.
  - In `admin/rename_test.go`, `TestUpdate_RenameRouting` becomes "a rename calls `UpdateUser` once
    with `change.Username` set". Delete the cases that expected `ErrConfig`, and the cases that
    expected `UpdateUser` never to see a username.
  - `TestNewUsers_SessionRevocationWiring` loses its "store that cannot rename" case.
- [ ] **Step 2: Run** the toy's conforming case, with the toy's `UpdateUser` stubbed to always report
  `renamed=true`.
  - Expected: FAIL in "No username in the update", on the `renamed` assertion.
- [ ] **Step 3: Implement.**
  - Move each store's `UpdateUserRenaming` body into `UpdateUser`. When `change.Username == nil`, skip
    the username's identifier lock and the `RenameAdminUser` statement, and report `renamed=false`.
  - Steps 2, 5 and 6 go through the existing shared helpers. Delete the old `UpdateUser`.
  - Remove `renameSkip`, `variantNoUsernameUpdater` and its guard case, and the `renamer` helpers.
  - Regenerate the `admin` mocks.
- [ ] **Step 4: Run** the service scope, then the store scope on PostgreSQL 18 and 15, then the toy
  load-bearing run.
  - Expected: PASS, and a verbose run shows no "rename cases skipped".
- [ ] **Step 5:** `rg -n 'UsernameUpdater|UpdateUserRenaming' --glob '!openspec/**' --glob '!.claude/**'` prints nothing.
- [ ] **Step 6: Commit** as `refactor(admin)!: UserStore.UpdateUser renames and reports the change`.

### Task 2 (tasks 6.2, 6.3): Offset and count fold into `UserStore`

**Files:**
- Modify:
  - `admin/ports.go`: `UserStore` gains `CountUsers`; delete `UserPager` and its `//go:generate`.
  - `admin/records.go`: `UserQuery.Offset`.
  - `admin/users.go`: `NewUsers`, `List` and `Count`.
  - `admin/users_options.go`.
  - `internal/pgschema/admin.go` and `internal/pgschema/admin_test.go`.
  - `store/{sqlstore,pgxstore,gormstore}/admin_users.go`.
  - `test/admin/{toystore_test.go,conformance_users.go,conformance_guard_test.go}`.
  - `test/sqlstore/admin_test.go`.
  - `admin/example_test.go`.
- Delete: `admin/userpager_mock_test.go`.

**Interfaces:**
- Consumes: Task 1's `UserStore`.
- Produces:

  ```go
  // admin.UserQuery gains:
  Offset int // users to skip in list order; non-zero only when AfterUsername and AfterID are empty
  // admin.UserStore gains (ListUsersFrom is deleted):
  CountUsers(ctx context.Context, query UserQuery) (int64, error)
  // pgschema: ListAdminUsers binds its existing $1-$8 plus $9 = OFFSET; ListAdminUsersFrom is deleted;
  // CountAdminUsers is unchanged.
  ```

- `List` sends `UserQuery{..., Offset: filter.Offset}` to `ListUsers` for any offset. It truncates the
  result to `Limit`, and sets `Next` only when `Offset == 0`.
- `Count` calls `CountUsers`. `WithMaxListOffset` refuses only `n < 0`.

- [ ] **Step 1: Write the failing tests.**
  - `admin/offset_test.go`:
    - "jump to a page" expects `ListUsers` with `Offset: 100`, `Limit: 50` and empty After fields;
    - delete the `ErrConfig`, plain-store and `storeFor` cases;
    - keep the validation, truncation and store-error cases.
  - `test/admin/conformance_users.go`: add "Offset zero with a cursor equals the cursor page" (Review
    Focus 2).
  - `internal/pgschema/admin_test.go`: `TestListAdminUsersUnchanged` now asserts the cursor
    comparison and `OFFSET $9`.
- [ ] **Step 2: Run** the failing tests.
  - First, `go test -race -run 'TestList_Offset' -count=1 ./admin/` against `List` still calling a
    stub `ListUsersFrom`. Expected: FAIL, because `ListUsers` was not called with the offset.
  - Then the toy's conforming case, with a toy `ListUsers` that ignores `Offset`. Expected: FAIL in
    "Jump to a page".
- [ ] **Step 3: Implement.**
  - Build `ListAdminUsers` from the filter fragment, with `OFFSET $9`, and delete
    `ListAdminUsersFrom`.
  - In each store, bind `query.Offset` as `$9` in its `listAdminUsers` helper, delete
    `ListUsersFrom`, and keep `CountUsers`.
  - Delete `pagerSkip`, `variantNoUserPager`, `toyUsersWithoutPager` and its guard case. Keep the
    offset-twice, count-deleted and offset-order defects.
  - Regenerate the mocks.
- [ ] **Step 4: Run** the service scope, the store scope on PostgreSQL 18 and 15, and the toy
  load-bearing run.
  - Expected: PASS, with every existing listing case green and no "offset and count cases skipped".
- [ ] **Step 5:** `rg -n 'UserPager|ListUsersFrom|ListAdminUsersFrom|pagerSkip' --glob '!openspec/**' --glob '!.claude/**'` prints nothing.
- [ ] **Step 6: Commit** as `refactor(admin)!: UserStore lists from an offset and counts`.

### Task 3 (tasks 8.1): Sessions fold `FamilyReader` and `RoleSelector`

**Files:**
- Modify:
  - `session/{store.go,family_reader.go,role_selector.go,store_encrypted.go,sign_in_state.go,reuse.go}`.
  - `httpsec/options.go`, around line 448.
  - `oidcprovider/{lineage,exchange,refresh}.go`: comments only, if no code is needed.
  - `store/{sqlstore,pgxstore,gormstore}/session.go`: assertions.
  - `test/storetest/{session_family_read_suite.go,session_suite.go}`.
- Delete or rewrite the listing-only and selector-hiding tests the survey named:
  - `session/store_family_read_test.go:270`;
  - `test/storetest/session_family_read_suite.go:251`;
  - `test/storetest/memory_test.go:100`;
  - `test/storetest/broken_test.go:200`;
  - `session/reuse_test.go` (`hidesSelector`);
  - `httpsec/role_switch_test.go` (`noSelectorStore`).

**Interfaces:**
- Produces:

  ```go
  // session.Store gains:
  ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*Session, error)
  SelectRole(ctx context.Context, id string, role string) error
  // deleted: FamilyReader, RoleSelector, (*Sessions).SelectsRoles, roleSelectingEncryptedStore, readFamily's fallback
  ```

- [ ] **Step 1: Write the failing tests.**
  - `TestEncryptedStore_ListByFamilyOpensRows`: a family read through `NewEncryptedStore` over a
    memory store returns opened sessions equal to the ones saved (Review Focus 1).
  - `TestLineageWrappersReadOneFamily`, in `oidcprovider`: each embedding wrapper answers a family
    read through the inner store's `ListByFamily`. The inner store holds an undecodable row for
    another family of the same user, which must not cause an error. This is the spec scenario "A
    store that can only list".
- [ ] **Step 2: Run** both, focused.
  - Expected: the wrapper test FAILS on the current code, which falls back to `ListByUser`.
  - The encrypted-store test may already pass. If it does, invert the open step once to show it can
    fail.
- [ ] **Step 3: Implement** the fold.
  - The encrypted store's `SelectRole` forwards to the inner store unchanged, because the role is not
    sealed.
  - Delete every refusal that consulted `SelectsRoles`.
- [ ] **Step 4: Run** the scoped verification for `session`, `oidcprovider`, `httpsec` and the session
  store suites, on PostgreSQL 18 and 15.
  - Expected: PASS, with the `storetest` family-read and role cases running on every store.
- [ ] **Step 5: Commit** in the worktree as `refactor(session)!: every session store reads one family and records a role`.

### Task 4 (tasks 8.2): OIDC links fold `LinkLister` and `LinkRemover`

**Files:**
- Modify:
  - `authenticate/oidc/{ports.go,broker_hook.go,link.go}`.
  - `store/{sqlstore,pgxstore,gormstore}/oidc_link.go`: assertions.
  - `test/oidc/linkstore_suite.go`.
  - The `LinkStore` test doubles: `broker_hook_*_test.go`, `httpsec/resource_server_dependency_test.go`
    and `test/oidc/linkstore_guard_test.go`.
- Regenerate: `authenticate/oidc/ports.go:11` and `httpsec/oidc_backchannel.go:17`.

**Interfaces:**
- Produces: `oidc.LinkStore` gains:
  - `ListByUser(ctx, user identity.UserID) ([]Link, error)`
  - `DeleteLink(ctx, link Link) (bool, error)`
- Deleted: `LinkLister`, `LinkRemover`, `canRecheckFresh`, `errNoLinkLister`, `errNoLinkRemover` and
  the `checkSignInHooks` refusal.

- [ ] **Step 1: Write the failing test** `TestNewBroker_HookOverConsumerLinkStore`.
  - A sign-in hook over a consumer `LinkStore` double, with several links per user not allowed,
    builds without error.
  - Its one-link rule calls the double's `ListByUser`.
  - This is the spec scenario "Link store that cannot list".
- [ ] **Step 2: Run** it with a double that implements only the old base interface.
  - Expected: FAIL with the construction refusal.
- [ ] **Step 3: Implement** the fold. In `linkstore_suite.go`, remove the four port skips and keep the
  zero-ID skip.
- [ ] **Step 4: Run** the scoped verification for `authenticate/oidc`, `httpsec` and `test/oidc`, on
  PostgreSQL 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(oidc)!: every link store lists and removes one link`.

### Task 5 (tasks 8.3): MFA enrolment stores record device proofs

**Files:**
- Modify:
  - `authenticate/mfa/{store.go,totp.go,enroller.go,doc.go}`.
  - `store/seal/mfa.go`: fold `provingEnrolmentStore` into `enrolmentStore`.
  - `store/{sqlstore,pgxstore,gormstore}/mfa.go`.
  - `httpsec/{mfa_enrol.go,mfa_enrol_options.go}`.
  - `policy/mfa_requirement_enrolment.go`.
  - `authenticate/passkey/mfa_method.go`.
  - `test/storetest/{mfa_suite.go,deviceproof_suite.go}`.
  - `test/{sqlstore,pgxstore,gormstore}/mfa_test.go`.
- Regenerate:
  - `authenticate/mfa/store.go:3`;
  - `store/seal/mfa.go:32-33`, now one generation;
  - `httpsec/mfa_verify.go:47`.

**Interfaces:**
- Produces: `mfa.EnrolmentStore` gains:
  - `ProveDevice(ctx, user identity.UserID, gen id.ID, step int64, code []byte, codeUntil, at time.Time) (bool, error)`
  - `Complete(ctx, user identity.UserID, gen id.ID, at time.Time) (bool, error)`
  - `ChargeEmailCode(ctx, user identity.UserID, gen id.ID, at time.Time) (int, bool, error)`
- `mfa.Enroller` loses `SupportsEnrolmentPath`.
- Deleted: `DeviceProofStore`, `errNoDeviceProofStore` and `provingEnrolmentStore`.
- The test module's `storetest.RequireDeviceProof`, `RunDeviceProofSuite` and
  `DeviceProofEnrolmentStore` are deleted. Their proof cases move into the MFA store suite and always
  run.
- "Can enrol through the path" now means the method implements `mfa.Enroller`.

- [ ] **Step 1: Write the failing test** `TestEnrolmentPath_OverSealedConsumerStore`, in `httpsec`.
  - The enrolment interceptor is built over TOTP with a `seal.NewEnrolmentStore` that wraps a
    consumer double. The double implements the old base interface plus the proof methods.
  - The interceptor assembles and completes one enrolment through the path.
  - This is the spec scenario "Store that cannot record a device proof".
- [ ] **Step 2: Run** it.
  - Expected: FAIL. The sealed wrapper hides the proof methods unless it picks the proving variant,
    so assembly refuses.
- [ ] **Step 3: Implement** the fold. The enrolment-path checks in `httpsec` and `policy` keep refusing
  a named method that is not an `mfa.Enroller`.
- [ ] **Step 4: Run** the scoped verification for `authenticate/mfa`, `store/seal`, `httpsec`, `policy`,
  `authenticate/passkey` and the MFA store suites, on PostgreSQL 18 and 15.
  - Expected: PASS, with the proof cases running on every store.
- [ ] **Step 5: Commit** in the worktree as `refactor(mfa)!: every enrolment store records device proofs`.

### Task 6 (tasks 8.6): Password encoders always recognise and report upgrades

**Files:**
- Modify:
  - `authenticate/password/encoder.go`, `authenticate/password.go` and
    `authenticate/password_upgrade.go`.
  - The encoder test doubles the survey named.
  - `admin/importer.go`: godoc only; the parameter stays `password.Recognizer`.
- Regenerate:
  - `authenticate/password.go:23`;
  - `httpsec/login.go:32`;
  - `authenticate/oidc/integration_test.go:3`;
  - `admin/limitedencoder_test.go:5`;
  - `admin/ports.go:195`.

**Interfaces:**
- Produces:

  ```go
  type Encoder interface {
      Encode(raw []byte) ([]byte, error) // unchanged signatures; check encoder.go
      Match(raw, encoded []byte) (bool, error)
      Recognizer // Recognizes(encoded []byte) bool
      Upgrader   // NeedsUpgrade(encoded []byte) bool
  }
  ```

- Deleted: `usableHash`'s fallback for an encoder that cannot recognise, and the "never upgrades"
  fallback for an encoder that cannot report upgrades.

- [ ] **Step 1: Write the failing test** `TestPassword_ConsumerEncoderThatRecognisesNothing`.
  - The provider uses a consumer encoder double whose `Recognizes` returns false, and which counts
    calls to `Match`.
  - A known user with a stored hash logs in with the right password.
  - Assert that the login fails, and that `Match` ran exactly once, against the reference hash.
  - This covers Review Focus 3 and the spec scenario "Consumer encoder that does not recognise a
    hash".
- [ ] **Step 2: Run** it with a double that does not yet implement `Recognizes`. Wrap an old-base
  double so it compiles.
  - Expected: FAIL, because the login succeeds.
- [ ] **Step 3: Implement** the embedding. Delete both fallbacks, and the encoders' redundant
  `var _ Recognizer` and `var _ Upgrader` lines.
- [ ] **Step 4: Run** the scoped verification for `authenticate/password`, `authenticate`, `httpsec`
  and `admin`. Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(password)!: every encoder recognises hashes and reports upgrades`.

### Task 7 (tasks 8.5): Limiters always report recent failures and their policy

**Files:**
- Modify:
  - `ratelimit/{limiter.go,guard.go,memory.go}` and `ratelimit/redisstore/limiter.go`.
  - `internal/unavailable/wrap.go` and `internal/pglimiter/runner.go`.
  - `store/{sqlstore,pgxstore}/limiter.go`.
  - `httpsec/{throttle.go,oidc_client_auth.go}`.
  - The limiter test doubles in the packages the survey listed.
- Regenerate:
  - `ratelimit/limiter.go:12`;
  - `internal/unavailable/wrap.go:15`;
  - the reflect-mode `Limiter` mocks in `oidcprovider`, `recovery`, `httpsec`, `authenticate/mfa` and
    `authenticate/passkey`.

**Interfaces:**
- Produces: `ratelimit.Limiter` gains:
  - `Policy() (limit int, window time.Duration)`
  - `HasRecentFailures(ctx context.Context, key string) (bool, error)`
- `unavailable.Wrap` returns a `ratelimit.Limiter` whose `Policy()` answers the limit and window it was
  built with. Its backend parameter is an internal interface without `Policy`.
- Deleted:
  - `PolicyReporter`, `RecentFailureReporter` and `errNoReport`;
  - the chain's warning and refusal for a limiter that reports no policy;
  - `limiterWindow`'s zero fallback.

- [ ] **Step 1: Write the failing tests.**
  - `TestChain_ExplicitAggregateOverConsumerLimiter`: an explicit /48 aggregate with multiplier 2,
    over a consumer limiter reporting 50 per minute, builds. Its aggregate limiter is asked for 100
    per minute. This is the spec scenario "Explicit aggregate over a limiter that reports no policy".
  - `TestWrap_PolicyWhileBackendDown`: `Policy()` returns the configured limit and window while the
    backend errors (Review Focus 4).
- [ ] **Step 2: Run** both.
  - Expected: the chain test FAILS with the current refusal.
  - If the wrap test already passes, prove it can fail by returning zero once.
- [ ] **Step 3: Implement** the fold.
- [ ] **Step 4: Run** the scoped verification for `ratelimit`, `ratelimit/redisstore`,
  `internal/unavailable`, `internal/pglimiter`, the limiter stores, `httpsec` and
  `test/ratelimittest`, on PostgreSQL 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(ratelimit)!: every limiter reports recent failures and its policy`.

### Task 8 (tasks 8.7): Attempt stores keep failure streaks

**Files:**
- Modify:
  - `policy/attempt_views.go`.
  - `policy/lockout/{attempts.go,lockout.go,lockout_observer.go,lockout_events.go,lockout_options.go}`.
  - `store/{sqlstore,pgxstore,gormstore}/attempts.go`.
  - `test/storetest/streak_suite.go`.
  - The attempt-store doubles in `policy/lockout`, `httpsec`, `httpsec/ginsec`, `httpsec/fibersec`
    and `test/storetest`.
- Regenerate: `policy/attempt_views.go:32`, `policy/lockout/attempts.go:59-60` and
  `httpsec/login.go:31`.

**Interfaces:**
- Produces:

  ```go
  // package policy (moved from lockout, no alias):
  type FailureStreak struct{ /* fields as lockout.FailureStreak today */ }
  func (s FailureStreak) Held() bool
  // policy.AttemptStore gains:
  AddStreakFailure(ctx context.Context, username string, at, since time.Time, limit int) (streak FailureStreak, setHold bool, err error)
  FailureStreak(ctx context.Context, username string, since time.Time) (FailureStreak, error)
  DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error)
  ```

- Deleted: `lockout.FailureStreakStore`, `lockout.FailureStreak`, the `streaks` field and the cap's
  store refusal.
- **Name clash:** the method `FailureStreak` and the type `policy.FailureStreak` can both exist,
  because a method is not a package-level identifier. Keep both names as shown.

- [ ] **Step 1: Write the failing test** `TestLockout_CapOverConsumerAttemptStore`.
  - A policy with a cap of 10 is built over a consumer attempt-store double whose streak methods
    report a held streak.
  - It builds, and refuses the next attempt as held.
  - This is the spec scenario "Store without consecutive counts".
- [ ] **Step 2: Run** it against the current code. Expected: FAIL with the construction refusal.
- [ ] **Step 3: Implement** the move and the fold.
- [ ] **Step 4: Run** the scoped verification:
  - `policy`, `policy/lockout`, `httpsec`, `httpsec/ginsec` and `httpsec/fibersec`;
  - the attempt and streak suites on the memory store and the three SQL stores, on PostgreSQL 18 and
    15 (Review Focus 5).

  Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(policy)!: every attempt store keeps failure streaks`.

### Task 9 (tasks 8.4, 8.9): MFA methods remove enrolments; recovery kinds list usable authenticators

**Files:**
- Modify:
  - `authenticate/mfa/{mfa.go,reset.go}`.
  - `recovery/{mfa_kind.go,reset.go,wayback.go}`.
  - `authenticate/passkey/{mfa_method.go,recovery_kind.go}`.
  - The `Method` and `AuthenticatorKind` stubs the survey listed.
- Regenerate:
  - `authenticate/mfa/reset.go:3`, `recovery/mfa_kind.go:3` and `recovery/reset.go:3`;
  - the `Method`, `ChallengeMethod` and `Enroller` mocks in `httpsec` and `recovery`;
  - `httpsec/signals_sources_test.go:3`.

**Interfaces:**
- Produces:
  - `mfa.Method` gains `RemoveEnrolment(ctx context.Context, user identity.UserID) error`.
  - `mfa.ResetDeps.Enrolments` becomes `[]mfa.Method`.
  - `recovery.AuthenticatorKind` gains `Usable(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)`.
- Deleted: `EnrolmentRemover`, `UsableLister`, the kind's `removers` map and its refusal, and
  `wayback.go`'s `usable` fallback.

- [ ] **Step 1: Write the failing tests.**
  - `TestMFAKind_ResetsThroughConsumerMethod`: the kind over a consumer method double builds, and a
    reset calls that method's `RemoveEnrolment` for `u-1`. This is the spec scenario "Method without
    a remover".
  - `TestAnotherWayBack_ConsumerKindWithOnlySuspended`: issued codes are enabled and the user has no
    password. A consumer kind holds one authenticator and reports none usable. The check reports no.
- [ ] **Step 2: Run** both against the current code.
  - Expected: the first FAILS with the construction refusal.
  - The second FAILS because the fallback counts the held authenticator.
- [ ] **Step 3: Implement** both folds.
- [ ] **Step 4: Run** the scoped verification for `authenticate/mfa`, `authenticate/passkey`,
  `recovery` and `httpsec`. Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(recovery)!: MFA methods remove enrolments and kinds list usable authenticators`.

### Task 10 (tasks 8.8): Pending-request stores count live requests

**Files:**
- Modify:
  - `oidcprovider/{store.go,store_memory.go,pending.go,options.go}`.
  - `store/{sqlstore,pgxstore,gormstore}/oidcprovider_stores.go`.
  - `test/storetest/oidcprovider_pending_suite.go`.
  - The pending-store doubles the survey listed.
- Regenerate: `oidcprovider/pending.go:19` (drop the counter) and `httpsec/oidc_cancel.go:7`.

**Interfaces:**
- Produces: `oidcprovider.PendingRequestStore` gains `CountLive(ctx context.Context, now time.Time) (int, error)`.
- Deleted: `PendingRequestCounter`, `errNoCounter` and the ceiling's store refusal.

- [ ] **Step 1: Write the failing test** `TestPendingCeiling_OverConsumerStore`.
  - A provider with a ceiling of 1, over a consumer double whose `CountLive` reports 1, builds.
  - It answers the next request to be parked with `temporarily_unavailable`.
  - This is the spec scenario "Store cannot count".
- [ ] **Step 2: Run** it against the current code. Expected: FAIL with the construction refusal.
- [ ] **Step 3: Implement** the fold.
- [ ] **Step 4: Run** the scoped verification for `oidcprovider`, `httpsec` and the pending suite, on
  PostgreSQL 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** in the worktree as `refactor(oidcprovider)!: every pending-request store counts live requests`.

### Task 11 (tasks 7.2): Changelog and README

**Files:**
- Modify:
  - `CHANGELOG.md`, under `## [Unreleased]`: rewrite the 7.1 entry and add `### BREAKING`.
  - `README.md`.

- [ ] **Step 1: Rewrite the 7.1 entry** as `tasks.md` 7.2 describes.
  - Add one BREAKING bullet per D15 fold. Each names the base interface, the methods to add, and the
    removed API.
  - Follow the file's existing style.
- [ ] **Step 2: Verify** with `rg -n 'UsernameUpdater|UserPager|FamilyReader|RoleSelector|LinkLister|LinkRemover|DeviceProofStore|EnrolmentRemover|RecentFailureReporter|PolicyReporter|FailureStreakStore|PendingRequestCounter|UsableLister|SelectsRoles|SupportsEnrolmentPath|RequireDeviceProof' README.md`.
  - It prints only text that describes a removal.
  - Every one of those names appears in the BREAKING section.
- [ ] **Step 3: Commit** as `docs: changelog and README for the admin additions and the folded ports`.

### Task 12 (tasks 8.10): Sweep (main session)

- [ ] **Step 1:** Run Task 11's pattern over `*.go`, excluding `openspec/` and `.claude/`.
  - Expected: no type assertion, interface or skip message for a folded port.
- [ ] **Step 2:** Run `go generate` over every package Tasks 1–10 touched.
  - Expected: `git status --short` shows no diff.
- [ ] **Step 3:** Run the build-and-vet loop from "Scoped verification" over every module.
  - Expected: clean.
- [ ] **Step 4:** Tick 8.10.

### Task 13 (tasks 9.1, 9.2): Final gate (main session only)

- [ ] **Step 1:** Run `make check` and `make spec-check` after the last code edit.
  - The main session reads the output and records it in the PR.
  - Expected: both green.
- [ ] **Step 2:** Dispatch a whole-branch Opus reviewer.
  - It first enumerates how the change fails.
  - Then it checks every requirement in every spec delta and every failure-mode row in `design.md`.
  - It marks each claimed defect REPRODUCED or UNREPRODUCED.
  - Findings go to a fresh dispatch of their lane, followed by Step 1 again.
- [ ] **Step 3:** Tick 9.1 and 9.2, commit, and push.

## Workflow follow-up

- `/opsx:archive admin-user-rename-and-paging`. Then check two things:
  - `security-administration` carries ten added and three modified requirements;
  - each of the other nine capabilities carries its modified requirements.
- Propose `username-case-folding` and `lockout-by-user-id`.
- `/opsx:explore` sharing the three SQL stores' duplicated logic.
