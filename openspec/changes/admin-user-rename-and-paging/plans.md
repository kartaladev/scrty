# Admin User Rename and Paging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `admin.Users` gains two abilities:
- **Rename.** `Update` can change a user's username, together with the email and under one version
  check, by the uniqueness rules of creation. It comes with opt-in session revocation, which runs
  only when the username actually changed, and a refusal before writing on stores that cannot
  rename.
- **Numbered pages.** `List` can page from any offset and `Count` reports how many users match, so a
  screen can show "10 of 999 records shown" and jump to any page. Cursor listing stays the default
  and is unchanged.

**Architecture:**
- **Rename:** `UserChange.Username` goes to an optional store method,
  `UsernameUpdater.UpdateUserRenaming`, which also reports whether the stored username changed.
  `UserStore.UpdateUser` is unchanged and never sees a username. `WithSessionRevocation` takes a
  `SessionRevoker`, which `*session.Sessions` satisfies.
- **Paging:** `UserFilter.Offset` and `Users.Count` go through an optional store port, `UserPager`.
- **SQL stores:** a rename writes the username alone first (`pgschema.RenameAdminUser`, as import
  does), then the other fields. The cursor listing, the offset listing and the count share one
  filter fragment.
- **Conformance:** the public suite runs the rename cases only for stores implementing
  `UsernameUpdater`, and the offset and count cases only for stores implementing `UserPager`.

**Tech Stack:** Go 1.27, testify, mockgen (`use-mockgen`), testcontainers PostgreSQL 18 and 15
(`use-testcontainers`).

**Spec:** `openspec/changes/admin-user-rename-and-paging/{proposal.md,design.md,specs/security-administration/spec.md,tasks.md}`.
Every plan task names the `tasks.md` numbers it carries out. This plan adds no scope beyond
`tasks.md`.

## Global Constraints

- **Test-first** (`golang-tdd.md`): see the focused red step fail for the intended reason before
  implementing. A compile error, a skipped test or a test that never compiled is not red. If a new
  name has to exist for a test to compile, add a stub first.
- **The toy store needs a build tag.** `test/admin` toy-store tests carry `//go:build admin_stub`.
  Every command that exercises them passes `-tags admin_stub`. The toy store runs the suite only in
  `TestAdminSuiteIsLoadBearing`'s case "a conforming store passes the whole suite".
- **Table tests** use the `table-test` skill: an `assert` closure and `t.Context()`.
- **Usernames** are compared exactly, byte for byte, deleted users included. A username clashes
  with another *live* user's email when they are equal ignoring case. The user's own username and
  email never clash.
- **Username validation** is `exactName("username", s, MaxTextBytes)`, as `Create` uses.
- **Clashes** give `AlreadyExistsError{Field: FieldUsername}` or `FieldEmail`. Error and event text
  never contain a username or an email.
- **`renamed`** is true when the stored username differed byte for byte. A case-only change counts.
  Re-sending the current username is still a write (the version increases, `username` is reported)
  with `renamed` false, and no revocation.
- **The lockout key is not touched.** D5 is accepted, so no code moves or clears lockout state.
- **List order** is `(lower(username), id)` for every listing, offset included.
- **Offsets:** 0 to `DefaultMaxListOffset` (10 000) inclusive, configurable with
  `WithMaxListOffset`. Offset 0 is the first page of the default listing and carries `Next`; a
  non-zero offset carries none. Page size stays 1 to 500, default 50.
- **Refusal order:** input validation (`ErrInvalidInput`), then store capability (`ErrConfig`),
  before any store call. Options that can never take effect on the store fail `NewUsers` with
  `ErrConfig`.
- **Agents** never edit `openspec/`, never run `git checkout --`, `restore`, `reset --hard`,
  `stash` or `clean`, and never cite the predecessor reference.

## Review Focus

Each line is pinned by a test `tasks.md` already lists. None needed scope beyond it.

1. **A profile save that re-sends the current username, with revocation on.** No sign-out. Task 1,
   case "current username re-sent" (tasks 1.4), and Task 2, case "same username again"
   asserting `renamed` false (tasks 2.1).
2. **A context cancelled after the store commits, before the revoker runs.** The error matches
   `ErrSessionsNotRevoked` and `context.Canceled`, never a silent success. Task 1 (tasks 1.4).
3. **A store that claims a capability but does not honour it.** Renames: the ignored-username and
   always-false-`renamed` defects (Task 4, tasks 2.7). Paging: the offset-twice and count-deleted
   defects (Task 9, tasks 6.5).
4. **An offset at the maximum, offset zero, and an over-maximum offset on a store without
   `UserPager`.** Accepted, first page with `Next`, and `ErrInvalidInput` respectively. Task 6
   (tasks 5.1, 5.2).
5. **A store returning a negative count or too many rows.** An error, or truncation; never "-1
   records". Tasks 6 and 7 (tasks 5.2, 5.3).

---

## Lanes, waves and models

| Lane | Plan tasks (tasks.md) | Owns | Model (reason) |
|---|---|---|---|
| A | 1 (1.1–1.5) | `admin/**`, including `userstore_mock_test.go`, the new `usernameupdater_mock_test.go` and `sessionrevoker_mock_test.go`, and `example_test.go` | Opus. The routing guard and the post-commit revocation are refusal logic where a mistake can pass the tests and still be wrong. |
| B1 | 2 (2.1–2.3) | `internal/pgschema/admin.go` and its test, `store/{sqlstore,pgxstore,gormstore}/admin_users.go`, `test/admin/**`, `test/{sqlstore,pgxstore,gormstore}/admin*_test.go` | Opus. Lock ordering and a two-statement conditional write across three stores, and a public-suite gate. |
| B2 | 3, 4 (2.4–2.7, 4.1) | the B1 files, `test/internal/adminfix/**` | Opus. Unique-index blocking, a barrier race and load-bearing defects. |
| C | 5 (3.1) | `test/sqlstore/rename_sessions_test.go` | Sonnet. A wiring test over a real store. |
| D | 6, 7 (5.1–5.4) | `admin/**`, including the new `userpager_mock_test.go` | Sonnet. Signatures and tests are given here; the validation and routing are small, decided logic. |
| E | 8, 9 (6.1–6.5) | the B1 and B2 files | Opus. It extracts a shared SQL fragment while keeping the cursor listing's behaviour, across three stores, and adds load-bearing defects. |
| F | 10 (7.1) | `CHANGELOG.md` | Sonnet. Changelog text. |

Waves:

1. **A.**
2. **B1 and D at the same time.** D runs in its own git worktree, because it edits `admin/**`,
   which B1 compiles against. B1 owns nothing D touches, so D's branch merges cleanly after both
   pass.
3. **B2.**
4. **C.** It compiles in package `test/sqlstore` beside files E edits, so it runs first.
5. **E.** It needs D's `UserPager` and B2's store files.
6. **F.**
7. **Final gate** in the main session (Task 11).

Reviewers: Opus for A, B1, B2 and E; Sonnet for C, D and F.

### Scoped verification

Dependents were computed on 2026-11-28 with `go list -test -deps` across every workspace module.
`admin` and `internal/pgschema` have dependents only in the root, `store/pgxstore`,
`store/gormstore` and `test` modules.

- **Service scope** (lanes A and D):

  ```sh
  go test -race -count=1 ./admin/... ./authenticate/passkey/... ./store/sqlstore/...
  (cd test && go test -race -count=1 . ./admin/... ./crossbackend/... ./gormstore/... ./httpsecconformance/... \
      ./internal/adminfix/... ./internal/storefix/... ./oidc/... ./pgxstore/... ./ratelimittest/... ./sqlstore/... ./storetest/...)
  (cd test && go test -race -count=1 -tags admin_stub -run '^(TestAdminSuiteIsLoadBearing|TestBrokenAdminStore)$' ./admin/)
  (cd store/pgxstore && go test -race -count=1 ./...)
  (cd store/gormstore && go test -race -count=1 ./...)
  ```
- **Store scope** (lanes B1, B2, C and E): the service scope, plus
  `go test -race -count=1 ./internal/pgschema/... ./internal/storekit/... ./internal/pglimiter/... ./session/...`.
  Then repeat the `test` module's database-backed dependents (`. ./sqlstore/... ./pgxstore/...
  ./gormstore/... ./crossbackend/... ./storetest/...`) with
  `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`, because the helper defaults to 18.6.
  (`internal/adminfix` holds the shared cases these packages run; it has no tests of its own.)
- **Every lane:** `go vet` and `gofmt -l` on the packages it touched.

---

### Task 1 (tasks 1.1–1.5): The service accepts, routes, guards and reports a rename

**Files:**
- Modify: `admin/records.go` (`UserChange`), `admin/users.go` (`NewUsers`, `Update`,
  `validateChange`, `changedUserFields`), `admin/users_options.go`, `admin/ports.go`
  (`UsernameUpdater`, `SessionRevoker`, their `//go:generate`), `admin/errors.go` (`ErrConfig`
  godoc, `ErrSessionsNotRevoked`), `admin/example_test.go` (`exampleUserStore` implements
  `UpdateUserRenaming`)
- Create: `admin/rename_test.go`, `admin/usernameupdater_mock_test.go`,
  `admin/sessionrevoker_mock_test.go`, `admin/example_rename_test.go`

**Interfaces:**
- Produces:

  ```go
  // UserChange gains, as its first field:
  Username *string // nil = unchanged

  type UsernameUpdater interface {
      UpdateUserRenaming(ctx context.Context, id identity.UserID, version int64,
          change UserChange) (updated User, renamed bool, err error)
  }

  type SessionRevoker interface {
      DeleteByUser(ctx context.Context, user identity.UserID) error
  }

  func WithSessionRevocation(r SessionRevoker) UsersOption // nil, typed-nil, or store without UsernameUpdater → NewUsers fails with ErrConfig

  var ErrSessionsNotRevoked = errors.New("admin: the renamed user's sessions were not revoked")

  const userFieldUsername = "username" // first in changedUserFields' output
  ```

- Update order:
  1. actor;
  2. id and version;
  3. `validateChange`, whose "names no field" check counts `Username`;
  4. if `change.Username != nil` and the store is not a `UsernameUpdater`, return an error
     matching `ErrConfig`;
  5. the audit "before" record;
  6. `UpdateUserRenaming` when `change.Username != nil`, else `UpdateUser`;
  7. the event and audit;
  8. if `renamed` and a revoker is set, call `DeleteByUser(ctx, userID)`. On error, return
     `updated, fmt.Errorf("%w: %w", ErrSessionsNotRevoked, err)`.

- [ ] **Step 1: Write the failing tests** in `admin/rename_test.go`. A renaming store is a test type
  embedding `*MockUserStore` and `*MockUsernameUpdater`.
  - `TestUpdate_UsernameValidation` (table):
    - `""`, `" ada"`, `"ada\x00"`, `"ada\x07"`, `"ada\xff"` and
      `strings.Repeat("a", MaxTextBytes+1)` each give `ErrInvalidInput`, with no store method
      called;
    - `UserChange{Username: ptr("ada.lovelace")}` alone, on the renaming store, reaches
      `UpdateUserRenaming` once.
  - `TestUpdate_RenameRouting` (table):
    - "store without support": the plain `MockUserStore` with an audit sink. A rename gives
      `errors.Is(err, ErrConfig)`, and `GetUser` and `UpdateUser` get `.Times(0)`;
    - "invalid username without support": `" ada"` gives `ErrInvalidInput`, not `ErrConfig`;
    - "other fields": a `Name` change calls `UpdateUser` and succeeds;
    - "rename routes": on the renaming store, a rename calls `UpdateUserRenaming` once and
      `UpdateUser` at `.Times(0)`.
  - `TestUpdate_RenameReported`: `UpdateUserRenaming` returns the user with the new username and a
    verification time set.
    - The event names `["username","email"]`, and its text contains neither `ada`, `ada.lovelace`
      nor the email.
    - The audit receives before and after.
    - A store `AlreadyExistsError{FieldUsername}` gives no event, and the error text has no
      username.
  - `TestUpdate_SessionRevocation` (table, with a mockgen `MockSessionRevoker`, on the renaming
    store):
    - default: no revoker, and nothing is called;
    - renamed: `UpdateUserRenaming` returns `renamed=true`, and `DeleteByUser(ctx, "u-ada")` is
      called once;
    - current username re-sent: `renamed=false`, `.Times(0)`;
    - `Name` only: `.Times(0)`;
    - refused rename (the store returns `AlreadyExistsError`): `.Times(0)`;
    - revoker error `errBoom`: matches `ErrSessionsNotRevoked` and `errBoom`, the text contains
      no username, the returned user has the new username, and one event is emitted (spec
      scenarios "Revocation fails", "Sessions not revoked", "Committed change with a failed
      follow-up");
    - context cancelled after commit: the store mock cancels `ctx` and succeeds with
      `renamed=true`, and the revoker returns `ctx.Err()`. The error matches
      `ErrSessionsNotRevoked` and `context.Canceled`. This checks the wrapping only; the revoker
      runs on the caller's context by design (D6).
  - `TestNewUsers_SessionRevocationWiring` (table), each giving `ErrConfig`:
    `WithSessionRevocation(nil)`, `WithSessionRevocation((*MockSessionRevoker)(nil))`, and a valid
    revoker over the plain `MockUserStore`.
  - `ExampleWithSessionRevocation` in `admin/example_rename_test.go`:
    `session.NewMemoryStore()`, `session.New(session.WithStore(store))`, then
    `admin.NewUsers(&exampleUserStore{...}, admin.WithSessionRevocation(sessions))`, with `// Output:`.
- [ ] **Step 2: Run** `go test -race -run 'TestUpdate_|TestNewUsers_SessionRevocationWiring|ExampleWithSessionRevocation' -count=1 ./admin/`.
  Expected: behavioural failures, recorded. For example, the username-only change is refused as
  naming no field, `UpdateUser` is called for a rename, and no `username` field is reported.
- [ ] **Step 3: Implement** the interfaces above. Write the godoc for task 1.5, as `tasks.md` lists
  it: defaults, D5 lockout (counts age out, holds never expire, call the lockout `Reset` on the old
  username), the standalone `JWTAuthenticator` caveat, `UpdateUser` never receiving a username, the
  embedding warning on `UsernameUpdater`, the user returned with `ErrSessionsNotRevoked`, the
  caller's-transaction caveat on `WithSessionRevocation`, leaving `Username` nil on stores without
  the port, and `ErrConfig`'s call-time rename case.
- [ ] **Step 4: Run** the service scope, `go doc ./admin UsernameUpdater`, `go doc ./admin UserChange`
  and `go vet ./admin`. Expected: PASS, with the godoc shown.
- [ ] **Step 5: Commit** with the message `feat(admin): updates may rename a user through stores
  that support it, with opt-in session revocation`.

### Task 2 (tasks 2.1–2.3): The stores apply the username

**Files:**
- Modify: `test/admin/conformance_users.go` (new `renameCases`, gated on the port),
  `test/admin/toystore_test.go` (`UpdateUserRenaming`), `internal/pgschema/admin.go`
  (`RenameAdminUser`), `test/sqlstore/admin_test.go` (`TestAdminStatementsMatchSchema` entry), and
  the `admin_users.go` of `store/sqlstore`, `store/pgxstore` and `store/gormstore`.

**Interfaces:**
- Consumes: `admin.UserChange.Username` and `admin.UsernameUpdater` (Task 1).
- Produces:
  `pgschema.RenameAdminUser = "UPDATE scrty_users SET username = $2 WHERE id = $1 AND username <> $2"`,
  and `UpdateUserRenaming` on each store's `IdentityStore`.
- `UpdateUserRenaming`, in one transaction:
  1. `lockAdminUser` (version check);
  2. the existing verification and organisation checks, as `UpdateUser`;
  3. one `checkIdentifiers(…, uid, *change.Username, email)` call, where `email` is the named email
     when it is non-empty and differs from the stored one, else `""` (gorm's variant takes no ctx);
  4. `RenameAdminUser`: a unique violation is `FieldUsername`, and one row affected is
     `renamed = true`;
  5. `UpdateAdminUserQuery` over the other fields (it always bumps the version): a unique violation
     is `FieldEmail`;
  6. attributes and the read-back, as `UpdateUser`.

  Share steps 2, 5 and 6 with `UpdateUser` through a helper, not a copy.

- [ ] **Step 1: Write the failing tests.**
  - `renameCases` runs only when `f.Users()` implements `admin.UsernameUpdater`, otherwise
    `t.Skip("admintest: the store does not implement admin.UsernameUpdater; rename cases skipped")`.
    It calls `UpdateUserRenaming` directly. The cases:
    - "Rename": `ada` → `ada.lovelace`, no other field. `renamed` is true, she loads with it, the
      version increased, and no live user is named `ada`.
    - "Username held by a deleted user": `FieldUsername`, nothing written.
    - "Username equal to another user's email": `CAROL@example.com` gives `FieldUsername`.
    - "Only the case changes": `Ada` is stored, and `renamed` is true.
    - "Stale rename": deactivate, then rename at the old version. `ErrStaleUpdate`; she stays
      inactive with the old username.
    - "Username follows a new email": both set to `ada@lovelace.dev`. The email is unverified, and
      the version increased by exactly 1.
    - "One field clashes": a free username with a taken email gives `FieldEmail`, and neither field
      changes.
    - "own email in the same change": succeeds.
    - "username and email equal ignoring case": `Ada@x.dev` and `ada@x.dev` succeed.
    - "same username again": the version increases, and `renamed` is false.
    - "normalisation differs": `"café"` → `"café"` succeeds, the bytes are stored as
      given, and `renamed` is true.
  - `TestAdminStatementsMatchSchema` gains `"RenameAdminUser": pgschema.RenameAdminUser`.
- [ ] **Step 2: Run**
  `(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$/conforming' -count=1 -v ./admin/)`.
  First give the toy store a stub `UpdateUserRenaming` that changes nothing and returns
  `renamed=false`; the conforming case passes on skipped cases, so without the stub the gated cases
  would skip and nothing could go red. Expected: the conforming-store case fails on the rename
  cases with the stub, then passes once the toy store applies the field. Then
  `(cd test && go test -run 'Admin' -count=1 -v ./sqlstore/ ./pgxstore/ ./gormstore/ | grep -i 'rename cases skipped')`
  shows the skip on each SQL store. Record both.
- [ ] **Step 3: Implement** in `sqlstore`, then `pgxstore`, then `gormstore`. For each store, first
  add a stub `UpdateUserRenaming` that returns the stored user unchanged with `renamed=false`, and
  see its rename cases fail on the unchanged username (the red step). Then implement the sequence
  above.
- [ ] **Step 4: Run** the store scope, on PostgreSQL 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** with the message `feat(store): user stores rename under the creation clash
  rules and report the change`.

### Task 3 (tasks 2.4, 2.5, 2.6, 4.1): Collisions, races, every store, and import after a rename

**Files:**
- Modify: `test/internal/adminfix/userstore.go` and `races.go`, `test/admin/conformance_users.go`,
  `test/admin/conformance_import.go`, and `test/{sqlstore,pgxstore,gormstore}/admin*_test.go` where a
  harness field is needed.

**Interfaces:**
- Consumes: Task 2's store behaviour; `adminfix.Harness{Users, DB, ...}`.

- [ ] **Step 1: Write the tests.**
  - `runRenameHitsUniqueIndex` in `adminfix` (tasks 2.4):
    1. Transaction T opens on `h.DB`, inserts a `scrty_users` row with username `collide-7f3a`
       without any advisory lock, and stays open.
    2. A goroutine renames `ada` to `collide-7f3a` through `UpdateUserRenaming`. It blocks on the unique
       index; wait until `pg_stat_activity` shows it waiting.
    3. Commit T.
    4. Assert `AlreadyExistsError` with `Field == FieldUsername`, and that the error text does not
       contain `collide-7f3a`.
  - `runRacingRename` in `adminfix/races.go` (tasks 2.5): a barrier releases a rename of `ada` to
    `x@example.com` and an email update of `bob` to `x@example.com`. At most one returns nil, and
    every other returns `ErrAlreadyExists`. Run 50 iterations.
  - "Library stores" (tasks 2.6) in `conformance_users.go`, gated as in Task 2: a rename through
    `admin.NewUsers(f.Users())` and `Update` applies.
  - "Import after a rename" (tasks 4.1) in `conformance_import.go`, gated on
    `admin.UsernameUpdater` with the same skip message. Rename `ada` to `ada.lovelace`, then import
    her identifier with `ada.lovelace` and otherwise equal values. The import reports unchanged and
    emits no event.
- [ ] **Step 2: Prove each test can fail.** These pin behaviour Task 2 already built, so they may
  pass at once. For each, break the behaviour it pins in a scratch copy, see it fail, and restore:
  - unique index: swap the two statements' field mapping;
  - race: remove the advisory-lock call from `checkIdentifiers` (both writes then succeed, because
    no unique index spans username and email);
  - library stores: return before the rename write;
  - import: rename without updating the stored username.

  Record each failure (`golang-tdd.md`).
- [ ] **Step 3: Fix** anything the tests expose.
- [ ] **Step 4: Run** the store scope with `-race`, on PostgreSQL 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** with the message `test(admin): renames collide, race and import safely on
  every store`.

### Task 4 (tasks 2.7): The rename cases are load-bearing

**Files:**
- Modify: `test/admin/toystore_test.go` (new defects), `test/admin/conformance_guard_test.go`.

**Interfaces:**
- Produces, in the `defect` constants:
  - `variantNoUsernameUpdater defect = "no-username-updater"`: the toy store hides
    `UpdateUserRenaming`;
  - `defectRenameIgnored defect = "rename-ignored"`: it leaves the username unchanged;
  - `defectRenameUnchecked defect = "rename-unchecked"`: it skips the username clash checks;
  - `defectRenamedFalse defect = "renamed-false"`: it always reports `renamed` false.

- [ ] **Step 1: Write the guard cases.**
  - In `TestAdminSuiteIsLoadBearing`'s fixed cases: `variantNoUsernameUpdater` on part `users`
    passes, and its output contains the skip message.
  - In `guards`:
    - `defectRenameIgnored` failing in "Rename";
    - `defectRenameUnchecked` failing in "Username held by a deleted user" and in "Username equal
      to another user's email";
    - `defectRenamedFalse` failing in "Rename".
- [ ] **Step 2: Run**
  `(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$' -count=1 ./admin/)`
  before the defects exist. Expected: the new guard cases fail, because the defect changes nothing.
  Record it.
- [ ] **Step 3: Implement** the defects in the toy store.
- [ ] **Step 4: Run** the same command, then the store scope. Expected: PASS.
- [ ] **Step 5: Commit** with the message `test(admin): prove the rename conformance cases catch
  broken stores`.

### Task 5 (tasks 3.1): Sessions end on an opted-in rename

**Files:**
- Create: `test/sqlstore/rename_sessions_test.go` (untagged, so `make test` and CI run it)

- [ ] **Step 1: Write the failing test** `TestRename_RevokesSessionsWhenOptedIn`.
  - Use the package's existing migrated-database helper for an `sqlstore.IdentityStore`, and
    create `ada`.
  - Set up `store, err := session.NewMemoryStore()` and
    `sessions, err := session.New(session.WithStore(store))`, failing on either error. Create two
    sessions for `ada`'s identifier with `sessions.Create`.
  - Build `admin.NewUsers(identityStore, admin.WithSessionRevocation(sessions))` and rename `ada`.
  - Assert that `sessions.Load` returns `session.ErrNotFound` for both.
  - Disable the revoker call in a scratch copy, see the test fail, then restore it.
- [ ] **Step 2: Run** `(cd test && go test -run TestRename_RevokesSessionsWhenOptedIn -count=1 ./sqlstore/)`.
  Expected: red as described, then green.
- [ ] **Step 3: Run** the store scope. Expected: PASS.
- [ ] **Step 4: Commit** with the message `test(admin): opted-in session revocation ends every
  session of a renamed user`.

### Task 6 (tasks 5.1, 5.2): Offset validation and routing in `List`

**Files:**
- Modify: `admin/records.go` (`UserFilter.Offset`), `admin/users.go` (`List`, `query`, `NewUsers`),
  `admin/users_options.go` (`WithMaxListOffset`, `DefaultMaxListOffset`, `usersConfig.offsetMax`,
  and whether the option was given), `admin/ports.go` (`UserPager`, its `//go:generate`)
- Create: `admin/offset_test.go`, `admin/userpager_mock_test.go` (generated)

**Interfaces:**
- Produces:

  ```go
  // UserFilter gains, after Cursor:
  Offset int // users to skip; 0 = the first page of the default listing. Not with Cursor.

  const DefaultMaxListOffset = 10_000

  func WithMaxListOffset(n int) UsersOption // n < 0, or a store without UserPager → NewUsers fails with ErrConfig

  type UserPager interface {
      ListUsersFrom(ctx context.Context, query UserQuery, offset int) ([]User, error)
      CountUsers(ctx context.Context, query UserQuery) (int64, error)
  }
  ```

- `List` routing, after `query` validates (validation errors come first):
  - `Offset == 0`: `ListUsers`, as today, with `Next` on a full page;
  - `Offset > 0` and the store is not a `UserPager`: an error matching `ErrConfig`;
  - `Offset > 0`: `ListUsersFrom(ctx, q, filter.Offset)`, truncated to `q.Limit`, with `Next` empty.

- [ ] **Step 1: Write the failing tests** in `admin/offset_test.go`. The pager store is a test type
  embedding `*MockUserStore` and `*MockUserPager`.
  - `TestList_OffsetValidation` (table; every store method `.Times(0)` on refusals):
    - `Offset: -1` gives `ErrInvalidInput`;
    - `Offset: 10, Cursor: <valid cursor>` gives `ErrInvalidInput`;
    - `Offset: 10_001` gives `ErrInvalidInput`, on the pager store and on the plain store;
    - `Offset: 10_000` reaches `ListUsersFrom` with offset 10 000;
    - with `WithMaxListOffset(50_000)`, `Offset: 40_000` reaches `ListUsersFrom`.
  - `TestNewUsers_MaxListOffset` (table), each giving `ErrConfig`: `WithMaxListOffset(-1)` on the
    pager store, and `WithMaxListOffset(100)` on the plain store.
  - `TestList_OffsetRouting` (table):
    - "jump to a page": `Offset: 100, PageSize: 50` calls `ListUsersFrom(ctx, q, 100)` with
      `q.Limit == 50` and empty `AfterUsername`. The page holds its users, and `Next == ""`;
    - "offset zero with a cursor": `Offset: 0` with a valid cursor calls `ListUsers` with the
      cursor's pair;
    - "offset zero": on both stores, `Offset: 0` calls `ListUsers`, and a full page has a
      non-empty `Next`;
    - "store without support": the plain store with `Offset: 50` gives `ErrConfig`, with
      `ListUsers` at `.Times(0)`;
    - "cursor listing on the same store": the plain store with a cursor returns its page;
    - "oversized result": `ListUsersFrom` returns 51 users for `PageSize: 50`, and the page holds
      50;
    - "store error": `errBoom` matches none of `ErrNotFound`, `ErrAlreadyExists`,
      `ErrStaleUpdate`, `ErrInvalidInput`, `ErrNoActor` or `ErrConfig`.
- [ ] **Step 2: Run** `go test -race -run 'TestList_Offset|TestNewUsers_MaxListOffset' -count=1 ./admin/`.
  Expected: behavioural failures, recorded.
- [ ] **Step 3: Implement** the interfaces above.
- [ ] **Step 4: Run** the focused command, then the service scope. Expected: PASS.
- [ ] **Step 5: Commit** with the message `feat(admin): list users from an offset, bounded, on stores
  that support it`.

### Task 7 (tasks 5.3, 5.4): `Users.Count`, godoc and example

**Files:**
- Modify: `admin/users.go` (`Count`, `List` godoc), `admin/records.go` (`UserPage.Next` and
  `UserFilter.Offset` godoc), `admin/users_options.go` (godoc), `admin/errors.go` (`ErrConfig`
  godoc), `admin/ports.go` (`UserPager` godoc), `admin/doc.go` (paging), `admin/example_test.go`
  (`exampleUserStore` implements `UserPager`)
- Create: `admin/count_test.go`, `admin/example_paging_test.go`

**Interfaces:**
- Consumes: `UserPager` and the filter validation from Task 6.
- Produces: `func (u *Users) Count(ctx context.Context, filter UserFilter) (int64, error)`. It
  validates as `List` does, on a copy of the filter with `PageSize`, `Offset` and `Cursor` zeroed.

- [ ] **Step 1: Write the failing tests** in `admin/count_test.go`.
  - `TestCount` (table):
    - "count beside a page": `Search: "ada", PageSize: 10, Offset: 20, Cursor: "x"` calls
      `CountUsers` once with `Search == "ada"` and empty cursor fields, returning 999;
    - "invalid search": a search of `MaxSearchBytes+1` bytes gives `ErrInvalidInput`, with
      `CountUsers` at `.Times(0)`;
    - "store without support": the plain store gives `ErrConfig`;
    - "negative count": `CountUsers` returns `-1`. The result is 0 with an error matching no
      administration reason;
    - "store error": `errBoom`, matching no administration reason.
  - `ExamplePagingWithCount` in `admin/example_paging_test.go`: over the example store holding 999
    users, list `Offset: 20, PageSize: 10` and count, then print
    `fmt.Printf("%d of %d records shown (page %d of %d)\n", len(page.Users), total, 3, 100)`, with
    `// Output: 10 of 999 records shown (page 3 of 100)`.
- [ ] **Step 2: Run** `go test -race -run 'TestCount|ExamplePagingWithCount' -count=1 ./admin/`.
  Expected: FAIL on the missing behaviour (a stub `Count` returns 0, nil). Record it.
- [ ] **Step 3: Implement** `Count`, and write the godoc for task 5.4, as `tasks.md` lists it:
  defaults, the skip-or-repeat trade-off with the cursor as the consistent choice, offset zero
  carrying `Next` and a non-zero offset not, the count as a separate read, the embedding warning on
  `UserPager`, and `ErrConfig`'s offset and count case.
- [ ] **Step 4: Run** the service scope, `go doc ./admin Users.Count`, `go doc ./admin UserPage` and
  `go vet ./admin`. Expected: PASS, with the godoc shown.
- [ ] **Step 5: Commit** with the message `feat(admin): count the users a filter matches`.

### Task 8 (tasks 6.1, 6.2, 6.3): Stores page by offset and count

**Files:**
- Modify: `test/admin/conformance_users.go` (new `pagerCases`), `test/admin/toystore_test.go`
  (`ListUsersFrom`, `CountUsers`), `internal/pgschema/admin.go`, `internal/pgschema/admin_test.go`,
  `test/sqlstore/admin_test.go` (`TestAdminStatementsMatchSchema`), and the `admin_users.go` of
  `store/sqlstore`, `store/pgxstore` and `store/gormstore`.

**Interfaces:**
- Consumes: `admin.UserPager` (Task 6).
- Produces in `pgschema`:
  - an unexported `adminUserFilter` fragment holding today's `WHERE` filters `$1`–`$5`;
  - `ListAdminUsers`: the same parameters and behaviour, built from the fragment;
  - `ListAdminUsersFrom`: the same columns and order, `LIMIT $6 OFFSET $7`, with no cursor
    comparison;
  - `CountAdminUsers`: `SELECT count(*) FROM scrty_users u WHERE` the fragment, over `$1`–`$5`.
- Each store gains `ListUsersFrom` and `CountUsers`, reusing its listing's argument binding and row
  reading.

- [ ] **Step 1: Write the failing tests.**
  - `pagerCases` runs only when `f.Users()` implements `admin.UserPager`, otherwise
    `t.Skip("admintest: the store does not implement admin.UserPager; offset and count cases skipped")`.
    The cases:
    - "Jump to a page": with 120 matching users, `ListUsersFrom(q{Limit:50}, 100)` equals the third
      cursor page, by identifier and order;
    - "consecutive offsets": offsets 0, 7, 57 and 107 at limit 50 partition the 120 users in order
      (7, then 50, 50 and 13);
    - "Offset past the end": offset 500 gives an empty slice and a nil error;
    - "offset honours filters": search, active, role and attribute each narrow the offset listing
      as they narrow the cursor listing;
    - "Count beside a page": 999 matching users count 999;
    - "Deleted users are not counted": three users matched by a search on their common username
      prefix, one soft-deleted, count 2;
    - "count honours filters": the same four filters.
  - `pgschema`: `TestListAdminUsersUnchanged` asserts that `ListAdminUsers` still binds `$1`–`$8`
    with the cursor comparison.
  - `TestAdminStatementsMatchSchema` gains `ListAdminUsersFrom` and `CountAdminUsers`.
  - The toy store first gets stub `ListUsersFrom` and `CountUsers` returning nothing and zero, so
    the gated cases run rather than skip.
- [ ] **Step 2: Run**
  `(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$/conforming' -count=1 -v ./admin/)`.
  Expected: red with the stubs, then green once the toy store implements the methods. Then the SQL stores'
  packages show the `UserPager` skip message. Record both.
- [ ] **Step 3: Implement** the `pgschema` statements, then each store. For each store, first add
  stubs returning an empty result and zero, and see its cases fail for that reason (the red step).
  Then implement.
- [ ] **Step 4: Run** the store scope, on PostgreSQL 18 and 15. Expected: PASS, including every
  existing listing case and the schema test.
- [ ] **Step 5: Commit** with the message `feat(store): user stores list from an offset and count
  matches`.

### Task 9 (tasks 6.4, 6.5): Every store through the service, and load-bearing cases

**Files:**
- Modify: `test/admin/conformance_users.go`, `test/admin/toystore_test.go` (defects),
  `test/admin/conformance_guard_test.go`.

**Interfaces:**
- Produces, in the `defect` constants:
  - `variantNoUserPager defect = "no-user-pager"`: the toy store hides `UserPager`;
  - `defectOffsetTwice defect = "offset-twice"`: it skips `2*offset`;
  - `defectCountDeleted defect = "count-deleted"`: it counts soft-deleted users;
  - `defectOffsetOrder defect = "offset-order"`: its offset listing orders by identifier only.

- [ ] **Step 1: Write the failing tests.**
  - "Library stores" in `pagerCases`, gated as in Task 8: with 120 users,
    `admin.NewUsers(f.Users())` then `List(Offset: 50, PageSize: 50)` and `Count` give 50 users and
    120.
  - In `TestAdminSuiteIsLoadBearing`: a fixed case where `variantNoUserPager` on part `users`
    passes, with the skip message in its output. In `guards`: `defectOffsetTwice` failing in "Jump
    to a page", `defectCountDeleted` in "Deleted users are not counted", and `defectOffsetOrder` in
    "consecutive offsets".
- [ ] **Step 2: Run**
  `(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$' -count=1 ./admin/)`
  before the defects exist. Expected: the guard cases fail, because the defect changes nothing.
  Record it.
- [ ] **Step 3: Implement** the four defects in the toy store.
- [ ] **Step 4: Run** the same command, then the store scope. Expected: PASS.
- [ ] **Step 5: Commit** with the message `test(admin): offset and count cases run on every store and
  catch broken ones`.

### Task 10 (tasks 7.1): Changelog

**Files:**
- Modify: `CHANGELOG.md`, the existing `## [Unreleased]` and its `### Added`.

- [ ] **Step 1: Write the entry** as `tasks.md` 7.1 lists it. It names the ten identifiers, says that
  consumer stores keep working and opt in through `UsernameUpdater` and `UserPager`, gives the
  embedding warning, and says cursor listing is unchanged. No BREAKING label. Follow the style of
  the current entries.
- [ ] **Step 2:** `grep` the entry for each of the ten identifiers. Expected: all found.
- [ ] **Step 3: Commit** with the message `docs: changelog for admin renames, offset paging and user
  counts`.

### Task 11 (tasks 8.1, 8.2): Final gate (main session only)

- [ ] **Step 1:** Run `make check` and `make spec-check` after the last code edit. The main session
  reads the output. Expected: both green, with the output recorded in the PR.
- [ ] **Step 2:** Dispatch a whole-branch Opus reviewer. It first enumerates how the change fails.
  Then it checks the ten added requirements, the three modified ones and every failure-mode row in
  both tables. Each claimed defect is marked REPRODUCED or UNREPRODUCED. Findings go to a fresh
  dispatch of their lane, followed by a re-run of Step 1.
- [ ] **Step 3:** Tick 8.1 and 8.2 in `tasks.md` (main session), then commit.

## Workflow follow-up

- `/opsx:archive admin-user-rename-and-paging`. Then check that `security-administration` carries
  the ten added and three modified requirements.
- Propose `username-case-folding` and `lockout-by-user-id`.
