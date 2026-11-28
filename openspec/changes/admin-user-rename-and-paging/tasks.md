# Tasks

Every task is test-first. For each one:

1. Write the failing test.
2. Run it with a focused `go test -run '<Name>' -count=1`.
3. Confirm it fails for the intended reason. A compile error is not a red step, and neither is a
   test that was skipped or never compiled.
4. Implement.
5. Re-run the test.

Each task states how completion is verified. Scoped verification follows `test-scope.md`: the changed
packages and their transitive dependents. The full suite runs once, in group 9.

The toy-store conformance tests in `test/admin` carry the build tag `admin_stub`. Without
`-tags admin_stub` they do not compile and a run passes vacuously. The toy store runs the suite only
inside `TestAdminSuiteIsLoadBearing`, through its "a conforming store passes the whole suite" case,
so a toy-store red or green step is that case, run as
`(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$' -count=1 ./admin/)`.

## 1. Service: rename through `Users.Update` (`admin`)

> Done before the 2026-11-28 revision. Its optional `UsernameUpdater` port is folded into
> `UserStore.UpdateUser` by group 6 (design D7 revised, D15).

- [x] 1.1 Add `Username *string` to `admin.UserChange`. Count it in `validateChange`'s "names no
  field" check, and validate it with `exactName` as `Create` does. Verify with a table test in
  `admin`:
  - blank, padded, NUL, other control character, invalid UTF-8 and over-`MaxTextBytes` usernames
    each give `ErrInvalidInput`, with the mocked store never called (spec scenario "Surrounding
    white space");
  - a change naming only a username reaches the store, over a store that implements
    `UsernameUpdater` (spec scenario "Rename", service side).
- [x] 1.2 Add the `UsernameUpdater` port with `UpdateUserRenaming(ctx, id, version, change) (User,
  bool, error)` (D7). `NewUsers` records whether the store implements it. `Update` sends a change
  naming a username to `UpdateUserRenaming`, every other change to `UpdateUser`, and refuses a
  change naming a username with an error matching `ErrConfig`, after validation and before the
  audit read and any store call, when the store does not implement it. Implement it on the package
  example's store (`admin/example_test.go`). Verify, using generated mocks:
  - "Consumer store without support": neither `GetUser` (audit read), `UpdateUser` nor any other
    store method is called;
  - "Other fields on the same store": the update succeeds through `UpdateUser`;
  - a rename on a store with the port calls `UpdateUserRenaming` once and `UpdateUser` never;
  - an invalid username on a store without the port gives `ErrInvalidInput`, not `ErrConfig`.
- [x] 1.3 Report a rename. `changedUserFields` adds `username`, first in the list, the audit sink
  receives the before and after records, a refused rename emits nothing, and no error text contains
  either username. Verify with the scenarios "Rename event" and "Refused rename". The expected
  fields account for `email_verified_at`, which appears when the returned user has no verification
  time.
- [x] 1.4 Add `WithSessionRevocation(SessionRevoker)`, off by default. A nil or typed-nil revoker,
  or any revoker over a store without `UsernameUpdater`, fails `NewUsers` with `ErrConfig`. The
  revoker runs only after a committed update for which the store reported `renamed`. A revoker
  failure returns the updated user together with an error matching `ErrSessionsNotRevoked` and the
  cause, with the event emitted. Verify, with a mockgen `SessionRevoker`:
  - "Default";
  - a rename the store reports as `renamed` calls `DeleteByUser` once;
  - "Current username re-sent": the store reports not `renamed`, and `DeleteByUser` is not called;
  - "No username in the update";
  - "Refused rename revokes nothing";
  - "Revocation fails", asserting the returned user;
  - a context cancelled after the store commits: the error matches `ErrSessionsNotRevoked` and the
    context's error (a wrapping check: the revoker runs on the caller's context, D6);
  - "Nil revoker", including the typed-nil case;
  - "Revoker with a store that cannot rename".
- [x] 1.5 Write the godoc for `UserChange.Username`, `UsernameUpdater`, `WithSessionRevocation`,
  `SessionRevoker`, `ErrSessionsNotRevoked` and `ErrConfig`. It names:
  - the default for each;
  - the accepted lockout behaviour (D5): counts age out, a hold never expires, and an administrator
    calls the lockout policy's `Reset` on the old username;
  - that the standalone `JWTAuthenticator` in username-subject mode keeps accepting old-username
    tokens until they expire;
  - that `UserStore.UpdateUser` never receives a username, and `ErrConfig`'s call-time rename case
    (D7);
  - that a consumer store embedding a scrty store and overriding `UpdateUser` must override
    `UpdateUserRenaming` too;
  - that `Update` returns the renamed user alongside `ErrSessionsNotRevoked`;
  - that the revoker runs when the store returns, so a caller that wraps updates in its own
    transaction revokes sessions after its own commit instead of using the option;
  - that callers on a store without `UsernameUpdater` leave `Username` nil unless it changed;
  - how a consumer revokes sessions with `*session.Sessions`.

  Add an `Example` test that wires `*session.Sessions` as the revoker. Verify that the example
  passes, that `go doc ./admin` shows the docs, and that `go vet ./admin` is clean.

## 2. Stores apply the username (`internal/pgschema`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `test/admin`, `test/internal/adminfix`, `test/sqlstore`)

> Done before the 2026-11-28 revision; group 6 retargets its tests at `UserStore.UpdateUser` and
> removes their `UsernameUpdater` gate (design D7, D8 revised, D15).

- [x] 2.1 Add rename cases to the `test/admin` conformance suite. They call `UpdateUserRenaming`, run
  only when the fixture's store implements `UsernameUpdater`, and are skipped with a message naming
  it otherwise (D8). Implement `UpdateUserRenaming` on the toy store. The cases are:
  - "Rename", asserting `renamed` is true;
  - "Username held by a deleted user";
  - "Username equal to another user's email";
  - "Only the case changes", asserting `renamed` is true;
  - "Stale rename";
  - "Username follows a new email";
  - "One field clashes";
  - rename to one's own email in the same change;
  - username and email of one user equal ignoring case in the same change;
  - renaming to the current username: still a write that increases the version, with `renamed`
    false;
  - rename between Unicode normalisation forms (NFC to NFD), stored as given, `renamed` true.

  Give the toy store a stub `UpdateUserRenaming` first, which changes nothing and reports
  `renamed` false, so the gated cases run (the conforming case passes on skipped cases, so a store
  without the method cannot show red). Verify through the toy store's conforming case (see the
  note above): red with the stub, green once the toy store applies the field. Verify that the SQL stores, which do not implement the port yet,
  skip the cases with the message.
- [x] 2.2 Add `pgschema.RenameAdminUser`, which writes the username alone where it differs and
  reports the change through rows affected (D2), and add it to `TestAdminStatementsMatchSchema`. Then
  in `sqlstore` and `pgxstore`, implement `UpdateUserRenaming`: first as a stub that changes nothing,
  and see the 2.1 cases go red on the unchanged username; then for real, in one transaction under
  the row lock:
  - take the identifier locks for the named username and email with one `checkIdentifiers` call;
  - check `UsernameTaken`, `EmailHeldByLiveUser` and `UsernameHeldByLiveUser`, excluding the user
    being written;
  - run `RenameAdminUser`, mapping a unique violation to `FieldUsername` and one affected row to
    `renamed`;
  - run the other fields through `UpdateAdminUserQuery`, mapping a unique violation to `FieldEmail`.

  Verify with the 2.1 cases passing on both, on PostgreSQL 18 and on 15
  (`SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`).
- [x] 2.3 Do the same in `gormstore`. Verify with the 2.1 cases passing in `test/gormstore`, on both
  PostgreSQL versions.
- [x] 2.4 Pin the field a late unique violation names. Verify with an `adminfix` test on each SQL
  store:
  - a raw transaction inserts a user with username `collide-7f3a` without the advisory locks and
    stays open;
  - a rename to `collide-7f3a` is started, and blocks on the unique index;
  - the raw transaction commits;
  - the rename fails with `AlreadyExistsError{FieldUsername}`, and its text does not contain
    `collide-7f3a`.
- [x] 2.5 Add the race test "Racing rename" to `test/internal/adminfix`. A barrier releases a
  rename of `ada` to `x@example.com` and an email update of another user to `x@example.com`
  together. Verify that at most one write succeeds on each SQL store, run with `-race`, and that the
  test fails in a scratch copy whose rename skips the advisory lock.
- [x] 2.6 Add the rename "Library stores" scenario: the toy, `sqlstore`, `pgxstore` and `gormstore`
  stores each apply a rename through `Users.Update`. Verify that it passes on all four.
- [x] 2.7 Make the rename cases load-bearing in `TestAdminSuiteIsLoadBearing` (D8):
  - a variant whose toy store does not implement `UsernameUpdater` passes, with the rename cases
    skipped ("Conformance suite on a store without rename support");
  - a defect whose `UpdateUserRenaming` ignores the username is caught by "Rename" ("Conformance
    suite on a store that claims but ignores renames");
  - a defect that skips the username clash checks is caught by "Username held by a deleted user"
    and "Username equal to another user's email";
  - a defect that always reports `renamed` as false is caught by "Rename".

  Verify that each guard case passes, and that each defect was seen to escape before its case
  existed.

## 3. Sessions end on rename when opted in (`test/sqlstore`)

> Done before the 2026-11-28 revision; group 6 retargets its tests at `UserStore.UpdateUser` and
> removes their `UsernameUpdater` gate (design D7, D8 revised, D15).

- [x] 3.1 Add the scenario "Consumer opts in" in an untagged test in `test/sqlstore`, over the real
  `sqlstore` identity store, so CI runs it. `ada` is signed in on two devices through
  `*session.Sessions` on its `MemoryStore`, the service is configured with
  `WithSessionRevocation(sessions)`, and `ada` is renamed. Verify that neither session loads
  afterwards, and that it was red with the revoker call disabled in a scratch copy.

## 4. Import after a rename (`test/admin`)

> Done before the 2026-11-28 revision; group 6 retargets its tests at `UserStore.UpdateUser` and
> removes their `UsernameUpdater` gate (design D7, D8 revised, D15).

- [x] 4.1 Add the scenario "Import after a rename", gated on `UsernameUpdater` as the rename cases
  are (D8): rename `ada`, then import her identifier with `ada.lovelace` and every other value equal to what is stored for her.
  Verify that the import reports unchanged and emits no event, on the toy store and every SQL store.

## 5. Service: offset listing and counting (`admin`)

> Done before the 2026-11-28 revision. Its optional `UserPager` port is folded into `UserStore` by
> group 6 (design D12 revised, D15).

- [x] 5.1 Add `UserFilter.Offset`, `DefaultMaxListOffset` (10 000) and `WithMaxListOffset(n)`.
  Validate the offset in the filter-to-query step. Verify with a table test in `admin`, the mocked
  store never called on a refusal:
  - "Negative offset", "Offset and cursor together" and "Offset beyond the maximum" give
    `ErrInvalidInput`;
  - "Offset at the maximum": offset 10 000 reaches the store;
  - "Consumer maximum": with `WithMaxListOffset(50000)`, offset 40 000 reaches the store;
  - "Negative maximum": `WithMaxListOffset(-1)` fails `NewUsers` with `ErrConfig`;
  - `WithMaxListOffset` over a store without `UserPager` fails `NewUsers` with `ErrConfig`;
  - an offset above the maximum on a store without `UserPager` gives `ErrInvalidInput`.
- [x] 5.2 Add the `UserPager` port. `NewUsers` records whether the store implements it. `List` with a
  non-zero offset calls `ListUsersFrom` and returns a page with an empty `Next`. Offset zero calls
  `ListUsers` and returns its `Next` as today. Verify with the generated mocks:
  - "Jump to a page", service side: `ListUsersFrom` receives the offset and the validated query, and
    `Next` is empty;
  - offset zero with a cursor continues the cursor listing through `ListUsers`;
  - "Offset zero": `ListUsers` is called, and a full page carries `Next`, on stores with and without
    `UserPager`;
  - "Consumer store without support", for a listing: `ErrConfig`, neither list method called;
  - "Cursor listing on the same store": the page is returned as before;
  - a `ListUsersFrom` that returns more than the page size is truncated to it, as `ListUsers` is;
  - a store error from `ListUsersFrom` matches no administration reason.
- [x] 5.3 Add `Users.Count`. It validates search, role and attribute as `List` does, ignores page
  size, offset and cursor, and calls `CountUsers`. Verify:
  - "Count beside a page", service side: a filter carrying a page size, an offset and a cursor is
    counted, and `CountUsers` receives its filters only;
  - an invalid search gives `ErrInvalidInput`, store not called;
  - "Consumer store without support", for a count: `ErrConfig`, store not called;
  - a negative count from the store is refused as an error matching no administration reason;
  - a store error matches no administration reason.
- [x] 5.4 Write the godoc for `UserFilter.Offset`, `DefaultMaxListOffset`, `WithMaxListOffset`,
  `Users.Count` and `UserPager`, rewrite the godoc of `Users.List` and `UserPage.Next` for offset
  mode, and extend `ErrConfig`'s with the call-time offset and count case (D12). It names:
  - the defaults;
  - the skip-or-repeat trade-off of offset paging, with the cursor as the consistent choice;
  - that offset zero is the first page and carries `Next`, while a page from a non-zero offset
    does not;
  - that a count and a page are separate reads;
  - that a consumer store embedding a scrty store and overriding `ListUsers` must override
    `ListUsersFrom` and `CountUsers` too.

  Add an `Example` that lists page 3 with a count and prints "10 of 999"-style text; the package
  example's store implements `UserPager`. Verify that the example passes, `go doc ./admin` shows the
  docs, and `go vet ./admin` is clean.

## 6. Fold the admin ports into `UserStore` (`admin`, `internal/pgschema`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `test/admin`, `test/internal/adminfix`, `test/sqlstore`)

The stores' offset and count code from the pre-revision work is already on the branch behind the
optional `UserPager` port (commit `8445f0dd`: the shared filter fragment, store methods, gated
conformance cases and their defects); these tasks move it, and the rename, onto `UserStore`.

- [x] 6.1 Fold renames into `UserStore.UpdateUser` (D7). `UpdateUser` takes a change that may name a
  username and returns `(User, renamed bool, error)`. Remove `UsernameUpdater`, `UpdateUserRenaming`,
  the `renamer` field, the call-time `ErrConfig` refusal, and `NewUsers`'s check of a revoker against
  the store. Every scrty store, the toy store and the package example's store implement the one
  method, sharing the existing helpers; every caller of `UpdateUser` follows (including
  `test/gormstore/admin_store_test.go`). The rename cases, the
  `adminfix` tests and "Import after a rename" call `UpdateUser` and run for every store: remove
  `renameSkip`, `variantNoUsernameUpdater` and its guard case. Regenerate the `admin` mocks and delete
  the `UsernameUpdater` mock. Verify:
  - a test that a change naming no username reports `renamed` false on every store, written first
    and seen red against a store stub that reports true;
  - a toy-store defect that always reports `renamed` true, with a guard row that expects "No
    username in the update" and "Same username again" to fail, so the over-reporting direction is
    load-bearing as the under-reporting one is;
  - a service test that a store reporting `renamed` for a change naming no username does not reach
    the revoker: `Update` revokes only when the change names a username and the store reports a
    rename, seen red against today's `Update`;
  - every existing rename, revocation, conformance, race and load-bearing test passes, retargeted
    at `UpdateUser`, on PostgreSQL 18 and 15;
  - the godoc of `UserStore.UpdateUser`, `UserChange.Username`, `WithSessionRevocation` and
    `ErrConfig` no longer mentions an optional port or a call-time refusal.
- [ ] 6.2 Fold offset and count into `UserStore` (D12, D13). `UserQuery` gains `Offset`, honoured by
  `ListUsers`; `UserStore` gains `CountUsers`. Each store's `ListUsers` refuses a negative offset, and
  a non-zero offset together with a cursor, with `ErrInvalidInput`, as `ListUsersFrom` did. Remove
  `UserPager`, `ListUsersFrom`, the `pager` field,
  the call-time `ErrConfig` refusals in `List` and `Count`, and `NewUsers`'s check of
  `WithMaxListOffset` against the store. In `pgschema`, one listing statement serves both modes (the
  cursor comparison plus `OFFSET`), built on the shared filter fragment, and `ListAdminUsersFrom` is
  removed; `TestListAdminUsersUnchanged` and `TestAdminStatementsMatchSchema` follow. Verify:
  - a service test that a non-zero offset reaches `ListUsers` with `Offset` set and no cursor
    fields, written first and seen red;
  - a store test, on each SQL store and the toy, that one statement answers a cursor page and an
    offset page in the same order, seen red against a store that ignores `Offset`;
  - a conformance case "Offset zero with a cursor equals the cursor page", and the conformance case
    "Store asked for a negative offset" (spec), each on every store;
  - every existing offset, count and listing test passes on PostgreSQL 18 and 15.
- [ ] 6.3 Run the offset and count conformance cases for every store (D14): remove `pagerSkip`,
  `variantNoUserPager`, `toyUsersWithoutPager` and its guard case. Keep the defects (offset applied
  twice, count including deleted users, offset listing in another order), each caught by its named
  case, and the paging "Library stores" case through `admin.Users`. Verify that each guard passes
  and that `TestAdminSuiteIsLoadBearing` lists no skip.

## 7. Documentation

> 7.1 was done before the 2026-11-28 revision; 7.2 rewrites its entry.

- [x] 7.1 Add to the existing `## [Unreleased]` section of `CHANGELOG.md`, under `### Added`:
  `UserChange.Username`, `UsernameUpdater`, `WithSessionRevocation`, `SessionRevoker`,
  `ErrSessionsNotRevoked`, `UserFilter.Offset`, `Users.Count`, `UserPager`, `WithMaxListOffset` and
  `DefaultMaxListOffset`. Say that:
  - consumer stores keep working unchanged, and opt into renames, offsets and counts by
    implementing `UsernameUpdater` and `UserPager`; until then those calls are `ErrConfig` and the
    conformance suite skips their cases;
  - a consumer store that embeds a scrty store and overrides `UpdateUser` or `ListUsers` must
    override the matching new methods too;
  - cursor listing is unchanged.

  Verify that the entry names each exported identifier, and that `make check`'s changelog checks
  pass, if any exist.

- [ ] 7.2 Rewrite the 7.1 entry for the revised design: drop "consumer stores keep working" and the
  opt-in wording, and name `UserStore.UpdateUser`'s `renamed` result, `UserQuery.Offset` and
  `UserStore.CountUsers` instead of `UsernameUpdater` and `UserPager`. Add a `### BREAKING` subsection
  to `## [Unreleased]` naming every port folded by D15, its base interface, and the methods a
  consumer implementation adds (with `lockout.Store` as the new type `lockout.New` takes), and every
  removed API (`Sessions.SelectsRoles`, `storetest.RequireDeviceProof`, `RunDeviceProofSuite`,
  `DeviceProofEnrolmentStore`), and the reset's new refusal when an MFA method does not remove. Update the `README.md` passages that describe a folded port as
  optional. Verify that each folded port and removed API is named, and that no passage still calls a
  folded port optional (`rg` over `README.md`, `CHANGELOG.md`'s Unreleased section and every godoc).

## 8. Fold the library's compatibility-only ports (D15)

Each task removes the port's type assertions, fallbacks, construction or call-time refusals,
forwarding wrappers, conformance skips and "absent" tests, and regenerates the affected mocks. Most
folds change no behaviour for any implementation that compiles before and after: they are mechanical
changes covered by existing tests (`golang-tdd.md`), and the spec scenario each one rewrites is
pinned by a test written with the fold, not claimed as a red step. Where behaviour does change, the
task names the test written first and seen red. Every task verifies its packages and their transitive
dependents in every workspace module (`test-scope.md`).

- [ ] 8.1 Sessions: `FamilyReader` and `RoleSelector` into `session.Store`. Remove `readFamily`'s
  listing fallback, `roleSelectingEncryptedStore` (the encrypted store gains `SelectRole`, keeping its
  fixed error text and sanitised cause), the inner fallback in `encryptedStore.ListByFamily`,
  `Sessions.SelectsRoles` and the refusals that consulted it in `session` and `httpsec`. The
  `storetest` family-read and role cases always run. Red first: the `oidcprovider` session wrappers
  that embed `session.Store` answer a family read through the inner store's `ListByFamily`, not its
  listing (spec scenario "A store that can only list"). Also tested: the encrypted store's
  `ListByFamily` reads no sealed field and returns no envelope, and its `SelectRole` error keeps its fixed text.
- [x] 8.2 OIDC links: `LinkLister` and `LinkRemover` into `oidc.LinkStore`. Remove the broker's
  construction refusal, `canRecheckFresh`, `errNoLinkLister`, `errNoLinkRemover` and the freshness
  skip, and the link store suite's skips. Pinned: a sign-in hook over a consumer link store, several
  links per user not allowed, builds and lists through that store (spec scenario "Link store that
  cannot list").
- [ ] 8.3 MFA device proofs: `DeviceProofStore` into `mfa.EnrolmentStore`. Fold
  `provingEnrolmentStore` into the one sealed store in `store/seal`, keeping the sealing of the
  emailed code a proof records; remove `errNoDeviceProofStore` and the proof-store refusal. Fold
  `storetest.RequireDeviceProof`, `RunDeviceProofSuite`, `DeviceProofEnrolmentStore` and the proof
  `optionalCase`s into the MFA store suite. `SupportsEnrolmentPath` stays (D15); TOTP reports it
  whatever its store. Pinned: the enrolment interceptor over a sealed consumer enrolment store
  assembles and completes an enrolment (spec scenario "Store that cannot record a device proof"),
  and the sealed store's recorded emailed code is sealed at rest.
- [ ] 8.4 MFA enrolment removal: `EnrolmentRemover` into `mfa.Method`; `mfa.ResetDeps.Enrolments`
  takes `[]mfa.Method`. Remove the recovery kind's construction refusal and its `removers` map. After
  removing, the kind reads the user's enrolments again and fails the reset when the method still
  holds one. Red first: a consumer method whose `RemoveEnrolment` reports success without removing
  makes the reset return an error (spec scenario "Method that does not remove"). Pinned: the kind
  over a consumer method resets through that method (spec scenario "Method without a remover").
- [ ] 8.5 Rate limiting: `RecentFailureReporter` and `PolicyReporter` into `ratelimit.Limiter`.
  `internal/unavailable.Wrap` gains the limit and window as fields and answers `Policy()` from them;
  its backend type stays narrow. Remove the guard's "cannot report" branch (an answer that fails still
  counts as recent failures), the chain's warning and refusal for a limiter without a policy, and
  `limiterWindow`'s zero fallback. Add `test/ratelimittest` cases for `Policy` and
  `HasRecentFailures` on every limiter. Red first: the shared limiter reports its built limit and
  window while its backend is down (spec scenario "Shared limiter with its backend down"), seen red
  against a `Policy()` stub that returns zero. Pinned: an explicit /48 aggregate with a multiplier of
  2 over a consumer limiter reporting 50 per minute allows 100 per minute; the default aggregate over
  a consumer limiter is built from its reported policy; a limiter whose recent-failures answer fails
  is reported to the verifier as having failures.
- [ ] 8.6 Password encoders: `Recognizer` and `Upgrader` embedded in `password.Encoder`, kept as named
  interfaces for `admin.NewImporter`. Remove the "recognises every non-empty hash" and "never needs
  an upgrade" fallbacks. Pinned: a consumer encoder that reports it does not recognise a stored hash
  makes the login cost one reference verification and fail (spec scenario "Consumer encoder that does
  not recognise a hash").
- [ ] 8.7 Lockout streaks: `FailureStreakStore` into a new `lockout.Store`, which embeds
  `policy.AttemptStore`; `lockout.New` takes it. `policy.AttemptStore`, the attempt view and
  `lockout.FailureStreak` are unchanged. Remove the cap's construction refusal and the `streaks`
  field; the streak calls stay gated on a cap being set. First, a regression guard: a policy without a
  cap, over a mock store with no streak expectations, records failures and resets without calling a
  streak method. Pinned: a cap over a consumer store is enforced from that store's streaks (spec
  scenario "Store without consecutive counts").
- [ ] 8.8 OpenID provider: `PendingRequestCounter` into `oidcprovider.PendingRequestStore`. Remove the
  ceiling's construction refusal and `errNoCounter`. Pinned: a ceiling over a consumer pending-request
  store is enforced from its count (spec scenario "Store cannot count").
- [ ] 8.9 Recovery: `UsableLister` into `recovery.AuthenticatorKind`. Remove the `usable` helper's
  fallback to `Held`. Pinned: a consumer kind that holds one authenticator and reports none usable
  makes the "another way back in" check report no (spec scenario "Consumer kind reports only usable
  authenticators").
- [ ] 8.10 Sweep: no type assertion, skip message or `optionalCase` remains for a folded port (`rg`
  for each port name and `go vet ./...` across every module), and the mocks regenerate with no diff
  (`go generate` over the touched packages). A diff goes back to the lane that owns the package.

## 9. Final gate and review

- [ ] 9.1 Run `make check` and `make spec-check` once, after the last code edit, and read the
  output. Verify that both are green, and record the output.
- [ ] 9.2 Run a whole-branch review against every requirement in every spec delta of this change,
  added and modified, and every row of `design.md`'s failure modes. Verify that each finding is
  fixed, with 9.1 re-run, or recorded as accepted in `design.md`.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify that the archived `security-administration` spec carries the ten added requirements and
  the three modified ones, and that the thirteen other capabilities carry their modified requirements.
- Propose the follow-ups `username-case-folding` and `lockout-by-user-id`.
- Explore sharing the logic the three SQL stores each write out (`/opsx:explore`).
