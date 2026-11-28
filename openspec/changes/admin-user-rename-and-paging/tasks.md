# Tasks

Every task is test-first. For each one:

1. Write the failing test.
2. Run it with a focused `go test -run '<Name>' -count=1`.
3. Confirm it fails for the intended reason. A compile error is not a red step, and neither is a
   test that was skipped or never compiled.
4. Implement.
5. Re-run the test.

Each task states how completion is verified. Scoped verification follows `test-scope.md`: the changed
packages and their transitive dependents. The full suite runs once, in group 8.

The toy-store conformance tests in `test/admin` carry the build tag `admin_stub`. Without
`-tags admin_stub` they do not compile and a run passes vacuously. The toy store runs the suite only
inside `TestAdminSuiteIsLoadBearing`, through its "a conforming store passes the whole suite" case,
so a toy-store red or green step is that case, run as
`(cd test && go test -tags admin_stub -run '^TestAdminSuiteIsLoadBearing$' -count=1 ./admin/)`.

## 1. Service: rename through `Users.Update` (`admin`)

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

- [ ] 2.1 Add rename cases to the `test/admin` conformance suite. They call `UpdateUserRenaming`, run
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
- [ ] 2.2 Add `pgschema.RenameAdminUser`, which writes the username alone where it differs and
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
- [ ] 2.3 Do the same in `gormstore`. Verify with the 2.1 cases passing in `test/gormstore`, on both
  PostgreSQL versions.
- [ ] 2.4 Pin the field a late unique violation names. Verify with an `adminfix` test on each SQL
  store:
  - a raw transaction inserts a user with username `collide-7f3a` without the advisory locks and
    stays open;
  - a rename to `collide-7f3a` is started, and blocks on the unique index;
  - the raw transaction commits;
  - the rename fails with `AlreadyExistsError{FieldUsername}`, and its text does not contain
    `collide-7f3a`.
- [ ] 2.5 Add the race test "Racing rename" to `test/internal/adminfix`. A barrier releases a
  rename of `ada` to `x@example.com` and an email update of another user to `x@example.com`
  together. Verify that at most one write succeeds on each SQL store, run with `-race`, and that the
  test fails in a scratch copy whose rename skips the advisory lock.
- [ ] 2.6 Add the rename "Library stores" scenario: the toy, `sqlstore`, `pgxstore` and `gormstore`
  stores each apply a rename through `Users.Update`. Verify that it passes on all four.
- [ ] 2.7 Make the rename cases load-bearing in `TestAdminSuiteIsLoadBearing` (D8):
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

- [ ] 3.1 Add the scenario "Consumer opts in" in an untagged test in `test/sqlstore`, over the real
  `sqlstore` identity store, so CI runs it. `ada` is signed in on two devices through
  `*session.Sessions` on its `MemoryStore`, the service is configured with
  `WithSessionRevocation(sessions)`, and `ada` is renamed. Verify that neither session loads
  afterwards, and that it was red with the revoker call disabled in a scratch copy.

## 4. Import after a rename (`test/admin`)

- [ ] 4.1 Add the scenario "Import after a rename", gated on `UsernameUpdater` as the rename cases
  are (D8): rename `ada`, then import her identifier with `ada.lovelace` and otherwise equal values.
  Verify that the import reports unchanged and emits no event, on the toy store and every SQL store.

## 5. Service: offset listing and counting (`admin`)

- [ ] 5.1 Add `UserFilter.Offset`, `DefaultMaxListOffset` (10 000) and `WithMaxListOffset(n)`.
  Validate the offset in the filter-to-query step. Verify with a table test in `admin`, the mocked
  store never called on a refusal:
  - "Negative offset", "Offset and cursor together" and "Offset beyond the maximum" give
    `ErrInvalidInput`;
  - "Offset at the maximum": offset 10 000 reaches the store;
  - "Consumer maximum": with `WithMaxListOffset(50000)`, offset 40 000 reaches the store;
  - "Negative maximum": `WithMaxListOffset(-1)` fails `NewUsers` with `ErrConfig`;
  - `WithMaxListOffset` over a store without `UserPager` fails `NewUsers` with `ErrConfig`;
  - an offset above the maximum on a store without `UserPager` gives `ErrInvalidInput`.
- [ ] 5.2 Add the `UserPager` port. `NewUsers` records whether the store implements it. `List` with a
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
- [ ] 5.3 Add `Users.Count`. It validates search, role and attribute as `List` does, ignores page
  size, offset and cursor, and calls `CountUsers`. Verify:
  - "Count beside a page", service side: a filter carrying a page size, an offset and a cursor is
    counted, and `CountUsers` receives its filters only;
  - an invalid search gives `ErrInvalidInput`, store not called;
  - "Consumer store without support", for a count: `ErrConfig`, store not called;
  - a negative count from the store is refused as an error matching no administration reason;
  - a store error matches no administration reason.
- [ ] 5.4 Write the godoc for `UserFilter.Offset`, `DefaultMaxListOffset`, `WithMaxListOffset`,
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

## 6. Stores page by offset and count (`internal/pgschema`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `test/admin`, `test/sqlstore`)

- [ ] 6.1 Add offset and count cases to the `test/admin` conformance suite, run only when the
  fixture's store implements `admin.UserPager` and skipped with a message naming it otherwise
  (D14). Implement `UserPager` on the toy store. The cases are:
  - "Jump to a page": 120 matching users, page size 50, offset 100 returns exactly the users of the
    third cursor page, in order;
  - consecutive offsets over an unchanged list, including one that is not a multiple of the page
    size, cover every user once, in order;
  - "Offset past the end": an empty result, no error;
  - offset listing honours search, active, role and attribute filters;
  - "Count beside a page": 999 matching users count 999;
  - "Deleted users are not counted": 3 users matched by a username search, one soft-deleted, count
    2 (a username search, because soft deletion clears the email);
  - the count honours the same filters as the listing.

  Give the toy store stub `ListUsersFrom` and `CountUsers` first, returning nothing and zero, so
  the gated cases run. Verify through the toy store's conforming case: red with the stubs, green
  once they are implemented.
  Verify that the SQL stores skip the cases with the message.
- [ ] 6.2 In `pgschema`, split `ListAdminUsers`'s filters into one shared fragment, keeping the
  cursor statement's parameters and behaviour, and add an offset listing statement and a count
  statement built on it. Add both to `TestAdminStatementsMatchSchema`. Implement `UserPager` in
  `sqlstore` and `pgxstore`: first as stubs returning nothing, and see the 6.1 cases go red for that
  reason, then for real. Verify with the 6.1 cases and the existing listing cases passing on both,
  on PostgreSQL 18 and 15.
- [ ] 6.3 Do the same in `gormstore`. Verify with the 6.1 cases passing in `test/gormstore`, on both
  PostgreSQL versions.
- [ ] 6.4 Add the paging "Library stores" scenario: the toy, `sqlstore`, `pgxstore` and `gormstore`
  stores each list from an offset and count through `admin.Users`. Verify that it passes on all
  four.
- [ ] 6.5 Make the offset and count cases load-bearing in `TestAdminSuiteIsLoadBearing` (D14):
  - a variant whose toy store does not implement `UserPager` passes, with the cases skipped
    ("Conformance suite on a store without support");
  - a defect applying the offset twice is caught by "Jump to a page";
  - a defect counting deleted users is caught by "Deleted users are not counted";
  - a defect ordering the offset listing differently from the cursor listing is caught by the
    consecutive-offsets case.

  Verify that each guard case passes, and that each defect was seen to escape before its case
  existed.

## 7. Documentation

- [ ] 7.1 Add to the existing `## [Unreleased]` section of `CHANGELOG.md`, under `### Added`:
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

## 8. Final gate and review

- [ ] 8.1 Run `make check` and `make spec-check` once, after the last code edit, and read the
  output. Verify that both are green, and record the output.
- [ ] 8.2 Run a whole-branch review against every requirement in the `security-administration` delta,
  added and modified, and every row of `design.md`'s failure modes. Verify that each finding is
  fixed, with 8.1 re-run, or recorded as accepted in `design.md`.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify that the archived `security-administration` spec carries the ten added requirements and
  the three modified ones.
- Propose the follow-ups `username-case-folding` and `lockout-by-user-id`.
