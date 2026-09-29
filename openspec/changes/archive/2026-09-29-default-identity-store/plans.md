# Default Identity Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an optional PostgreSQL implementation of scrty's four identity ports and the new password-history port, in three adapters, proven by the identity ports' one public conformance suite, plus a password reuse guard and a named password-changed-at field.

**Architecture:** The identity model gains one named field (`FieldPasswordChangedAt`) and a local-change option naming hash and time together. The `password` package gains a `History` port, a `ReuseGuard` keyed by the user's loaded record that hands its write the change time, and `ProvisionerWrite`, a ready-made write over any provisioner. The consumer calls the guard from their own change function. A new migration set (`migrate.Identity()`) creates seven tables with no foreign keys. `sqlstore`, `pgx` and `gorm` each gain `NewIdentityStore`, sharing SQL text through `internal/pgschema`. The existing suite in `test/identity` is extended and every adapter runs it. `httpsec` gains one status row.

**Tech Stack:** Go 1.27, `database/sql`, pgx v5, gorm, goose-format SQL, testify and mockgen (tests only), testcontainers PostgreSQL through `test.RunTestPostgres`.

**Spec:** `openspec/changes/default-identity-store/` — `proposal.md`, `design.md` (Decisions 1–12), `specs/{default-identity-store,identity-model,password-encoding,http-error-propagation,http-security-chain}/spec.md`, `tasks.md`. Task numbers below (`1.1`, `5.3`) are `tasks.md` numbers; every plan task maps to one, and no plan task exists without one.

## Global Constraints

- Test-first for every task (`.claude/rules/golang-tdd.md`): write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, re-run, refactor. Record the red output in the dispatch report.
- Table tests follow the project `table-test` skill (the `assert` closure form, `t.Context()`); doubles come from `use-mockgen`; PostgreSQL comes from `test.RunTestPostgres` (`use-testcontainers`), never a hand-rolled fake.
- The core module gains no third-party dependency and no PostgreSQL driver, not even from a `_test.go` file. PostgreSQL tests of `sqlstore` live in the `test` module.
- No other scrty module imports `github.com/kartaladev/scrty/test`.
- Every default is documented in godoc and replaceable; a wiring mistake is a construction error wrapping the package's `ErrConfig`, naming the mistake and never a value (`.claude/rules/library-design.md`).
- Error text never contains a username, a password, a hash or a user reference.
- No code, tests, comments or wording copied from or citing the established design, as the project's rules require.
- A defect claim needs a failing test or an `UNREPRODUCED` label (`.claude/rules/defect-claims.md`).
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit anything under `openspec/`.
- `request-input-and-log-flush`, which held several `httpsec`, `fibersec`, `oidc` and `policy` files, is pushed and archived (`origin/main` 6e1525d). No file is held by another change.

## Review Focus

1. **A mirrored password during federated login** (the `oidc` mirror update and just-in-time provisioning, which name only the password) must never move the password-changed-at time. It is pinned in Task 1.4 at the source, Task 2.1's "unnamed password write" case, and Task 5.2's PostgreSQL run of it. A reviewer should confirm no adapter adds the column whenever `FieldPassword` is set, and that the oidc paths never use `WithUserPasswordChange`.
2. **A caller's transaction after a failed provision** must stay usable (PostgreSQL aborts a transaction on any failed statement). It is pinned in Task 2.5 and run per adapter in 5.3, 6.1 and 7.1. Reviewers check that every statement of Provision, Update and RetirePassword inside an ambient transaction runs under a savepoint.
3. **A user reference that is not a UUID** reaching the MFA lookup or history read must be user-not-found (lookup) or an error (history), never "not required" or an empty history. It is pinned in Task 5.1 and 5.5 tables.
4. **Stored duplicate grants under a consumer generator that sorts backwards** must keep the first *given* grant. It is pinned in Task 5.2 with a descending generator; reviewers check that grant order is by `position`, never `id`.
5. **Password-history pruning when N shrinks** must bound a user to the new N−1 on their next change, and never restore pruned rows when N grows. It is pinned in Task 3.3 (guard) and Task 5.5 (store: retire with a smaller `keep` after a larger one).

---

## Lanes and dispatch order

| Lane | Tasks | Files owned | Model | Runs after |
|---|---|---|---|---|
| A: identity field + suite | 1.1–1.4, 2.1–2.6 | `identity/ports.go`, `identity/*_test.go`, `oidc/password_changed_at_test.go` (new; no other `oidc` file), `test/identity/*` | Opus (public contract every adapter compiles against) | — |
| B: password guard | 3.1–3.4, 3.6 | `password/history.go`, `password/reuse.go`, `password/provisionerwrite.go`, `password/*reuse*_test.go`, `password/provisionerwrite_test.go`, `password/*_mock_test.go` | Opus (security-critical refusal logic, fail-closed order) | A1 (needs `WithUserPasswordChange` for 3.6) |
| B2: history suite | 3.5 | `test/identity/history*.go` | Sonnet (well-specified suite over a stated port) | A and B |
| C: migrations + SQL | 4.1–4.2 | `migrate/migrate.go`, `migrate/identity/*.sql`, `migrate/migrate_test.go`, `internal/pgschema/identity.go`, `test/migrate_identity_test.go` | Sonnet (schema written out in the design) | — (parallel with A, B) |
| D: sqlstore | 5.1–5.3, then 5.4–5.6 | `sqlstore/identity*.go`, `sqlstore/options.go` (godoc only), `test/sqlstore/identity*_test.go` | Opus (row locks, savepoints, races) | A, B2, C |
| E: pgx | 6.1–6.2 | `pgx/identity*.go`, `test/pgxstore/identity*_test.go` | Opus | D |
| F: gorm | 7.1–7.2 | `gorm/identity*.go`, `gorm/models.go` (identity models appended), `test/gormstore/identity*_test.go` | Opus | D (parallel with E) |
| G: HTTP | 8.1–8.2 | `httpsec/status.go`, `httpsec/status_test.go`, `httpsec/passwordchange_test.go` | Sonnet (one table row, two scenario tests) | B |
| H: docs + gate | 9.1–9.2 | godoc in files of lanes B–F | Sonnet for 9.1; the main session runs 9.2 | all |

Lane A is ten tasks, so it runs as two sequential dispatches: A1 = 1.1–1.4 and 2.1; A2 = 2.2–2.6. Lane B starts once A1 is verified, running in parallel with A2 and C. Lane D runs as D1 = 5.1–5.3 and D2 = 5.4–5.6. Each dispatch is followed by the main session's verification and a fresh reviewer (`subagent-delegation.md`).

Callers of the changed definitions: adding `FieldPasswordChangedAt` before `fieldCount` changes no caller. Removing `Fixture.SeedPasswordChangedAt` affects only `test/identity/inmem.go` and `test/identity/conformance_guard_test.go` (confirm with `gopls references` before dispatch A1), and both are in lane A.

---

### Task 1.1: `FieldPasswordChangedAt` and `WithUserPasswordChangedAt`

**Files:**
- Modify: `identity/ports.go` (the `Field` constants, `NewUser`, the options)
- Test: `identity/ports_test.go` (create it if absent; otherwise add to the existing options test)

**Interfaces:**
- Produces: `const FieldPasswordChangedAt Field` (declared after `FieldPassword`, before `fieldCount`); `NewUser.PasswordChangedAt time.Time`; `func WithUserPasswordChangedAt(t time.Time) UserOption`; `func WithUserPasswordChange(hash []byte, at time.Time) UserOption`, which names `FieldPassword` and `FieldPasswordChangedAt`.

- [ ] **Step 1: Write the failing test**

```go
func TestWithUserPasswordChangedAt_NamesTheField(t *testing.T) {
	t.Parallel()

	at := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		opts   []identity.UserOption
		assert func(t *testing.T, u *identity.NewUser)
	}{
		{
			name: "named time is set and carried",
			opts: []identity.UserOption{identity.WithUserPasswordChangedAt(at)},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldPasswordChangedAt))
				assert.Equal(t, at, u.PasswordChangedAt)
			},
		},
		{
			name: "zero time still names the field, a request to clear it",
			opts: []identity.UserOption{identity.WithUserPasswordChangedAt(time.Time{})},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldPasswordChangedAt))
				assert.True(t, u.PasswordChangedAt.IsZero())
			},
		},
		{
			name: "local-change option names the password and the time",
			opts: []identity.UserOption{identity.WithUserPasswordChange([]byte("h"), at)},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldPassword))
				assert.True(t, u.IsSet(identity.FieldPasswordChangedAt))
				assert.Equal(t, []byte("h"), u.Password)
				assert.Equal(t, at, u.PasswordChangedAt)
				assert.False(t, u.IsSet(identity.FieldName))
			},
		},
		{
			name: "password named alone does not name the time",
			opts: []identity.UserOption{identity.WithUserPassword([]byte("h"))},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.False(t, u.IsSet(identity.FieldPasswordChangedAt))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.assert(t, identity.ApplyUserOptions(tt.opts...))
		})
	}
}
```

`identity.ApplyUserOptions` already exists (the `oidc` mirror uses it).

- [ ] **Step 2: Run it and confirm the red step.** First add only the constant, the field and stubs of both options that return `func(*NewUser) {}`, so the test compiles. Run `go test -run TestWithUserPasswordChangedAt -count=1 ./identity/`. Expected: FAIL on `IsSet(FieldPasswordChangedAt)` being false.
- [ ] **Step 3: Implement**

```go
// WithUserPasswordChangedAt names when the password was last changed.
//
// Name it on a local password change, together with WithUserPassword, and the
// store records the rotation that password-age policy reads. Leave it unnamed
// when the password is mirrored from an identity provider: a password named
// alone never moves the stored time, so a mirror written on every federated
// login cannot keep a user permanently fresh. Naming the zero time clears it.
func WithUserPasswordChangedAt(t time.Time) UserOption {
	return func(u *NewUser) { u.PasswordChangedAt = t; u.mark(FieldPasswordChangedAt) }
}

// WithUserPasswordChange names a local password change: the already-hashed
// password and when it changed, together.
//
// Use it wherever the user changed their own password, or an administrator
// reset it; password.ProvisionerWrite uses it for the reuse guard. A password
// mirrored from an identity provider is named with WithUserPassword alone, so
// it never moves the time.
func WithUserPasswordChange(hash []byte, at time.Time) UserOption {
	return func(u *NewUser) {
		WithUserPassword(hash)(u)
		WithUserPasswordChangedAt(at)(u)
	}
}
```

Also add to the `WithUserPassword` godoc: "Named alone, it leaves the stored password-changed time as it was. That is right for a mirrored password, and wrong for a local change: use WithUserPasswordChange there, or the user is never challenged by password-age policy."


- [ ] **Step 4: Run** `go test -count=1 ./identity/` and `go vet ./identity/`. Expected: PASS.

### Task 1.2: The identity-model contract in godoc

**Files:** Modify `identity/ports.go` (the `UserProvisioner.Provision` and `Update` comments) and `identity/details.go` or wherever `Details.PasswordChangedAt` is declared (find it with `gopls` definition).

- [ ] **Step 1:** Replace "never changes PasswordChangedAt, including when the password is written" in `Update`, and "Neither Provision nor Update moves it" on `Details.PasswordChangedAt`, with the modified contract. The time is written only when the caller names it, with `WithUserPasswordChange` for a local change, or `WithUserPasswordChangedAt` to set or clear it alone. A password named alone leaves it as stored (on Provision: zero). Naming zero clears it. Add one example to the `Update` comment:

```go
//	// a local change records itself; a mirror names only the hash
//	store.Update(ctx, username, identity.WithUserPasswordChange(hash, now))
```

- [ ] **Step 2:** Run `go doc ./identity UserProvisioner`, `go doc ./identity Details` and `go vet ./identity/`. Expected: the new text, and no vet findings. This is a documentation step, so it has no red step.

### Task 1.4: Federated login never names the time

**Files:** Create `oidc/password_changed_at_test.go`. Touch no other `oidc` file: `broker.go`, `manager.go` and `handoff.go` are held by the other change.

**Interfaces:**
- Consumes: `identity.FieldPasswordChangedAt` (Task 1.1). Read how the existing `oidc` tests build a `Broker` with a mapped password claim and mirroring on (find the constructor options with `gopls` references to `mappedUserOptions`' configuration), and reuse those test helpers.

- [ ] **Step 1: Write the test.** A recording `identity.UserProvisioner` (a mockgen mock with `DoAndReturn` capturing `identity.ApplyUserOptions(opts...)`) records every `NewUser` it receives. Two table rows:
  - **mirror:** a linked login whose mapped bcrypt password claim differs from the stored hash. Assert `Update` was called, `IsSet(FieldPassword)` is true and `IsSet(FieldPasswordChangedAt)` is false;
  - **just-in-time provisioning** with a mapped password claim: the same assertions on `Provision`.
- [ ] **Step 2: See red.** Temporarily change the password row of `mirroredFields` in `oidc/mirror.go` to `identity.WithUserPasswordChange(u.Password, time.Now())` on your working copy. The mirror row FAILs on `IsSet(FieldPasswordChangedAt)`. Record the output, then edit the line back by hand (never `git checkout`/`restore`). `mirror.go` is not held by the other change, but the edit must not survive.
- [ ] **Step 3: Run** `go test -count=1 -run TestFederatedLoginNeverNamesPasswordChangedAt ./oidc/`. Expected: PASS, and `git diff oidc/mirror.go` is empty.

### Task 1.3 + 2.1: In-memory store honours the named time; suite checks it through the ports

**Files:**
- Modify: `test/identity/conformance.go` (remove `SeedPasswordChangedAt` from `Fixture`; replace the cases that used it)
- Modify: `test/identity/inmem.go` (drop the seed method; write the time only when `IsSet(FieldPasswordChangedAt)`)
- Modify: `test/identity/conformance_guard_test.go` (defects)

**Interfaces:**
- Consumes: `identity.WithUserPasswordChangedAt`, `identity.FieldPasswordChangedAt` (Task 1.1).
- Produces: `Fixture` without `SeedPasswordChangedAt`. The existing `defectProvisionStampsChangedAt` and `defectUpdateStampsChangedAt` are retargeted to "stamps when not named". New defects: `defectIgnoresNamedChangedAt`, `defectKeepsChangedAtOnNamedZero`, `defectStampsWhenUnset` and `defectDropsPasswordWithTime`, the last two added by the review of this dispatch.

- [ ] **Step 1: Write the failing cases** in `RunProvisionerSuite`, each with a username unique to the case. Replace the old seed-based case with these four:

```go
t.Run("PasswordChangedAt", func(t *testing.T) {
	t.Parallel()
	recorded := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		act    func(t *testing.T, f Fixture, user string) *identity.Details
		assert func(t *testing.T, got *identity.Details)
	}{
		{
			name: "update naming only the password leaves a recorded time",
			act: func(t *testing.T, f Fixture, user string) *identity.Details {
				mustProvision(t, f, user, identity.WithUserPasswordChangedAt(recorded))
				return mustUpdate(t, f, user, identity.WithUserPassword([]byte("h2")))
			},
			assert: func(t *testing.T, got *identity.Details) {
				assert.True(t, recorded.Equal(got.PasswordChangedAt))
			},
		},
		{
			name: "provision naming only the password leaves the time zero",
			act: func(t *testing.T, f Fixture, user string) *identity.Details {
				return mustProvision(t, f, user, identity.WithUserPassword([]byte("h1")))
			},
			assert: func(t *testing.T, got *identity.Details) { assert.True(t, got.PasswordChangedAt.IsZero()) },
		},
		{
			name: "update naming password and time records the time",
			act: func(t *testing.T, f Fixture, user string) *identity.Details {
				mustProvision(t, f, user, identity.WithUserPasswordChangedAt(recorded))
				return mustUpdate(t, f, user,
					identity.WithUserPassword([]byte("h2")), identity.WithUserPasswordChangedAt(later))
			},
			assert: func(t *testing.T, got *identity.Details) { assert.True(t, later.Equal(got.PasswordChangedAt)) },
		},
		{
			name: "naming the zero time clears it",
			act: func(t *testing.T, f Fixture, user string) *identity.Details {
				mustProvision(t, f, user, identity.WithUserPasswordChangedAt(recorded))
				return mustUpdate(t, f, user, identity.WithUserPasswordChangedAt(time.Time{}))
			},
			assert: func(t *testing.T, got *identity.Details) { assert.True(t, got.PasswordChangedAt.IsZero()) },
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			user := uniqueName(t, "pwtime", i)
			got := tt.act(t, f, user)
			tt.assert(t, got)
			// the stored value, not only the returned one
			tt.assert(t, mustLoad(t, f, user))
		})
	}
})
```

`mustProvision`, `mustUpdate`, `mustLoad` and `uniqueName` are unexported helpers in `conformance.go`. Reuse any that already exist under another name (check with `gopls` symbol search), and add only the missing ones. `uniqueName(t, prefix, i)` returns `prefix + "-" + <first 12 hex characters of sha256(t.Name())> + "-" + strconv.Itoa(i)`, which keeps names under 64 characters for consumers' own tables. The A2 review found that names must also be unique per run, not only per test name. That fix belongs to the next dispatch of this lane. Times compare with `Equal`, because PostgreSQL returns microsecond precision in UTC. The test times above are whole seconds.

- [ ] **Step 2: See red.** Leave `inmem.go` stamping nothing new yet, so it ignores the named time. Run `go test -run 'TestInMemoryStoreConformance/Provisioner/PasswordChangedAt' -count=1 ./identity/` in `test/`. Expected: FAIL on "update naming password and time records the time" (a zero time where 2031-06-01 is expected).
- [ ] **Step 3: Implement** in `inmem.go`: on Provision and Update, `if u.IsSet(identity.FieldPasswordChangedAt) { rec.PasswordChangedAt = u.PasswordChangedAt }`. Remove `SeedPasswordChangedAt` from the interface and the store.
- [ ] **Step 4: Retarget the defects** in `conformance_guard_test.go`. Rename `defectProvisionStampsChangedAt` and `defectUpdateStampsChangedAt` in place to stamp `now` when the password is named and the time is *not*. Add `defectIgnoresNamedChangedAt`, which skips the `IsSet(FieldPasswordChangedAt)` write. Add each to the load-bearing table, so `TestConformanceSuiteIsLoadBearing` asserts the suite fails for it.
- [ ] **Step 5: Run** `go test -count=1 ./identity/...` in `test/`. Expected: PASS, including the load-bearing test for all three defects.

### Task 2.2: Organization hook and the loading rules

**Files:** Modify `test/identity/conformance.go`, `test/identity/inmem.go`, `test/identity/conformance_guard_test.go`.

**Interfaces:**
- Produces: `Fixture.SeedOrganization(ctx context.Context, org *identity.Organization) error`, which records an organization and its group (if any) so a user provisioned with `WithUserOrganization(&identity.Organization{ID: org.ID})` loads the full organization.

- [ ] **Step 1: Write failing cases** in `RunUserLoaderSuite`, each using a unique username:
  - fully populated user: seed an organization with a group, provision with two roles, seed grants where the second is primary with a validity window, and name a time. The load returns every value, with the primary grant first;
  - an organization without a group loads with `Group == nil`;
  - a dangling organization reference (provisioned with `&identity.Organization{ID: "<unseeded id>"}`) loads with `Organization == nil` and no error;
  - `Alice` provisioned and `alice` loaded is `identity.ErrUserNotFound`.
- [ ] **Step 2: See red:** a compile failure on `SeedOrganization` is not the red step. Add the method to `inmem.go` as a no-op first, run `go test -run 'TestInMemoryStoreConformance/UserLoader' -count=1 ./identity/`, and expect FAIL on the organization's group being nil.
- [ ] **Step 3: Implement** the in-memory organization table. On load, resolve the organization by ID from that table. A miss gives `nil`. The group comes from the seeded organization.

  **Compatibility:** today the in-memory store keeps the `*Organization` a caller provisioned. The suite now treats an organization as a reference, so the in-memory store resolves it by ID. Every existing case that provisioned a full organization seeds it first; update those cases in the same step.
- [ ] **Step 4: Add a defect** `defectDropsOrganizationGroup` and register it as load-bearing.
- [ ] **Step 5: Run** `go test -count=1 ./identity/...` in `test/`. Expected: PASS.

### Task 2.3: Every hook required, no skips

**Files:** Modify `test/identity/conformance.go`, `test/identity/conformance_guard_test.go`.

- [ ] **Step 1: Write the failing self-test.** Add a fixture wrapper whose `SeedMFARequired` is flagged absent. Because a Go interface method cannot be nil, the suite detects absence through an optional interface. Add:

```go
// ErrHookUnsupported is returned by a hook the implementation cannot provide.
// The suite treats it as a missing hook and fails the run, naming it.
var ErrHookUnsupported = errors.New("identitytest: hook not supported")
```

The suite's preflight calls each hook once on a probe fixture, before any case, with a probe username unique to the run. A hook returning `ErrHookUnsupported` fails the run with `t.Fatalf("identitytest: required hook %s is missing", name)`. The self-test runs the suite in a subprocess (reuse the file's existing re-exec guard) against a fixture whose `SeedMFARequired` returns `ErrHookUnsupported`. It asserts the output contains `required hook SeedMFARequired is missing` and that no case ran (`--- RUN` count for cases is 0).
- [ ] **Step 2: See red:** the output does not contain the message, because the suite has no preflight.
- [ ] **Step 3: Implement** the preflight. Delete every `t.Skip` in `conformance.go` and the "may skip" sentences in the `FailUserLoads`/`FailMFALookups` godoc. State instead that a fixture wraps its store and returns the error from the port call.
- [ ] **Step 4: Run** `go test -count=1 ./identity/...` in `test/`. Expected: PASS.

### Task 2.4: One shared database per run

**Files:** Modify `test/identity/conformance.go`, `test/identity/conformance_test.go`.

- [ ] **Step 1: Write the failing test** in `conformance_test.go`:

```go
func TestInMemoryStoreConformance_SharedStore(t *testing.T) {
	t.Parallel()

	shared := identitytest.NewInMemoryStore()
	identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
		t.Helper()
		return shared
	})
}
```

- [ ] **Step 2: See red:** cases that use fixed names (`alice`, `bob`, role `auditor`) collide. Expect FAIL with `ErrUserExists` or foreign grants.
- [ ] **Step 3: Implement:** route every username and role name in the suite through `uniqueName`. Fixed names stay only where the case's point is the name itself (`Alice` versus `alice`), with the unique suffix appended to both.
- [ ] **Step 4: Run** `go test -race -count=1 ./identity/...` in `test/`. Expected: PASS for both the per-case and shared factories.

### Task 2.5: `RunAmbientTx`

**Files:** Create `test/identity/ambient.go`; modify `test/identity/conformance_guard_test.go`.

**Interfaces:**
- Produces:

```go
// AmbientHarness is what the ambient-transaction part needs beyond Fixture.
type AmbientHarness interface {
	Fixture
	// Begin starts a caller-owned transaction and returns a context carrying
	// it, with commit and rollback. The store must see it through that context
	// (or through the consumer resolver it was configured with).
	Begin(ctx context.Context) (txCtx context.Context, commit, rollback func() error, err error)
	// WriteUnrelated writes one row outside the identity tables inside txCtx and
	// reports, after commit, whether it is stored.
	WriteUnrelated(txCtx context.Context, key string) error
	UnrelatedStored(ctx context.Context, key string) (bool, error)
	// FailGrantWrites makes the next grant write of a Provision fail partway,
	// after the user row was written.
	FailGrantWrites()
}

func RunAmbientTx(t *testing.T, newHarness func(t *testing.T) AmbientHarness)
```

- [ ] **Step 1: Write the cases:**
  - uncommitted rows are visible inside the transaction's context and not-found outside it (provision a user, seed a privilege and the MFA flag inside the transaction);
  - write an unrelated row, `FailGrantWrites`, provision (expect an error), commit. The unrelated row is stored and the user is not-found;
  - provision inside a transaction, roll back, and the user is not-found.
- [ ] **Step 2: See red:** build an in-memory harness in `conformance_guard_test.go` whose `Begin` returns a context the in-memory store ignores (writes go straight to the store). Run `go test -run TestAmbient -count=1 ./identity/`. Expect FAIL on "not-found outside the transaction".
- [ ] **Step 3: Implement** the suite only. The real implementations are the adapters (5.3, 6.1, 7.1). The in-memory store gains no transactions; the broken harness is the suite's load-bearing proof.
- [ ] **Step 4: Run** and expect PASS: the load-bearing self-test asserts the suite fails against the ignoring harness.

### Task 2.6: Remaining known defects

**Files:** Modify `test/identity/conformance_guard_test.go` (and `conformance.go` if a defect is not caught).

- [ ] **Step 1:** Add defects `defectAmendedFieldsOnly` (Update returns a `Details` with only the named fields) and `defectKeepsLastDuplicate` (the rebuild keeps the last stored duplicate grant). Register both in the load-bearing table.
- [ ] **Step 2:** Run `go test -run TestConformanceSuiteIsLoadBearing -count=1 ./identity/`. If a defect passes the suite (red for the *suite*), add the missing case to `conformance.go` and re-run. Record which defects needed new cases.
- [ ] **Step 2b: The unknown-user MFA answer (design Decision 7, `identity-model` delta).** Flip the `RunMFALookupSuite` case "an unknown user is answered rather than refused" to "an unknown user is refused, never answered as not required":

```go
assert: func(t *testing.T, required bool, err error) {
	require.ErrorIs(t, err, identity.ErrUserNotFound,
		"an unknown user is refused, never answered as not required")
	assert.False(t, required)
},
```

  Add a case "a stored user with no requirement recorded is not required" (provision a user, never seed the flag, expect `(false, nil)`). See red: the flipped case FAILs against the current in-memory store, which answers `(false, nil)`. Then make `InMemoryStore.Required` return `identity.ErrUserNotFound` when no stored user has the reference, and see green. Add the defect `defectMFAUnknownNotRequired` (the store answers `(false, nil)` for an unknown user), register it in `everyDefect`, and confirm the load-bearing test catches it. Tighten the ambient part too: `assertNotStored` now accepts either answer when it reads an uncommitted user from outside the transaction, and must require user-not-found, since such a user is unknown there.
- [ ] **Step 3:** Run `go test -race -count=1 ./identity/...` in `test/`. Expected: PASS.

### Task 3.1: `History` port, errors, `NewReuseGuard` construction

**Files:**
- Create: `password/history.go` (port + errors), `password/reuse.go` (guard), `password/reuse_test.go`, `password/history_mock_test.go` (mockgen, per `use-mockgen`)

**Interfaces:**
- Produces (exact, from design Decision 12):

```go
type History interface {
	RecentPasswords(ctx context.Context, user identity.UserID, n int) ([][]byte, error)
	RetirePassword(ctx context.Context, user identity.UserID, hash []byte, keep int) error
	ForgetPasswords(ctx context.Context, user identity.UserID) error
}
var (
	ErrPasswordReused     = errors.New("password: matches a recent password")
	ErrHistoryUnavailable = errors.New("password: password history could not be read or written")
	ErrConfig             = errors.New("password: invalid configuration")
)
type ReuseGuard struct{ /* unexported */ }
type ReuseOption func(*reuseConfig)
func NewReuseGuard(h History, enc Encoder, depth int, opts ...ReuseOption) (*ReuseGuard, error)
func WithReuseMatchers(encs ...Encoder) ReuseOption
func WithReuseClock(now func() time.Time) ReuseOption // default time.Now

// WriteFunc stores user's new password hash and the time it changed. A write
// that ignores changedAt leaves the stored time as it was, which exempts the
// user from password-age policy.
type WriteFunc func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error
```

- [ ] **Step 1: Write the failing table test** `TestNewReuseGuard_RefusesWiringMistakes`. Rows: nil history (message names "history port"); typed-nil history (`(*memHistory)(nil)`); nil encoder ("encoder"); depth 0 and −1 ("depth"); `WithReuseMatchers(nil)` ("matcher"); `WithReuseClock(nil)` ("clock"). Each asserts `errors.Is(err, password.ErrConfig)`, a nil guard, and the named word. A success row uses a consumer history (a mock) with depth 5. Detect typed-nil with the project's `internal/nilcheck` helper (read its godoc first).
- [ ] **Step 2: See red:** a stub `NewReuseGuard` returning `&ReuseGuard{}, nil`. Expect FAIL on every refusal row.
- [ ] **Step 3: Implement** the checks, in the order given. The error is `fmt.Errorf("%w: <what> is required", ErrConfig)` or similar fixed text.
- [ ] **Step 4: Run** `go test -run TestNewReuseGuard -count=1 ./password/`. Expected: PASS.

### Task 3.2: `Check`

**Files:** Modify `password/reuse.go` and `password/reuse_test.go`.

**Interfaces:** `func (g *ReuseGuard) Check(ctx context.Context, user *identity.Details, candidate string) error`. `user.ID` keys history; `user.Password` is the current hash.

- [ ] **Step 1: Write failing tests**, using real encoders at their floor parameters to keep the run fast, and an in-test map-backed `History`:
  - a nil user: `errors.Is(err, ErrConfig)`, and the mock history expects no call;
  - depth 3, `user.Password` = hash of `p4`, history `[p3, p2, p1]` (newest first): `p4`, `p3` and `p2` are refused with `ErrPasswordReused`, and `p1` is accepted. This also asserts `RecentPasswords` was called with `n = depth-1 = 2`;
  - depth 1: current `p2` is refused, and `p1` in history is accepted, because history is never read (n = 0 means no read at all);
  - `user.Password` nil and no history: accepted;
  - the history holds Argon2id at 64 MiB and the guard's encoder is Argon2id at 128 MiB: refused;
  - the history holds bcrypt cost 12 and the guard's encoder is Argon2id with no matchers configured: refused;
  - a consumer matcher (a test `Encoder` whose `Match` recognises a `"plain:"+p` prefix): refused only when configured through `WithReuseMatchers`.
- [ ] **Step 2: See red:** stub `Check` returns nil. Expect FAIL on every refusal row.
- [ ] **Step 3: Implement.** The matchers are the guard's encoder plus the extras. The default extras are `NewArgon2idEncoder()`, `NewBcryptEncoder()` and `NewScryptEncoder()`, built once at construction, leaving out the built-in of the same concrete type as the guard's own encoder (design Decision 12), so a stored hash of the guard's algorithm costs one derivation. Consumer-supplied matchers are never left out. Refuse a nil user with `ErrConfig` before any read. Check `user.Password` first; if it has length 0 it matches nothing. Then check each retired hash against each matcher, stopping at the first match. A read error is `fmt.Errorf("%w", ...)` wrapping as Task 3.4 specifies.
- [ ] **Step 4: Run** `go test -run TestReuseGuard_Check -count=1 ./password/`. Expected: PASS.

### Task 3.3: `Change` and its fail-closed order

**Files:** Modify `password/reuse.go` and `password/reuse_test.go`.

**Interfaces:** `func (g *ReuseGuard) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error`.

- [ ] **Step 1: Write failing tests:**
  - with `WithReuseClock(func() time.Time { return fixed })`, the write receives the same `*identity.Details` pointer, the new hash and `fixed`;
  - depth 3, changes `p1→p2→p3→p4→p5`, each with a `Details` whose `Password` is the previous new hash: the history finally holds hashes of `p4` and `p3` (newest first), and `write` received the `p5` hash;
  - a failed write followed by a retry: the history holds `p2` and `p1` exactly (the same-bytes rule means the second retire of `p2` adds nothing);
  - user `b` changing to `p1` when user `a` has `p1` in history: accepted;
  - the mock `RecentPasswords` returns an error: `ErrHistoryUnavailable`, and `write` is not called (`gomock` with `Times(0)` on a write spy);
  - `RecentPasswords` succeeds but `RetirePassword` fails: `ErrHistoryUnavailable`, and `write` is not called;
  - order: a `gomock.InOrder` expectation of `RecentPasswords(ctx, user.ID, depth-1)` then `RetirePassword(ctx, user.ID, user.Password, depth-1)`, then write;
  - lowering N (Review Focus 5): depth 3 builds history `[p3, p2]`; a depth-2 guard then changes `p4→p5`, and the history holds only `[p4]`.
- [ ] **Step 2: See red:** stub `Change` calls `write(ctx, user, nil, time.Time{})`. Expect FAIL on the history contents, the hash and the time.
- [ ] **Step 3: Implement** steps 1–5 of design Decision 12: `Check`; then `RetirePassword(ctx, user.ID, user.Password, g.depth-1)` when `len(user.Password) > 0`; then `g.enc.Encode(candidate)`; then `write(ctx, user, hash, g.now())`. Return the write's error unchanged.
- [ ] **Step 4: Run** `go test -run TestReuseGuard_Change -count=1 ./password/`. Expected: PASS.

### Task 3.4: Error hygiene

**Files:** Modify `password/reuse.go` and `password/reuse_test.go`.

- [ ] **Step 1: Write failing tests:**
  - refusing `Tr0ub4dor&3` as reused for `&identity.Details{ID: "u-123", Username: "ada"}`: the error text contains neither the password, `u-123`, `ada`, nor any 8-byte window of any stored hash;
  - the port fails with `errors.New("boom " + string(storedHash))`: the returned text does not contain the stored hash, `errors.Is(err, portErr)` is true, and `errors.Is(err, ErrHistoryUnavailable)` is true.
- [ ] **Step 2: See red** if Tasks 3.2/3.3 wrapped with `%w: %v`: expect FAIL on the hash appearing in the text.
- [ ] **Step 3: Implement** a wrapper type whose `Error()` returns `ErrHistoryUnavailable.Error()` only. It supports `Unwrap() []error { return []error{ErrHistoryUnavailable, cause} }`, and `errors.As` reaches the cause.
- [ ] **Step 4: Run** `go test -count=1 ./password/`, then `go vet ./password/`. Expected: PASS. Confirm there are no `log`/`slog` imports in `reuse.go`.

### Task 3.6: `ProvisionerWrite`

**Files:** Create `password/provisionerwrite.go`, `password/provisionerwrite_test.go`, `password/provisioner_mock_test.go` (mockgen of `identity.UserProvisioner`, per `use-mockgen`).

**Interfaces:**
- Consumes: `identity.WithUserPasswordChange`, `identity.ApplyUserOptions` (Task 1.1); `WriteFunc` (Task 3.1).
- Produces: `func ProvisionerWrite(p identity.UserProvisioner) (WriteFunc, error)`.

- [ ] **Step 1: Write the failing tests:**
  - refusal rows: nil `p` and typed-nil `p` give `ErrConfig` and a nil `WriteFunc`;
  - the write calls `Update` once with `user.Username`. `ApplyUserOptions(opts...)` names exactly `FieldPassword` and `FieldPasswordChangedAt`, with the given hash and time. Assert `IsSet` is false for every other field (loop over the exported `Field` constants);
  - `Update` returning an error: the write returns it unchanged (`errors.Is`);
  - the write-that-ignores-the-time scenario, end to end over `identitytest.InMemoryStore` with a consumer `WriteFunc` that calls `Update` with `WithUserPassword` alone: the change succeeds and `PasswordChangedAt` is unchanged. This scenario moved to Task 3.5, which owns `test/identity/history*.go`. The core module cannot import the test module, and lane A owns the rest of `test/identity`.
- [ ] **Step 2: See red:** a stub returning `func(...) error { return nil }, nil`. Expect FAIL on the refusal rows and on `Update` never being called.
- [ ] **Step 3: Implement.** Check nil and typed-nil with `internal/nilcheck`. The godoc says it joins an attached transaction because the provisioner's update does, and that a consumer with their own storage passes their own `WriteFunc`.
- [ ] **Step 4: Run** `go test -count=1 ./password/` and `go test -count=1 ./identity/...` in `test/`. Expected: PASS.

### Task 3.5: In-memory history and `RunPasswordHistory`

**Files:** Create `test/identity/history.go` (in-memory `History` + `RunPasswordHistory`), `test/identity/history_test.go`, `test/identity/history_guard_test.go`.

**Interfaces:**
- Produces:

```go
type HistoryHarness interface {
	password.History
	Begin(ctx context.Context) (txCtx context.Context, commit, rollback func() error, err error)
}
func RunPasswordHistory(t *testing.T, newHarness func(t *testing.T) HistoryHarness)
func NewInMemoryHistory() *InMemoryHistory // its harness's Begin stages writes and applies them on commit (Step 3)
```

`RunPasswordHistory` takes no identity hooks (spec: running the identity part does not require these hooks, and vice versa). User references are generated per case as UUIDv7 strings from `pkg/id`, so stores that parse the reference accept them.

- [ ] **Step 1: Write the suite's cases:**
  - `h1..h4` retired with keep 3: reading 3 returns `h4, h3, h2`, and reading 10 returns the same three;
  - the `n` bound: reading 2 returns `h4, h3`;
  - same bytes twice: one entry;
  - keep 0 after `h1, h2`: none;
  - `ForgetPasswords` leaves another user's entries unchanged;
  - ambient rollback: retire inside `Begin`, roll back, and there are no entries.

  Write `history_guard_test.go` with two broken stores (oldest-first, never-prunes) and a load-bearing assertion that the suite fails for each.
- [ ] **Step 2: See red** against the broken stores: the load-bearing test fails while the suite has no cases.
- [ ] **Step 3: Implement** `InMemoryHistory`. The ambient-rollback case needs a harness whose `Begin` isolates writes. The in-memory one records writes to a staging copy applied on commit, which keeps the case honest in memory too.
- [ ] **Step 3b: The write that ignores the time** (moved from Task 3.6): over `identitytest.InMemoryStore`, a consumer `WriteFunc` that calls `Update` with `WithUserPassword` alone completes the change and leaves `PasswordChangedAt` unchanged.
- [ ] **Step 4: Run** `go test -race -count=1 ./identity/...` in `test/`. Expected: PASS.

### Task 4.1: `migrate.Identity()` and its PostgreSQL behaviour

**Files:**
- Create: `migrate/identity/20260928000000_identity.sql`, `test/migrate_identity_test.go`
- Modify: `migrate/migrate.go`, `migrate/migrate_test.go`

**Interfaces:** Produces `const IdentityVersionTable = "goose_identity"` and `func Identity() Set` (`Dir: "identity"`).

- [ ] **Step 1: Write failing tests.**
  - `migrate_test.go`: `Identity()` returns `Dir == "identity"` and `VersionTable == "goose_identity"`; its FS holds exactly one `.sql` file with `-- +goose Up` and `-- +goose Down`; no statement contains `REFERENCES` or `FOREIGN KEY` (a case-insensitive scan of the file text).
  - `test/migrate_identity_test.go`, each case with `test.RunTestPostgres(t, test.WithTestPostgresMigrations(...))`:
    - identity set alone creates exactly the seven tables (query `information_schema.tables`), and `sessions` is absent;
    - security-state set alone: no `users` and no `goose_identity`;
    - both applied, then the identity set rolled back with goose `DownTo(0)` on `goose_identity`: the identity tables are gone and every security-state table plus `goose_security_state` rows remain;
    - `app_identity_versions` as the version table records the version there.
- [ ] **Step 2: See red:** `Identity` undefined is a compile error, not the red step. Add `func Identity() Set { return Set{} }` first, then run `go test -run TestIdentity -count=1 ./migrate/`. Expect FAIL on `Dir`.
- [ ] **Step 3: Implement.** The embed is `//go:embed identity/*.sql`. The SQL is the shipped migration, `migrate/identity/20260928000000_identity.sql`. It follows the security-state set's conventions (design Decision 2):
- string columns are `text`;
- `created_at` and `updated_at` are `timestamptz NOT NULL` with no database default, and the store binds them from its clock;
- `password_history.seq` is `bigint GENERATED ALWAYS AS IDENTITY`;
- no table declares a foreign key;
- Down drops the seven tables in reverse order with `IF EXISTS`.

The catalogue test in `test/migrate_identity_test.go` pins every column, default, unique constraint and index.
- [ ] **Step 4: Run** `go test -count=1 ./migrate/` in the core module, then `go test -count=1 -run 'TestMigrateIdentity' .` in `test/`. Expected: PASS.

### Task 4.2: Shared identity SQL in `internal/pgschema`

**Files:** Create `internal/pgschema/identity.go`.

- [ ] **Step 1:** Write the statements as exported constants, each with a comment naming its contract. They are:
  - `UserByUsername`, `UserByID`, `GrantsByUser` (`ORDER BY is_primary DESC, position`), `OrganizationByID`, `GroupByID`;
  - `PrivilegesByRole` (`ORDER BY resource_group, resource, privilege`);
  - `InsertUser` (`... ON CONFLICT (username) DO NOTHING`, with `password_changed_at` as a parameter the store passes NULL for when the time is unnamed);
  - `LockUserByUsername` (`SELECT id FROM users WHERE username = $1 FOR UPDATE`);
  - `DeleteGrantsByUser`, `InsertGrant`, `MFARequiredByID`;
  - `NewestHistory` (`SELECT password FROM password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT 1`), `InsertHistory`;
  - `PruneHistory`: `DELETE FROM password_history WHERE user_id = $1 AND seq NOT IN (SELECT seq FROM password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT $2)`;
  - `RecentHistory` (`ORDER BY seq DESC LIMIT $2`), `ForgetHistory`.

  The partial `UPDATE users SET ...` is built in the adapters from the named fields. Column names come from a fixed allow-list, never input.
- [ ] **Step 2:** Verification is through Tasks 5.1–5.5, which run every statement against PostgreSQL. This task has no red step of its own, because constants carry no behaviour. The first 5.x red step exercises them.

### Task 5.1: `sqlstore.NewIdentityStore`, loaders and MFA lookup

**Files:**
- Create: `sqlstore/identity.go` (type, constructor, loaders, lookup), `test/sqlstore/identity_test.go`
- Modify: `sqlstore/options.go` (godoc listing `IdentityStore` among the stores honouring `WithIDGenerator` and `WithClock`)

**Interfaces:**
- Consumes: `migrate.Identity()`, `pgschema` identity constants, `identitytest.RunUserLoaderSuite` / `RunRoleLoaderSuite` / `RunMFALookupSuite` and `Fixture` with `SeedOrganization`.
- Produces: `type IdentityStore struct` and `func NewIdentityStore(db *sql.DB, opts ...Option) (*IdentityStore, error)`, with compile-time assertions `var _ identity.UserLoader = (*IdentityStore)(nil)`, and likewise for `RoleLoader`, `UserProvisioner`, `MFARequirementLookup` and `password.History`.

- [ ] **Step 1: Write failing tests** in `test/sqlstore/identity_test.go`:
  - a `migratedIdentityDB(t)` helper applying both sets;
  - an `identityFixture` wrapping the store. It implements the seed hooks with raw SQL through `conn.DB`: `SeedRole` inserts `resource_privileges`, `SeedMFARequired` updates `users.mfa_required`, `SeedRoleGrants` deletes and inserts `assigned_roles` with positions, `SeedOrganization` inserts `organizations` and `groups`. `FailUserLoads`/`FailMFALookups` are wrapper fields returning the error;
  - run the three suites with a factory returning the fixture over the shared database (Task 2.4 made that safe);
  - construction: a nil db is `ErrConfig`; `WithResealOnRead` is refused as not honoured; `WithClock` is honoured and binds every `created_at`/`updated_at` (the identity tables have no database default for them, like the security-state tables);
  - the MFA lookup for `not-a-uuid` is `ErrUserNotFound`;
  - an inactive user (set `users.active = false` with raw SQL) loads with `Active == false` and no error. This is adapter-only, because the ports cannot deactivate a user and the spec names no hook for it;
  - the lookup and load with the `users` table renamed (`ALTER TABLE users RENAME TO users_gone` inside a transaction passed through `WithTx`, then rolled back): the error is not `ErrUserNotFound` and the lookup does not report "not required".
- [ ] **Step 2: See red:** a stub constructor with methods returning `nil, errors.New("unimplemented")`. Expect the suites to FAIL by assertion.
- [ ] **Step 3: Implement** the loaders through the resolved handle (reuse the package's existing `handle(ctx)` resolution — find it with `gopls` in `sqlstore/tx.go`). Parse the `UserID` with `id.Parse`; a parse error is `ErrUserNotFound` for `LoadByUserID` and `Required`. Error wrapping follows the package's `errors.go` (operation name, no values).
- [ ] **Step 4: Run** `go test -count=1 -run 'TestIdentity' ./sqlstore/` in `test/`. Expected: PASS.

### Task 5.2: Provision and Update

**Files:** Modify `sqlstore/identity.go` (or create `sqlstore/identity_write.go`) and `test/sqlstore/identity_test.go`.

- [ ] **Step 1: Write failing tests:**
  - run `identitytest.RunProvisionerSuite` over the fixture;
  - descending-generator cases with a test `id.Generator` returning `ffffffff-...`, then decreasing values: grants load in given order, and the first stored duplicate keeps its super role after an update naming `admin` (Review Focus 4);
  - a generator failing on the second grant: provisioning errors with `errors.Is(err, genErr)`, and the username is not-found;
  - the collision error's text lacks `ada@example.test`.
- [ ] **Step 2: See red:** the provisioner suite FAILs by assertion against the Task 5.1 stubs.
- [ ] **Step 3: Implement.**
  - **Provision:** in one transaction (or a savepoint, per 5.3), run `InsertUser` with `password_changed_at` bound to the named time or NULL. Zero rows affected means `identity.ErrUserExists`. Then insert one grant per occurrence with `position = i` and `is_primary = i == 0`, and set `users.role` to the first name.
  - **Update:** `LockUserByUsername` (no row is `ErrUserNotFound`). Build the partial `UPDATE` from `IsSet` over the fixed column map `{FieldName: "name", FieldPassword: "password", FieldOrganization: "organization_id", FieldPasswordChangedAt: "password_changed_at"}`. A zero named time binds NULL. `FieldEmail` writes nothing (Decision 8). If roles are named and at least one survives, collapse them, read the existing grants `ORDER BY position`, keep the first of each name, delete, re-insert with new positions, and set `users.role`. Then re-select the complete record.
- [ ] **Step 4: Run** `go test -count=1 -run 'TestIdentity' ./sqlstore/` in `test/`. Expected: PASS.

### Task 5.3: Savepoints inside an ambient transaction

**Files:** Modify `sqlstore/identity.go` and `test/sqlstore/identity_test.go`.

- [ ] **Step 1: Write failing tests:** run `identitytest.RunAmbientTx`. The harness's `Begin` opens `conn.DB.BeginTx` and returns `sqlstore.WithTx(ctx, tx)`. `WriteUnrelated` inserts into a scratch table the test creates. `FailGrantWrites` arms a consumer `id.Generator` on that fixture's store that returns the identifier of an existing grant row, so PostgreSQL itself refuses the grant insert with a primary-key violation after the user row is written. A Go-side error that sends no statement would never abort the transaction, and the case would pass without savepoints. A trigger is ruled out because cases share one database. Add a second case with `WithTxResolver` over the consumer's own transaction, then roll back.
- [ ] **Step 2: See red:** without savepoints, the failed-provision case FAILs at commit with `pq: current transaction is aborted` (or pgx's equivalent), and the unrelated row is missing.
- [ ] **Step 3: Implement** `SAVEPOINT scrty_identity_<n>`, `ROLLBACK TO SAVEPOINT`, `RELEASE`. `<n>` comes from a per-store `atomic.Uint64`, never from input. Outside an ambient transaction, run `db.BeginTx` / `Commit`.
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestIdentity' ./sqlstore/` in `test/`. Expected: PASS.

### Task 5.4: Forced interleavings

**Files:** Create `test/sqlstore/identity_race_test.go`.

- [ ] **Step 1: Write the tests.**
  - **Insert atomicity:** transaction A provisions `race-user` and is held open. B provisions the same user on another connection and blocks on the unique index. Poll `pg_stat_activity` until B's `wait_event_type = 'Lock'`, then commit A. B returns `ErrUserExists`, not a driver error.
  - **Update serialisation:** the user holds `admin`. A updates to `viewer` inside a held transaction. B updates to `admin` and blocks on `FOR UPDATE` (confirmed through `pg_stat_activity`). A commits, then B. The final grants are exactly `admin`.
  - Also eight concurrent provisions of one name: exactly one success, and seven `ErrUserExists`.
- [ ] **Step 2: See red against broken variants.** The store's internals are unreachable from the `test` module, so each variant is built from outside:
  - **preceding read:** a wrapper that loads the username first and, when the load misses, runs the insert through a resolver that swallows the `ON CONFLICT` zero-row result as success. Two racing callers then both "succeed";
  - **no row lock:** a `WithTxResolver` whose `DBTX` rewrites `pgschema.LockUserByUsername` without ` FOR UPDATE`.

  Record the failing output for both, and keep them as named load-bearing subtests that assert the case fails against the variant.
- [ ] **Step 3: Run** `go test -race -count=3 -run 'TestIdentityRace' ./sqlstore/` in `test/`. Expected: PASS for the real store, three runs in a row.

### Task 5.5: `password.History` on the store

**Files:** Create `sqlstore/identity_history.go`; modify `test/sqlstore/identity_test.go`.

- [ ] **Step 1: Write failing tests:**
  - `identitytest.RunPasswordHistory` over the store, with `Begin` as in 5.3;
  - a descending generator: `h1` then `h2`, and reading returns `h2` first;
  - five `Update` calls naming a password, and the history is empty;
  - retiring into a renamed table: the error text contains neither the hash bytes (hex or raw) nor the user reference;
  - `not-a-uuid`: `RecentPasswords` errors and returns nil;
  - retire with keep 3 four times, then keep 1: one row (Review Focus 5).
- [ ] **Step 2: See red:** stub methods return `nil, nil` and nil. Expect the suite to FAIL on the newest-first case.
- [ ] **Step 3: Implement.** `RetirePassword` in one savepointed group: when `keep == 0`, run `ForgetHistory` only. Otherwise, if `NewestHistory` equals `hash` (`bytes.Equal`), skip the insert; else `InsertHistory` with a generator ID and the clock's time. Then `PruneHistory` with `keep`. `retired_at` comes from the store's clock (`WithClock`, honoured since 5.1).
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestIdentity' ./sqlstore/` in `test/`. Expected: PASS.

### Task 5.6: The reuse guard end to end over the store

**Files:** Create `test/sqlstore/identity_reuse_test.go`.

- [ ] **Step 1: Write the tests.**
  - Provision a user with a hash of `p1` and load their `Details`. With `write, _ := password.ProvisionerWrite(store)` and a guard using `WithReuseClock` fixed at `now`, run `guard.Change(txCtx, details, "p2", write)` in one transaction (`sqlstore.WithTx`); then roll back. The password is still `p1`, the history is empty, and the time is zero.
  - The same, committed: the password matches `p2`, the history holds `p1`, and the time is `now`.
- [ ] **Step 2: See red:** run it first with a consumer `WriteFunc` that calls `store.Update` with `WithUserPassword` alone. The committed case FAILs on the time being zero, which confirms the assertion bites. Then switch to `ProvisionerWrite`.
- [ ] **Step 3: Run** `go test -count=1 -run TestIdentityReuse ./sqlstore/` in `test/`. Expected: PASS.

### Task 6.1: `pgx.NewIdentityStore`

**Files:** Create `pgx/identity.go`, `pgx/identity_history.go`, `test/pgxstore/identity_test.go`.

**Interfaces:** Produces `func NewIdentityStore(pool *pgxpool.Pool, opts ...Option) (*IdentityStore, error)` with the same five compile-time assertions as 5.1.

- [ ] **Step 1: Write failing tests** mirroring 5.1–5.3 and 5.5 in `test/pgxstore`: all identity suites, `RunAmbientTx` (with `Begin` over `pool.Begin` and `pgx.WithTx`), `RunPasswordHistory`, and construction errors.
- [ ] **Step 2: See red:** stubs returning errors make the suites FAIL by assertion.
- [ ] **Step 3: Implement** over the `pgschema` constants with pgx row scanning (`pgx/uuid.go` has the UUID conversion helpers; read them first). Issue `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` / `RELEASE SAVEPOINT` on the resolved handle with store-counter names, releasing after rollback too (design Decision 6); pgx's `Tx.Begin` nesting never releases a rolled-back savepoint.
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestIdentity' ./pgxstore/` in `test/`, and `go vet ./...` in `pgx/`. Expected: PASS.

### Task 6.2: pgx interleavings

**Files:** Create `test/pgxstore/identity_race_test.go`.

- [ ] **Step 1:** Write Task 5.4's three cases against the pgx store, including the red step against a pre-read wrapper and an unlocked variant.
- [ ] **Step 2:** Run `go test -race -count=3 -run 'TestIdentityRace' ./pgxstore/` in `test/`. Expected: PASS.

### Task 7.1: `gorm.NewIdentityStore`

**Files:** Create `gorm/identity.go`, `gorm/identity_history.go`, `test/gormstore/identity_test.go`; modify `gorm/models.go` (append the identity models).

**Interfaces:** Produces `func NewIdentityStore(db *gormdb.DB, opts ...Option) (*IdentityStore, error)` with the same five assertions.

- [ ] **Step 1: Write failing tests** mirroring Task 6.1 in `test/gormstore`.
- [ ] **Step 2: See red:** stubs make the suites FAIL by assertion.
- [ ] **Step 3: Implement** with `clause.OnConflict{Columns: []clause.Column{{Name: "username"}}, DoNothing: true}` and `RowsAffected == 0` for the collision; `clause.Locking{Strength: "UPDATE"}` for the lock; and savepoint statements sent through `Exec` inside an ambient transaction, released after rollback too (design Decision 6; gorm's `SavePoint`/`RollbackTo` discard the statement's error and never release). Partial updates use `map[string]any` built from the fixed column map, so gorm's zero-value skipping never decides what is written. Pruning and the reads use `db.Exec`/raw queries over the `pgschema` statement text, imported directly: the gorm module's path sits under the core module's, so Go permits the `internal` import, as the gorm security-state stores already do.
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestIdentity' ./gormstore/` in `test/`, and `go vet ./...` in `gorm/`. Expected: PASS.

### Task 7.2: gorm interleavings

**Files:** Create `test/gormstore/identity_race_test.go`.

- [ ] **Step 1:** Write Task 5.4's three cases against the gorm store, including the red step.
- [ ] **Step 2:** Run `go test -race -count=3 -run 'TestIdentityRace' ./gormstore/` in `test/`. Expected: PASS.

### Task 8.1: 422 for a reused password

**Files:** Modify `httpsec/status.go` and `httpsec/status_test.go`.

- [ ] **Step 1: Write failing rows** in the existing status table test: `password.ErrPasswordReused` gives 422; `fmt.Errorf("change: %w", password.ErrPasswordReused)` gives 422; `password.ErrHistoryUnavailable` gives 500.
- [ ] **Step 2: See red:** the two reuse rows FAIL with 500.
- [ ] **Step 3: Implement** one `errors.Is` row placed between the 413 and 423 rows, as the spec table orders them. Update the `StatusForError` godoc table.
- [ ] **Step 4: Run** `go test -count=1 -run TestStatusForError ./httpsec/`. Expected: PASS.

### Task 8.2: The resolve endpoint with a reuse guard

**Files:** Modify `httpsec/passwordchange_test.go`.

- [ ] **Step 1: Write the tests.** The first builds a chain with a session owing a password change and `WithChangePasswordEndpoint("/password", fn)`, where `fn` loads the caller's `Details` from an in-test `UserLoader`/`UserProvisioner` pair (`httpsec` tests cannot import the `test` module), reads the new password from the form, and calls `guard.Change(ctx, details, candidate, write)` with `write` from `password.ProvisionerWrite(provisioner)`, over an in-test history seeded so the candidate is reused. POST returns 422 through the default error handling, and the next request on the session is refused with a password-change challenge (403). The second uses the same chain with an `fn` that calls no guard and "changes" to the current password: POST succeeds, and the next request passes.
- [ ] **Step 2: See red:** confirm the first test can fail by temporarily making `fn` return nil, which clears the marker, so the "still refused" assertion FAILs. Then restore `fn`. No production change is expected. If a test fails for another reason, stop and report it as a finding under `defect-claims.md`.
- [ ] **Step 3: Run** `go test -count=1 -run TestChangePassword ./httpsec/`. Expected: PASS.

### Task 9.1: Godoc

**Files:** godoc in `sqlstore/identity*.go`, `pgx/identity*.go`, `gorm/identity*.go`, `migrate/migrate.go`, `password/history.go`, `password/reuse.go`.

- [ ] **Step 1:** Each constructor states the default and the override for every option it honours. `IdentityStore` states:
  - user deletion is the consumer's, and must delete grants and call `ForgetPasswords` in the same transaction;
  - organizations, groups, privileges and the MFA flag are written by the consumer's tooling;
  - a password named alone never moves the password-changed-at time.

  `ReuseGuard` states:
  - the cost, about one key derivation per stored hash, up to N;
  - the two-simultaneous-changes limit;
  - the transaction recipe from design Decision 12, with `ProvisionerWrite(store)` as the write;
  - on `WriteFunc` and `ProvisionerWrite`: the time is recorded by default only on this path, and a write that ignores `changedAt` gives up password-age policy for that user.
- [ ] **Step 2:** Run `go doc` on each new exported symbol, and `go vet ./...` in the core, `pgx`, `gorm` and `test` modules. Expected: clean.

### Task 9.2: Final gate (main session)

- [ ] Run these in the core, `pgx`, `gorm`, `ginsec`, `fibersec` and `test` modules: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` (empty), `golangci-lint run`.
- [ ] Dispatch one fresh reviewer across the whole branch against every requirement in the change's five spec files, reporting `REPRODUCED`/`UNREPRODUCED` per claim.
- [ ] Commit by explicit path only.

---

## Session handoff (2026-09-28)

Done and reviewed: 1.1–1.4, 2.1–2.6, 3.1–3.6, 4.1–4.2, 5.1–5.3, 8.1–8.2 (23/32). Next: lane D2 (5.4–5.6), then lanes E (6.x) and F (7.x) in parallel, then H (9.x). Every finished dispatch went through verification and at least one fresh review, and every finding was folded in.

Settled during implementation. The pgx and gorm lanes must follow these; they are also recorded in spec.md and design.md:
- **Driver errors leave the chain.** The identity store returns the driver's primary message and SQLSTATE as text, and never the driver's error value, whose detail can carry a failing row. `sqlstore/identity_errors.go` (`dbFailed`, `scanFailed`, `detached`) is the reference. Task 5.5's history methods must use it too.
- **References are byte-exact.** User and organization references are canonical lowercase UUID text. An upper-case spelling of a user reference is user-not-found. A non-canonical organization reference is refused before any write, with fixed text.
- **`FailGrantWrites` fails a real statement.** It is implemented with an armed consumer `id.Generator` that re-issues an existing grant id, so PostgreSQL raises a primary-key violation. Run `RunAmbientTx` once through `WithTx` and once through a consumer resolver.
- **Savepoints and panics.** A panic in `fn`, or in a savepoint statement, rolls the savepoint back and propagates the original panic. Update locks the user row `FOR UPDATE` first, then plans its grants (ids minted before any write), then writes.
- **Privilege order.** Groups are ordered by resource group, then resource. The order inside a group is unspecified, and the suite compares it as a set.
- **Parallel history cases.** The password-history suite's ambient cases call the store outside an open transaction, so a pooled harness needs more connections than the number of cases run in parallel.

Open items noticed, not yet in any task: `password/reuse_test.go` has two unused helper methods (`seed`, `entries`), flagged by gopls. Remove them before the 9.2 lint gate.

## Session handoff (2026-09-29)

Done and reviewed this session: 5.4–5.6, 6.1–6.2, 7.1–7.2 (30/32). Next: lane H — 9.1 (godoc, Sonnet), then 9.2 (final gate and whole-branch review, main session). Nothing is committed yet: the uncommitted tree holds all of this session's work.

Settled during implementation (recorded in design.md Decision 6 where marked):
- **Every adapter issues its own savepoint statements and releases after rollback too** (Decision 6, updated). pgx's `Tx.Begin` nesting never released a rolled-back savepoint; a review reproduced 70 refused provisions leaving 64 open subtransactions with the cache overflowed. gorm's `SavePoint`/`RollbackTo` discard the statement's error and never release, so gorm sends the statements through `Exec`. Each adapter's `TestIdentityStore_RefusalsLeaveNoOpenSavepoint` pins it, including the panic path. It works on PostgreSQL 15 by writing once in the caller's transaction and counting `transactionid` locks in `pg_locks`, and adds `pg_stat_get_backend_subxact()` on 16+ (read once, last).
- **gorm imports `internal/pgschema` directly.** No copied constant and no guard test; plans.md 7.1 is corrected.
- **gorm consumer configurations are pinned:** `PrepareStmt: true` (no savepoint statement is prepared) and `TranslateError: true` (collision still `ErrUserExists`, no driver error in the chain).
- **Forced-interleaving tests** (`TestIdentityRace` in each adapter) detect the missing row lock through the revoked grant coming back with its old identifier and super role; the final grant names alone stay `[admin]` without the lock.
- **`ForgetPasswords` runs without a savepoint** by choice: the spec requires only a failed retire to leave the caller's transaction usable, and forgetting runs inside the consumer's user deletion.

Open items, not in any task yet (decide before or during 9.2):
- The spec sentence "Updates to different users SHALL NOT block each other" (requirement "Concurrent updates of one user serialise") has no test in any adapter or in the suite.
- The conformance suite has no case clearing an organization through Update (a gorm probe passed; untested everywhere).
- No test pins that insert and prune in `RetirePassword` roll back together in the store's own transaction (outside a caller's); the savepoint path is tested.
- Carried from the previous handoff: `password/reuse_test.go` has two unused helpers (`seed`, `entries`); remove before the 9.2 lint gate.

## Final gate (2026-09-29)

9.1 and 9.2 are done (32/32). The gate is green in the core, `pgx`, `gorm`, `ginsec`, `fibersec` and `test` modules: `go test -race -count=1 ./...`, `go vet`, `gofmt -l` and `golangci-lint run` (0 issues).

- **Whole-branch review:** it found no defect. Its coverage findings are all pinned now, in all three adapters and the shared suite, each test seen to fail against a broken copy of the code first:
  - Provision is atomic outside a caller's transaction.
  - RetirePassword's insert and prune roll back together, in both modes.
  - Updates to different users do not block.
  - The default generator mints UUIDv7.
  - Update clears an organization.
- **Error text (design Decision 11.2, updated):** the identity stores return fixed library text naming the operation, plus the SQLSTATE read through `SQLState()`. The driver's primary message is dropped, per the `internal/diag` rule the lint gate enforces. All three adapters give identical text.
- **Three pre-existing flakes in the test module's container helpers**, fixed with the user's approval, each cause reproduced first:
  - SMTP teardown: the stop grace equalled the cleanup context.
  - Keycloak: `WithWaitStrategy` silently caps waits at 60s. It now uses `WithWaitStrategyAndDeadline`.
  - PostgreSQL: Docker Desktop occasionally runs a container with no published port. The helper now waits for the mapping, and retries such a container up to 3 times.

  The PostgreSQL retry path has no permanent in-tree test. A deterministic `NetworkMode=none` fault would make one.
- **Not addressed:** the suite has no case clearing an organization via an empty `&identity.Organization{}`. The contract only says a nil organization clears it.
- **Next:** commit, then `/opsx:archive`.
