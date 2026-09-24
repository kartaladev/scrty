# Authentication Methods Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the three authentication methods scrty is missing — a second factor, a passwordless email link and a machine credential — plus the email transport they need, with every known failure mode of each closed by a construction error or a tested requirement.

**Architecture:** Four new core packages hold the decisions (`notify`, `mfa`, `magiclink`, `apikey`) and none of them imports `httpsec`; `httpsec` holds each method's interceptor, registered in the ordered slots `http-security` already reserved (`OrderMagicLink`, `OrderAPIKey`, `OrderMFAChallenge`). Every one-time credential is check-then-consume, so a refusal never spends it, and every refusal leaves the chain as an error for the consumer to render.

**Tech Stack:** Go 1.27, `github.com/pquerna/otp` (new, core module), `net/smtp` and `mime` from the standard library, `go.uber.org/mock` (mockgen), `stretchr/testify`, `testing/synctest`, `go.uber.org/goleak`, `testcontainers-go` (test module only).

**Spec:** `openspec/changes/auth-methods/` — `proposal.md`, `design.md`, `specs/multi-factor-auth/spec.md`, `specs/magic-link/spec.md`, `specs/api-keys/spec.md`, `specs/email-notification/spec.md`. Every plan task cites the `tasks.md` numbers it implements.

---

## Global Constraints

- Module `github.com/kartaladev/scrty`, Go 1.27 minimum. The core module gains exactly one third-party dependency from this change: `github.com/pquerna/otp`. It pulls `github.com/boombuler/barcode` in as an indirect requirement, which is allowed — it is not a framework, driver, scheduler or DI container. `testcontainers-go` goes in `test/go.mod` **only**; `TestModuleLayout` fails the build if it reaches a production import.
- **Test-first, always.** Write the failing test, run it, read the output and confirm it fails for the intended reason. A compile error is **not** a red step — stub the symbol so the test compiles and fails on the assertion. Never tick a step for a test that has not been seen to fail.
- Table-driven tests follow the project's `table-test` skill: the `assert` closure form (never `want`/`wantErr` fields), a `ctx` modifier where context matters, and `t.Context()` over `context.Background()`.
- Test doubles come from `mockgen` (`use-mockgen` skill): a `//go:generate mockgen -destination=<x>_mock_test.go -package=<pkg>_test -typed <import path> <Interface>` directive beside the consumer, output in `_test.go` files only. Heavy services come from `use-testcontainers` helpers — one `RunTestX(t *testing.T, opts ...TestOption)` per service in the owning module's `testutils.go`, never a hand-rolled fake and never Docker Compose.
- **Library design:** every behaviour has a safe default that needs no configuration, and every default is replaceable without forking. Each option's godoc names the default it replaces; each port's godoc says what the library uses when the consumer supplies none. A contradictory configuration is a `New` error, never a surprise at first use. Where "safe" and "convenient" disagree, the safe one is the default and the convenient one is the option.
- **Nothing brand-specific in any default.** The TOTP issuer is required configuration with no fallback; the default magic-link message names no product, brand or organisation; no SMTP header names scrty.
- **Secrets come from `crypto/rand`.** TOTP secrets are 20 bytes, API key secrets 32 bytes, binding decoys 16 bytes. A random-source failure returns an error and writes nothing.
- **Legacy reference:** `.claude/.legacy/` is read-only. Never copy its code, tests or comments, and never cite it — not its name, module path, package paths, commit, or "legacy"/"ported"/"v2" wording. Exclude it from text searches (`rg --glob '!.claude/.legacy'`).
- **No defect claim without a failing test.** Any assertion that existing code is wrong needs a reproducing test, or the label `UNREPRODUCED` with the reason.
- Navigate Go code with `gopls` (references, definitions, implementations), not `grep`. `grep` is for comments, strings and config only.
- Never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. The tree holds other agents' uncommitted work. Undo by editing the file back.
- **Never edit anything under `openspec/`.** Report a disagreement between the code and the artifacts; the main session writes them. That includes ticking a `tasks.md` checkbox.
- Gate before reporting: `go test -race -count=1 ./...` in the module touched, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run ./...` clean. The full gate is `make check`.

### Names the artifacts get wrong

`design.md`'s Go snippets predate the code that now exists. Use the right-hand column, and do not "fix" the code to match the design:

| design.md writes | the code exports |
|---|---|
| `identity.Channel` | `factor.Channel` — `factor` owns the vocabulary and imports nothing |
| a first-factor kind as a string | `factor.Kind`: `factor.Password`, `factor.MagicLink`, `factor.APIKey`, `factor.Basic`, `factor.OIDC` |
| identity-model's "authenticator-app channel" | `factor.AuthenticatorApp` |
| a new `mfa.EnrolmentLookup` with `Enrolment(ctx, user) (bool, factor.Channel, error)` | the existing `policy.MFAMethodLookup` with `Enrolled(ctx, user) (bool, error)` and `Channel() factor.Channel`. Its godoc already pins "a store failure, or a stored secret that will not decrypt, is an error — never a false". `mfa.LookupFor` **adapts** a `Method` to it; it declares no new port. |
| a new unexported redirect helper in `httpsec` | the existing `internal/origin.Allowlist` — `NewAllowlist(entries, declaredOrigins, entryOption, originOption)` and `(*Allowlist).Resolve(requested) string`, which already validate entries and declared origins and fall back to `/` |
| "sessions provides rotation" | it does **not** — Task 1 adds it |

**Three prerequisite APIs.** The archived `sessions` and `identity-model` capabilities did not ship three things these specs require, so Tasks 1 and 2 add them before any method work. Nothing is tagged, so they are additive:

| Added | Where | Required by |
|---|---|---|
| `Session.MFASatisfiedAt time.Time` | `session/session.go` | multi-factor-auth: "records the second-factor-satisfied time" |
| `(*session.Manager).Rotate(ctx, *Session) (*Session, error)` | `session/manager.go` | multi-factor-auth: "rotate the session handle", D5 (session fixation) |
| `identity.UserLoader.LoadByUserID(ctx, identity.UserID) (*Details, error)` | `identity/ports.go` | magic-link D7: "load the user by that reference" |

Task 38 records all of this in `design.md` and reports the drift in the archived specs. Do not edit the archived specs.

### What this change does not close

- The API-key rotation scenario that demands atomicity inside an attached transaction: no transactional store exists until `durable-persistence` lands. Task 22 builds the two-write behaviour and documents it; Task 38 flags the atomic case.
- An enrolment path for a user already required to use MFA (`mfa-enrolment-path`). Requiring MFA for all locks out every unenrolled user, and that is a documented limit, not a bug to work around.
- Recovery codes, WebAuthn, SMS and push. The method port admits them later.
- HTTP endpoints for TOTP enrolment or for API key issuance, listing, rotation and revocation. Those are Go APIs the consumer puts behind their own authenticated routes.

---

## File Structure

**`notify/` (new)** — standard library only:

| File | Responsibility |
|---|---|
| `doc.go` | package godoc: the port, the two built-in senders, what each bounds |
| `notify.go` | `Message`, `Sender`, `NonBlocking`, the sentinels |
| `smtp.go` | `SMTPSender`, its one deadline, STARTTLS, encoding |
| `smtpoptions.go` | `SMTPOption` and construction validation |
| `queued.go` | `QueuedSender`, its workers, drop-on-full and `Close` |
| `queuedoptions.go` | `QueuedOption` and construction validation |

**`mfa/` (new)** — imports `factor`, `identity`, `policy`, `ratelimit`, `pkg/logsample`, `pquerna/otp`:

| File | Responsibility |
|---|---|
| `doc.go` | package godoc: the method port, what a lost enrolment must not do |
| `mfa.go` | `Method`, the sentinels, `LookupFor` |
| `store.go` | `Enrolment`, `EnrolmentStore` and its contract godoc |
| `memory.go` | the in-memory `EnrolmentStore` default |
| `totp.go` | `TOTP`: code matching, replay refusal, enrolment |
| `totpoptions.go` | `TOTPOption` and construction validation |
| `throttle.go` | the per-user verification throttle and its sampled logs |

**`apikey/` (new)** — imports `factor`, `identity`, `pkg/id`:

| File | Responsibility |
|---|---|
| `doc.go` | package godoc: shown once, hashed, prefixed, revocable |
| `apikey.go` | `Key`, the sentinels, presented-form parsing |
| `manager.go` | `Manager`: `Issue`, `Verify`, `Revoke`, `Rotate`, `List` |
| `options.go` | `Option` and construction validation |
| `store.go` | the `Store` port and its contract godoc |
| `memory.go` | the in-memory `Store` default |

**`magiclink/` (new)** — imports `factor`, `identity`, `onetime`, `notify`, `policy`:

| File | Responsibility |
|---|---|
| `doc.go` | package godoc: uniform requests, check-then-consume redemption |
| `magiclink.go` | `RequestResult`, `Redemption`, `Check`, the sentinel |
| `manager.go` | `Manager`: `Request`, `Redeem`, `BindingEnabled`, `TTL` |
| `options.go` | `Option` and construction validation, including the synchronous-sender refusal |
| `render.go` | the default neutral renderer and the `Renderer` type |

**`httpsec/` (modified)** — one file per method, matching the package's existing shape:

| File | Responsibility |
|---|---|
| `mfaverify.go` | `EnableMFA`, the verify endpoint, the pending gate |
| `magiclink.go` | `EnableMagicLink`, the request and consume endpoints, binding cookie, accounting |
| `apikey.go` | `EnableAPIKey`, header matching, throttle, stateless phase |
| `options.go` | extended: the three `Enable*` options and their sub-options |
| `chain.go` | extended: the assembly refusal for an unenforced MFA challenge |

**Modified elsewhere:** `session/session.go` and `session/manager.go` (Task 1), `identity/ports.go` (Task 2), `go.mod` (Task 13), `test/testutils.go` and `test/go.mod` (Task 9).

---

## Task 1: The second-factor time and session handle rotation

**Implements:** tasks.md 1.1, 1.2, 1.3

**Files:**
- Modify: `session/session.go` — add `MFASatisfiedAt`, carry it through `clone`
- Modify: `session/manager.go` — add `Rotate`
- Test: `session/rotate_test.go` (create), `session/session_test.go`

**Interfaces:**
- Produces: `session.Session.MFASatisfiedAt time.Time`; `func (m *Manager) Rotate(ctx context.Context, s *Session) (*Session, error)`. Task 28 calls both from the MFA verify endpoint.

- [ ] **Step 1: Write the failing test for the satisfied time**

`MFASatisfiedAt` is library-owned, so it sits beside `MFA` as a field. The point of the test is that it survives a store round-trip and that a consumer cannot forge it through `Data`.

```go
func TestSessionMFASatisfiedAt(t *testing.T) {
	t.Parallel()

	satisfied := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		mutate func(s *session.Session)
		assert func(t *testing.T, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "round-trips through the store",
			mutate: func(s *session.Session) {
				s.MFA = session.MFASatisfied
				s.MFASatisfiedAt = satisfied
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFASatisfied, loaded.MFA)
				assert.True(t, loaded.MFASatisfiedAt.Equal(satisfied))
			},
		},
		{
			name:   "zero until a second factor is accepted",
			mutate: func(s *session.Session) { s.MFA = session.MFAPending },
			assert: func(t *testing.T, loaded *session.Session) {
				assert.True(t, loaded.MFASatisfiedAt.IsZero())
			},
		},
		{
			name: "a consumer data entry cannot forge it",
			mutate: func(s *session.Session) {
				s.MFA = session.MFAPending
				s.Data = map[string]string{"MFASatisfiedAt": satisfied.Format(time.RFC3339)}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFAPending, loaded.MFA)
				assert.True(t, loaded.MFASatisfiedAt.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			m := newTestManager(t)
			s, err := m.Create(ctx, "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			tc.mutate(s)
			require.NoError(t, m.Save(ctx, s))

			loaded, err := m.Load(ctx, s.ID)
			require.NoError(t, err)
			tc.assert(t, loaded)
		})
	}
}
```

`newTestManager` is the helper `session`'s existing tests already use. Reuse it; do not write a second one.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestSessionMFASatisfiedAt -count=1 ./session/`
Add the field as `MFASatisfiedAt time.Time` with no `clone` handling yet, so the test compiles. Expected: FAIL on the round-trip row — the loaded session's time is zero because `clone` drops it.

- [ ] **Step 3: Implement**

In `session/session.go`, beside `MFA`:

```go
	// MFASatisfiedAt is when the second factor was accepted, read from the
	// manager's clock. It is zero until then, including while a challenge is
	// pending. Library-owned, like MFA itself: a consumer cannot set it
	// through Data, so a satisfied second factor is something the library
	// recorded and not something a consumer key can claim.
	MFASatisfiedAt time.Time
```

`clone` copies it with the other value fields — confirm the existing `clone` copies the struct by value and only deep-copies `Data`, in which case no change is needed there, and the failure was in the store's own serialization. Fix it wherever the round-trip actually drops the field.

- [ ] **Step 4: Run it and confirm green**

Run: `go test -run TestSessionMFASatisfiedAt -count=1 ./session/` → PASS.

- [ ] **Step 5: Write the failing test for rotation**

Rotation exists to close session fixation: a handle obtained before the privilege change must not survive it.

```go
func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T) session.Store
		assert func(t *testing.T, m *session.Manager, old *session.Session, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "the old handle stops loading and the new one carries everything",
			store: func(t *testing.T) session.Store { return session.NewMemoryStore() },
			assert: func(t *testing.T, m *session.Manager, old, got *session.Session, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, old.ID, got.ID)
				assert.Equal(t, old.UserID, got.UserID)
				assert.Equal(t, old.FirstFactor, got.FirstFactor)
				assert.Equal(t, old.Data, got.Data)
				assert.True(t, got.CreatedAt.Equal(old.CreatedAt))
				assert.True(t, got.AbsoluteExpiresAt.Equal(old.AbsoluteExpiresAt))

				_, loadErr := m.Load(t.Context(), old.ID)
				assert.Error(t, loadErr)

				reloaded, loadErr := m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.UserID, reloaded.UserID)
			},
		},
		{
			name: "a failed write leaves the old handle loadable",
			store: func(t *testing.T) session.Store {
				return &failingSaveStore{Store: session.NewMemoryStore()}
			},
			assert: func(t *testing.T, m *session.Manager, old, got *session.Session, err error) {
				require.Error(t, err)
				assert.Nil(t, got)

				reloaded, loadErr := m.Load(t.Context(), old.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.ID, reloaded.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			m := newTestManagerWithStore(t, tc.store(t))
			old, err := m.Create(ctx, "u-1", session.WithFirstFactor(factor.MagicLink))
			require.NoError(t, err)
			old.Data = map[string]string{"tenant": "acme"}
			require.NoError(t, m.Save(ctx, old))

			before := old.clone()

			got, err := m.Rotate(ctx, old)
			tc.assert(t, m, before, got, err)
		})
	}
}
```

`failingSaveStore` embeds a real store and returns an error from the write the rotation uses. Write it in the test file; it is three lines and belongs beside the case that needs it.

- [ ] **Step 6: Run it and confirm the red step**

Run: `go test -run TestManagerRotate -count=1 ./session/`
Declare `Rotate` returning `(nil, nil)`, so the test compiles. Expected: FAIL on `require.NoError` reading a nil session — nothing rotated.

- [ ] **Step 7: Implement rotation**

Write first, then delete. The order matters: a delete-then-write that fails in the middle destroys a live session, while a write-then-delete that fails leaves one extra entry the sweeper will expire.

```go
// Rotate moves s to a new identifier and returns it under that identifier.
//
// It exists for the moment a session's privilege changes — a second factor
// accepted, a step-up completed — because a handle someone obtained before
// that change must not still answer requests after it. Everything except the
// identifier is carried over: the user, the first factor, both deadlines, the
// challenge state and the consumer's own data.
//
// The new entry is written before the old one is deleted. A failure of the
// write leaves the old handle working and returns the error, so a caller that
// refuses on the error has lost nothing. A failure of the delete is returned
// too, and the old entry then expires on its own deadline rather than living
// forever.
//
// s is not modified. The returned session is the one to use.
func (m *Manager) Rotate(ctx context.Context, s *Session) (*Session, error) {
	if s == nil {
		return nil, fmt.Errorf("session: rotate was given no session")
	}

	id, err := m.newIdentifier()
	if err != nil {
		return nil, err
	}

	rotated := s.clone()
	rotated.ID = id

	if err := m.store.Save(ctx, rotated); err != nil {
		return nil, err
	}

	if err := m.store.Delete(ctx, s.ID); err != nil {
		return nil, err
	}

	return rotated, nil
}
```

Match the real `Store` method names and the manager's own error style; read `Save` and `Delete` in `manager.go` before writing this, and use `m.store` exactly as its neighbours do.

- [ ] **Step 8: Run it and confirm green**

Run: `go test -run TestManagerRotate -count=1 ./session/` → PASS.

- [ ] **Step 9: Write the concurrency test**

```go
func TestManagerRotateConcurrent(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	m := newTestManager(t)
	s, err := m.Create(ctx, "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	const goroutines = 16

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ids   []string
		start = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			rotated, rotErr := m.Rotate(ctx, s)
			if rotErr == nil {
				mu.Lock()
				ids = append(ids, rotated.ID)
				mu.Unlock()
			}
		}()
	}

	close(start)
	wg.Wait()

	live := 0
	for _, id := range ids {
		if _, loadErr := m.Load(ctx, id); loadErr == nil {
			live++
		}
	}

	assert.Equal(t, 1, live, "exactly one rotated handle may remain loadable")

	_, err = m.Load(ctx, s.ID)
	assert.Error(t, err, "the original handle must not survive")
}
```

- [ ] **Step 10: Run it and confirm the red step, then green**

Run: `go test -run TestManagerRotateConcurrent -race -count=1 ./session/`
Expected first: FAIL — sixteen unconditional write-then-delete pairs leave sixteen live handles. Make the delete of the old identifier the step that decides the winner: a rotation whose delete finds nothing to delete lost the race and must remove the entry it wrote and return an error. Re-run: PASS, with no race reported.

- [ ] **Step 11: Commit**

```bash
git add session/
git commit -m "feat(session): record when a second factor was accepted and rotate handles

A handle obtained before a privilege change no longer survives it, which is
what the MFA verify endpoint needs to close session fixation.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Loading a user by reference

**Implements:** tasks.md 1.4, 1.5

**Files:**
- Modify: `identity/ports.go` — add `LoadByUserID` to `UserLoader`
- Test: `identity/ports_test.go`, `identity/ports_guard_test.go`
- Modify: every `//go:generate mockgen ... UserLoader` output in the tree

**Interfaces:**
- Produces: `identity.UserLoader.LoadByUserID(ctx context.Context, id identity.UserID) (*Details, error)`. Task 26 calls it from magic-link redemption to refuse a reissued username.

- [ ] **Step 1: Write the failing test**

The contract is the one `LoadByUsername` already documents, and the whole reason the method exists is that a miss must be distinguishable from an outage: redemption returns the uniform invalid-link error for both, but it logs them at different levels and only one of them is worth an alert.

```go
func TestUserLoaderLoadByUserID(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		loader identity.UserLoader
		id     identity.UserID
		assert func(t *testing.T, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name:   "a hit returns the details",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {UserID: "u-1", Username: "ada"}}},
			id:     "u-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), d.UserID)
			},
		},
		{
			name:   "a miss is ErrUserNotFound",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
			id:     "u-missing",
			assert: func(t *testing.T, d *identity.Details, err error) {
				assert.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)
			},
		},
		{
			name:   "an outage is not ErrUserNotFound",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
			id:     "u-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)
			},
		},
		{
			name: "the reference is matched byte-for-byte",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {UserID: "u-1"},
			}},
			id: "U-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				assert.ErrorIs(t, err, identity.ErrUserNotFound, "references are not case-folded")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := tc.loader.LoadByUserID(t.Context(), tc.id)
			tc.assert(t, d, err)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestUserLoaderLoadByUserID -count=1 ./identity/`
Add the method to `stubLoader` returning `(nil, nil)` so it compiles. Expected: FAIL on the hit row — nil details.

- [ ] **Step 3: Implement**

`identity` ships no loader, so the work here is the interface and its contract godoc. In `identity/ports.go`:

```go
type UserLoader interface {
	// LoadByUsername loads the user with this username, passed exactly as
	// presented and never trimmed or case-folded. A miss returns ErrUserNotFound;
	// any other failure returns an error that is not ErrUserNotFound, so a caller
	// can tell "no such user" from "the store is down".
	LoadByUsername(ctx context.Context, username string) (*Details, error)

	// LoadByUserID loads the user with this reference, matched byte-for-byte and
	// never parsed, trimmed or case-folded. The same miss-versus-outage contract
	// applies: a miss returns ErrUserNotFound, and any other failure returns an
	// error that is not.
	//
	// A flow that recorded a reference and later resolves it — redeeming a
	// sign-in link, for one — must load by that reference rather than by the
	// username it was requested with. A username is a reusable handle: reissued
	// to another person, it would let a credential minted for the first
	// authenticate the second.
	LoadByUserID(ctx context.Context, id UserID) (*Details, error)
}
```

- [ ] **Step 4: Run it and confirm green**

Run: `go test -run 'TestUserLoaderLoadByUserID|TestPortsGuard' -count=1 ./identity/` → PASS. The guard test walks the port surface; if it enumerates methods, extend its expectation in the same commit.

- [ ] **Step 5: Regenerate the mocks**

Find every consumer with a `UserLoader` mock — `gopls` references on the interface, not grep — and regenerate:

```bash
go generate ./...
go build ./...
(cd ginsec && go build ./...) && (cd fibersec && go build ./...) && (cd test && go build ./...)
make generate-check
```

Any hand-written `UserLoader` stub in a test that now fails to compile gets the method added, returning `ErrUserNotFound` unless the test needs otherwise. Do not convert hand-written stubs to mocks in this task.

- [ ] **Step 6: Run the affected suites**

Run: `go test -count=1 ./...` in the core module, then in `ginsec`, `fibersec` and `test`. All green.

- [ ] **Step 7: Commit**

```bash
git add identity/ && git add -u
git commit -m "feat(identity): load a user by reference, not only by username

A credential that recorded a user reference must resolve it by that reference,
so a reissued username cannot inherit a live credential.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: The notify message, the port and header refusal

**Implements:** tasks.md 2.1, 2.2

**Files:**
- Create: `notify/notify.go`, `notify/doc.go`
- Test: `notify/notify_test.go`, `notify/headers_test.go`

**Interfaces:**
- Produces: `notify.Message{To, From, Subject, TextBody string}`, `notify.Sender`, `notify.NonBlocking`, `notify.ErrUnsafeHeaderValue`, `notify.ErrQueueFull`, `notify.ErrSenderClosed`, and the unexported `refuseUnsafeHeaders(Message) error`. Tasks 4–10 and 23 consume all of it.

- [ ] **Step 1: Write the failing test for the sentinels and the port**

```go
func TestNotifySentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		notify.ErrUnsafeHeaderValue,
		notify.ErrQueueFull,
		notify.ErrSenderClosed,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			assert.NotErrorIs(t, a, b, "sentinels must be distinguishable")
		}
	}

	for _, err := range sentinels {
		assert.NotContains(t, err.Error(), "scrty: ", "each names its own package")
		assert.Contains(t, err.Error(), "notify: ")
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestNotifySentinels -count=1 ./notify/`
Declare the three as `errors.New("")` so it compiles. Expected: FAIL on `assert.Contains` — no message.

- [ ] **Step 3: Implement the message, the port and the sentinels**

```go
// Package notify sends the email scrty's own flows need.
package notify

import (
	"context"
	"errors"
)

// Message is one email. Every field is the consumer's content: the library
// stores and sends it unchanged, and interprets none of it.
//
// TextBody is plain text. There is no HTML body and no template system: the
// messages the library itself sends carry a link and a sentence, and anything
// richer is the consumer's renderer's business.
type Message struct {
	// To is the recipient address. A flow that knows the address it was asked
	// about forces this field, so a renderer cannot redirect a sign-in link.
	To string

	// From is the sender address. Empty means the sender's configured default
	// is used; a sender with no default refuses a message that names none.
	From string

	// Subject is the subject header, encoded by the sender when it is not
	// ASCII.
	Subject string

	// TextBody is the plain-text body, normalised to CRLF by the sender.
	TextBody string
}

// Sender delivers a Message.
//
// This is the port every library component that sends email depends on. A
// consumer's own implementation — a transactional-email API client, a queue, a
// test double — receives every message such a component would have sent,
// unchanged, and the built-in SMTP sender is then not used at all.
//
// An implementation is expected to be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// NonBlocking is implemented by senders whose Send returns without waiting for
// delivery.
//
// A flow whose response time would otherwise reveal whether an address has an
// account asks for this before it will use a sender. Reporting true is a
// promise: Send must not wait on the network. QueuedSender reports true;
// SMTPSender does not implement this interface at all.
type NonBlocking interface {
	NonBlocking() bool
}

var (
	// ErrUnsafeHeaderValue refuses a message whose recipient, sender or
	// subject contains a carriage return or line feed, before anything is
	// sent. The value is never stripped or escaped instead: escaping changes
	// the caller's content silently, and header folding is easy to get subtly
	// wrong.
	ErrUnsafeHeaderValue = errors.New("notify: header value contains a line break")

	// ErrQueueFull reports that a queued sender dropped a message because its
	// queue was full. It never blocks waiting for space.
	ErrQueueFull = errors.New("notify: send queue is full")

	// ErrSenderClosed refuses a send to a sender that has been closed.
	ErrSenderClosed = errors.New("notify: sender is closed")
)
```

- [ ] **Step 4: Run it and confirm green**

Run: `go test -run TestNotifySentinels -count=1 ./notify/` → PASS.

- [ ] **Step 5: Write the failing test for header refusal**

The refusal must happen before any network activity, so the test asserts on a sender pointed at a port nothing listens on: if it dials, it fails with a connection error instead of the sentinel.

```go
func TestSMTPSenderRefusesUnsafeHeaders(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		msg    notify.Message
		assert func(t *testing.T, err error, dialled bool)
	}

	good := notify.Message{
		To:       "ada@example.com",
		From:     "no-reply@example.com",
		Subject:  "Sign in",
		TextBody: "link",
	}

	unsafe := func(mutate func(m *notify.Message)) notify.Message {
		m := good
		mutate(&m)
		return m
	}

	refused := func(t *testing.T, err error, dialled bool) {
		assert.ErrorIs(t, err, notify.ErrUnsafeHeaderValue)
		assert.False(t, dialled, "nothing may be dialled before the refusal")
	}

	cases := []testCase{
		{
			name:   "line break in the subject",
			msg:    unsafe(func(m *notify.Message) { m.Subject = "Hello\r\nBcc: attacker@example.com" }),
			assert: refused,
		},
		{
			name:   "line feed in the recipient",
			msg:    unsafe(func(m *notify.Message) { m.To = "a@example.com\nBcc: b@example.com" }),
			assert: refused,
		},
		{
			name:   "carriage return in the sender",
			msg:    unsafe(func(m *notify.Message) { m.From = "no-reply@example.com\rBcc: b@example.com" }),
			assert: refused,
		},
		{
			name:   "a bare line feed in the body is not a header refusal",
			msg:    unsafe(func(m *notify.Message) { m.TextBody = "line one\nline two" }),
			assert: func(t *testing.T, err error, dialled bool) {
				assert.NotErrorIs(t, err, notify.ErrUnsafeHeaderValue)
				assert.True(t, dialled, "a clean message reaches the network")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dialled atomic.Bool
			s, err := notify.NewSMTPSender("127.0.0.1",
				notify.WithSMTPPort(freePort(t)),
				notify.WithSMTPTimeout(200*time.Millisecond),
				notify.WithSMTPDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialled.Store(true)
					return nil, errors.New("refused")
				}),
			)
			require.NoError(t, err)

			tc.assert(t, s.Send(t.Context(), tc.msg), dialled.Load())
		})
	}
}
```

`WithSMTPDialer` is an unexported-in-spirit seam the package needs anyway for Task 6's deadline test. Export it, and document it as the hook a consumer uses to route SMTP through a proxy or a fixed resolver — a real override, not a test affordance.

- [ ] **Step 6: Run it and confirm the red step**

Run: `go test -run TestSMTPSenderRefusesUnsafeHeaders -count=1 ./notify/`
Expected: FAIL on the first three rows — `dialled` is true and the error is a dial error, because nothing checks the headers yet.

- [ ] **Step 7: Implement**

```go
// refuseUnsafeHeaders rejects a message whose header fields could inject
// headers of their own.
//
// Only the fields that become headers are checked. The body is data: a line
// break in it is content, and it is normalised to CRLF rather than refused.
func refuseUnsafeHeaders(msg Message) error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{"recipient", msg.To},
		{"sender", msg.From},
		{"subject", msg.Subject},
	} {
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("%w: %s", ErrUnsafeHeaderValue, f.name)
		}
	}

	return nil
}
```

The error names the field but never quotes the value: the value is attacker-supplied, and it goes into whatever records the caller's error.

Call it as the first statement of `Send`, before the deadline is fixed and before anything is dialled.

- [ ] **Step 8: Run it and confirm green**

Run: `go test -run TestSMTPSenderRefusesUnsafeHeaders -count=1 ./notify/` → PASS.

- [ ] **Step 9: Commit**

```bash
git add notify/
git commit -m "feat(notify): the sending port, and header injection refused before the dial

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: SMTP construction and the sender address

**Implements:** tasks.md 2.3, 2.4

**Files:**
- Create: `notify/smtp.go`, `notify/smtpoptions.go`
- Test: `notify/smtpoptions_test.go`

**Interfaces:**
- Produces: `notify.NewSMTPSender(host string, opts ...SMTPOption) (*SMTPSender, error)`; options `WithSMTPPort`, `WithSMTPAuth`, `WithSMTPFrom`, `WithSMTPTimeout`, `WithSMTPOpportunisticTLS`, `WithSMTPDialer`, `WithSMTPLogger`. Task 23 refuses this type as a magic-link sender because it does not implement `NonBlocking`.

- [ ] **Step 1: Write the failing construction test**

D13: a missing host or a non-positive timeout is a construction error, not a surprise at first send.

```go
func TestNewSMTPSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		host   string
		opts   []notify.SMTPOption
		assert func(t *testing.T, s *notify.SMTPSender, err error)
	}

	configError := func(t *testing.T, s *notify.SMTPSender, err error) {
		require.Error(t, err)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name: "defaults",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 587, s.Port())
				assert.Equal(t, 30*time.Second, s.Timeout())
			},
		},
		{name: "missing host", host: "", assert: configError},
		{name: "port zero", host: "smtp.example.com", opts: []notify.SMTPOption{notify.WithSMTPPort(0)}, assert: configError},
		{name: "port too high", host: "smtp.example.com", opts: []notify.SMTPOption{notify.WithSMTPPort(65536)}, assert: configError},
		{name: "negative port", host: "smtp.example.com", opts: []notify.SMTPOption{notify.WithSMTPPort(-1)}, assert: configError},
		{name: "zero timeout", host: "smtp.example.com", opts: []notify.SMTPOption{notify.WithSMTPTimeout(0)}, assert: configError},
		{name: "negative timeout", host: "smtp.example.com", opts: []notify.SMTPOption{notify.WithSMTPTimeout(-time.Second)}, assert: configError},
		{
			name: "consumer port and timeout",
			host: "smtp.example.com",
			opts: []notify.SMTPOption{notify.WithSMTPPort(2525), notify.WithSMTPTimeout(5 * time.Second)},
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2525, s.Port())
				assert.Equal(t, 5*time.Second, s.Timeout())
			},
		},
		{
			name: "does not declare itself non-blocking",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				_, ok := any(s).(notify.NonBlocking)
				assert.False(t, ok, "SMTP waits for delivery and must not claim otherwise")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := notify.NewSMTPSender(tc.host, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestNewSMTPSender -count=1 ./notify/`
Expected: FAIL on the refusal rows — construction accepts everything.

- [ ] **Step 3: Implement construction**

```go
// SMTPSender delivers a Message over SMTP submission.
//
// It requires STARTTLS by default, bounds the whole send — dial included — by
// one deadline, and refuses header values that could inject headers. It does
// not implement NonBlocking: Send waits for the server, and a flow that must
// not wait wraps it in a QueuedSender.
type SMTPSender struct {
	host       string
	port       int
	from       string
	auth       smtp.Auth
	timeout    time.Duration
	opportunis bool
	dial       DialFunc
	logger     *slog.Logger
	tlsConfig  *tls.Config
}

// DialFunc opens the connection to the SMTP server.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewSMTPSender builds a sender for host.
//
// Defaults: port 587 (WithSMTPPort), no AUTH (WithSMTPAuth), no default sender
// address (WithSMTPFrom), a 30-second bound on the whole send
// (WithSMTPTimeout), STARTTLS required (WithSMTPOpportunisticTLS relaxes it),
// a net.Dialer (WithSMTPDialer) and a discarding logger (WithSMTPLogger).
//
// Construction fails when host is empty, when the port is outside 1 to 65535,
// or when the timeout is zero or less. Each is a wiring mistake that would
// otherwise only surface at the first send, which for a sign-in link means in
// production, for one user, silently.
func NewSMTPSender(host string, opts ...SMTPOption) (*SMTPSender, error) {
	s := &SMTPSender{
		host:    host,
		port:    defaultSMTPPort,
		timeout: defaultSMTPTimeout,
		dial:    (&net.Dialer{}).DialContext,
		logger:  slog.New(slog.DiscardHandler),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.host == "" {
		return nil, errors.New("notify: smtp sender requires a host")
	}

	if s.port < 1 || s.port > 65535 {
		return nil, fmt.Errorf("notify: smtp port %d is outside 1-65535", s.port)
	}

	if s.timeout <= 0 {
		return nil, fmt.Errorf("notify: smtp timeout must be positive, got %s", s.timeout)
	}

	if s.dial == nil {
		return nil, errors.New("notify: smtp dialer must not be nil")
	}

	if s.tlsConfig == nil {
		s.tlsConfig = &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
	}

	return s, nil
}

// Port reports the port the sender connects to. Default: 587.
func (s *SMTPSender) Port() int { return s.port }

// Timeout reports the bound on a whole send. Default: 30s.
func (s *SMTPSender) Timeout() time.Duration { return s.timeout }
```

Write the options in `smtpoptions.go`, each with godoc naming the default it replaces.

- [ ] **Step 4: Run it and confirm green**

Run: `go test -run TestNewSMTPSender -count=1 ./notify/` → PASS.

- [ ] **Step 5: Write the failing test for the sender address**

```go
func TestSMTPSenderFrom(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		opts     []notify.SMTPOption
		msgFrom  string
		assert   func(t *testing.T, srv *scriptedServer, err error)
	}

	cases := []testCase{
		{
			name:    "the configured default is used when the message names none",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "the message overrides the default",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "support@example.com",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "support@example.com")
				assert.NotContains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "neither is an error before any network activity",
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.Error(t, err)
				assert.False(t, srv.Dialled(), "nothing may be dialled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())
			s, err := notify.NewSMTPSender(srv.Host(), append(tc.opts,
				notify.WithSMTPPort(srv.Port()),
				notify.WithSMTPOpportunisticTLS(),
				notify.WithSMTPDialer(srv.Dial),
			)...)
			require.NoError(t, err)

			tc.assert(t, srv, s.Send(t.Context(), notify.Message{
				To:       "ada@example.com",
				From:     tc.msgFrom,
				Subject:  "Sign in",
				TextBody: "link",
			}))
		})
	}
}
```

This depends on the scripted server from Task 5. Write Task 5 first if the steps are being executed out of order; the two commit together otherwise.

- [ ] **Step 6: Run it and confirm the red step, then implement and confirm green**

Run: `go test -run TestSMTPSenderFrom -count=1 ./notify/`
Expected: FAIL on the third row — a message with no sender reaches the network and the server rejects it there.

Implement in `Send`, right after `refuseUnsafeHeaders`:

```go
	from := msg.From
	if from == "" {
		from = s.from
	}

	if from == "" {
		return errors.New("notify: message names no sender address and the sender has no default")
	}
```

Re-run: PASS.

- [ ] **Step 7: Commit**

```bash
git add notify/
git commit -m "feat(notify): SMTP construction refuses wiring mistakes up front

A missing host, an out-of-range port and a non-positive timeout are
configuration errors rather than a first-send surprise.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: The scripted SMTP server

**Implements:** tasks.md 3.1

**Files:**
- Create: `notify/scriptedserver_test.go`
- Test: `notify/scriptedserver_test.go` (self-verifying)

**Interfaces:**
- Produces, for `notify`'s tests only: `startScriptedServer(t *testing.T, script script) *scriptedServer` with `Host()`, `Port()`, `Dial`, `Dialled() bool`, `Lines() []string`, `MailFrom() string`, `Rcpt() []string`, `Data() string`; and the scripts `scriptOK()`, `scriptSilentGreeting()`, `scriptNoSTARTTLS()`, `scriptBrokenTLS()`, `scriptRejectAt(cmd string)`. Tasks 4, 6, 7 and 8 all drive it.

- [ ] **Step 1: Write the self-test first**

The helper is test infrastructure, so its own red step is a send that must succeed through it.

```go
func TestScriptedServerDelivers(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptOK())

	s, err := notify.NewSMTPSender(srv.Host(),
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPDialer(srv.Dial),
	)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "here is your link",
	}))

	assert.Contains(t, srv.MailFrom(), "no-reply@example.com")
	assert.Contains(t, srv.Rcpt(), "ada@example.com")
	assert.Contains(t, srv.Data(), "here is your link")
	assert.Contains(t, srv.Lines(), "QUIT")
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestScriptedServerDelivers -count=1 ./notify/`
Expected: FAIL to compile until the helper exists, then FAIL on the send — which is the point at which to write the server.

- [ ] **Step 3: Implement the server**

It speaks only as much SMTP as submission needs, and records every line it was sent so a test can assert that `DATA` never happened.

```go
// scriptedServer is an in-process SMTP server whose behaviour each test
// chooses. It exists so the deadline, the STARTTLS rules and the encoding can
// be driven against a server that stalls, lies or refuses on command — none of
// which a real server does reliably.
type scriptedServer struct {
	t   *testing.T
	ln  net.Listener
	scr script

	mu       sync.Mutex
	lines    []string
	mailFrom string
	rcpt     []string
	data     string
	dialled  atomic.Bool
}

// script decides what the server does at each point of the exchange.
type script struct {
	// greet is written on connect. An empty greet means the server accepts the
	// connection and says nothing, which is what a stalled server looks like.
	greet string

	// offerSTARTTLS puts STARTTLS in the EHLO response.
	offerSTARTTLS bool

	// tlsConfig serves the upgrade. Nil with offerSTARTTLS true is a server
	// that advertises STARTTLS and then cannot speak it.
	tlsConfig *tls.Config

	// rejectAt names a command the server answers with 550.
	rejectAt string
}

func scriptOK() script {
	return script{greet: "220 scripted ESMTP ready"}
}

func scriptSilentGreeting() script { return script{} }

func scriptNoSTARTTLS() script { return script{greet: "220 scripted ESMTP ready"} }

func scriptSTARTTLS(t *testing.T) script {
	t.Helper()
	return script{
		greet:         "220 scripted ESMTP ready",
		offerSTARTTLS: true,
		tlsConfig:     selfSignedTLSConfig(t),
	}
}

func scriptBrokenTLS() script {
	return script{greet: "220 scripted ESMTP ready", offerSTARTTLS: true}
}

func scriptRejectAt(cmd string) script {
	return script{greet: "220 scripted ESMTP ready", rejectAt: cmd}
}

func startScriptedServer(t *testing.T, scr script) *scriptedServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &scriptedServer{t: t, ln: ln, scr: scr}

	go srv.accept()

	t.Cleanup(func() { _ = ln.Close() })

	return srv
}

// Dial is the DialFunc the sender under test is given, so the server sees the
// connection attempt even when it intends to stall.
func (s *scriptedServer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	s.dialled.Store(true)
	return (&net.Dialer{}).DialContext(ctx, network, s.ln.Addr().String())
}
```

`accept` loops over connections and serves each with the script: write `greet` (or nothing), answer `EHLO` with `250-<host>` plus `250-STARTTLS` when the script offers it, upgrade on `STARTTLS` when a TLS config is present, record `MAIL FROM`, `RCPT TO` and the `DATA` payload, and answer `550` at `rejectAt`. Record every received line under the mutex; the getters read it under the same mutex. `selfSignedTLSConfig` generates a certificate for `127.0.0.1` with `crypto/x509` at test time — no fixture file.

- [ ] **Step 4: Run it and confirm green**

Run: `go test -run TestScriptedServerDelivers -race -count=1 ./notify/` → PASS, no race.

- [ ] **Step 5: Commit**

```bash
git add notify/scriptedserver_test.go
git commit -m "test(notify): a scriptable in-process SMTP server

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: One deadline bounds the whole send

**Implements:** tasks.md 3.2, 3.3, 3.4

**Files:**
- Modify: `notify/smtp.go`
- Test: `notify/smtpdeadline_test.go`

**Interfaces:**
- Consumes: `scriptedServer` (Task 5), `DialFunc` (Task 4).
- Produces: `(*SMTPSender).Send` with its deadline fixed before the dial.

- [ ] **Step 1: Write the failing tests**

The bound is a *single absolute* deadline. A dial timeout followed by a fresh exchange deadline would allow nearly twice the configured bound, which is the mistake the third case exists to catch.

```go
func TestSMTPSenderDeadline(t *testing.T) {
	t.Parallel()

	t.Run("a server that never greets fails within the bound", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptSilentGreeting())
		s := newTestSMTPSender(t, srv, notify.WithSMTPTimeout(2*time.Second))

		start := time.Now()
		err := s.Send(t.Context(), testMessage())
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.Less(t, elapsed, 3*time.Second, "the bound must hold")
		assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond, "and must not fire early")
	})

	t.Run("a context already ended fails before any network activity", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptOK())
		s := newTestSMTPSender(t, srv)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		require.Error(t, s.Send(ctx, testMessage()))
		assert.False(t, srv.Dialled(), "an ended context must not reach the network")
	})
}

func TestSMTPSenderDeadlineSpansDial(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())

	slowDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return srv.Dial(ctx, network, address)
	}

	s, err := notify.NewSMTPSender(srv.Host(),
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPOpportunisticTLS(),
		notify.WithSMTPTimeout(2*time.Second),
		notify.WithSMTPDialer(slowDial),
	)
	require.NoError(t, err)

	start := time.Now()
	sendErr := s.Send(t.Context(), testMessage())
	elapsed := time.Since(start)

	require.Error(t, sendErr)
	assert.Less(t, elapsed, 3*time.Second,
		"the bound covers the dial: 1.5s connecting plus a stalled greeting must not cost 3.5s")
}

func TestSMTPSenderContextDeadline(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())
	s := newTestSMTPSender(t, srv) // default 30s

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	start := time.Now()
	require.Error(t, s.Send(ctx, testMessage()))
	assert.Less(t, time.Since(start), 2*time.Second, "the earlier caller deadline wins")
}

func TestSMTPSenderCancelMidTransfer(t *testing.T) {
	t.Parallel()

	srv := startScriptedServer(t, scriptSilentGreeting())
	s := newTestSMTPSender(t, srv, notify.WithSMTPTimeout(30*time.Second))

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- s.Send(ctx, testMessage()) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation must unblock a send waiting on the server")
	}
}
```

`newTestSMTPSender` and `testMessage` are two small helpers in the test file; write them once and use them across Tasks 6–8.

- [ ] **Step 2: Run them and confirm the red steps**

Run: `go test -run 'TestSMTPSenderDeadline|TestSMTPSenderContextDeadline|TestSMTPSenderCancelMidTransfer' -count=1 ./notify/`
Expected, with a naive `Send` that dials with the timeout and then sets no connection deadline: the stalled-greeting case hangs until the test's own deadline, and the cancellation case times out at 2s. Read the output and confirm those are the reasons.

- [ ] **Step 3: Implement**

```go
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	if err := refuseUnsafeHeaders(msg); err != nil {
		return err
	}

	from := msg.From
	if from == "" {
		from = s.from
	}

	if from == "" {
		return errors.New("notify: message names no sender address and the sender has no default")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// One absolute deadline, fixed before the dial and never recomputed. A
	// dial timeout followed by a fresh exchange deadline would let a slow
	// server have nearly twice the bound the consumer configured.
	deadline := time.Now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	conn, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// The same deadline governs every read and write of the exchange, so a
	// server that greets and then stalls is bounded exactly as one that never
	// greets.
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	// net/smtp blocks in a read that no context reaches. Forcing the deadline
	// to now is what unblocks it, so a cancelled request does not hold a
	// worker until the deadline it would otherwise wait for.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	return s.exchange(ctx, conn, from, msg)
}
```

`exchange` does the `smtp.NewClient`, `EHLO`, STARTTLS, AUTH, `MAIL FROM`, `RCPT TO`, `DATA` and `QUIT` — Tasks 7 and 8 fill in its TLS and encoding rules.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestSMTPSenderDeadline|TestSMTPSenderContextDeadline|TestSMTPSenderCancelMidTransfer' -race -count=1 ./notify/` → PASS.

- [ ] **Step 5: Confirm the bound cannot be disabled**

There is no option that removes it: `WithSMTPTimeout(0)` is a construction error (Task 4), and the caller's context can only make it earlier. Confirm by reading `smtpoptions.go` that no code path sets `timeout` to a non-positive value after validation.

- [ ] **Step 6: Commit**

```bash
git add notify/
git commit -m "feat(notify): one absolute deadline bounds the dial and the whole SMTP exchange

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: STARTTLS required by default

**Implements:** tasks.md 3.5, 3.6

**Files:**
- Modify: `notify/smtp.go`
- Test: `notify/smtptls_test.go`

**Interfaces:**
- Consumes: `scriptedServer` scripts `scriptSTARTTLS`, `scriptNoSTARTTLS`, `scriptBrokenTLS`.
- Produces: the TLS branch of `exchange`, and `WithSMTPOpportunisticTLS`'s behaviour.

- [ ] **Step 1: Write the failing tests**

D12: these messages carry live sign-in links, and opportunistic STARTTLS can be stripped by an on-path attacker. The safe behaviour is the default; the convenient one is the option.

```go
func TestSMTPSenderRequiresSTARTTLS(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		opts   []notify.SMTPOption
		assert func(t *testing.T, srv *scriptedServer, err error)
	}

	refusedBeforeData := func(t *testing.T, srv *scriptedServer, err error) {
		require.Error(t, err)
		assert.NotContains(t, srv.Lines(), "DATA", "no message data may be sent")
		assert.Empty(t, srv.Data())
	}

	cases := []testCase{
		{
			name:   "a server without STARTTLS is refused",
			script: scriptNoSTARTTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS but cannot speak it is refused",
			script: scriptBrokenTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS is upgraded and delivers",
			script: scriptSTARTTLS(t),
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Lines(), "STARTTLS")
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
		{
			name:   "opportunistic delivers to a local relay without STARTTLS",
			script: scriptNoSTARTTLS(),
			opts:   []notify.SMTPOption{notify.WithSMTPOpportunisticTLS()},
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, tc.script)
			s := newTestSMTPSenderRaw(t, srv, tc.opts...)

			tc.assert(t, srv, s.Send(t.Context(), testMessage()))
		})
	}
}
```

`newTestSMTPSenderRaw` is `newTestSMTPSender` without the automatic `WithSMTPOpportunisticTLS()` the other tasks' helper adds, so these cases exercise the real default.

```go
func TestSMTPSenderOpportunisticTLS(t *testing.T) {
	t.Parallel()

	t.Run("credentials are not sent over an unencrypted non-loopback connection", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptNoSTARTTLS())

		// PlainAuth is constructed for a non-loopback host name, so net/smtp's
		// own rule applies even though the connection goes to the test server.
		s, err := notify.NewSMTPSender("smtp.example.com",
			notify.WithSMTPPort(srv.Port()),
			notify.WithSMTPFrom("no-reply@example.com"),
			notify.WithSMTPOpportunisticTLS(),
			notify.WithSMTPAuth("ada", "hunter2"),
			notify.WithSMTPDialer(srv.Dial),
		)
		require.NoError(t, err)

		err = s.Send(t.Context(), testMessage())
		require.Error(t, err, "net/smtp refuses PLAIN over an unencrypted connection")
		assert.NotContains(t, strings.Join(srv.Lines(), "\n"), "hunter2")
	})
}
```

- [ ] **Step 2: Run them and confirm the red steps**

Run: `go test -run 'TestSMTPSenderRequiresSTARTTLS|TestSMTPSenderOpportunisticTLS' -count=1 ./notify/`
Expected: FAIL on the first two rows — with no TLS rule, the send proceeds in plaintext and `DATA` reaches the server.

- [ ] **Step 3: Implement the TLS branch**

```go
// upgrade applies the sender's encryption rule to an established client.
//
// Required (the default) means the server must offer STARTTLS and the upgrade
// must succeed; anything else fails the send before AUTH or any message data.
// Opportunistic upgrades when the server offers it and otherwise continues in
// plaintext, which exists for a relay on the same host and is documented as
// giving up on-path protection.
func (s *SMTPSender) upgrade(c *smtp.Client) error {
	ok, _ := c.Extension("STARTTLS")

	if !ok {
		if s.opportunis {
			return nil
		}
		return fmt.Errorf("notify: %s does not offer STARTTLS and encryption is required", s.host)
	}

	if err := c.StartTLS(s.tlsConfig); err != nil {
		return fmt.Errorf("notify: STARTTLS upgrade to %s failed: %w", s.host, err)
	}

	return nil
}
```

Call it in `exchange` immediately after `EHLO` and before AUTH or `MAIL FROM`. Leave `smtp.PlainAuth` to enforce the credential rule: it already refuses to send PLAIN over an unencrypted connection except to localhost, and relying on it is better than writing a second copy of the same check.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestSMTPSenderRequiresSTARTTLS|TestSMTPSenderOpportunisticTLS' -race -count=1 ./notify/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add notify/
git commit -m "feat(notify): require STARTTLS by default, with opportunistic as an explicit option

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Encoding and log hygiene

**Implements:** tasks.md 3.7, 3.10

**Files:**
- Modify: `notify/smtp.go`
- Test: `notify/smtpencoding_test.go`

**Interfaces:**
- Produces: the message-building half of `exchange`, and the sender's logging.

- [ ] **Step 1: Write the failing tests**

D14: RFC 5322 header fields are ASCII without SMTPUTF8, so a raw UTF-8 subject can be mangled or rejected.

```go
func TestSMTPSenderEncoding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		msg    notify.Message
		assert func(t *testing.T, data string)
	}

	cases := []testCase{
		{
			name: "a non-ASCII subject is Q-encoded and decodes back exactly",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Masuk ke akun Anda — tautan",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				raw := headerValue(t, data, "Subject")
				assert.True(t, strings.HasPrefix(raw, "=?UTF-8?"), "got %q", raw)

				decoded, err := new(mime.WordDecoder).DecodeHeader(raw)
				require.NoError(t, err)
				assert.Equal(t, "Masuk ke akun Anda — tautan", decoded)
			},
		},
		{
			name: "an ASCII subject is written as-is",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "Sign in", headerValue(t, data, "Subject"))
			},
		},
		{
			name: "bare line feeds in the body are normalised to CRLF",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "line one\nline two",
			},
			assert: func(t *testing.T, data string) {
				body := bodyOf(t, data)
				assert.Contains(t, body, "line one\r\nline two")
				assert.NotRegexp(t, regexp.MustCompile(`[^\r]\n`), body)
			},
		},
		{
			name: "the content type names UTF-8 plain text",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "text/plain; charset=UTF-8", headerValue(t, data, "Content-Type"))
			},
		},
		{
			name: "no header names scrty or any product",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				for name, value := range headersOf(t, data) {
					assert.NotContains(t, strings.ToLower(name), "scrty")
					assert.NotContains(t, strings.ToLower(value), "scrty")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())
			s := newTestSMTPSender(t, srv)

			require.NoError(t, s.Send(t.Context(), tc.msg))
			tc.assert(t, srv.Data())
		})
	}
}
```

`headerValue`, `headersOf` and `bodyOf` parse the recorded `DATA` payload with `net/mail`; write them once in this file.

```go
func TestSMTPSenderLogsCarryNoBody(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := startScriptedServer(t, scriptRejectAt("DATA"))
	s := newTestSMTPSender(t, srv, notify.WithSMTPLogger(logger))

	link := "https://app.example.com/login/magic/confirm?token=abc123secret"
	require.Error(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "Follow " + link + " to sign in.",
	}))

	assert.NotContains(t, buf.String(), link)
	assert.NotContains(t, buf.String(), "abc123secret")
	assert.NotContains(t, buf.String(), "Follow ")
}
```

- [ ] **Step 2: Run them and confirm the red steps**

Run: `go test -run 'TestSMTPSenderEncoding|TestSMTPSenderLogsCarryNoBody' -count=1 ./notify/`
Expected: FAIL on the Q-encoding row (raw UTF-8 in the header) and on the CRLF row.

To be sure the log test can catch a leak, temporarily log the message with `slog.String("body", msg.TextBody)` and re-run: it must fail. Remove it before implementing.

- [ ] **Step 3: Implement**

```go
// build renders msg as the RFC 5322 message to hand to DATA.
//
// The subject is Q-encoded when it is not ASCII, because a header field is
// ASCII without SMTPUTF8 and raw bytes there are mangled or rejected. The body
// is normalised to CRLF, because a bare LF in SMTP data is not a line ending
// and servers disagree about what to do with one. No header names the library
// or any product: a header like that tells anyone with the message which
// software sent it, and buys the consumer nothing.
func build(from string, msg Message) []byte {
	var b strings.Builder

	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + msg.To + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", msg.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(normalizeCRLF(msg.TextBody))

	return []byte(b.String())
}

// normalizeCRLF turns every bare LF into CRLF, leaving existing CRLF pairs
// alone so a body that already uses them is not doubled.
func normalizeCRLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}
```

`mime.QEncoding.Encode` leaves an ASCII-only string untouched, which is what the second row asserts — no branch is needed.

For logging: the sender logs a failure with the recipient's presence, the server host and the error, and never the body or the subject. Write it as `s.logger.LogAttrs(ctx, slog.LevelError, "notify: smtp send failed", slog.String("host", s.host), slog.Any("error", err))`.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestSMTPSenderEncoding|TestSMTPSenderLogsCarryNoBody' -race -count=1 ./notify/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add notify/
git commit -m "feat(notify): encode non-ASCII subjects, normalise the body, name no product

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: The testcontainers SMTP helper and real delivery

**Implements:** tasks.md 3.8, 3.9

**Files:**
- Create or modify: `test/testutils.go`
- Modify: `test/go.mod`
- Create: `test/notify_smtp_test.go`
- Test: also `layout_guard_test.go` at the core root (unchanged, must stay green)

**Interfaces:**
- Produces: `RunTestSMTP(t *testing.T, opts ...TestOption) SMTPConn` in the `test` module, where `SMTPConn` carries `Host`, `Port`, `Username`, `Password` and `Messages(t)` for reading what the server received.

- [ ] **Step 1: Write the failing integration test**

The scripted server proves the rules; the container proves the wire format against a real server.

```go
func TestSMTPSenderIntegration(t *testing.T) {
	t.Parallel()

	conn := RunTestSMTP(t)

	s, err := notify.NewSMTPSender(conn.Host,
		notify.WithSMTPPort(conn.Port),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPAuth(conn.Username, conn.Password),
		notify.WithSMTPOpportunisticTLS(),
	)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Masuk ke akun Anda — tautan",
		TextBody: "line one\nline two",
	}))

	msgs := conn.Messages(t)
	require.Len(t, msgs, 1)

	got := msgs[0]
	assert.Equal(t, "Masuk ke akun Anda — tautan", got.DecodedSubject)
	assert.Contains(t, got.Body, "line one\r\nline two")

	for name, value := range got.Headers {
		assert.NotContains(t, strings.ToLower(name), "scrty")
		assert.NotContains(t, strings.ToLower(value), "scrty")
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestSMTPSenderIntegration -count=1 ./...` in `test`.
Expected: FAIL to compile — `RunTestSMTP` does not exist. That is the cue to write it, not a red step; the red step is the first run after the helper exists, which must fail on an assertion rather than on the helper.

If Docker is unavailable, the helper skips with a clear message and this task is reported as unverified rather than passed. Do not fake it.

- [ ] **Step 3: Add the dependency to the test module only**

```bash
cd test && go get github.com/testcontainers/testcontainers-go@latest && go mod tidy
```

Then confirm it did not reach a production build:

```bash
cd .. && go test -run TestLayoutGuard -count=1 ./...
```

`forbiddenProduction` in `layout_guard_test.go` already lists `github.com/testcontainers/testcontainers-go`, so this is the check that the placement is right. It must stay green.

- [ ] **Step 4: Implement the helper**

One helper per service, in the owning module's `testutils.go`, per the `use-testcontainers` skill. Follow the shape of whatever helper already lives there; if `testutils.go` does not exist yet, create it with this as its first entry.

```go
// SMTPConn is how a test reaches the SMTP server RunTestSMTP started.
type SMTPConn struct {
	Host     string
	Port     int
	Username string
	Password string

	api string // the container's HTTP API, for reading received messages
}

// ReceivedMessage is one message the test server accepted.
type ReceivedMessage struct {
	DecodedSubject string
	Body           string
	Headers        map[string]string
}

// RunTestSMTP starts an SMTP server for one test and returns how to reach it.
//
// The container is torn down with the test. Every test that needs SMTP calls
// this rather than starting its own: one helper means one place to change the
// image, the ports and the readiness rule.
//
// It skips the test when Docker is unavailable, because an unrunnable
// integration test is more useful skipped than failing for a reason that has
// nothing to do with the code.
func RunTestSMTP(t *testing.T, opts ...TestOption) SMTPConn {
	t.Helper()
	// ...start the container, wait for the submission port to accept, read the
	// mapped ports, and register cleanup.
}

// Messages returns what the server has received, newest last.
func (c SMTPConn) Messages(t *testing.T) []ReceivedMessage {
	t.Helper()
	// ...read the container's message API and decode each subject with
	// mime.WordDecoder so the caller compares decoded text.
}
```

Pick an image that exposes both an SMTP submission port and an HTTP API for reading messages, and pin it by digest in one constant beside the helper.

- [ ] **Step 5: Run it and confirm the red step, then green**

Run: `go test -run TestSMTPSenderIntegration -count=1 ./...` in `test`.
First run after the helper exists: it must fail on an assertion — the subject or the CRLF — if Task 8's encoding were wrong. Confirm it passes with Task 8 in place, and confirm it fails when Task 8's `mime.QEncoding.Encode` is temporarily replaced with the raw subject. Restore.

- [ ] **Step 6: Commit**

```bash
git add test/
git commit -m "test: an SMTP container helper, and delivery verified against a real server

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: The queued sender

**Implements:** tasks.md 4.1, 4.2, 4.3, 4.4, 4.5, 4.6

**Files:**
- Create: `notify/queued.go`, `notify/queuedoptions.go`
- Test: `notify/queued_test.go`

**Interfaces:**
- Produces: `notify.NewQueuedSender(inner Sender, opts ...QueuedOption) (*QueuedSender, error)`, `(*QueuedSender).Send`, `(*QueuedSender).Close(ctx) error`, `(*QueuedSender).NonBlocking() bool`; options `WithQueueWorkers`, `WithQueueSize`, `WithQueueSendTimeout`, `WithQueueLogger`. Task 23 requires this type (or another `NonBlocking`) for a magic-link manager.

- [ ] **Step 1: Write the failing construction test**

```go
func TestNewQueuedSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		inner  notify.Sender
		opts   []notify.QueuedOption
		assert func(t *testing.T, s *notify.QueuedSender, err error)
	}

	configError := func(t *testing.T, s *notify.QueuedSender, err error) {
		require.Error(t, err)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name:  "defaults",
			inner: &recordingSender{},
			assert: func(t *testing.T, s *notify.QueuedSender, err error) {
				require.NoError(t, err)
				t.Cleanup(func() { _ = s.Close(context.WithoutCancel(t.Context())) })

				assert.Equal(t, 2, s.Workers())
				assert.Equal(t, 256, s.QueueSize())
				assert.Equal(t, 30*time.Second, s.SendTimeout())
				assert.True(t, s.NonBlocking())
			},
		},
		{name: "no inner sender", inner: nil, assert: configError},
		{name: "typed-nil inner sender", inner: (*recordingSender)(nil), assert: configError},
		{name: "zero workers", inner: &recordingSender{}, opts: []notify.QueuedOption{notify.WithQueueWorkers(0)}, assert: configError},
		{name: "negative workers", inner: &recordingSender{}, opts: []notify.QueuedOption{notify.WithQueueWorkers(-1)}, assert: configError},
		{name: "zero queue", inner: &recordingSender{}, opts: []notify.QueuedOption{notify.WithQueueSize(0)}, assert: configError},
		{name: "zero send timeout", inner: &recordingSender{}, opts: []notify.QueuedOption{notify.WithQueueSendTimeout(0)}, assert: configError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := notify.NewQueuedSender(tc.inner, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
```

The typed-nil row matters: an interface holding a nil pointer is not `== nil`, and a consumer wiring `var s *MySender` into this constructor would otherwise get a panic at the first send. Use `internal/nilcheck.IsNil`.

- [ ] **Step 2: Run it and confirm the red step, then implement construction**

Run: `go test -run TestNewQueuedSender -count=1 ./notify/` → FAIL on the refusal rows.

```go
// QueuedSender hands each message to a pool of workers and returns as soon as
// it is queued.
//
// It exists so a flow's response time does not depend on a mail server. A
// magic-link request that waited for delivery would take measurably longer for
// an address that has an account than for one that does not, which is exactly
// what the flow is built not to reveal.
//
// Messages live only in memory. A crash, or a shutdown that skips Close, loses
// whatever is still queued. A consumer who needs delivery to survive that
// supplies a Sender backed by a durable queue instead.
type QueuedSender struct {
	inner   Sender
	queue   chan Message
	timeout time.Duration
	logger  *slog.Logger

	wg     sync.WaitGroup
	closed atomic.Bool
	mu     sync.RWMutex
}

// NewQueuedSender wraps inner and starts its workers.
//
// Defaults: 2 workers (WithQueueWorkers), a queue of 256 messages
// (WithQueueSize), a 30-second bound on each delivery (WithQueueSendTimeout)
// and a discarding logger (WithQueueLogger). Construction fails on an absent
// inner sender, or a worker count, queue size or send timeout of zero or less.
//
// The workers run until Close, which the consumer calls at shutdown. Wiring
// through di-wiring registers Close as a shutdown hook.
func NewQueuedSender(inner Sender, opts ...QueuedOption) (*QueuedSender, error) {
	cfg := queuedConfig{workers: 2, size: 256, timeout: 30 * time.Second}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if nilcheck.IsNil(inner) {
		return nil, errors.New("notify: queued sender requires a sender to wrap")
	}

	if cfg.workers <= 0 {
		return nil, fmt.Errorf("notify: queued sender workers must be positive, got %d", cfg.workers)
	}

	if cfg.size <= 0 {
		return nil, fmt.Errorf("notify: queued sender queue size must be positive, got %d", cfg.size)
	}

	if cfg.timeout <= 0 {
		return nil, fmt.Errorf("notify: queued sender send timeout must be positive, got %s", cfg.timeout)
	}

	s := &QueuedSender{
		inner:   inner,
		queue:   make(chan Message, cfg.size),
		timeout: cfg.timeout,
		logger:  cfg.logger,
	}

	s.wg.Add(cfg.workers)
	for range cfg.workers {
		go s.work()
	}

	return s, nil
}

// NonBlocking reports true: Send returns once the message is queued.
func (s *QueuedSender) NonBlocking() bool { return true }
```

Re-run: PASS.

- [ ] **Step 3: Write the failing tests for queuing and detachment**

```go
func TestQueuedSenderReturnsBeforeDelivery(t *testing.T) {
	t.Parallel()

	t.Run("returns while the inner sender is still working", func(t *testing.T) {
		t.Parallel()

		inner := &blockingSender{release: make(chan struct{})}
		s := newQueued(t, inner)

		start := time.Now()
		require.NoError(t, s.Send(t.Context(), testMessage()))
		assert.Less(t, time.Since(start), 50*time.Millisecond)

		close(inner.release)
	})

	t.Run("the caller's cancellation does not stop the delivery", func(t *testing.T) {
		t.Parallel()

		inner := &recordingSender{}
		s := newQueued(t, inner)

		ctx, cancel := context.WithCancel(t.Context())
		require.NoError(t, s.Send(ctx, testMessage()))
		cancel()

		require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
		assert.Equal(t, 1, inner.Count())
	})

	t.Run("the caller's values survive", func(t *testing.T) {
		t.Parallel()

		type key struct{}

		var seen atomic.Value
		inner := senderFunc(func(ctx context.Context, _ notify.Message) error {
			seen.Store(ctx.Value(key{}))
			return nil
		})

		s := newQueued(t, inner)

		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "tenant-acme"))
		require.NoError(t, s.Send(ctx, testMessage()))
		cancel()

		require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
		assert.Equal(t, "tenant-acme", seen.Load())
	})
}
```

- [ ] **Step 4: Run and confirm the red step, then implement Send**

Run: `go test -run TestQueuedSenderReturnsBeforeDelivery -count=1 ./notify/` → FAIL.

```go
// Send queues msg and returns.
//
// The caller's context is detached with context.WithoutCancel: its values go
// with the message, because a tenant or a trace belongs to the delivery, while
// its cancellation does not, because the request ending is not a reason to
// abandon a sign-in link. Each delivery is bounded by the send timeout
// instead.
//
// A full queue drops the message and returns ErrQueueFull. It never waits for
// space: waiting would put delivery time back into the caller's response, and
// it would be longest exactly when the system is most loaded.
func (s *QueuedSender) Send(ctx context.Context, msg Message) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed.Load() {
		return ErrSenderClosed
	}

	msg.ctx = context.WithoutCancel(ctx) // unexported field on the queued item

	select {
	case s.queue <- msg:
		return nil
	default:
		s.logger.LogAttrs(ctx, slog.LevelError, "notify: send queue is full, message dropped")
		return ErrQueueFull
	}
}
```

Carrying the context alongside the message needs a small unexported wrapper type rather than a field on the exported `Message` — a context in an exported struct would be part of the consumer's API. Define `type queued struct { msg Message; ctx context.Context }` and make the channel `chan queued`.

Re-run: PASS.

- [ ] **Step 5: Write and pass the remaining behaviour tests**

```go
func TestQueuedSenderFull(t *testing.T) {
	t.Parallel()

	inner := &blockingSender{release: make(chan struct{})}
	s, err := notify.NewQueuedSender(inner,
		notify.WithQueueWorkers(1),
		notify.WithQueueSize(1),
	)
	require.NoError(t, err)

	// One message occupies the single worker.
	require.NoError(t, s.Send(t.Context(), testMessage()))
	inner.WaitStarted(t)

	// One fills the queue of 1.
	require.NoError(t, s.Send(t.Context(), testMessage()))

	// The next has nowhere to go.
	start := time.Now()
	err = s.Send(t.Context(), testMessage())
	assert.ErrorIs(t, err, notify.ErrQueueFull)
	assert.Less(t, time.Since(start), 50*time.Millisecond, "it must not wait for space")

	close(inner.release)
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
}

func TestQueuedSenderClose(t *testing.T) {
	t.Parallel()

	inner := &recordingSender{delay: 100 * time.Millisecond}
	s := newQueued(t, inner)

	for range 3 {
		require.NoError(t, s.Send(t.Context(), testMessage()))
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
	defer cancel()

	require.NoError(t, s.Close(ctx))
	assert.Equal(t, 3, inner.Count(), "close drains what was queued")
	assert.ErrorIs(t, s.Send(t.Context(), testMessage()), notify.ErrSenderClosed)
}

func TestQueuedSenderRecoversPanic(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	inner := senderFunc(func(context.Context, notify.Message) error {
		if calls.Add(1) == 1 {
			panic("inner sender exploded")
		}
		return nil
	})

	s, err := notify.NewQueuedSender(inner, notify.WithQueueWorkers(1))
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

	assert.Equal(t, int64(2), calls.Load(), "the worker survives the panic and takes the next message")
}

func TestQueuedSenderWorkers(t *testing.T) {
	t.Parallel()

	var concurrent, peak atomic.Int64
	inner := senderFunc(func(context.Context, notify.Message) error {
		n := concurrent.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		concurrent.Add(-1)
		return nil
	})

	s, err := notify.NewQueuedSender(inner, notify.WithQueueWorkers(8), notify.WithQueueSize(32))
	require.NoError(t, err)

	for range 16 {
		require.NoError(t, s.Send(t.Context(), testMessage()))
	}
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

	assert.Equal(t, int64(8), peak.Load(), "eight workers run eight deliveries at once")
}

func TestQueuedSenderNoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	s, err := notify.NewQueuedSender(&recordingSender{}, notify.WithQueueWorkers(4))
	require.NoError(t, err)
	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Close(context.WithoutCancel(t.Context())))
}
```

Run each, confirm each red step, then implement:

```go
// work is one worker's loop. It ends when the queue is closed and drained.
func (s *QueuedSender) work() {
	defer s.wg.Done()

	for q := range s.queue {
		s.deliver(q)
	}
}

// deliver sends one message, bounded by the send timeout, and never lets a
// failure or a panic take the worker with it.
//
// The timeout bounds an inner sender that honours context cancellation
// mid-transfer. SMTPSender does. A custom sender that ignores its context can
// occupy a worker for as long as it likes, and this is documented rather than
// defended against: killing a goroutine is not something Go offers.
func (s *QueuedSender) deliver(q queued) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.LogAttrs(q.ctx, slog.LevelError,
				"notify: sender panicked while delivering",
				slog.Any("panic", r))
		}
	}()

	ctx, cancel := context.WithTimeout(q.ctx, s.timeout)
	defer cancel()

	if err := s.inner.Send(ctx, q.msg); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError,
			"notify: delivery failed", slog.Any("error", err))
	}
}

// Close stops intake and waits for what is queued to be delivered, bounded by
// ctx. A send after Close returns ErrSenderClosed.
//
// Call it at shutdown. Messages still queued when the process ends are lost.
func (s *QueuedSender) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed.Swap(true) {
		s.mu.Unlock()
		return nil
	}
	close(s.queue)
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

The `mu` read lock in `Send` and the write lock in `Close` are what stop a send from writing to a channel `Close` is closing. Note in the godoc that the panic is logged and the message is lost — not retried.

- [ ] **Step 6: Run the whole package with the race detector**

Run: `go test -race -count=1 ./notify/` → PASS, no leaks.

- [ ] **Step 7: Commit**

```bash
git add notify/
git commit -m "feat(notify): a queued sender that drops rather than blocks

Delivery leaves the caller's response time, which is what keeps a magic-link
request from taking measurably longer for an address that has an account.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: The MFA method port and the policy lookup

**Implements:** tasks.md 5.1, 5.2, 5.3

**Files:**
- Create: `mfa/mfa.go`, `mfa/doc.go`
- Test: `mfa/mfa_test.go`, `mfa/lookup_test.go`

**Interfaces:**
- Consumes: `policy.MFAMethodLookup`, `factor.Channel`, `internal/nilcheck.IsNil`.
- Produces: `mfa.Method`, `mfa.ErrInvalidCode`, `mfa.ErrAlreadyEnrolled`, `mfa.ErrSameChannel`, `mfa.ErrVerifyThrottled`, `mfa.LookupFor(m Method) (policy.MFAMethodLookup, error)`. Tasks 13–18 and 28 consume all of it.

- [ ] **Step 1: Write the failing test**

`Method` is deliberately a superset of `policy.MFAMethodLookup`, so a method satisfies the policy port with no adapter at all. `LookupFor` exists to *validate* — it is the one place a method with an empty channel is caught (D1).

```go
func TestMethodSatisfiesLookup(t *testing.T) {
	t.Parallel()

	var m mfa.Method = &stubMethod{channel: factor.AuthenticatorApp}

	_, ok := any(m).(policy.MFAMethodLookup)
	assert.True(t, ok, "a Method is usable as a policy lookup without an adapter")
}

func TestMFASentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		mfa.ErrInvalidCode,
		mfa.ErrAlreadyEnrolled,
		mfa.ErrSameChannel,
		mfa.ErrVerifyThrottled,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j {
				assert.NotErrorIs(t, a, b)
			}
		}
		assert.Contains(t, a.Error(), "mfa: ")
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, then implement**

Run: `go test -run 'TestMethodSatisfiesLookup|TestMFASentinels' -count=1 ./mfa/` → FAIL.

```go
// Method is one way a user proves a second factor.
//
// # The channel
//
// Channel is the medium this method's codes travel over, and it must be
// constant for the method's lifetime and never empty. It is compared with the
// channel of the first factor the session was established with: a code that
// arrives the same way the first factor did is not a second factor, and the
// verify endpoint refuses one outright.
//
// The values are factor's. This package defines no channel of its own, so
// there is one vocabulary to read. The built-in TOTP method reports
// factor.AuthenticatorApp, which is the channel of no first-factor kind the
// library names. A consumer's method reports whichever factor channel its
// codes travel over — factor.Email for an emailed one-time code, for one.
//
// # Enrolment answers
//
// Enrolled reports false only when the store definitively holds no confirmed
// enrolment. A store failure, or an enrolment whose secret cannot be read, is
// an error. Reporting either as false would let a login through on its first
// factor for exactly the users who had enrolled, which is the downgrade this
// whole capability exists to prevent.
//
// An implementation is expected to be safe for concurrent use.
type Method interface {
	// Name identifies the method in logs and in a consumer's own routing.
	Name() string

	// Channel reports the medium this method's codes travel over. Constant,
	// never empty.
	Channel() factor.Channel

	// Enrolled reports whether user has a confirmed, readable enrolment.
	Enrolled(ctx context.Context, user identity.UserID) (bool, error)

	// Verify checks code for user. A wrong, reused or malformed code returns
	// ErrInvalidCode.
	Verify(ctx context.Context, user identity.UserID, code string) error
}
```

Declare the four sentinels with `errors.New("mfa: ...")`.

Re-run: PASS.

- [ ] **Step 3: Write the failing test for LookupFor**

```go
func TestLookupFor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method mfa.Method
		assert func(t *testing.T, l policy.MFAMethodLookup, err error)
	}

	configError := func(t *testing.T, l policy.MFAMethodLookup, err error) {
		require.Error(t, err)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:   "a method with a channel",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			assert: func(t *testing.T, l policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, factor.AuthenticatorApp, l.Channel())
			},
		},
		{name: "an empty channel", method: &stubMethod{channel: ""}, assert: configError},
		{name: "a nil method", method: nil, assert: configError},
		{name: "a typed-nil method", method: (*stubMethod)(nil), assert: configError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := mfa.LookupFor(tc.method)
			tc.assert(t, l, err)
		})
	}
}

func TestLookupContract(t *testing.T) {
	t.Parallel()

	outage := errors.New("dial tcp: connection refused")

	type testCase struct {
		name   string
		method mfa.Method
		assert func(t *testing.T, enrolled bool, err error)
	}

	cases := []testCase{
		{
			name:   "a confirmed enrolment is true",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: true},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name:   "no enrolment is false",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: false},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.False(t, enrolled)
			},
		},
		{
			name:   "a store outage is an error, never a false",
			method: &stubMethod{channel: factor.AuthenticatorApp, err: outage},
			assert: func(t *testing.T, enrolled bool, err error) {
				assert.ErrorIs(t, err, outage)
				assert.False(t, enrolled, "and the bool must not be read as an answer")
			},
		},
		{
			name:   "an unreadable secret is an error",
			method: &stubMethod{channel: factor.AuthenticatorApp, err: errors.New("cipher: message authentication failed")},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupFor(tc.method)
			require.NoError(t, err)

			enrolled, lookupErr := l.Enrolled(t.Context(), "u-1")
			tc.assert(t, enrolled, lookupErr)
		})
	}
}
```

- [ ] **Step 4: Run them and confirm the red step, then implement**

Run: `go test -run 'TestLookupFor|TestLookupContract' -count=1 ./mfa/` → FAIL on the refusal rows.

```go
// LookupFor adapts a Method to the lookup the security policies consult.
//
// A Method already has the two methods policy.MFAMethodLookup needs, so this
// is a validating constructor rather than a translation: it is the one place a
// method with no channel is caught. An empty channel equals the channel of an
// unrecorded first factor, so every session established without a recorded
// kind would be refused at verify as a same-channel attempt — a wiring mistake
// whose symptom appears far from its cause, which is why it is refused here.
//
// The returned lookup carries the method's contract unchanged: Enrolled is
// true only for a confirmed, readable enrolment, and a store failure is an
// error rather than a false.
func LookupFor(m Method) (policy.MFAMethodLookup, error) {
	if nilcheck.IsNil(m) {
		return nil, errors.New("mfa: lookup requires a method")
	}

	if m.Channel() == "" {
		return nil, fmt.Errorf("mfa: method %q reports no channel", m.Name())
	}

	return m, nil
}
```

Re-run: PASS.

- [ ] **Step 5: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): the method port, its channel rule and the policy lookup

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: The enrolment store and its in-memory default

**Implements:** tasks.md 5.4, 5.5, 5.6

**Files:**
- Create: `mfa/store.go`, `mfa/memory.go`
- Test: `mfa/memory_test.go`

**Interfaces:**
- Produces: `mfa.Enrolment{User, Secret, ConfirmedAt, LastStep, CreatedAt}`, `mfa.EnrolmentStore` with `Get`, `PutPending`, `Confirm`, `AcceptStep`, `Delete`, and `mfa.NewMemoryEnrolmentStore()`. Tasks 13–16 use them; `durable-persistence` implements the port on each backend.

- [ ] **Step 1: Write the port and its contract godoc**

The port is where the replay guarantee is decided, so its godoc is the specification a durable adapter is written against.

```go
// Enrolment is one user's registration on a method.
type Enrolment struct {
	// User is the consumer's own reference, matched byte-for-byte.
	User identity.UserID

	// Secret is the shared secret. A durable store seals it; an unreadable
	// secret is an error on the way out, never an absent enrolment.
	Secret []byte

	// ConfirmedAt is when a valid code proved the enrolment. Zero means
	// pending, and a pending enrolment is not an enrolment: it does not count
	// as enrolled and cannot satisfy a challenge.
	ConfirmedAt time.Time

	// LastStep is the most recent time step accepted for this user. It is what
	// makes a code single-use within its window.
	LastStep int64

	// CreatedAt is when the enrolment was begun.
	CreatedAt time.Time
}

// EnrolmentStore holds enrolments.
//
// Two of its operations decide an outcome by the write rather than by a
// preceding read, and an implementation that reads first and then writes is
// wrong however careful the read is:
//
//   - PutPending must refuse when a confirmed enrolment exists, decided by the
//     write, so two concurrent begins cannot both replace one confirmed
//     enrolment.
//   - AcceptStep must be one conditional update — set the last step to this
//     one only where the enrolment is confirmed and the recorded step is
//     strictly lower — and report whether it changed anything. On a SQL
//     backend that is a single UPDATE with the condition in its WHERE clause.
//     It is what makes each time step usable once per user, so of concurrent
//     verifications of one code, exactly one succeeds.
//
// A store failure, or a secret that cannot be read, is returned as an error.
// Never as an absent enrolment: a caller reads absence as "this user has no
// second factor" and lets the login through on its first factor.
//
// An implementation is expected to be safe for concurrent use, and must pass
// the store-conformance suite.
type EnrolmentStore interface {
	// Get returns the user's enrolment. The bool is false only when the store
	// definitively holds none.
	Get(ctx context.Context, user identity.UserID) (Enrolment, bool, error)

	// PutPending stores e as a pending enrolment, replacing an existing
	// pending one. It returns ErrAlreadyEnrolled when a confirmed enrolment
	// exists, decided by the write.
	PutPending(ctx context.Context, e Enrolment) error

	// Confirm marks the user's pending enrolment confirmed at the given time
	// and records step. It reports false when there was no pending enrolment
	// to confirm.
	Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error)

	// AcceptStep records step for user in the same operation that decides
	// whether it may be accepted. It reports false when the enrolment is not
	// confirmed, or when the recorded step is already at or past step.
	AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error)

	// Delete removes the user's enrolment. Deleting an absent enrolment is not
	// an error: the caller wanted it gone and it is gone.
	Delete(ctx context.Context, user identity.UserID) error
}
```

- [ ] **Step 2: Write the failing test for the in-memory store**

```go
func TestMemoryEnrolmentStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		run    func(t *testing.T, s mfa.EnrolmentStore) (any, error)
		assert func(t *testing.T, got any, err error)
	}

	cases := []testCase{
		{
			name: "an unknown user holds no enrolment and is not an error",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				_, ok, err := s.Get(t.Context(), "nobody")
				return ok, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
		{
			name: "a pending enrolment is stored and readable",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("secret"), CreatedAt: now,
				}))
				e, _, err := s.Get(t.Context(), "u-1")
				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				e := got.(mfa.Enrolment)
				assert.Equal(t, []byte("secret"), e.Secret)
				assert.True(t, e.ConfirmedAt.IsZero(), "a stored pending enrolment is not confirmed")
			},
		},
		{
			name: "a pending enrolment is replaced by a later begin",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("first")}))
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("second")}))
				e, _, err := s.Get(t.Context(), "u-1")
				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("second"), got.(mfa.Enrolment).Secret)
			},
		},
		{
			name: "a confirmed enrolment refuses a new pending one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("first")}))
				ok, err := s.Confirm(t.Context(), "u-1", 100, now)
				require.NoError(t, err)
				require.True(t, ok)

				return nil, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("second")})
			},
			assert: func(t *testing.T, got any, err error) {
				assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)
			},
		},
		{
			name: "confirming an absent enrolment reports false",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				return s.Confirm(t.Context(), "nobody", 1, now)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
		{
			name: "AcceptStep refuses a pending enrolment",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("s")}))
				return s.AcceptStep(t.Context(), "u-1", 100)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool), "an unconfirmed enrolment accepts no step")
			},
		},
		{
			name: "AcceptStep refuses a step at or below the recorded one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				s2 := confirmed(t, s, "u-1", 100, now)
				first, err := s2.AcceptStep(t.Context(), "u-1", 101)
				require.NoError(t, err)
				require.True(t, first)

				same, err := s2.AcceptStep(t.Context(), "u-1", 101)
				require.NoError(t, err)
				older, err := s2.AcceptStep(t.Context(), "u-1", 100)
				require.NoError(t, err)

				return []bool{same, older}, nil
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []bool{false, false}, got)
			},
		},
		{
			name: "a returned enrolment shares no memory with the stored one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("secret")}))

				e, _, err := s.Get(t.Context(), "u-1")
				require.NoError(t, err)
				e.Secret[0] = 'X'

				again, _, err := s.Get(t.Context(), "u-1")
				return again, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("secret"), got.(mfa.Enrolment).Secret)
			},
		},
		{
			name: "deleting an absent enrolment is not an error",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				return nil, s.Delete(t.Context(), "nobody")
			},
			assert: func(t *testing.T, got any, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.run(t, mfa.NewMemoryEnrolmentStore())
			tc.assert(t, got, err)
		})
	}
}
```

- [ ] **Step 3: Run it and confirm the red step, then implement**

Run: `go test -run TestMemoryEnrolmentStore -count=1 ./mfa/` → FAIL.

Implement with a `sync.RWMutex` and a `map[identity.UserID]Enrolment`, copying `Secret` on the way in and on the way out with `bytes.Clone`. `AcceptStep` and `PutPending` take the write lock and make their decision inside it, which is the in-memory equivalent of the conditional write. Document the type as the non-durable default: enrolments are lost on restart, and because the requirement lives with the user, losing them fails closed rather than open.

Re-run: PASS.

- [ ] **Step 4: Write and pass the concurrency test**

```go
func TestMemoryEnrolmentStoreAcceptStepRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	s := mfa.NewMemoryEnrolmentStore()
	require.NoError(t, s.PutPending(ctx, mfa.Enrolment{User: "u-1", Secret: []byte("s")}))
	ok, err := s.Confirm(ctx, "u-1", 100, time.Now())
	require.NoError(t, err)
	require.True(t, ok)

	const goroutines = 16

	var (
		wg        sync.WaitGroup
		accepted  atomic.Int64
		start     = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if got, stepErr := s.AcceptStep(ctx, "u-1", 101); stepErr == nil && got {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), accepted.Load(), "one step, one acceptance")
}
```

Run: `go test -run TestMemoryEnrolmentStoreAcceptStepRace -race -count=1 ./mfa/` → PASS, no race. If it passes on the first run, confirm it can fail: temporarily split `AcceptStep` into a read, a sleep and a write, and see the count exceed one. Restore.

- [ ] **Step 5: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): the enrolment store contract and its in-memory default

AcceptStep decides acceptance in the write, so one time step is accepted once
per user however many verifications race.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: The otp dependency and TOTP construction

**Implements:** tasks.md 6.1, 6.2, 6.3

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `mfa/totp.go`, `mfa/totpoptions.go`
- Test: `mfa/totpoptions_test.go`

**Interfaces:**
- Produces: `mfa.NewTOTP(store EnrolmentStore, issuer string, opts ...TOTPOption) (*TOTP, error)`; options `WithDigits`, `WithPeriod`, `WithClock`, `WithRandom`. `(*TOTP)` satisfies `mfa.Method`.

- [ ] **Step 1: Add the dependency and confirm the guard**

```bash
go get github.com/pquerna/otp@latest && go mod tidy
go test -run TestLayoutGuard -count=1 ./...
make vuln
```

`boombuler/barcode` arrives as an indirect requirement — it is used only to render a QR image, which scrty does not do. The guard's `forbiddenProduction` and `integrationModules` lists name neither, so it passes. If the guard fails, stop and report rather than editing the guard.

- [ ] **Step 2: Write the failing construction test**

D3: the issuer is required configuration with no brand default, and it goes into the provisioning URI where `:` is the separator — so an issuer containing one is refused rather than silently producing a malformed URI.

```go
func TestNewTOTP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		opts   []mfa.TOTPOption
		assert func(t *testing.T, m *mfa.TOTP, err error)
	}

	configError := func(t *testing.T, m *mfa.TOTP, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
	}

	namesIssuer := func(t *testing.T, m *mfa.TOTP, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
		assert.Contains(t, strings.ToLower(err.Error()), "issuer")
	}

	cases := []testCase{
		{
			name:   "defaults",
			issuer: "Example Payroll",
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				assert.Equal(t, 6, m.Digits())
				assert.Equal(t, 30*time.Second, m.Period())
			},
		},
		{name: "no issuer", issuer: "", assert: namesIssuer},
		{name: "issuer with a colon", issuer: "Example: Payroll", assert: namesIssuer},
		{name: "seven digits", issuer: "Example", opts: []mfa.TOTPOption{mfa.WithDigits(7)}, assert: configError},
		{name: "zero digits", issuer: "Example", opts: []mfa.TOTPOption{mfa.WithDigits(0)}, assert: configError},
		{name: "zero period", issuer: "Example", opts: []mfa.TOTPOption{mfa.WithPeriod(0)}, assert: configError},
		{name: "negative period", issuer: "Example", opts: []mfa.TOTPOption{mfa.WithPeriod(-time.Second)}, assert: configError},
		{
			name:   "eight digits and a consumer period",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithDigits(8), mfa.WithPeriod(60 * time.Second)},
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				assert.Equal(t, 8, m.Digits())
				assert.Equal(t, 60*time.Second, m.Period())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), tc.issuer, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

func TestTOTPChannel(t *testing.T) {
	t.Parallel()

	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	assert.Equal(t, factor.AuthenticatorApp, m.Channel())

	for _, kind := range factor.AllKinds() {
		assert.NotEqual(t, m.Channel(), kind.Channel(),
			"an authenticator code must not arrive on any first factor's channel: %s", kind)
	}
}
```

`factor.AllKinds` lives in `factor/export_test.go`, so it is visible only to that package's tests. Either add an exported enumeration to `factor` in this task, or list the five kinds explicitly here — prefer the explicit list, because adding public API to `factor` is outside this change.

Rewrite the loop as:

```go
	for _, kind := range []factor.Kind{
		factor.Password, factor.Basic, factor.MagicLink, factor.OIDC, factor.APIKey,
	} {
		assert.NotEqual(t, m.Channel(), kind.Channel(), "kind %s", kind)
	}
```

- [ ] **Step 3: Run them and confirm the red step, then implement**

Run: `go test -run 'TestNewTOTP|TestTOTPChannel' -count=1 ./mfa/` → FAIL.

```go
// TOTP is the built-in second-factor method: RFC 6238 time-based codes from an
// authenticator app.
//
// Codes are HMAC-SHA-1 with a tolerance of one step either side. The algorithm
// and the tolerance are fixed rather than configurable, because authenticator
// apps widely ignore any other algorithm parameter in a provisioning URI, so
// an option here would mostly produce enrolments that cannot be used.
type TOTP struct {
	store   EnrolmentStore
	issuer  string
	digits  int
	period  time.Duration
	now     func() time.Time
	random  io.Reader
}

// NewTOTP builds the method for issuer.
//
// issuer is required and appears in every provisioning URI, which is what an
// authenticator app shows beside the code. The library supplies no default:
// a name belongs to the consumer's product, not to scrty, and an issuer that
// was stored but never shown would be worse than none.
//
// Defaults: 6 digits (WithDigits, which also accepts 8), a 30-second step
// (WithPeriod), time.Now (WithClock) and crypto/rand.Reader (WithRandom).
//
// Construction fails on an empty issuer, an issuer containing ':' — the
// separator of the provisioning URI's label — a digit count that is neither 6
// nor 8, and a period of zero or less.
func NewTOTP(store EnrolmentStore, issuer string, opts ...TOTPOption) (*TOTP, error) {
	t := &TOTP{
		store:  store,
		issuer: issuer,
		digits: 6,
		period: 30 * time.Second,
		now:    time.Now,
		random: rand.Reader,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}

	if nilcheck.IsNil(t.store) {
		return nil, errors.New("mfa: totp requires an enrolment store")
	}

	if t.issuer == "" {
		return nil, errors.New("mfa: totp requires an issuer, which the library does not default")
	}

	if strings.Contains(t.issuer, ":") {
		return nil, fmt.Errorf("mfa: totp issuer must not contain ':', got %q", t.issuer)
	}

	if t.digits != 6 && t.digits != 8 {
		return nil, fmt.Errorf("mfa: totp digits must be 6 or 8, got %d", t.digits)
	}

	if t.period <= 0 {
		return nil, fmt.Errorf("mfa: totp period must be positive, got %s", t.period)
	}

	if t.now == nil || t.random == nil {
		return nil, errors.New("mfa: totp clock and random source must not be nil")
	}

	return t, nil
}

// Name reports "totp".
func (t *TOTP) Name() string { return "totp" }

// Channel reports factor.AuthenticatorApp, the channel of no first-factor kind
// the library names.
func (t *TOTP) Channel() factor.Channel { return factor.AuthenticatorApp }

// Digits reports the configured code length. Default: 6.
func (t *TOTP) Digits() int { return t.digits }

// Period reports the configured time step. Default: 30s.
func (t *TOTP) Period() time.Duration { return t.period }
```

Re-run: PASS.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum mfa/
git commit -m "feat(mfa): TOTP construction with a required issuer and no brand default

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: TOTP code matching

**Implements:** tasks.md 6.4, 6.5

**Files:**
- Modify: `mfa/totp.go`
- Test: `mfa/totp_test.go`

**Interfaces:**
- Produces: the unexported `(*TOTP).match(secret []byte, code string, at time.Time) (step int64, ok bool)`, which Task 15 wraps with the store call and Task 16 reuses for confirmation.

- [ ] **Step 1: Write the failing test with the RFC vectors**

```go
// rfc6238SHA1Secret is the ASCII seed RFC 6238 Appendix B uses for HMAC-SHA-1,
// "12345678901234567890", which the test encodes as base32 because that is the
// form an enrolment carries.
const rfc6238SHA1Secret = "12345678901234567890"

func TestTOTPRFC6238Vectors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		unix int64
		code string
	}

	// Appendix B, the SHA-1 rows, at 8 digits.
	cases := []testCase{
		{unix: 59, code: "94287082"},
		{unix: 1111111109, code: "07081804"},
		{unix: 1111111111, code: "14050471"},
		{unix: 1234567890, code: "89005924"},
		{unix: 2000000000, code: "69279037"},
		{unix: 20000000000, code: "65353130"},
	}

	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.unix, 10), func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			at := time.Unix(tc.unix, 0).UTC()
			store := mfa.NewMemoryEnrolmentStore()

			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithDigits(8),
				mfa.WithClock(func() time.Time { return at }),
			)
			require.NoError(t, err)

			enrolConfirmed(t, store, "u-1", []byte(rfc6238SHA1Secret))

			assert.NoError(t, m.Verify(ctx, "u-1", tc.code))
		})
	}
}
```

`enrolConfirmed` writes a confirmed enrolment straight to the store with a `LastStep` well below the step under test, so the verification is not refused as a replay. Write it once in the test file.

```go
func TestTOTPStepWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		offset time.Duration
		mutate func(code string) string
		assert func(t *testing.T, err error)
	}

	ok := func(t *testing.T, err error) { assert.NoError(t, err) }
	invalid := func(t *testing.T, err error) { assert.ErrorIs(t, err, mfa.ErrInvalidCode) }

	cases := []testCase{
		{name: "the current step", offset: 0, assert: ok},
		{name: "one step back", offset: -30 * time.Second, assert: ok},
		{name: "one step forward", offset: 30 * time.Second, assert: ok},
		{name: "two steps back", offset: -60 * time.Second, assert: invalid},
		{name: "two steps forward", offset: 60 * time.Second, assert: invalid},
		{name: "a wrong code", offset: 0, mutate: func(string) string { return "000000" }, assert: invalid},
		{name: "too few digits", offset: 0, mutate: func(c string) string { return c[:5] }, assert: invalid},
		{name: "too many digits", offset: 0, mutate: func(c string) string { return c + "0" }, assert: invalid},
		{name: "not digits", offset: 0, mutate: func(string) string { return "12345a" }, assert: invalid},
		{name: "unicode digits", offset: 0, mutate: func(string) string { return "١٢٣٤٥٦" }, assert: invalid},
		{name: "empty", offset: 0, mutate: func(string) string { return "" }, assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingEnrolmentStore{EnrolmentStore: mfa.NewMemoryEnrolmentStore()}
			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithClock(func() time.Time { return base }),
			)
			require.NoError(t, err)

			secret := []byte(rfc6238SHA1Secret)
			enrolConfirmed(t, store, "u-1", secret)

			code := codeAt(t, secret, base.Add(tc.offset), 6, 30*time.Second)
			if tc.mutate != nil {
				code = tc.mutate(code)
			}

			before := store.AcceptStepCalls()
			tc.assert(t, m.Verify(ctx, "u-1", code))

			if tc.mutate != nil {
				assert.Equal(t, before, store.AcceptStepCalls(),
					"a malformed code must not reach the store")
			}
		})
	}
}
```

`codeAt` computes the expected code with `github.com/pquerna/otp/totp` directly, so the test does not compute it the same way the implementation does.

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestTOTPRFC6238Vectors|TestTOTPStepWindow' -count=1 ./mfa/`
Expected: FAIL — `Verify` returns nothing useful yet. Confirm the vectors fail on the assertion, not on a missing store fixture.

- [ ] **Step 3: Implement matching**

```go
// match finds the time step whose code equals the presented one.
//
// The shape matters. The code is rejected on its form first, so a malformed
// code never reaches the store. Then every candidate step is computed and
// compared in constant time — every one of them, without an early return —
// because returning as soon as one matches leaks, through timing, which step
// the code belonged to.
//
// The window is one step either side. A verifier with no tolerance refuses
// codes from a phone whose clock drifted by seconds; a wider one multiplies
// the codes an attacker may guess at.
func (t *TOTP) match(secret []byte, code string, at time.Time) (int64, bool) {
	if len(code) != t.digits || !isASCIIDigits(code) {
		return 0, false
	}

	step := at.Unix() / int64(t.period.Seconds())

	var (
		matched  int64
		found    bool
	)

	for _, candidate := range []int64{step - 1, step, step + 1} {
		expected, err := codeForStep(secret, candidate, t.digits)
		if err != nil {
			continue
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched, found = candidate, true
		}
	}

	return matched, found
}

// isASCIIDigits reports whether s is entirely ASCII 0-9.
//
// strconv.Atoi would accept a leading sign, and unicode.IsDigit would accept
// digits from other scripts that no authenticator produces. Neither is what a
// six-character numeric code means.
func isASCIIDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return len(s) > 0
}
```

`codeForStep` calls `github.com/pquerna/otp/totp.GenerateCodeCustom` with the step's time, the configured digits and SHA-1.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestTOTPRFC6238Vectors|TestTOTPStepWindow' -count=1 ./mfa/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): RFC 6238 code matching with a one-step window, compared in constant time

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Replay refusal

**Implements:** tasks.md 6.6, 6.7

**Files:**
- Modify: `mfa/totp.go`
- Test: `mfa/totpreplay_test.go`

**Interfaces:**
- Produces: `(*TOTP).Verify` in full — match, then `AcceptStep`, then the result.

- [ ] **Step 1: Write the failing tests**

D2 is a defect claim, and this is its proof: RFC 6238 §5.2 requires that a verifier not accept an OTP a second time after a successful validation.

```go
func TestTOTPReplay(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(func() time.Time { return base }))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)

	code := codeAt(t, secret, base, 6, 30*time.Second)

	require.NoError(t, m.Verify(ctx, "u-1", code), "the first presentation is accepted")
	assert.ErrorIs(t, m.Verify(ctx, "u-1", code), mfa.ErrInvalidCode,
		"the same code within its step is refused")
}

func TestTOTPVerifyRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(func() time.Time { return base }))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)
	code := codeAt(t, secret, base, 6, 30*time.Second)

	const goroutines = 16

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		start    = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if m.Verify(ctx, "u-1", code) == nil {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), accepted.Load(), "exactly one of sixteen may succeed")
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestTOTPReplay|TestTOTPVerifyRace' -race -count=1 ./mfa/`
Expected: FAIL — with `Verify` returning nil on any match, the replay is accepted and all sixteen goroutines succeed. Read the output: the replay case must fail on the second `Verify` returning nil, not on the first.

- [ ] **Step 3: Implement**

```go
// Verify checks code for user.
//
// The order is: read the enrolment, match the code against the accepted steps,
// then ask the store to accept the matched step. The store call is last and is
// the only thing that decides acceptance, because it is the one operation that
// is atomic: a code matched by two concurrent verifications reaches AcceptStep
// twice, and exactly one of those calls changes anything.
//
// Every refusal is ErrInvalidCode — an unknown user, an unconfirmed enrolment,
// a wrong code, a code from outside the window, and a replay. They are
// deliberately indistinguishable: telling them apart would say whether a user
// exists and whether they have enrolled.
//
// A store failure is returned as itself, never as ErrInvalidCode, so a caller
// can tell a refusal from an outage. It is also never reported as "not
// enrolled".
func (t *TOTP) Verify(ctx context.Context, user identity.UserID, code string) error {
	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return err
	}

	if !ok || e.ConfirmedAt.IsZero() {
		return ErrInvalidCode
	}

	step, matched := t.match(e.Secret, code, t.now())
	if !matched {
		return ErrInvalidCode
	}

	accepted, err := t.store.AcceptStep(ctx, user, step)
	if err != nil {
		return err
	}

	if !accepted {
		return ErrInvalidCode
	}

	return nil
}

// Enrolled reports whether user has a confirmed, readable enrolment.
//
// A store failure is an error, never a false. See the Method godoc.
func (t *TOTP) Enrolled(ctx context.Context, user identity.UserID) (bool, error) {
	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return false, err
	}

	return ok && !e.ConfirmedAt.IsZero(), nil
}
```

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestTOTPReplay|TestTOTPVerifyRace' -race -count=1 ./mfa/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): a TOTP code is accepted once per user per time step

RFC 6238 5.2 requires a verifier not accept an OTP a second time after a
successful validation. The store's conditional write is what decides it, so
concurrent verifications of one code yield one success.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: TOTP enrolment

**Implements:** tasks.md 6.8, 6.9, 6.10, 6.11

**Files:**
- Modify: `mfa/totp.go`
- Test: `mfa/totpenrolment_test.go`

**Interfaces:**
- Produces: `mfa.Provisioning{Secret, URI string}`, `(*TOTP).BeginEnrolment(ctx, user, accountLabel) (Provisioning, error)`, `(*TOTP).ConfirmEnrolment(ctx, user, code) error`, `(*TOTP).RemoveEnrolment(ctx, user) error`.

- [ ] **Step 1: Write the failing test for beginning**

```go
func TestTOTPBeginEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		label  string
		random io.Reader
		assert func(t *testing.T, p mfa.Provisioning, err error, stored bool)
	}

	cases := []testCase{
		{
			name:  "the URI names the issuer, the label and the parameters",
			label: "ada@example.com",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.NoError(t, err)
				assert.True(t, stored)

				u, parseErr := url.Parse(p.URI)
				require.NoError(t, parseErr)

				assert.Equal(t, "otpauth", u.Scheme)
				assert.Equal(t, "totp", u.Host)
				assert.Equal(t, "/Example Payroll:ada@example.com", u.Path)
				assert.Equal(t, "Example Payroll", u.Query().Get("issuer"))
				assert.Equal(t, "6", u.Query().Get("digits"))
				assert.Equal(t, "30", u.Query().Get("period"))
				assert.Equal(t, p.Secret, u.Query().Get("secret"))

				raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(p.Secret)
				require.NoError(t, decErr)
				assert.Len(t, raw, 20, "20 bytes from the OS random source")
			},
		},
		{
			name:  "an empty label is refused",
			label: "",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.Error(t, err)
				assert.False(t, stored)
			},
		},
		{
			name:  "a label with a colon is refused",
			label: "ada:example",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.Error(t, err)
				assert.False(t, stored)
			},
		},
		{
			name:   "a random source failure stores nothing",
			label:  "ada@example.com",
			random: failingReader{},
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.Error(t, err)
				assert.False(t, stored, "no pending enrolment may be written")
				assert.Empty(t, p.Secret)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := mfa.NewMemoryEnrolmentStore()

			opts := []mfa.TOTPOption{}
			if tc.random != nil {
				opts = append(opts, mfa.WithRandom(tc.random))
			}

			m, err := mfa.NewTOTP(store, "Example Payroll", opts...)
			require.NoError(t, err)

			p, beginErr := m.BeginEnrolment(ctx, "u-1", tc.label)

			_, stored, getErr := store.Get(ctx, "u-1")
			require.NoError(t, getErr)

			tc.assert(t, p, beginErr, stored)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, then implement**

Run: `go test -run TestTOTPBeginEnrolment -count=1 ./mfa/` → FAIL.

```go
// Provisioning is what a user needs to add the enrolment to an authenticator.
type Provisioning struct {
	// Secret is the shared secret in base32, for a user typing it in.
	Secret string

	// URI is the otpauth:// URI, which an authenticator reads from a QR code
	// the consumer renders. The library renders no image.
	URI string
}

// BeginEnrolment starts an enrolment for user and returns what to show them.
//
// accountLabel is what the authenticator app displays beside the issuer,
// typically the user's email address. It belongs to the consumer and is never
// derived from the user reference, which may be an internal identifier the
// user has never seen and should not be shown. An empty label, or one
// containing ':', is refused: ':' separates the issuer from the label in the
// provisioning URI.
//
// The enrolment is pending until ConfirmEnrolment accepts a code from it. A
// pending enrolment does not count as enrolled and satisfies no challenge, so
// a user who begins and abandons enrolment is exactly where they started.
//
// Beginning again while an enrolment is pending replaces the pending secret.
// Beginning for a user with a confirmed enrolment fails with
// ErrAlreadyEnrolled and changes nothing: replacing a working second factor
// silently is how a user is locked out of their own account.
func (t *TOTP) BeginEnrolment(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, error) {
	if accountLabel == "" {
		return Provisioning{}, errors.New("mfa: totp enrolment requires an account label")
	}

	if strings.Contains(accountLabel, ":") {
		return Provisioning{}, fmt.Errorf("mfa: totp account label must not contain ':', got %q", accountLabel)
	}

	secret := make([]byte, 20)
	if _, err := io.ReadFull(t.random, secret); err != nil {
		return Provisioning{}, fmt.Errorf("mfa: totp could not read a secret: %w", err)
	}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	if err := t.store.PutPending(ctx, Enrolment{
		User:      user,
		Secret:    secret,
		CreatedAt: t.now(),
	}); err != nil {
		return Provisioning{}, err
	}

	return Provisioning{Secret: encoded, URI: t.provisioningURI(accountLabel, encoded)}, nil
}

// provisioningURI builds the otpauth URI. The label is escaped as a path
// segment, so an address with a '+' or a space survives it.
func (t *TOTP) provisioningURI(label, secret string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + t.issuer + ":" + label,
	}

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", t.issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(t.digits))
	q.Set("period", strconv.Itoa(int(t.period.Seconds())))
	u.RawQuery = q.Encode()

	return u.String()
}
```

Note the ordering: the random read happens *before* the store write, so a random failure writes nothing.

Re-run: PASS.

- [ ] **Step 3: Write and pass confirmation, replacement and removal**

```go
func TestTOTPConfirmEnrolment(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		code   func(t *testing.T, secret string) string
		assert func(t *testing.T, m *mfa.TOTP, err error)
	}

	cases := []testCase{
		{
			name: "a valid code confirms",
			code: func(t *testing.T, secret string) string { return codeForSecret(t, secret, base) },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.True(t, enrolled)
			},
		},
		{
			name: "a wrong code does not",
			code: func(t *testing.T, string) string { return "000000" },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.False(t, enrolled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
				mfa.WithClock(func() time.Time { return base }))
			require.NoError(t, err)

			p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
			require.NoError(t, err)

			pending, err := m.Enrolled(ctx, "u-1")
			require.NoError(t, err)
			require.False(t, pending, "a pending enrolment is not an enrolment")

			tc.assert(t, m, m.ConfirmEnrolment(ctx, "u-1", tc.code(t, p.Secret)))
		})
	}
}

func TestTOTPBeginEnrolmentTwice(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(func() time.Time { return base }))
	require.NoError(t, err)

	first, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)

	second, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err, "a pending enrolment is replaced")
	assert.NotEqual(t, first.Secret, second.Secret)

	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, second.Secret, base)))

	_, err = m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

	// The existing authenticator still works: nothing was replaced.
	later := base.Add(time.Minute)
	m2, err := mfa.NewTOTP(storeOf(m), "Example", mfa.WithClock(func() time.Time { return later }))
	require.NoError(t, err)
	assert.NoError(t, m2.Verify(ctx, "u-1", codeForSecret(t, second.Secret, later)))
}

func TestTOTPRemoveEnrolment(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(func() time.Time { return base }))
	require.NoError(t, err)

	p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, base)))

	required := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

	require.NoError(t, m.RemoveEnrolment(ctx, "u-1"))

	enrolled, err := m.Enrolled(ctx, "u-1")
	require.NoError(t, err)
	assert.False(t, enrolled)

	stillRequired, err := required.Required(ctx, "u-1")
	require.NoError(t, err)
	assert.True(t, stillRequired, "removing an enrolment cannot clear the requirement")
}
```

`storeOf` is a test helper that returns the store a method was built with — or, simpler, hold the store in a variable in the test and pass it to both methods. Prefer the variable; do not add an accessor to production code for a test's convenience.

Implement `ConfirmEnrolment` (read the pending enrolment, `match` against its secret, call `store.Confirm` with the matched step, return `ErrInvalidCode` when the match or the confirm fails) and `RemoveEnrolment` (`store.Delete`, with godoc saying it removes only the enrolment record and never the requirement).

Run each, red then green: `go test -run 'TestTOTPConfirmEnrolment|TestTOTPBeginEnrolmentTwice|TestTOTPRemoveEnrolment' -count=1 ./mfa/`.

- [ ] **Step 4: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): TOTP enrolment is begin-then-confirm, and never silently replaced

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: The per-user verification throttle

**Implements:** tasks.md 7.1, 7.2, 7.3, 7.4

**Files:**
- Create: `mfa/throttle.go`
- Test: `mfa/throttle_test.go`

**Interfaces:**
- Consumes: `ratelimit.Limiter`, `pkg/logsample.Sampler`.
- Produces: `mfa.NewVerifyThrottle(opts ...ThrottleOption) (*VerifyThrottle, error)` with `Check(ctx, user) error` and `RecordFailure(ctx, user)`; options `WithVerifyLimiter`, `WithVerifyLogInterval`, `WithVerifyLogger`. Task 28 wires it into the verify endpoint.

- [ ] **Step 1: Write the failing tests**

D4 is a defect claim: an unthrottled 6-digit code with a ±1 step window falls to online guessing within hours. The key is the user, not the source (design decision 6) — the attacker already holds the first factor and can rotate addresses at will, so the user is the resource under attack.

```go
//go:generate mockgen -destination=limiter_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/ratelimit Limiter

func TestVerifyThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limiter func(t *testing.T) ratelimit.Limiter
		assert  func(t *testing.T, th *mfa.VerifyThrottle)
	}

	cases := []testCase{
		{
			name: "five failures in the window then a refusal",
			limiter: func(t *testing.T) ratelimit.Limiter {
				l, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
				require.NoError(t, err)
				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 5 {
					require.NoError(t, th.Check(ctx, "u-1"))
					th.RecordFailure(ctx, "u-1")
				}

				assert.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
			},
		},
		{
			name: "another user is unaffected",
			limiter: func(t *testing.T) ratelimit.Limiter {
				l, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
				require.NoError(t, err)
				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 5 {
					th.RecordFailure(ctx, "u-1")
				}

				assert.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
				assert.NoError(t, th.Check(ctx, "u-2"))
			},
		},
		{
			name: "a success spends nothing",
			limiter: func(t *testing.T) ratelimit.Limiter {
				l, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
				require.NoError(t, err)
				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 100 {
					require.NoError(t, th.Check(ctx, "u-1"))
				}
			},
		},
		{
			name: "a limiter that cannot decide refuses",
			limiter: func(t *testing.T) ratelimit.Limiter {
				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().
					Exceeded(gomock.Any(), gomock.Any()).
					Return(false, errors.New("redis: connection refused")).
					AnyTimes()
				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				assert.ErrorIs(t, th.Check(t.Context(), "u-1"), mfa.ErrVerifyThrottled,
					"an undecidable limiter fails closed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			th, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(tc.limiter(t)))
			require.NoError(t, err)

			tc.assert(t, th)
		})
	}
}

func TestVerifyThrottleConsumerLimiter(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	shared := NewMockLimiter(ctrl)

	shared.EXPECT().Exceeded(gomock.Any(), gomock.Eq("mfa-verify|u-1")).Return(false, nil).Times(1)
	shared.EXPECT().RecordFailure(gomock.Any(), gomock.Eq("mfa-verify|u-1")).Return(nil).Times(1)

	th, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(shared))
	require.NoError(t, err)

	require.NoError(t, th.Check(t.Context(), "u-1"))
	th.RecordFailure(t.Context(), "u-1")
}
```

The expected key names the flow and the user reference. Pin the exact string in the test — a key that silently changes shape pools or splits buckets, and neither is visible from the outside.

```go
func TestVerifyThrottleLogSampling(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	l, err := ratelimit.NewMemoryLimiter(1, 15*time.Minute)
	require.NoError(t, err)

	th, err := mfa.NewVerifyThrottle(
		mfa.WithVerifyLimiter(l),
		mfa.WithVerifyLogger(logger),
		mfa.WithVerifyLogInterval(time.Minute),
	)
	require.NoError(t, err)

	ctx := t.Context()
	th.RecordFailure(ctx, "u-1")

	for range 200 {
		_ = th.Check(ctx, "u-1")
	}

	assert.Equal(t, 1, strings.Count(buf.String(), "mfa: verification throttled"),
		"200 refusals in one window write one record")
}

func TestMFALogsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example",
		mfa.WithClock(func() time.Time { return base }),
		mfa.WithTOTPLogger(logger),
	)
	require.NoError(t, err)

	p, err := m.BeginEnrolment(t.Context(), "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(t.Context(), "u-1", codeForSecret(t, p.Secret, base)))

	assert.ErrorIs(t, m.Verify(t.Context(), "u-1", "123456"), mfa.ErrInvalidCode)

	logged := buf.String()
	assert.NotContains(t, logged, "123456", "a presented code must not be logged")
	assert.NotContains(t, logged, p.Secret, "an enrolment secret must not be logged")
	assert.NotContains(t, logged, p.URI, "a provisioning URI must not be logged")
	assert.NotContains(t, logged, "otpauth://")
}
```

- [ ] **Step 2: Run them and confirm each red step**

Run: `go test -run 'TestVerifyThrottle|TestMFALogsCarryNoSecrets' -count=1 ./mfa/`
Expected: FAIL — nothing throttles yet. For the log test, temporarily log `slog.String("code", code)` in `Verify` and re-run to confirm the assertion can fail. Remove it.

- [ ] **Step 3: Implement**

```go
// VerifyThrottle limits how many failed code verifications one user may
// accumulate.
//
// It is keyed by the user reference rather than by the request's source,
// because by the time a second factor is being verified the attacker already
// holds the first — a password — and can present codes from as many addresses
// as they like. The user is the resource under attack, so the user is what is
// counted.
//
// The price is stated plainly: an attacker who holds a user's password can
// lock that user out of MFA verification for the window. That is accepted, and
// the window and the limiter are both replaceable.
type VerifyThrottle struct {
	limiter  ratelimit.Limiter
	sampler  *logsample.Sampler
	logger   *slog.Logger
}

// throttleFlow prefixes every bucket key, so this flow's failures never share
// a bucket with another flow's.
const throttleFlow = "mfa-verify"

// NewVerifyThrottle builds the throttle.
//
// Defaults: an in-memory limiter of 5 failures per 15 minutes
// (WithVerifyLimiter), a one-minute log-sampling window
// (WithVerifyLogInterval) and a discarding logger (WithVerifyLogger). The
// log interval governs MFA verification logs alone and nothing else.
//
// A nil or typed-nil limiter is a configuration error.
func NewVerifyThrottle(opts ...ThrottleOption) (*VerifyThrottle, error) {
	// ...apply options, default the limiter with ratelimit.NewMemoryLimiter(5, 15*time.Minute),
	// refuse a nil limiter with nilcheck.IsNil, build the sampler.
}

// Check reports whether user may present another code.
//
// A limiter that cannot answer refuses. An undecidable limiter is an outage,
// and an outage that let guesses through would turn a dependency failure into
// an open door.
func (t *VerifyThrottle) Check(ctx context.Context, user identity.UserID) error {
	key := throttleFlow + "|" + string(user)

	exceeded, err := t.limiter.Exceeded(ctx, key)
	if err != nil {
		t.sampled(ctx, "mfa: verification throttle could not be consulted", "limiter-error")
		return ErrVerifyThrottled
	}

	if exceeded {
		t.sampled(ctx, "mfa: verification throttled", "throttled")
		return ErrVerifyThrottled
	}

	return nil
}

// RecordFailure counts one failed verification against user.
//
// A successful verification records nothing: the limit is on guessing, and a
// user who gets it right has not guessed.
func (t *VerifyThrottle) RecordFailure(ctx context.Context, user identity.UserID) {
	if err := t.limiter.RecordFailure(ctx, throttleFlow+"|"+string(user)); err != nil {
		t.sampled(ctx, "mfa: verification failure could not be recorded", "record-error")
	}
}
```

`sampled` keys the sampler by the refusal reason, as the spec requires, and the record carries the reason but never the user's code or secret.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestVerifyThrottle|TestMFALogsCarryNoSecrets' -race -count=1 ./mfa/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add mfa/
git commit -m "feat(mfa): throttle failed code verifications per user

An unthrottled six-digit code with a one-step window falls to online guessing
within hours. The user is keyed rather than the source, because the attacker
already holds the first factor.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 18: Failing closed for a required user

**Implements:** tasks.md 7.5, 7.6

**Files:**
- Test: `mfa/failclosed_test.go`
- Modify: `policy` godoc for the require-for-all option (documentation only)

**Interfaces:**
- Consumes: `policy.NewMFARequirementPolicy`, `mfa.LookupFor`, `identity.MFARequirementLookup`.
- Produces: no new API. This task proves the guarantee end to end.

- [ ] **Step 1: Write the failing test**

Design decision 7 is the whole point of the capability, and it is only real if the test runs the *whole* path — the requirement lookup, the enrolment lookup, the policy — rather than a stub standing in for the policy.

```go
func TestRequiredUserFailsClosed(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name  string
		store func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore
	}

	cases := []testCase{
		{
			name: "the enrolment was removed",
			store: func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore {
				require.NoError(t, healthy.Delete(t.Context(), "u-1"))
				return healthy
			},
		},
		{
			name: "the enrolment store is down",
			store: func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore {
				return failingEnrolmentStore{err: errors.New("dial tcp: connection refused")}
			},
		},
		{
			name: "the stored secret cannot be opened",
			store: func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore {
				return failingEnrolmentStore{err: errors.New("cipher: message authentication failed")}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			// A user who is enrolled and required to use MFA.
			healthy := mfa.NewMemoryEnrolmentStore()
			setup, err := mfa.NewTOTP(healthy, "Example", mfa.WithClock(func() time.Time { return base }))
			require.NoError(t, err)

			p, err := setup.BeginEnrolment(ctx, "u-1", "ada@example.com")
			require.NoError(t, err)
			require.NoError(t, setup.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, base)))

			// Now break the enrolment, leaving the requirement alone.
			method, err := mfa.NewTOTP(tc.store(t, healthy), "Example",
				mfa.WithClock(func() time.Time { return base }))
			require.NoError(t, err)

			lookup, err := mfa.LookupFor(method)
			require.NoError(t, err)

			required := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

			pol, err := policy.NewMFARequirementPolicy(required, lookup)
			require.NoError(t, err)

			engine, err := policy.NewEngine(policy.WithPolicies(pol))
			require.NoError(t, err)

			d := engine.EvaluatePhase(ctx, policy.PostAuthentication, &policy.Input{
				Username:    "ada",
				Principal:   &identity.Principal{ID: "u-1"},
				FirstFactor: factor.Password,
				Now:         base,
			})

			assert.Equal(t, policy.Deny, d.Outcome,
				"a required user with no usable enrolment is refused, never completed on the first factor")
			require.Error(t, d.Reason)
		})
	}
}
```

Read `policy.NewMFARequirementPolicy`'s real signature and `policy.NewEngine`'s real options before writing this; match them exactly rather than the shape sketched here.

```go
func TestRequireForAllLocksOutUnenrolled(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(func() time.Time { return base }))
	require.NoError(t, err)

	lookup, err := mfa.LookupFor(method)
	require.NoError(t, err)

	// Required of everyone, and this user never enrolled.
	pol, err := policy.NewMFARequirementPolicy(policy.RequireForAll(), lookup)
	require.NoError(t, err)

	engine, err := policy.NewEngine(policy.WithPolicies(pol))
	require.NoError(t, err)

	d := engine.EvaluatePhase(ctx, policy.PostAuthentication, &policy.Input{
		Username:    "newcomer",
		Principal:   &identity.Principal{ID: "u-new"},
		FirstFactor: factor.Password,
		Now:         base,
	})

	assert.Equal(t, policy.Deny, d.Outcome)
	require.Error(t, d.Reason)
}
```

`policy.RequireForAll()` stands for whatever the require-for-all configuration actually is; read `policy/mfarequirement.go` and use the real one.

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestRequiredUserFailsClosed|TestRequireForAllLocksOutUnenrolled' -count=1 ./mfa/`
These may pass on the first run, because the policies already deny on a lookup error. That is not a red step. Prove the tests can fail: temporarily change `LookupFor`'s returned lookup to swallow the error and report `false`, and confirm every row flips to `Allow`. Restore, and record in the report that this is how the red step was seen.

- [ ] **Step 3: Confirm the limit is documented**

Read the godoc of the require-for-all option in `policy`. It must say, in its own words:
- enrol users before enabling it, out of band or through a session established by an exempt login;
- a user with no usable enrolment is refused at every non-exempt login and this capability offers them no way to enrol through that refusal;
- `mfa-enrolment-path` will add the path.

If any of that is missing, add it. This is a documentation change to an existing package, which the test-first rule exempts.

Run: `go doc ./policy` and read it back.

- [ ] **Step 4: Commit**

```bash
git add mfa/ policy/
git commit -m "test(mfa): a lost or unreadable enrolment never downgrades a required user

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 19: The API key record, store and construction

**Implements:** tasks.md 8.1, 8.2, 8.3

**Files:**
- Create: `apikey/apikey.go`, `apikey/store.go`, `apikey/memory.go`, `apikey/options.go`, `apikey/doc.go`
- Test: `apikey/apikey_test.go`, `apikey/memory_test.go`, `apikey/options_test.go`

**Interfaces:**
- Produces: `apikey.Key`, `apikey.Store`, `apikey.ErrVerificationFailed`, `apikey.ErrKeyNotFound`, `apikey.NewMemoryStore()`, `apikey.NewManager(opts ...Option) (*Manager, error)`; options `WithStore`, `WithPrefix`, `WithDigest`, `WithIDGenerator`, `WithClock`, `WithRandom`.

- [ ] **Step 1: Write the failing test that the record holds no secret**

```go
func TestKeyCarriesNoSecret(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeFor[apikey.Key]()

	for i := range rt.NumField() {
		name := strings.ToLower(rt.Field(i).Name)
		assert.NotEqual(t, "secret", name, "the record must never hold the secret itself")
		if strings.Contains(name, "secret") {
			assert.Contains(t, name, "digest",
				"a secret-ish field may only be a digest, got %s", rt.Field(i).Name)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, then implement the record**

Run: `go test -run TestKeyCarriesNoSecret -count=1 ./apikey/`
Declare `Key` with a `Secret []byte` field so the test compiles *and fails* — then remove it in the implementation step. That is the red step.

```go
// Key is the stored record of one API key. It never holds the secret.
type Key struct {
	// ID identifies the record and appears in the presented key. It is not a
	// secret: it is a library-owned identifier, so it is a pkg/id.ID.
	ID id.ID

	// Principal is the consumer's own reference for the machine caller this
	// key authenticates. Stored and returned unchanged, never parsed.
	Principal identity.UserID

	// Name is the consumer's label for the key, shown to whoever manages it.
	Name string

	// Scopes are the consumer's own scope strings, stored and returned exactly
	// as given. The library assigns them no meaning; enforcing them is the
	// authorization capability's job.
	Scopes []string

	// SecretDigest is the one-way digest of the secret. The secret itself is
	// never stored, so a leaked store yields nothing that authenticates.
	SecretDigest []byte

	// ExpiresAt is when the key stops being accepted. Nil means it never
	// expires.
	ExpiresAt *time.Time

	// RevokedAt is when the key was revoked. Nil means it is live.
	RevokedAt *time.Time

	// LastUsedAt is when a verification last succeeded, written best effort.
	// Nil means it has never been used.
	LastUsedAt *time.Time

	// CreatedAt is when the key was issued.
	CreatedAt time.Time
}
```

Re-run: PASS.

- [ ] **Step 3: Write the failing construction test**

```go
func TestNewAPIKeyManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []apikey.Option
		assert func(t *testing.T, m *apikey.Manager, err error)
	}

	configError := func(t *testing.T, m *apikey.Manager, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "sk", m.Prefix())
			},
		},
		{name: "uppercase prefix", opts: []apikey.Option{apikey.WithPrefix("Bad-Prefix")}, assert: configError},
		{name: "prefix with a hyphen", opts: []apikey.Option{apikey.WithPrefix("acme-co")}, assert: configError},
		{name: "prefix with an underscore", opts: []apikey.Option{apikey.WithPrefix("ac_me")}, assert: configError},
		{name: "empty prefix", opts: []apikey.Option{apikey.WithPrefix("")}, assert: configError},
		{name: "prefix too long", opts: []apikey.Option{apikey.WithPrefix("abcdefghijklmnopq")}, assert: configError},
		{name: "nil digest", opts: []apikey.Option{apikey.WithDigest(nil)}, assert: configError},
		{name: "nil id generator", opts: []apikey.Option{apikey.WithIDGenerator(nil)}, assert: configError},
		{name: "nil clock", opts: []apikey.Option{apikey.WithClock(nil)}, assert: configError},
		{name: "nil random", opts: []apikey.Option{apikey.WithRandom(nil)}, assert: configError},
		{name: "typed-nil store", opts: []apikey.Option{apikey.WithStore((*apikey.MemoryStore)(nil))}, assert: configError},
		{
			name: "a sixteen-character alphanumeric prefix",
			opts: []apikey.Option{apikey.WithPrefix("acme0123456789ab")},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "acme0123456789ab", m.Prefix())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := apikey.NewManager(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
```

- [ ] **Step 4: Run it and confirm the red step, then implement**

Run: `go test -run TestNewAPIKeyManager -count=1 ./apikey/` → FAIL.

Validate the prefix with an explicit loop over the bytes rather than a regexp — the rule is 1 to 16 of `[a-z0-9]`, and a loop says so without a second language to read. Default the store to `NewMemoryStore()`, the digest to SHA-256, the generator to `pkg/id`'s UUIDv7, the clock to `time.Now` and the random source to `crypto/rand.Reader`, each named in its option's godoc.

Re-run: PASS.

- [ ] **Step 5: Write and pass the in-memory store test**

```go
func TestMemoryKeyStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, s apikey.Store) (any, error)
		assert func(t *testing.T, got any, err error)
	}

	rec := func() apikey.Key {
		return apikey.Key{
			ID:           id.MustParse("01930000-0000-7000-8000-000000000001"),
			Principal:    "svc-billing",
			Name:         "nightly export",
			Scopes:       []string{"invoices:read"},
			SecretDigest: []byte("digest"),
			CreatedAt:    time.Now(),
		}
	}

	cases := []testCase{
		{
			name: "an unknown key is ErrKeyNotFound",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return s.Get(t.Context(), id.MustParse("01930000-0000-7000-8000-00000000ffff"))
			},
			assert: func(t *testing.T, got any, err error) {
				assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
			},
		},
		{
			name: "revoking an unknown key is ErrKeyNotFound",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return nil, s.Revoke(t.Context(), id.MustParse("01930000-0000-7000-8000-00000000ffff"), time.Now())
			},
			assert: func(t *testing.T, got any, err error) {
				assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
			},
		},
		{
			name: "returned scopes are a copy",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))

				got, err := s.Get(t.Context(), k.ID)
				require.NoError(t, err)
				got.Scopes[0] = "invoices:write"

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"invoices:read"}, got.(apikey.Key).Scopes)
			},
		},
		{
			name: "stored scopes are a copy of what was passed in",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))
				k.Scopes[0] = "invoices:write"

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"invoices:read"}, got.(apikey.Key).Scopes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.run(t, apikey.NewMemoryStore())
			tc.assert(t, got, err)
		})
	}
}
```

Implement with a `sync.RWMutex` and `slices.Clone` on `Scopes` and `bytes.Clone` on `SecretDigest`, both directions. Red then green.

- [ ] **Step 6: Commit**

```bash
git add apikey/
git commit -m "feat(apikey): the key record, its store and a prefix that fails construction when wrong

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 20: Issuing and parsing a key

**Implements:** tasks.md 8.4, 8.5

**Files:**
- Create: `apikey/manager.go`
- Test: `apikey/issue_test.go`, `apikey/parse_test.go`

**Interfaces:**
- Produces: `(*Manager).Issue(ctx, principal identity.UserID, name string, scopes []string, lifetime time.Duration) (presented string, rec Key, err error)`, `(*Manager).List(ctx, principal) ([]Key, error)`, and the unexported `parsePresented(string) (id.ID, string, bool)`.

- [ ] **Step 1: Write the failing issue test**

```go
func TestManagerIssue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		principal identity.UserID
		random    io.Reader
		assert    func(t *testing.T, presented string, rec apikey.Key, err error, stored int)
	}

	cases := []testCase{
		{
			name:      "the presented key carries the prefix, the id and the secret",
			principal: "svc-billing",
			assert: func(t *testing.T, presented string, rec apikey.Key, err error, stored int) {
				require.NoError(t, err)
				assert.Equal(t, 1, stored)

				assert.True(t, strings.HasPrefix(presented, "sk_"), "got %q", presented)

				rest := strings.TrimPrefix(presented, "sk_")
				idPart, secretPart, found := strings.Cut(rest, ".")
				require.True(t, found)
				assert.Equal(t, rec.ID.String(), idPart)

				raw, decErr := base64.RawURLEncoding.DecodeString(secretPart)
				require.NoError(t, decErr)
				assert.Len(t, raw, 32, "32 bytes from the OS random source")

				assert.Equal(t, identity.UserID("svc-billing"), rec.Principal)
				assert.NotContains(t, fmt.Sprintf("%+v", rec), secretPart,
					"the record must not carry the secret")
			},
		},
		{
			name:      "an empty principal is refused and stores nothing",
			principal: "",
			assert: func(t *testing.T, presented string, rec apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored)
			},
		},
		{
			name:      "a random source failure stores nothing",
			principal: "svc-billing",
			random:    failingReader{},
			assert: func(t *testing.T, presented string, rec apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored, "the store must receive no write")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}

			opts := []apikey.Option{apikey.WithStore(store)}
			if tc.random != nil {
				opts = append(opts, apikey.WithRandom(tc.random))
			}

			m, err := apikey.NewManager(opts...)
			require.NoError(t, err)

			presented, rec, issueErr := m.Issue(ctx, tc.principal, "nightly export",
				[]string{"invoices:read", "invoices:export"}, 0)

			tc.assert(t, presented, rec, issueErr, store.Writes())
		})
	}
}

func TestListRevealsNoSecret(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	m, err := apikey.NewManager()
	require.NoError(t, err)

	presented, _, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")

	keys, err := m.List(ctx, "svc-billing")
	require.NoError(t, err)
	require.Len(t, keys, 1)

	assert.NotContains(t, fmt.Sprintf("%+v", keys[0]), secret)
}
```

- [ ] **Step 2: Run them and confirm the red step, then implement Issue**

Run: `go test -run 'TestManagerIssue|TestListRevealsNoSecret' -count=1 ./apikey/` → FAIL.

```go
// Issue mints a key for principal and returns it once.
//
// The returned string is the only time the secret exists outside the caller's
// hands: the store receives a digest, and no read of the record ever produces
// the secret again. A caller who loses it issues a new key.
//
// lifetime of zero or less means the key never expires. That is deliberate —
// a machine credential with no rotation schedule is common — and the tradeoff
// is that revocation, not expiry, is what ends such a key. LastUsedAt is what
// finds the ones nobody is using any more.
//
// scopes are the consumer's own strings, stored and returned unchanged. The
// library assigns them no meaning.
func (m *Manager) Issue(
	ctx context.Context,
	principal identity.UserID,
	name string,
	scopes []string,
	lifetime time.Duration,
) (string, Key, error) {
	if principal == "" {
		return "", Key{}, errors.New("apikey: a key requires a principal reference")
	}

	// Everything that can fail without touching the store happens first, so a
	// failure here leaves nothing behind.
	secret := make([]byte, 32)
	if _, err := io.ReadFull(m.random, secret); err != nil {
		return "", Key{}, fmt.Errorf("apikey: could not read a secret: %w", err)
	}

	keyID, err := m.ids.New()
	if err != nil {
		return "", Key{}, err
	}

	now := m.now()

	rec := Key{
		ID:           keyID,
		Principal:    principal,
		Name:         name,
		Scopes:       slices.Clone(scopes),
		SecretDigest: m.digest(secret),
		CreatedAt:    now,
	}

	if lifetime > 0 {
		expires := now.Add(lifetime)
		rec.ExpiresAt = &expires
	}

	if err := m.store.Put(ctx, rec); err != nil {
		return "", Key{}, err
	}

	presented := m.prefix + "_" + keyID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)

	return presented, rec, nil
}
```

Re-run: PASS.

- [ ] **Step 3: Write the failing parse test**

```go
func TestManagerParsePresented(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		presented func(valid string) string
	}

	cases := []testCase{
		{name: "empty", presented: func(string) string { return "" }},
		{name: "no prefix", presented: func(v string) string { return strings.TrimPrefix(v, "sk_") }},
		{name: "wrong prefix", presented: func(v string) string { return "acme_" + strings.TrimPrefix(v, "sk_") }},
		{name: "prefix only", presented: func(string) string { return "sk_" }},
		{name: "no dot", presented: func(v string) string { return strings.ReplaceAll(v, ".", "") }},
		{name: "unparsable id", presented: func(string) string { return "sk_not-an-id.c2VjcmV0" }},
		{name: "empty secret", presented: func(v string) string { return v[:strings.Index(v, ".")+1] }},
		{name: "prefix of the prefix", presented: func(v string) string { return "s_" + strings.TrimPrefix(v, "sk_") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}
			m, err := apikey.NewManager(apikey.WithStore(store))
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			before := store.Reads()

			_, _, verifyErr := m.Verify(ctx, tc.presented(valid))
			assert.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)
			assert.Equal(t, before, store.Reads(), "a malformed key must not reach the store")
		})
	}
}
```

- [ ] **Step 4: Run it and confirm the red step, then implement parsing**

Run: `go test -run TestManagerParsePresented -count=1 ./apikey/` → FAIL.

```go
// parsePresented splits a presented key into its record identifier and its
// secret.
//
// It is strict on purpose, and it runs before any store call: a key whose
// shape is wrong is refused without a lookup, so a scanner firing malformed
// strings at the endpoint costs one string comparison rather than a query.
//
// The prefix is matched with the underscore attached, so a configured prefix
// of "s" does not accept a key issued under "sk".
func (m *Manager) parsePresented(presented string) (id.ID, string, bool) {
	rest, ok := strings.CutPrefix(presented, m.prefix+"_")
	if !ok {
		return id.ID{}, "", false
	}

	idPart, secret, ok := strings.Cut(rest, ".")
	if !ok || secret == "" {
		return id.ID{}, "", false
	}

	parsed, err := id.Parse(idPart)
	if err != nil {
		return id.ID{}, "", false
	}

	return parsed, secret, true
}
```

Re-run: PASS.

- [ ] **Step 5: Commit**

```bash
git add apikey/
git commit -m "feat(apikey): issue a key shown once, and refuse a malformed one without a lookup

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 21: Verifying a key

**Implements:** tasks.md 8.6, 8.7

**Files:**
- Modify: `apikey/manager.go`
- Test: `apikey/verify_test.go`

**Interfaces:**
- Produces: `(*Manager).Verify(ctx, presented string) (identity.Principal, Key, error)`, `(*Manager).Revoke(ctx, id id.ID) error`.

- [ ] **Step 1: Write the failing test**

Every failure is one error. A revoked key that looked different from an unknown one would tell a scanner which identifiers were ever real.

```go
func TestManagerVerify(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		prepare func(t *testing.T, m *apikey.Manager, valid string) (presented string)
		store   func(inner apikey.Store) apikey.Store
		at      time.Time
		assert  func(t *testing.T, p identity.Principal, rec apikey.Key, err error)
	}

	refused := func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Empty(t, p.ID)
	}

	cases := []testCase{
		{
			name:    "a valid key yields a service principal",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string { return valid },
			at:      base,
			assert: func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.KindService, p.Kind)
				assert.True(t, p.IsService())
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.DisplayName)
				assert.Equal(t, []string{"invoices:read", "invoices:export"}, p.Scopes)
			},
		},
		{
			name: "an unknown identifier",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string {
				other, _ := id.New()
				_, secret, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")
				return "sk_" + other.String() + "." + secret
			},
			at:     base,
			assert: refused,
		},
		{
			name: "a wrong secret",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")
				return "sk_" + idPart + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "an expired key",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string { return valid },
			at:      base.Add(8 * 24 * time.Hour),
			assert:  refused,
		},
		{
			name: "a revoked key",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")
				parsed, err := id.Parse(idPart)
				require.NoError(t, err)
				require.NoError(t, m.Revoke(t.Context(), parsed))
				return valid
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "a store outage",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string { return valid },
			store:   func(inner apikey.Store) apikey.Store { return failingKeyStore{err: errors.New("dial tcp: connection refused")} },
			at:      base,
			assert:  refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			now := base
			inner := apikey.NewMemoryStore()

			m, err := apikey.NewManager(
				apikey.WithStore(inner),
				apikey.WithClock(func() time.Time { return now }),
			)
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "nightly export",
				[]string{"invoices:read", "invoices:export"}, 7*24*time.Hour)
			require.NoError(t, err)

			presented := tc.prepare(t, m, valid)

			verifier := m
			if tc.store != nil {
				verifier, err = apikey.NewManager(
					apikey.WithStore(tc.store(inner)),
					apikey.WithClock(func() time.Time { return now }),
				)
				require.NoError(t, err)
			}

			now = tc.at

			p, rec, verifyErr := verifier.Verify(ctx, presented)
			tc.assert(t, p, rec, verifyErr)
		})
	}
}

func TestManagerExpiry(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	now := base

	m, err := apikey.NewManager(apikey.WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	never, _, err := m.Issue(ctx, "svc-billing", "forever", nil, 0)
	require.NoError(t, err)

	now = base.AddDate(5, 0, 0)

	_, _, err = m.Verify(ctx, never)
	assert.NoError(t, err, "a lifetime of zero or less never expires")
}

func TestManagerRevoke(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	m, err := apikey.NewManager()
	require.NoError(t, err)

	presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
	require.NoError(t, err)

	_, _, err = m.Verify(ctx, presented)
	require.NoError(t, err)

	require.NoError(t, m.Revoke(ctx, rec.ID))

	_, _, err = m.Verify(ctx, presented)
	assert.ErrorIs(t, err, apikey.ErrVerificationFailed)

	unknown, err := id.New()
	require.NoError(t, err)
	assert.ErrorIs(t, m.Revoke(ctx, unknown), apikey.ErrKeyNotFound)
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestManagerVerify|TestManagerExpiry|TestManagerRevoke' -count=1 ./apikey/`
Expected: FAIL — `Verify` is not written. Confirm the outage row fails on the *uniform* error, not on a different one leaking through.

- [ ] **Step 3: Implement**

```go
// Verify checks a presented key and returns the principal it authenticates.
//
// Every failure is ErrVerificationFailed: a wrong shape, an unknown
// identifier, a wrong secret, an expired key, a revoked key and a store
// outage. They are one error on purpose. A caller who could tell them apart
// could enumerate which identifiers were ever issued, and an outage that
// looked different from a refusal would say when the store was down.
//
// The digest comparison is constant time, so the length of a shared prefix
// between a guess and the stored digest cannot be measured.
//
// No error and no log record written here contains the presented key.
func (m *Manager) Verify(ctx context.Context, presented string) (identity.Principal, Key, error) {
	keyID, secret, ok := m.parsePresented(presented)
	if !ok {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	rec, err := m.store.Get(ctx, keyID)
	if err != nil {
		// Including ErrKeyNotFound: an unknown key and an unreachable store
		// are the same answer to whoever asked.
		m.logger.LogAttrs(ctx, levelFor(err), "apikey: verification failed",
			slog.Any("error", err))
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	if subtle.ConstantTimeCompare(m.digest(raw), rec.SecretDigest) != 1 {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	now := m.now()

	if rec.RevokedAt != nil || (rec.ExpiresAt != nil && now.After(*rec.ExpiresAt)) {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	// Best effort: a key that works must not stop working because the store
	// could not record when it was last used.
	if err := m.store.TouchLastUsed(ctx, rec.ID, now); err != nil {
		m.logger.LogAttrs(ctx, slog.LevelWarn, "apikey: could not record last use",
			slog.Any("error", err))
	}

	rec.LastUsedAt = &now

	return identity.Principal{
		ID:          rec.Principal,
		Kind:        identity.KindService,
		DisplayName: rec.Name,
		Scopes:      slices.Clone(rec.Scopes),
	}, rec, nil
}
```

Check the real `identity.Principal` field names before writing this — the design writes `Principal{ID: ...}` and the struct may spell it differently.

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestManagerVerify|TestManagerExpiry|TestManagerRevoke' -count=1 ./apikey/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add apikey/
git commit -m "feat(apikey): verification is uniform, constant-time and says nothing about the cause

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 22: Rotation, last use and the consumer overrides

**Implements:** tasks.md 8.8, 8.9, 8.10

**Files:**
- Modify: `apikey/manager.go`
- Test: `apikey/rotate_test.go`, `apikey/overrides_test.go`

**Interfaces:**
- Produces: `(*Manager).Rotate(ctx, id id.ID, lifetime time.Duration) (string, Key, error)`.

- [ ] **Step 1: Write the failing rotation test**

```go
func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(inner apikey.Store) apikey.Store
		target func(t *testing.T, rec apikey.Key) id.ID
		assert func(t *testing.T, m *apikey.Manager, old string, fresh string, err error)
	}

	cases := []testCase{
		{
			name:   "the new key works and the old one does not",
			target: func(t *testing.T, rec apikey.Key) id.ID { return rec.ID },
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, err error) {
				require.NoError(t, err)

				p, _, verifyErr := m.Verify(t.Context(), fresh)
				require.NoError(t, verifyErr)
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.DisplayName)
				assert.Equal(t, []string{"invoices:read"}, p.Scopes)

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.ErrorIs(t, oldErr, apikey.ErrVerificationFailed)
			},
		},
		{
			name: "an unknown key issues nothing",
			target: func(t *testing.T, rec apikey.Key) id.ID {
				other, err := id.New()
				require.NoError(t, err)
				return other
			},
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				assert.Len(t, keys, 1, "nothing new may be issued for an unknown key")
			},
		},
		{
			name:   "a failed revoke is an error rather than a silently split credential",
			store:  func(inner apikey.Store) apikey.Store { return revokeFailsStore{Store: inner} },
			target: func(t *testing.T, rec apikey.Key) id.ID { return rec.ID },
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh, "the new key is returned only when both steps succeed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner)
			}

			m, err := apikey.NewManager(apikey.WithStore(store))
			require.NoError(t, err)

			old, rec, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
			require.NoError(t, err)

			fresh, _, rotateErr := m.Rotate(ctx, tc.target(t, rec), 0)
			tc.assert(t, m, old, fresh, rotateErr)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, then implement**

Run: `go test -run TestManagerRotate -count=1 ./apikey/` → FAIL.

```go
// Rotate issues a replacement for the key with this identifier and revokes the
// old one.
//
// The replacement carries the same principal reference, name and scopes, with
// whatever lifetime the caller gives — rotation is for replacing a secret, not
// for changing what a key may do.
//
// # Atomicity
//
// These are two writes. Outside a transaction the caller attached to the store
// — through the adapter's WithTx or its transaction resolver — a failure
// between them leaves the new key issued and the old one live, and the error
// says so. Inside an attached transaction, a rollback undoes both.
//
// The new key is returned only when both steps succeed, so a caller that acts
// on the returned string is acting on a completed rotation.
func (m *Manager) Rotate(ctx context.Context, keyID id.ID, lifetime time.Duration) (string, Key, error) {
	existing, err := m.store.Get(ctx, keyID)
	if err != nil {
		return "", Key{}, err
	}

	presented, rec, err := m.Issue(ctx, existing.Principal, existing.Name, existing.Scopes, lifetime)
	if err != nil {
		return "", Key{}, err
	}

	if err := m.store.Revoke(ctx, keyID, m.now()); err != nil {
		return "", Key{}, fmt.Errorf("apikey: rotated key %s was issued but %s could not be revoked: %w",
			rec.ID, keyID, err)
	}

	return presented, rec, nil
}
```

The error text names both identifiers, because an operator reading it needs to know which key to revoke by hand. Neither identifier is a secret.

Re-run: PASS.

- [ ] **Step 3: Write and pass the last-use test**

```go
func TestManagerLastUsed(t *testing.T) {
	t.Parallel()

	t.Run("a successful verification records the time", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
		store := apikey.NewMemoryStore()

		m, err := apikey.NewManager(
			apikey.WithStore(store),
			apikey.WithClock(func() time.Time { return at }),
		)
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, _, err = m.Verify(ctx, presented)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)
		require.NotNil(t, stored.LastUsedAt)
		assert.True(t, stored.LastUsedAt.Equal(at))
	})

	t.Run("a failure to record does not fail verification", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		inner := apikey.NewMemoryStore()
		m, err := apikey.NewManager(apikey.WithStore(touchFailsStore{Store: inner}))
		require.NoError(t, err)

		presented, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, _, err = m.Verify(ctx, presented)
		assert.NoError(t, err, "a best-effort write may not refuse a valid key")
	})
}
```

Red then green — the second case fails if `Verify` returns the touch error.

- [ ] **Step 4: Write and pass the overrides test**

```go
func TestAPIKeyConsumerOverrides(t *testing.T) {
	t.Parallel()

	t.Run("a consumer prefix, and a key from another prefix is refused without a lookup", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		def, err := apikey.NewManager()
		require.NoError(t, err)
		underDefault, _, err := def.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}
		acme, err := apikey.NewManager(apikey.WithPrefix("acme"), apikey.WithStore(store))
		require.NoError(t, err)

		underAcme, _, err := acme.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(underAcme, "acme_"))

		before := store.Reads()
		_, _, err = acme.Verify(ctx, underDefault)
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Equal(t, before, store.Reads(), "a wrong prefix costs no lookup")
	})

	t.Run("a consumer digest is used for issuance and verification", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		digest := func(b []byte) []byte {
			sum := sha512.Sum512(b)
			return sum[:]
		}

		store := apikey.NewMemoryStore()
		m, err := apikey.NewManager(apikey.WithStore(store), apikey.WithDigest(digest))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")
		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)
		assert.Equal(t, digest(raw), stored.SecretDigest)

		_, _, err = m.Verify(ctx, presented)
		assert.NoError(t, err)
	})

	t.Run("a consumer store serves every operation", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}
		m, err := apikey.NewManager(apikey.WithStore(store))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)
		_, _, err = m.Verify(ctx, presented)
		require.NoError(t, err)
		_, err = m.List(ctx, "svc-billing")
		require.NoError(t, err)
		_, _, err = m.Rotate(ctx, rec.ID, 0)
		require.NoError(t, err)

		assert.Positive(t, store.Writes())
		assert.Positive(t, store.Reads())
		assert.Positive(t, store.Lists())
	})
}
```

- [ ] **Step 5: Report what could not be closed**

The spec's scenario "Revoke fails inside a transaction … the transaction is rolled back … no new key exists and the old key still verifies" needs a store that can carry a transaction. None exists until `durable-persistence` lands. Record in the task report: `UNREPRODUCED — no transactional store exists; belongs to store-conformance in durable-persistence`. Do not weaken the scenario, and do not invent a transaction abstraction here.

- [ ] **Step 6: Run the package and commit**

Run: `go test -race -count=1 ./apikey/` → PASS.

```bash
git add apikey/
git commit -m "feat(apikey): rotation, best-effort last use, and the consumer overrides

Rotation is two writes outside an attached transaction, and says so.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 23: The magic-link manager's construction

**Implements:** tasks.md 9.1, 9.2, 9.3, 9.4

**Files:**
- Create: `magiclink/magiclink.go`, `magiclink/manager.go`, `magiclink/options.go`, `magiclink/render.go`, `magiclink/doc.go`
- Test: `magiclink/options_test.go`

**Interfaces:**
- Consumes: `notify.Sender`, `notify.NonBlocking`, `onetime.Manager`, `identity.UserLoader`.
- Produces: `magiclink.NewManager(tokens *onetime.Manager, users identity.UserLoader, sender notify.Sender, linkBaseURL string, opts ...Option) (*Manager, error)`, `(*Manager).BindingEnabled() bool`, `(*Manager).TTL() time.Duration`, `magiclink.ErrInvalidLink`, `magiclink.RequestResult`, `magiclink.Redemption`, `magiclink.Check`, `magiclink.Renderer`; options `WithConfirmPath`, `WithIssuanceLimit`, `WithAddressResolver`, `WithRenderer`, `WithSameDeviceBinding`, `WithSynchronousDelivery`, `WithLogger`.

- [ ] **Step 1: Write the failing test for the base URL**

D11: a host-relative link in an email cannot be followed, so the empty default was broken. The `https` rule is the one already applied to redirect origins.

```go
func TestNewMagicLinkManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		baseURL string
		assert  func(t *testing.T, m *magiclink.Manager, err error)
	}

	configError := func(t *testing.T, m *magiclink.Manager, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
	}

	ok := func(t *testing.T, m *magiclink.Manager, err error) {
		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	cases := []testCase{
		{name: "missing", baseURL: "", assert: configError},
		{name: "host-relative", baseURL: "/login", assert: configError},
		{name: "cleartext on a public host", baseURL: "http://app.example.com", assert: configError},
		{name: "scheme only", baseURL: "https://", assert: configError},
		{name: "not a URL", baseURL: "://nonsense", assert: configError},
		{name: "https", baseURL: "https://app.example.com", assert: ok},
		{name: "https with a port", baseURL: "https://app.example.com:8443", assert: ok},
		{name: "loopback over http", baseURL: "http://localhost:3000", assert: ok},
		{name: "loopback by address", baseURL: "http://127.0.0.1:3000", assert: ok},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := newManager(t, tc.baseURL)
			tc.assert(t, m, err)
		})
	}
}
```

`newManager` builds a manager with a real `onetime.Manager`, a stub loader and a non-blocking sender, varying only the base URL.

- [ ] **Step 2: Write the failing test for the synchronous-sender refusal**

D6: the timing channel was closed only for deployments that remembered to wrap their sender. Here it is closed by construction.

```go
func TestManagerRefusesSynchronousSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		sender func(t *testing.T) notify.Sender
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Manager, err error)
	}

	cases := []testCase{
		{
			name: "the SMTP sender is refused",
			sender: func(t *testing.T) notify.Sender {
				s, err := notify.NewSMTPSender("smtp.example.com")
				require.NoError(t, err)
				return s
			},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
				assert.Nil(t, m)
				assert.Contains(t, strings.ToLower(err.Error()), "synchronous")
			},
		},
		{
			name: "a sender reporting NonBlocking false is refused",
			sender: func(t *testing.T) notify.Sender {
				return liarSender{nonBlocking: false}
			},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
				assert.Nil(t, m)
			},
		},
		{
			name: "the queued sender is accepted",
			sender: func(t *testing.T) notify.Sender {
				inner, err := notify.NewSMTPSender("smtp.example.com")
				require.NoError(t, err)

				q, err := notify.NewQueuedSender(inner)
				require.NoError(t, err)
				t.Cleanup(func() { _ = q.Close(context.WithoutCancel(t.Context())) })

				return q
			},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "the consumer may accept synchronous delivery explicitly",
			sender: func(t *testing.T) notify.Sender {
				s, err := notify.NewSMTPSender("smtp.example.com")
				require.NoError(t, err)
				return s
			},
			opts: []magiclink.Option{magiclink.WithSynchronousDelivery()},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name:   "a nil sender is refused",
			sender: func(t *testing.T) notify.Sender { return nil },
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := magiclink.NewManager(
				testTokens(t), stubLoader{}, tc.sender(t), "https://app.example.com", tc.opts...)

			tc.assert(t, m, err)
		})
	}
}
```

- [ ] **Step 3: Write the failing test for the remaining options**

```go
func TestMagicLinkOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Manager, err error)
	}

	configError := func(t *testing.T, m *magiclink.Manager, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.True(t, m.BindingEnabled(), "same-device binding is on by default")
				assert.Equal(t, 15*time.Minute, m.TTL(), "the link's lifetime is the token manager's")
			},
		},
		{name: "issuance limit of zero", opts: []magiclink.Option{magiclink.WithIssuanceLimit(0)}, assert: configError},
		{name: "negative issuance limit", opts: []magiclink.Option{magiclink.WithIssuanceLimit(-1)}, assert: configError},
		{name: "absolute confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("https://evil.example/confirm")}, assert: configError},
		{name: "empty confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("")}, assert: configError},
		{name: "protocol-relative confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("//evil.example/confirm")}, assert: configError},
		{name: "nil renderer", opts: []magiclink.Option{magiclink.WithRenderer(nil)}, assert: configError},
		{
			name: "binding disabled",
			opts: []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.False(t, m.BindingEnabled())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := newManager(t, "https://app.example.com", tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
```

- [ ] **Step 4: Run all three and confirm the red steps**

Run: `go test -run 'TestNewMagicLinkManager|TestManagerRefusesSynchronousSender|TestMagicLinkOptions' -count=1 ./magiclink/` → FAIL on the refusal rows.

- [ ] **Step 5: Implement construction**

```go
// NewManager builds the magic-link flow.
//
// linkBaseURL is where the emailed link points — the origin of the page that
// will post the token back. It is required and must be absolute https, with
// one exception: http on a loopback host, for local development. An emailed
// link that is host-relative cannot be followed at all, and one over cleartext
// carries a live credential past anyone on the path.
//
// Defaults: /login/magic/confirm (WithConfirmPath), 5 links per user per the
// token manager's issuance window (WithIssuanceLimit), the submitted address
// passed to the user loader as a username (WithAddressResolver), a neutral
// plain-text message naming no product (WithRenderer), same-device binding on
// (WithSameDeviceBinding), and delivery that must not block
// (WithSynchronousDelivery accepts one that does).
//
// The link's lifetime is the token manager's TTL, configured there rather than
// here: there is one place a one-time credential's lifetime is set.
func NewManager(
	tokens *onetime.Manager,
	users identity.UserLoader,
	sender notify.Sender,
	linkBaseURL string,
	opts ...Option,
) (*Manager, error) {
	// ...apply options, then validate in this order: tokens, users, sender,
	// base URL, confirm path, issuance limit, renderer.
}

// requireNonBlocking refuses a sender that would put delivery time into the
// caller's response.
//
// A request that waited for the mail server would take measurably longer for
// an address that has an account than for one that does not, which is the one
// thing the whole request path is built not to reveal. The refusal is at
// construction because the alternative — documenting that deployments should
// wrap their sender — closes the channel only for the deployments that
// remember.
func requireNonBlocking(sender notify.Sender, accepted bool) error {
	if accepted {
		return nil
	}

	nb, ok := sender.(notify.NonBlocking)
	if !ok || !nb.NonBlocking() {
		return errors.New(
			"magiclink: sender waits for delivery, which reveals which addresses have accounts; " +
				"wrap it in notify.NewQueuedSender, or accept it with WithSynchronousDelivery")
	}

	return nil
}
```

`WithSynchronousDelivery`'s godoc states plainly that response time then reveals which addresses have accounts.

For the base URL, reuse `internal/origin.Normalize` and the loopback rule rather than writing a second parser — it already decides scheme, host and port, and `internal/origin` already knows what loopback means.

- [ ] **Step 6: Run them and confirm green, then commit**

Run: `go test -run 'TestNewMagicLinkManager|TestManagerRefusesSynchronousSender|TestMagicLinkOptions' -count=1 ./magiclink/` → PASS.

```bash
git add magiclink/
git commit -m "feat(magiclink): construction refuses a cleartext base URL and a blocking sender

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 24: Request uniformity and address resolution

**Implements:** tasks.md 9.5, 9.6, 9.7

**Files:**
- Modify: `magiclink/manager.go`
- Test: `magiclink/request_test.go`

**Interfaces:**
- Produces: `(*Manager).Request(ctx context.Context, address, next string) RequestResult`. Note the signature returns **no error**: a caller cannot branch on the outcome because there is nothing to branch on.

- [ ] **Step 1: Write the failing uniformity table**

This is the test the whole capability rests on. One table, every branch, one assertion: the result is identical and nothing observable differs.

```go
func TestRequestIsUniform(t *testing.T) {
	t.Parallel()

	known := &identity.Details{UserID: "u-1", Username: "ada@example.com", Enabled: true}

	type testCase struct {
		name    string
		loader  identity.UserLoader
		tokens  func(t *testing.T) *onetime.Manager
		sender  notify.Sender
		prepare func(t *testing.T, m *magiclink.Manager)
		wantSent bool
	}

	cases := []testCase{
		{
			name:     "an active user, and a link is sent",
			loader:   stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			wantSent: true,
		},
		{
			name:   "an unknown address",
			loader: stubLoader{byUsername: map[string]*identity.Details{}},
		},
		{
			name: "a disabled user",
			loader: stubLoader{byUsername: map[string]*identity.Details{
				"ada@example.com": {UserID: "u-1", Username: "ada@example.com", Enabled: false},
			}},
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
		},
		{
			name:   "the issuance limit is reached",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			prepare: func(t *testing.T, m *magiclink.Manager) {
				for range 5 {
					m.Request(t.Context(), "ada@example.com", "/")
				}
			},
		},
		{
			name:   "the token store fails",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			tokens: func(t *testing.T) *onetime.Manager { return tokensWithFailingStore(t) },
		},
		{
			name:   "the message cannot be sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			sender: failingSender{err: errors.New("smtp: 451 temporary failure")},
			wantSent: true, // the attempt is made; the failure is swallowed
		},
	}

	var baseline magiclink.RequestResult

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			sender := tc.sender
			recorder := &recordingSender{}
			if sender == nil {
				sender = recorder
			}

			tokens := testTokens(t)
			if tc.tokens != nil {
				tokens = tc.tokens(t)
			}

			m, err := magiclink.NewManager(tokens, tc.loader, sender, "https://app.example.com")
			require.NoError(t, err)

			if tc.prepare != nil {
				tc.prepare(t, m)
			}

			got := m.Request(ctx, "ada@example.com", "/dashboard")

			// Every branch produces a result of the same shape. The nonce
			// differs in value when a link was issued; a caller must not be
			// able to tell from the shape alone.
			assert.Len(t, got.BindingNonce, expectedNonceLen,
				"every branch returns a nonce of the same length")

			if i == 0 {
				baseline = got
			}

			assert.Equal(t, len(baseline.BindingNonce), len(got.BindingNonce))

			if !tc.wantSent {
				assert.Zero(t, recorder.Count(), "no message may be sent on a refusing branch")
			}
		})
	}
}
```

Read `identity.Details` before writing this — the enabled field may be spelled differently — and match it.

The decoy nonce is what makes the shape constant. If the design's `RequestResult` returns an empty nonce on a refusing branch, the *interceptor* supplies the decoy (Task 31); assert here only what `Request` itself guarantees, and pin the interceptor's constant-shape cookie in Task 31 where it belongs. Choose one and make the two tests agree.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestRequestIsUniform -count=1 ./magiclink/`
Expected: FAIL — `Request` does not exist, or sends on a branch that must not send.

- [ ] **Step 3: Implement**

```go
// Request issues and sends a sign-in link for the submitted address.
//
// It returns no error, and every branch returns the same result. That is the
// point: an unknown address, a disabled user, a loader outage, a reached
// issuance limit, a failed token write and a failed send are indistinguishable
// to the caller, so a caller cannot leak the difference to the client even by
// accident. Each cause is logged server-side.
//
// A small timing difference remains: the store read and the token insert run
// only for an address that resolves. The queued sender removes the largest
// part of it — the delivery — and the rest is documented rather than closed
// here.
func (m *Manager) Request(ctx context.Context, address, next string) RequestResult {
	details, ok := m.resolve(ctx, address)
	if !ok {
		return RequestResult{}
	}

	count, err := m.tokens.IssuedCount(ctx, string(details.UserID))
	if err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: issuance count unavailable", slog.Any("error", err))
		return RequestResult{}
	}

	if count >= m.issuanceLimit {
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: issuance limit reached")
		return RequestResult{}
	}

	// ...issue the token with subject = the user reference, build the link,
	// render, force To, send.
}

// resolve turns a submitted address into user details, or reports that the
// request goes no further.
//
// Every refusal is logged and none is returned: the caller of Request is not
// told which of them happened.
func (m *Manager) resolve(ctx context.Context, address string) (*identity.Details, bool) {
	details, err := m.resolver(ctx, address)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: no account for the submitted address")
		return nil, false
	case err != nil:
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: address could not be resolved", slog.Any("error", err))
		return nil, false
	case details == nil || !details.Enabled:
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: account is not active")
		return nil, false
	}

	return details, true
}
```

No log line contains the submitted address. A debug record that quoted it would put every address anyone typed into the log, which is the enumeration the flow exists to prevent, moved one layer down.

- [ ] **Step 4: Write and pass resolution and the issuance limit**

```go
func TestRequestResolvesAddress(t *testing.T) {
	t.Parallel()

	t.Run("by default the address reaches the loader unchanged", func(t *testing.T) {
		t.Parallel()

		loader := &recordingLoader{}
		m, err := magiclink.NewManager(testTokens(t), loader, &recordingSender{}, "https://app.example.com")
		require.NoError(t, err)

		m.Request(t.Context(), " Ada@Example.com", "/")

		assert.Equal(t, []string{" Ada@Example.com"}, loader.Usernames(),
			"never trimmed, never case-folded")
	})

	t.Run("a consumer resolver is the only path", func(t *testing.T) {
		t.Parallel()

		loader := &recordingLoader{}
		sender := &recordingSender{}

		resolver := func(ctx context.Context, address string) (*identity.Details, error) {
			if address == "ada@example.com" {
				return &identity.Details{UserID: "u-7", Enabled: true}, nil
			}
			return nil, identity.ErrUserNotFound
		}

		m, err := magiclink.NewManager(testTokens(t), loader, sender, "https://app.example.com",
			magiclink.WithAddressResolver(resolver))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/")

		assert.Empty(t, loader.Usernames(), "LoadByUsername is not called")
		assert.Equal(t, 1, sender.Count())
	})
}

func TestRequestIssuanceLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		opts  []magiclink.Option
		limit int
	}

	cases := []testCase{
		{name: "the default of five", limit: 5},
		{name: "a consumer limit of two", opts: []magiclink.Option{magiclink.WithIssuanceLimit(2)}, limit: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender := &recordingSender{}
			m, err := magiclink.NewManager(testTokens(t),
				stubLoader{byUsername: map[string]*identity.Details{
					"ada@example.com": {UserID: "u-1", Enabled: true},
				}},
				sender, "https://app.example.com", tc.opts...)
			require.NoError(t, err)

			for range tc.limit + 1 {
				m.Request(t.Context(), "ada@example.com", "/")
			}

			assert.Equal(t, tc.limit, sender.Count(),
				"the attempt past the limit issues nothing and sends nothing")
		})
	}
}
```

Red then green.

- [ ] **Step 5: Commit**

```bash
git add magiclink/
git commit -m "feat(magiclink): requesting a link tells the caller nothing

Every branch returns the same result and Request returns no error at all, so a
caller cannot leak which addresses have accounts even by accident.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 25: Building and sending the link

**Implements:** tasks.md 9.8, 9.9

**Files:**
- Modify: `magiclink/manager.go`, `magiclink/render.go`
- Test: `magiclink/link_test.go`, `magiclink/render_test.go`

**Interfaces:**
- Produces: `magiclink.Renderer func(link, next string) notify.Message`, and the default renderer.

- [ ] **Step 1: Write the failing tests**

```go
func TestRequestBuildsLink(t *testing.T) {
	t.Parallel()

	t.Run("the link joins the base, the confirm path, the token and the target", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}
		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com")
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/dashboard?tab=a&b=c")

		require.Equal(t, 1, sender.Count())
		link := extractLink(t, sender.Last().TextBody)

		u, err := url.Parse(link)
		require.NoError(t, err)

		assert.Equal(t, "https", u.Scheme)
		assert.Equal(t, "app.example.com", u.Host)
		assert.Equal(t, "/login/magic/confirm", u.Path)
		assert.NotEmpty(t, u.Query().Get("token"))
		assert.Equal(t, "/dashboard?tab=a&b=c", u.Query().Get("next"),
			"the target is query-escaped, so its own separators survive")
	})

	t.Run("a consumer renderer chooses the subject but not the recipient", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		renderer := func(link, next string) notify.Message {
			return notify.Message{
				To:       "other@example.com", // must be overridden
				Subject:  "Sign in to Payroll",
				TextBody: "Go to " + link,
			}
		}

		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com",
			magiclink.WithRenderer(renderer))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/")

		require.Equal(t, 1, sender.Count())
		assert.Equal(t, "Sign in to Payroll", sender.Last().Subject)
		assert.Equal(t, "ada@example.com", sender.Last().To,
			"the recipient is the submitted address, whatever the renderer returns")
	})
}

func TestDefaultRenderer(t *testing.T) {
	t.Parallel()

	sender := &recordingSender{}
	m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com")
	require.NoError(t, err)

	m.Request(t.Context(), "ada@example.com", "/")

	require.Equal(t, 1, sender.Count())
	msg := sender.Last()

	assert.Contains(t, msg.TextBody, "https://app.example.com/login/magic/confirm?")
	assert.Regexp(t, `(?i)expires`, msg.TextBody)
	assert.Regexp(t, `(?i)once`, msg.TextBody)

	for _, brand := range []string{"scrty", "kartala", "Payroll", "Acme"} {
		assert.NotContains(t, strings.ToLower(msg.Subject), strings.ToLower(brand))
		assert.NotContains(t, strings.ToLower(msg.TextBody), strings.ToLower(brand))
	}
}
```

- [ ] **Step 2: Run them and confirm the red step, then implement**

Run: `go test -run 'TestRequestBuildsLink|TestDefaultRenderer' -count=1 ./magiclink/` → FAIL.

```go
// buildLink assembles the URL the message carries.
//
// next is query-escaped, so a target with its own query string arrives intact
// rather than merging into the link's parameters.
func (m *Manager) buildLink(token, next string) string {
	q := url.Values{}
	q.Set("token", token)
	q.Set("next", next)

	return m.baseURL + m.confirmPath + "?" + q.Encode()
}
```

```go
// Renderer turns a link and its redirect target into the message to send.
//
// Whatever it returns, the recipient is forced to the address that was
// submitted: a renderer is for wording, not for choosing who receives a live
// sign-in link.
type Renderer func(link, next string) notify.Message

// defaultRenderer writes a neutral plain-text message.
//
// It names no product, brand or organisation, because scrty does not know the
// consumer's and must not invent one. A consumer who wants their name in the
// message supplies a renderer.
func defaultRenderer(link, _ string) notify.Message {
	return notify.Message{
		Subject: "Your sign-in link",
		TextBody: "Use this link to sign in:\n\n" + link +
			"\n\nIt expires shortly and can be used once." +
			"\n\nIf you did not ask to sign in, you can ignore this message.\n",
	}
}
```

In `Request`, after rendering: `msg.To = address`, unconditionally, with a comment saying why.

Re-run: PASS.

- [ ] **Step 3: Commit**

```bash
git add magiclink/
git commit -m "feat(magiclink): build the link and send a neutral message to the submitted address

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 26: Redemption ordering

**Implements:** tasks.md 10.1, 10.2, 10.3, 10.4

**Files:**
- Modify: `magiclink/manager.go`
- Test: `magiclink/redeem_test.go`

**Interfaces:**
- Consumes: `onetime.Manager.Redeem(ctx, presented, binding string, checks ...onetime.Check) (Token, error)`, `identity.UserLoader.LoadByUserID` (Task 2).
- Produces: `(*Manager).Redeem(ctx, token, bindingNonce string, checks ...Check) (Redemption, error)`.

- [ ] **Step 1: Write the failing ordering test**

Check-then-consume is the settled rule, and the proof is a store that counts consumes: every refusing step must leave that count at zero.

```go
func TestRedeemOrdering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		loader identity.UserLoader
		checks []magiclink.Check
		assert func(t *testing.T, r magiclink.Redemption, err error, consumes int)
	}

	notConsumed := func(wantErr error) func(*testing.T, magiclink.Redemption, error, int) {
		return func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
			assert.ErrorIs(t, err, wantErr)
			assert.Zero(t, consumes, "a refusal before the last step must not spend the link")
		}
	}

	consumerErr := errors.New("terms not accepted")

	cases := []testCase{
		{
			name:   "the user is gone",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name: "the user is disabled",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {UserID: "u-1", Enabled: false},
			}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "a consumer check refuses",
			loader: activeByID(),
			checks: []magiclink.Check{
				func(context.Context, identity.Principal, time.Time) error { return consumerErr },
			},
			assert: notConsumed(consumerErr),
		},
		{
			name:   "everything passes",
			loader: activeByID(),
			assert: func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
				assert.Equal(t, 1, consumes, "success is the only thing that spends it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingTokenStore{Store: onetime.NewMemoryStore()}
			tokens := tokensWithStore(t, store)

			m, err := magiclink.NewManager(tokens, tc.loader, &recordingSender{}, "https://app.example.com",
				magiclink.WithSameDeviceBinding(false))
			require.NoError(t, err)

			presented := issueFor(t, tokens, "u-1")

			before := store.Consumes()
			r, redeemErr := m.Redeem(ctx, presented, "", tc.checks...)
			tc.assert(t, r, redeemErr, store.Consumes()-before)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, then implement**

Run: `go test -run TestRedeemOrdering -count=1 ./magiclink/` → FAIL.

```go
// Check is a consumer's refusal check, run against the resolved principal
// before the link is spent.
//
// A check must have no side effects. Several racing redemptions of one link
// each run every check, and only one of them goes on to consume, so a check
// that wrote something would write it once per racing attempt.
//
// The first check that returns an error stops the redemption, later checks do
// not run, and the error is returned to the caller unchanged.
type Check func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

// Redeem spends a link and reports who it authenticates.
//
// The order is the one-time-token capability's: the token is checked, the
// refusal checks run, and the token is consumed last and atomically. Account
// resolution is placed inside that ordering as the first refusal check, so a
// user who has been deleted, disabled or reassigned costs the holder nothing —
// the link stays redeemable until it expires.
//
// Every failure except a consumer check's is ErrInvalidLink. A caller cannot
// tell a wrong token from a disabled user from a store outage.
func (m *Manager) Redeem(ctx context.Context, token, bindingNonce string, checks ...Check) (Redemption, error) {
	var resolved Redemption

	// The first check resolves the account and records it for the caller.
	// Placing it here rather than before the call is what puts it under the
	// capability's own ordering guarantee: it runs before the consume, and its
	// refusal leaves the token unspent.
	all := make([]onetime.Check, 0, len(checks)+1)

	all = append(all, func(ctx context.Context, tok onetime.Token) error {
		user := identity.UserID(tok.Subject)

		details, err := m.users.LoadByUserID(ctx, user)
		switch {
		case errors.Is(err, identity.ErrUserNotFound):
			m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the link's user no longer exists")
			return ErrInvalidLink
		case err != nil:
			m.logger.LogAttrs(ctx, slog.LevelError,
				"magiclink: the link's user could not be loaded", slog.Any("error", err))
			return ErrInvalidLink
		case details == nil || !details.Enabled:
			m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the link's user is not active")
			return ErrInvalidLink
		case details.UserID != user:
			// The loader answered with somebody else. A link authenticates the
			// user it was minted for and nobody else, so this is refused
			// rather than trusted.
			m.logger.LogAttrs(ctx, slog.LevelError,
				"magiclink: the loader returned a different user than the link records")
			return ErrInvalidLink
		}

		resolved = Redemption{
			Principal:         identity.PrincipalFromDetails(details),
			PasswordChangedAt: details.PasswordChangedAt,
		}

		return nil
	})

	for _, check := range checks {
		all = append(all, func(ctx context.Context, _ onetime.Token) error {
			return check(ctx, resolved.Principal, resolved.PasswordChangedAt)
		})
	}

	if _, err := m.tokens.Redeem(ctx, token, bindingNonce, all...); err != nil {
		return Redemption{}, m.redemptionError(ctx, err)
	}

	return resolved, nil
}
```

Read `onetime.Check`'s real signature and `identity`'s real principal-mapping helper before writing this, and match them.

Re-run: PASS.

- [ ] **Step 3: Write and pass the reference-binding test**

D7 is the reason `LoadByUserID` exists.

```go
func TestRedeemBindsToUserReference(t *testing.T) {
	t.Parallel()

	t.Run("a reissued username does not inherit a live link", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		loader := &mutableLoader{
			byUsername: map[string]*identity.Details{
				"ada": {UserID: "u-1", Username: "ada", Enabled: true},
			},
			byID: map[identity.UserID]*identity.Details{
				"u-1": {UserID: "u-1", Username: "ada", Enabled: true},
			},
		}

		tokens := testTokens(t)
		m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		// u-1 is deleted and the username is given to u-2.
		delete(loader.byID, "u-1")
		loader.byUsername["ada"] = &identity.Details{UserID: "u-2", Username: "ada", Enabled: true}
		loader.byID["u-2"] = loader.byUsername["ada"]

		r, err := m.Redeem(ctx, presented, "")
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
		assert.Empty(t, r.Principal.ID, "no session may be established for u-2")
	})

	t.Run("a loader that answers with another user is refused", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		loader := stubLoader{byID: map[identity.UserID]*identity.Details{
			"u-1": {UserID: "u-9", Enabled: true}, // asked for u-1, answers u-9
		}}

		tokens := testTokens(t)
		m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		_, err = m.Redeem(ctx, issueFor(t, tokens, "u-1"), "")
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
	})
}
```

- [ ] **Step 4: Write and pass the refusal-does-not-spend and racing tests**

```go
func TestRefusalDoesNotSpendLink(t *testing.T) {
	t.Parallel()

	t.Run("a refusal, then the cause is fixed, then the same link works", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		mustEnrol := errors.New("enrolment required")
		enrolled := false

		check := func(context.Context, identity.Principal, time.Time) error {
			if !enrolled {
				return mustEnrol
			}
			return nil
		}

		tokens := testTokens(t)
		m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(ctx, presented, "", check)
		require.ErrorIs(t, err, mustEnrol)

		enrolled = true

		r, err := m.Redeem(ctx, presented, "", check)
		require.NoError(t, err, "the link survived the refusal")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})

	t.Run("a transient loader failure, then recovery", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		loader := &flakyLoader{err: errors.New("dial tcp: connection refused")}

		tokens := testTokens(t)
		m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(ctx, presented, "")
		require.ErrorIs(t, err, magiclink.ErrInvalidLink)

		loader.Recover()

		_, err = m.Redeem(ctx, presented, "")
		assert.NoError(t, err)
	})
}

func TestRedeemRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	tokens := testTokens(t)
	m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")

	const goroutines = 16

	var (
		wg        sync.WaitGroup
		succeeded atomic.Int64
		start     = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if _, redeemErr := m.Redeem(ctx, presented, ""); redeemErr == nil {
				succeeded.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "one link, one session")
}
```

Run: `go test -run 'TestRedeemBindsToUserReference|TestRefusalDoesNotSpendLink|TestRedeemRace' -race -count=1 ./magiclink/` — red then green.

- [ ] **Step 5: Commit**

```bash
git add magiclink/
git commit -m "feat(magiclink): check everything, then consume, and only for the user it was minted for

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 27: Uniform redemption failures and consumer checks

**Implements:** tasks.md 10.5, 10.6, 10.7

**Files:**
- Modify: `magiclink/manager.go`
- Test: `magiclink/redeemerrors_test.go`

**Interfaces:**
- Produces: the unexported `(*Manager).redemptionError(ctx, err) error`.

- [ ] **Step 1: Write the failing test**

```go
func TestRedeemFailuresAreUniform(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, tokens *onetime.Manager, valid string) (presented, binding string)
		loader  identity.UserLoader
		store   func(inner onetime.Store) onetime.Store
	}

	cases := []testCase{
		{name: "malformed token", prepare: func(t *testing.T, _ *onetime.Manager, _ string) (string, string) { return "nonsense", "" }},
		{name: "unknown token", prepare: func(t *testing.T, _ *onetime.Manager, _ string) (string, string) { return freshUnknownToken(t), "" }},
		{
			name: "expired token",
			prepare: func(t *testing.T, tokens *onetime.Manager, valid string) (string, string) {
				advanceClockPast(t, tokens)
				return valid, ""
			},
		},
		{
			name: "already consumed",
			prepare: func(t *testing.T, tokens *onetime.Manager, valid string) (string, string) {
				consume(t, tokens, valid)
				return valid, ""
			},
		},
		{name: "wrong binding", prepare: func(t *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "wrong-nonce" }},
		{
			name:   "user not found",
			prepare: func(t *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "" },
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
		},
		{
			name:   "user disabled",
			prepare: func(t *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "" },
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {UserID: "u-1", Enabled: false}}},
		},
		{
			name:   "loader outage",
			prepare: func(t *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "" },
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
		},
		{
			name:    "the consume write fails",
			prepare: func(t *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "" },
			store:   func(inner onetime.Store) onetime.Store { return consumeFailsStore{Store: inner} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			loader := tc.loader
			if loader == nil {
				loader = activeByID()
			}

			inner := onetime.NewMemoryStore()
			store := onetime.Store(inner)
			if tc.store != nil {
				store = tc.store(inner)
			}

			tokens := tokensWithStore(t, store)

			m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
				magiclink.WithSameDeviceBinding(false))
			require.NoError(t, err)

			valid := issueFor(t, tokens, "u-1")
			presented, binding := tc.prepare(t, tokens, valid)

			r, redeemErr := m.Redeem(ctx, presented, binding)

			assert.ErrorIs(t, redeemErr, magiclink.ErrInvalidLink,
				"every one of these is the same error to the caller")
			assert.Empty(t, r.Principal.ID, "no session may be established")
		})
	}
}

func TestConsumerChecksReturnedUnchanged(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	termsNotAccepted := errors.New("terms not accepted")

	var secondRan atomic.Bool

	first := func(context.Context, identity.Principal, time.Time) error { return termsNotAccepted }
	second := func(context.Context, identity.Principal, time.Time) error {
		secondRan.Store(true)
		return nil
	}

	tokens := testTokens(t)
	m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")

	_, err = m.Redeem(ctx, presented, "", first, second)

	assert.ErrorIs(t, err, termsNotAccepted, "returned unchanged, not wrapped in ErrInvalidLink")
	assert.NotErrorIs(t, err, magiclink.ErrInvalidLink)
	assert.False(t, secondRan.Load(), "later checks do not run")

	// And the link survived.
	_, err = m.Redeem(ctx, presented, "")
	assert.NoError(t, err)
}

func TestRedeemLogsCarryNoSecrets(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tokens := testTokens(t)
	m, err := magiclink.NewManager(tokens,
		stubLoader{err: errors.New("dial tcp: connection refused")},
		&recordingSender{}, "https://app.example.com",
		magiclink.WithLogger(logger))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")
	binding := "the-binding-nonce"

	m.Request(ctx, "ada@example.com", "/")
	_, _ = m.Redeem(ctx, presented, binding)

	logged := buf.String()
	assert.NotContains(t, logged, presented, "the token must not be logged")
	assert.NotContains(t, logged, binding, "the binding value must not be logged")
	assert.NotContains(t, logged, "ada@example.com", "the submitted address must not be logged")
}
```

- [ ] **Step 2: Run them and confirm each red step**

Run: `go test -run 'TestRedeemFailuresAreUniform|TestConsumerChecksReturnedUnchanged|TestRedeemLogsCarryNoSecrets' -count=1 ./magiclink/`

For the log test, temporarily add `slog.String("token", token)` to a redemption log line and re-run to confirm the assertion catches it. Remove it.

- [ ] **Step 3: Implement**

```go
// redemptionError maps a failure from the token capability to what the caller
// sees.
//
// A consumer's own check error passes through unchanged, because it is the
// consumer's contract with their own caller and the library has no business
// rewriting it. Everything else becomes ErrInvalidLink, logged at debug for
// the traffic that is simply wrong and at error for the traffic that means
// something is broken.
func (m *Manager) redemptionError(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrInvalidLink):
		// Already mapped by the resolver check.
		return err
	case errors.Is(err, onetime.ErrInvalidToken), errors.Is(err, onetime.ErrTokenExpired),
		errors.Is(err, onetime.ErrTokenConsumed):
		m.logger.LogAttrs(ctx, slog.LevelDebug, "magiclink: the presented link is not redeemable")
		return ErrInvalidLink
	case isStoreFailure(err):
		m.logger.LogAttrs(ctx, slog.LevelError,
			"magiclink: the token store failed during redemption", slog.Any("error", err))
		return ErrInvalidLink
	default:
		// A consumer check's error.
		return err
	}
}
```

Read `onetime`'s real sentinels and use them. If distinguishing a store failure from a consumer check error is not possible by sentinel alone, capture the consumer check errors in the closure — as Task 33 does for the policy check — rather than guessing from the error's shape.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -race -count=1 ./magiclink/` → PASS.

```bash
git add magiclink/
git commit -m "feat(magiclink): one error for every redemption failure, and consumer checks untouched

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 28: EnableMFA and the verify endpoint

**Implements:** tasks.md 11.1, 11.2, 11.3, 11.4, 11.5, 11.6

**Files:**
- Create: `httpsec/mfaverify.go`
- Modify: `httpsec/options.go`
- Test: `httpsec/mfaverify_test.go`

**Interfaces:**
- Consumes: `mfa.Method`, `mfa.LookupFor`, `mfa.VerifyThrottle`, `session.Manager.Rotate` (Task 1), `Exchange`, `ChallengeError`.
- Produces: `httpsec.EnableMFA(method mfa.Method, opts ...MFAOption) Option`; options `WithMFAVerifyPath`, `WithMFAVerifyLimiter`, `WithMFALogInterval`.

- [ ] **Step 1: Write the failing construction test**

```go
func TestEnableMFA(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method mfa.Method
		opts   []httpsec.MFAOption
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.Error(t, err)
		assert.Nil(t, c)
	}

	cases := []testCase{
		{
			name:   "a method with a channel",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			assert: func(t *testing.T, c *httpsec.Chain, err error) { require.NoError(t, err) },
		},
		{name: "an empty channel", method: &stubMethod{channel: ""}, assert: configError},
		{name: "a nil method", method: nil, assert: configError},
		{name: "a typed-nil method", method: (*stubMethod)(nil), assert: configError},
		{
			name:   "a nil limiter",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(nil)},
			assert: configError,
		},
		{
			name:   "a limiter interface holding a nil pointer",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert: configError,
		},
		{
			name:   "an empty verify path",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyPath("")},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := newChain(t, httpsec.EnableMFA(tc.method, tc.opts...))
			tc.assert(t, c, err)
		})
	}
}
```

`newChain` is the helper `httpsec`'s existing tests already use to assemble a chain with sessions, a token generator and a policy engine. Reuse it.

- [ ] **Step 2: Run it and confirm the red step, then implement construction**

Run: `go test -run TestEnableMFA -count=1 ./httpsec/` → FAIL.

`EnableMFA` validates by calling `mfa.LookupFor(method)` — the one place an empty channel is caught — and returns its error as the chain's construction error, so there is one rule and one message. Register the interceptor at `OrderMFAChallenge`.

Re-run: PASS.

- [ ] **Step 3: Write the failing ordering test**

The order is the requirement. Each row asserts what the step did *and* what it did not do.

```go
func TestMFAVerifyOrdering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		session func(t *testing.T, m *session.Manager) *session.Session
		method  *recordingMethod
		prepare func(t *testing.T, th *recordingThrottle)
		assert  func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle)
	}

	cases := []testCase{
		{
			name:    "no session",
			session: func(*testing.T, *session.Manager) *session.Session { return nil },
			method:  &recordingMethod{channel: factor.AuthenticatorApp},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle) {
				assert.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Zero(t, method.VerifyCalls(), "no code is read without a session")
				assert.Zero(t, th.Checks(), "the throttle is not consulted")
			},
		},
		{
			name:    "the method's channel is the first factor's",
			session: pendingSessionWith(factor.MagicLink),
			method:  &recordingMethod{channel: factor.Email},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle) {
				assert.ErrorIs(t, err, mfa.ErrSameChannel)
				assert.Zero(t, method.VerifyCalls(), "the code is not read, let alone verified")
				assert.Zero(t, th.Checks(), "and no failure is recorded against the user")
				assert.Zero(t, th.Failures())
			},
		},
		{
			name:    "the user is throttled",
			session: pendingSessionWith(factor.Password),
			method:  &recordingMethod{channel: factor.AuthenticatorApp},
			prepare: func(t *testing.T, th *recordingThrottle) { th.Throttle() },
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle) {
				assert.ErrorIs(t, err, mfa.ErrVerifyThrottled)
				assert.Zero(t, method.VerifyCalls(), "a throttled user's code is not checked")
			},
		},
		{
			name:    "a wrong code records a failure",
			session: pendingSessionWith(factor.Password),
			method:  &recordingMethod{channel: factor.AuthenticatorApp, err: mfa.ErrInvalidCode},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, method.VerifyCalls())
				assert.Equal(t, 1, th.Failures())
			},
		},
		{
			name:    "a valid code records no failure",
			session: pendingSessionWith(factor.Password),
			method:  &recordingMethod{channel: factor.AuthenticatorApp},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, method *recordingMethod, th *recordingThrottle) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Zero(t, th.Failures())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// ...assemble the chain with tc.method and a recording throttle,
			// establish tc.session, POST code=123456 to /mfa/totp, and hand
			// the recorder and the chain's error to tc.assert.
		})
	}
}
```

- [ ] **Step 4: Run it and confirm the red step, then implement the endpoint**

Run: `go test -run TestMFAVerifyOrdering -count=1 ./httpsec/` → FAIL.

```go
// verifyMFA handles a POST to the verify path.
//
// The order is deliberate, and each step's placement is a requirement rather
// than a convenience:
//
//  1. No session: there is nothing to add a second factor to.
//  2. Same channel, checked before the code is even read. A code that would
//     arrive the way the first factor did is not a second factor, so reading
//     it, counting it or verifying it would all be wrong. The challenge stays
//     pending and nothing is recorded: the user has not failed anything, the
//     deployment has.
//  3. The throttle, before the code is checked, so guessing costs attempts
//     rather than time.
//  4. The code itself. A failure is recorded against the user and the error is
//     returned unchanged, so a consumer sees mfa's own sentinel.
//  5. Success: resolve, rotate, publish, answer.
func (i *mfaInterceptor) verify(ex *Exchange) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	if i.method.Channel() == s.FirstFactor.Channel() {
		return mfa.ErrSameChannel
	}

	ctx := ex.Context()
	user := s.UserID

	if err := i.throttle.Check(ctx, user); err != nil {
		return err
	}

	if err := i.method.Verify(ctx, user, ex.Request.FormValue("code")); err != nil {
		i.throttle.RecordFailure(ctx, user)
		return err
	}

	now := i.now()

	s.MFA = session.MFASatisfied
	s.MFASatisfiedAt = now

	// Rotated after the state is set and before anything is published, so the
	// handle the consumer receives is the one that carries the satisfied
	// second factor. A handle obtained before the second factor stays valid
	// after it otherwise, which is session fixation with extra steps.
	rotated, err := i.sessions.Rotate(ctx, s)
	if err != nil {
		return err
	}

	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))
	ex.SetSessionHandle(rotated.ID)

	ex.ResponseWriter.WriteHeader(http.StatusOK)

	return nil
}
```

`SetSessionHandle` stands for however this `Exchange` publishes a new handle to the consumer's response or cookie writer — read `exchange.go` and use the real mechanism. The save must happen before the rotation or as part of it; confirm `Rotate` writes the session as it is, so setting the fields first is what persists them.

Re-run: PASS.

- [ ] **Step 5: Write and pass the remaining endpoint tests**

```go
func TestMFAVerifySameChannel(t *testing.T) {
	t.Parallel()

	t.Run("an email code after a magic-link login is refused", func(t *testing.T) {
		// method channel factor.Email, session first factor factor.MagicLink
		// → mfa.ErrSameChannel, method.Verify never called, session still MFAPending.
	})

	t.Run("an authenticator code after a magic-link login proceeds", func(t *testing.T) {
		// method channel factor.AuthenticatorApp, same session
		// → no error, session MFASatisfied.
	})
}

func TestMFAVerifySuccess(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ...assemble, establish a pending session, capture its handle.
	old := s.ID

	// POST a valid code.

	assert.Equal(t, http.StatusOK, rec.Code)

	_, err := sessions.Load(ctx, old)
	assert.Error(t, err, "the previous handle no longer loads")

	rotated, err := sessions.Load(ctx, newHandle)
	require.NoError(t, err)
	assert.Equal(t, session.MFASatisfied, rotated.MFA)
	assert.False(t, rotated.MFASatisfiedAt.IsZero())
	assert.False(t, handlerCalled, "the request does not reach later handlers")
}

func TestMFAVerifyFailure(t *testing.T) {
	t.Parallel()

	t.Run("a wrong code changes nothing", func(t *testing.T) {
		// → mfa.ErrInvalidCode propagates, session still MFAPending,
		//   the handle still loads and is unchanged.
	})

	t.Run("a GET to the verify path passes through", func(t *testing.T) {
		// → the handler runs, method.Verify never called.
	})
}

func TestMFAVerifyConsumerPath(t *testing.T) {
	t.Parallel()
	// WithMFAVerifyPath("/auth/second-factor"), POST a valid code there
	// → the challenge is resolved; a POST to /mfa/totp passes through.
}
```

Fill each body following the shape of `TestMFAVerifyOrdering`. Run each, red then green:
`go test -run 'TestMFAVerifySameChannel|TestMFAVerifySuccess|TestMFAVerifyFailure|TestMFAVerifyConsumerPath' -count=1 ./httpsec/`

- [ ] **Step 6: Commit**

```bash
git add httpsec/
git commit -m "feat(httpsec): the second-factor verify endpoint rotates the handle on success

A same-channel code is refused before it is read, and a handle obtained before
the second factor does not survive it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 29: The pending gate and the logout exemption

**Implements:** tasks.md 11.7, 11.8

**Files:**
- Modify: `httpsec/mfaverify.go`, `httpsec/chain.go`
- Test: `httpsec/mfagate_test.go`

**Interfaces:**
- Produces: the gate half of the MFA interceptor, and the assembly step that hands it the configured logout path.

- [ ] **Step 1: Write the failing tests**

D15 is a defect claim: the gate's slot is outside logout's, so a user stranded mid-challenge cannot sign out — on a shared device, that is a session they cannot end.

```go
func TestMFAGate(t *testing.T) {
	t.Parallel()

	var handlerCalled atomic.Bool

	// ...assemble a chain with EnableMFA and a handler that sets handlerCalled.
	// Establish a session with MFA pending. GET /invoices.

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, err, &ch)
	assert.Equal(t, policy.ChallengeMFA, ch.Kind)
	assert.NotNil(t, ch.Session)
	assert.False(t, handlerCalled.Load(), "the route's handler is not called")
}

func TestMFAGateLogoutExempt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		logoutOpts []httpsec.Option
		path       string
	}

	cases := []testCase{
		{name: "the default logout path", path: "/logout"},
		{
			name:       "a consumer logout path",
			logoutOpts: []httpsec.Option{httpsec.WithLogoutPath("/auth/sign-out")},
			path:       "/auth/sign-out",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			// ...assemble with EnableMFA, EnableLogout and tc.logoutOpts.
			// Establish a session with MFA pending, capture its handle.

			err := post(t, chain, tc.path, nil, withSessionHandle(handle))

			require.NoError(t, err, "a pending session must always be able to log out")

			var ch *httpsec.ChallengeError
			assert.NotErrorAs(t, err, &ch)

			_, loadErr := sessions.Load(ctx, handle)
			assert.Error(t, loadErr, "the session is deleted, pending challenge included")
		})
	}
}

func TestMFAGateVerifyExempt(t *testing.T) {
	t.Parallel()
	// A POST to the verify path is not refused by the gate, whatever the slot
	// order: the gate and the endpoint are the same interceptor.
}
```

Read the real logout option's name — `WithLogoutPath` here stands for whatever `httpsec/logout.go` exports.

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestMFAGate|TestMFAGateLogoutExempt|TestMFAGateVerifyExempt' -count=1 ./httpsec/`
Expected: FAIL — the logout case is refused with a challenge error, which is exactly the defect D15 names.

- [ ] **Step 3: Implement**

```go
// gate refuses a request whose session owes a second factor.
//
// Two requests are exempt. The verify endpoint, obviously — it is what
// resolves the challenge, and refusing it would make the challenge
// unsatisfiable. And logout, which is not obvious: the gate's slot is outside
// logout's, so without this a user mid-challenge could not end their own
// session. On a shared device that is the one thing they most need to do.
//
// The logout path is given to the gate at assembly rather than configured on
// it, so a consumer who moves logout moves the exemption with it and the two
// cannot drift apart.
func (i *mfaInterceptor) gate(ex *Exchange) error {
	s := ex.Session
	if s == nil || s.MFA != session.MFAPending {
		return nil
	}

	if i.isExempt(ex.Request) {
		return nil
	}

	return &ChallengeError{Kind: policy.ChallengeMFA, Session: s}
}

// isExempt reports whether this request is one of the two a pending session
// may still make.
func (i *mfaInterceptor) isExempt(r Request) bool {
	if r.Method() != http.MethodPost {
		return false
	}

	return r.Path() == i.verifyPath || (i.logoutPath != "" && r.Path() == i.logoutPath)
}
```

In `chain.go`'s assembly, after every option has been applied, hand the configured logout path to the MFA interceptor. Do it in the same place the chain already resolves cross-interceptor wiring, and add a comment saying why it cannot be an option on `EnableMFA`: a consumer who set one and not the other would get a gate whose exemption points at a path nothing serves.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -run 'TestMFAGate|TestMFAGateLogoutExempt|TestMFAGateVerifyExempt' -count=1 ./httpsec/` → PASS.

```bash
git add httpsec/
git commit -m "feat(httpsec): a session owing a second factor reaches nothing but verify and logout

A user stranded mid-challenge can still end their session, which matters most
on a device that is not theirs.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 29A: The verify response, so rotation does not strand the caller

**Implements:** tasks.md 11.9, 11.10

**Files:**
- Modify: `httpsec/mfaverify.go`, `httpsec/options.go`
- Test: `httpsec/mfaresponder_test.go`

**Interfaces:**
- Consumes: `mfaInterceptor` and its success path from Task 28; `(*session.Manager).Rotate` from Task 1; `token.Generator.Generate(ctx, sessionID, principal)` and the `loginDocument` body shape already in `httpsec/login.go`.
- Produces:

  ```go
  // MFAResult is what a successful second factor produced, handed to whatever
  // writes the response.
  type MFAResult struct {
      // Token is the access token issued for the rotated session.
      Token string

      // Session is the session, carrying its new handle.
      Session *session.Session
  }

  type MFAResponder func(ex *Exchange, result MFAResult) error

  func WithMFAResponder(fn MFAResponder) MFAOption
  ```

**Why this task exists.** Task 28 rotated the handle (D5) and answered a bare 200. The endpoint answers the request itself, so no downstream handler runs, and with `Chain.Middleware()` a consumer has no hook that sees the rotated identifier. `deps.tokens.Generate(ctx, s.ID, principal)` makes the session identifier the token's `jti`, so after rotation a bearer caller's token names a session that no longer loads: completing the second factor signs the user out. This is the defect claim, and step 1 reproduces it before anything is built.

`httpsec` already solved this shape — `LoginResponder` exists because "a login is the library's own endpoint and the application has no route behind it". The verify endpoint has the same shape, so it takes the same kind of thing.

- [ ] **Step 1: Write the failing test that reproduces the stranded caller**

This is the red step that matters. Run it against Task 28's bare-200 endpoint and watch the caller lose its session.

```go
func TestMFAVerifyDoesNotStrandCaller(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	h := newMFAHarness(t)

	// ...establish a session with MFA pending, capture its handle and the
	// access token the login issued.

	rec := httptest.NewRecorder()
	err := h.postVerify(ctx, rec, h.handle, validCode)
	require.NoError(t, err)

	// The credential the verify response returned, not the one from login.
	var got struct {
		AccessToken string    `json:"access_token"`
		ValidUntil  time.Time `json:"valid_until"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got),
		"the verify response carries a credential for the rotated session")
	require.NotEmpty(t, got.AccessToken)
	assert.NotEqual(t, h.loginToken, got.AccessToken,
		"the pre-MFA token named the session that rotation deleted")

	// It must actually work on a protected route.
	err = h.get(ctx, "/invoices", withBearer(got.AccessToken))
	require.NoError(t, err, "a caller that completed its second factor is not signed out")
	assert.True(t, h.handlerCalled.Load())
}
```

- [ ] **Step 2: Run it and confirm it fails for the intended reason**

Run: `go test -run TestMFAVerifyDoesNotStrandCaller -count=1 ./httpsec/`

Expected: FAIL on the assertion, not on a compile error. The body is empty, so the unmarshal assertion fires first:

```
Error: Error "unexpected end of JSON input" ...
Messages: the verify response carries a credential for the rotated session
```

Confirm this is the defect and not a harness fault by asserting the old token is genuinely dead — a request with `h.loginToken` after a successful verify must fail to authenticate. That failure is the user-visible symptom: **REPRODUCED**.

- [ ] **Step 3: Write the responder type, the option and the default**

In `options.go`, beside the other `MFAOption`s, matching `WithLoginResponder`'s godoc shape — naming the default it replaces:

```go
// WithMFAResponder replaces the response written when a second factor
// succeeds.
//
// With none supplied, the library writes a JSON document carrying an access
// token for the rotated session and that session's validity, the same shape a
// successful login answers with, so a client handles both alike.
//
// It is called instead of the downstream handler, because the verify endpoint
// is the library's own and the application has no route behind it. The session
// it receives carries the handle rotation produced, which is the only place
// that handle is available: an error it returns leaves the chain as the
// request's refusal, and nothing else will hand the caller a usable credential.
func WithMFAResponder(fn MFAResponder) MFAOption {
	return func(i *mfaInterceptor) error {
		if fn == nil {
			return newConfigError("httpsec: WithMFAResponder was given no function")
		}

		i.respond = fn

		return nil
	}
}
```

In `mfaverify.go`, replace the bare 200 on the success path. The token is issued **after** the rotation, against the new identifier:

```go
rotated, err := i.sessions.Rotate(ctx, s)
if err != nil {
	return err
}

ex.Session = rotated

// The rotated identifier is the new token's jti; issuing before the rotation
// would mint a token naming the session that is about to be deleted, which is
// exactly the defect this responder exists to close.
tok, err := i.tokens.Generate(ctx, rotated.ID, principal)
if err != nil {
	return err
}

return i.respond(ex, MFAResult{Token: tok, Session: rotated})
```

and the default, reusing `login.go`'s `loginDocument` so the two responses cannot drift:

```go
// writeMFAResult is the response a second factor succeeds with when the
// consumer supplies no responder. It writes login.go's document, so a client
// that can read a login can read this, and the empty refresh token field
// carries the same forward-compatibility promise it does there.
func writeMFAResult(ex *Exchange, result MFAResult) error {
	body := loginDocument{AccessToken: result.Token}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	//nolint:gosec // G117: the access token is the document's purpose, not a leak of one
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(encoded)

	return err
}
```

`writeLoginResult` in `login.go` is now this function with a different name. If the two
bodies are identical once written, collapse them into one unexported helper both responders
call, rather than leaving a copy to drift — that is the `/simplify` pass in task 16.1, and
worth doing there rather than inventing a third abstraction here.

- [ ] **Step 4: Run the reproducing test and confirm it passes**

Run: `go test -run TestMFAVerifyDoesNotStrandCaller -count=1 ./httpsec/` → PASS.

Then re-run Task 28's suite unchanged: `go test -run 'TestMFAVerify|TestEnableMFA' -count=1 ./httpsec/` → PASS. `TestMFAVerifySuccess` still asserts the previous handle no longer loads; rotation is unchanged, only the response is new.

- [ ] **Step 5: Write the responder tests**

```go
func TestMFAVerifyResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MFAOption
		assert func(t *testing.T, rec *httptest.ResponseRecorder, err error, rotatedID string)
	}

	cases := []testCase{
		{
			name: "the default names the rotated session and not the previous one",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, rotatedID string) {
				require.NoError(t, err)
				// ...decode the token and assert its jti is rotatedID.
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(
				func(*httpsec.Exchange, httpsec.MFAResult) error { return errResponder },
			)},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error, _ string) {
				require.ErrorIs(t, err, errResponder)
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(nil)},
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, err error, _ string) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
	}

	// ...table body per the table-test skill's assert closure form.
}

func TestMFAVerifyConsumerResponder(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	var seen httpsec.MFAResult

	h := newMFAHarness(t, httpsec.WithMFAResponder(func(ex *httpsec.Exchange, r httpsec.MFAResult) error {
		seen = r
		http.SetCookie(ex.Writer, &http.Cookie{
			Name: "session", Value: r.Token, HttpOnly: true, Secure: true,
		})

		return nil
	}))

	// ...establish a pending session, post a valid code.

	assert.Empty(t, rec.Body.String(), "the consumer's responder replaces the default entirely")
	assert.Equal(t, seen.Session.ID, rotatedID, "the responder receives the rotated session")
	require.Len(t, rec.Result().Cookies(), 1)
}
```

- [ ] **Step 6: Run them, confirm each fails, then green**

Run: `go test -run 'TestMFAVerifyResponder|TestMFAVerifyConsumerResponder' -count=1 ./httpsec/`

The nil-responder row must be written before the `fn == nil` guard exists and seen to fail with `An error is expected but got nil`. If the consumer-responder test passes on first run, invert: make the success path call `writeMFAResult` unconditionally and confirm `the consumer's responder replaces the default entirely` fails, then restore.

- [ ] **Step 7: Full package run and commit**

Run: `go test -race -count=1 ./httpsec/` → PASS. `go vet ./httpsec/...`, `gofmt -l httpsec/` empty.

```bash
git add httpsec/
git commit -m "feat(httpsec): a completed second factor answers with a usable credential

Rotating the handle deleted the session the caller's token named, so passing
the second factor signed the user out. The endpoint now answers through a
responder that carries a token for the rotated session, replaceable by a
consumer who would rather set a cookie.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 30: EnableMagicLink construction and redirect targets

**Implements:** tasks.md 12.1, 12.2

**Files:**
- Create: `httpsec/magiclink.go`
- Modify: `httpsec/options.go`
- Test: `httpsec/magiclinkoptions_test.go`, `httpsec/magiclinkredirect_test.go`

**Interfaces:**
- Consumes: `internal/origin.NewAllowlist`, `(*origin.Allowlist).Resolve`.
- Produces: `httpsec.EnableMagicLink(m *magiclink.Manager, opts ...MagicLinkOption) Option`; options `WithMagicLinkRequestPath`, `WithMagicLinkConsumePath`, `WithBindingCookieName`, `WithAllowedRedirects`, `WithAllowedOrigins`, `WithMagicLinkCountRefusals`, `WithMagicLinkLimiter`.

- [ ] **Step 1: Write the failing construction test**

```go
func TestEnableMagicLink(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(t *testing.T) *magiclink.Manager
		opts    []httpsec.MagicLinkOption
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.Error(t, err)
		assert.Nil(t, c)
	}

	cases := []testCase{
		{name: "defaults", manager: testMagicLinkManager, assert: func(t *testing.T, c *httpsec.Chain, err error) { require.NoError(t, err) }},
		{name: "nil manager", manager: func(*testing.T) *magiclink.Manager { return nil }, assert: configError},
		{
			name:    "nil limiter",
			manager: testMagicLinkManager,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(nil)},
			assert:  configError,
		},
		{
			name:    "a limiter interface holding a nil pointer",
			manager: testMagicLinkManager,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert:  configError,
		},
		{
			name:    "an empty cookie name",
			manager: testMagicLinkManager,
			opts:    []httpsec.MagicLinkOption{httpsec.WithBindingCookieName("")},
			assert:  configError,
		},
		{
			name:    "the request and consume paths collide",
			manager: testMagicLinkManager,
			opts: []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkRequestPath("/login/magic"),
				httpsec.WithMagicLinkConsumePath("/login/magic"),
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := newChain(t, httpsec.EnableMagicLink(tc.manager(t), tc.opts...))
			tc.assert(t, c, err)
		})
	}
}
```

The colliding-paths row is not in the spec, but it is a contradictory configuration and the project rule says those fail at construction. Keep it.

- [ ] **Step 2: Write the failing redirect test**

```go
func TestMagicLinkRedirects(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		allowed   []string
		origins   []string
		submitted string
		assert    func(t *testing.T, resolved string, buildErr error)
	}

	configErrorNaming := func(entry string) func(*testing.T, string, error) {
		return func(t *testing.T, resolved string, buildErr error) {
			require.Error(t, buildErr)
			assert.Contains(t, buildErr.Error(), entry, "the error names the entry at fault")
		}
	}

	resolvesTo := func(want string) func(*testing.T, string, error) {
		return func(t *testing.T, resolved string, buildErr error) {
			require.NoError(t, buildErr)
			assert.Equal(t, want, resolved)
		}
	}

	cases := []testCase{
		{name: "the default allowlist is empty", submitted: "/dashboard", assert: resolvesTo("/")},
		{name: "an exact host-relative match", allowed: []string{"/dashboard"}, submitted: "/dashboard", assert: resolvesTo("/dashboard")},
		{name: "a prefix is not a match", allowed: []string{"/dashboard"}, submitted: "/dashboard.evil.example", assert: resolvesTo("/")},
		{name: "protocol-relative is not a match", allowed: []string{"/dashboard"}, submitted: "//evil.example/dashboard", assert: resolvesTo("/")},
		{name: "a trailing slash is not a match", allowed: []string{"/dashboard"}, submitted: "/dashboard/", assert: resolvesTo("/")},
		{name: "an empty entry", allowed: []string{""}, assert: configErrorNaming("")},
		{name: "an undeclared absolute entry", allowed: []string{"https://partner.example.com/landing"}, assert: configErrorNaming("https://partner.example.com/landing")},
		{name: "an entry with userinfo", allowed: []string{"https://a@partner.example.com/landing"}, origins: []string{"https://partner.example.com"}, assert: configErrorNaming("https://a@partner.example.com/landing")},
		{name: "a cleartext declared origin", origins: []string{"http://partner.example.com"}, assert: configErrorNaming("http://partner.example.com")},
		{name: "a declared origin with a path", origins: []string{"https://partner.example.com/app"}, assert: configErrorNaming("https://partner.example.com/app")},
		{
			name:      "a declared origin makes its entry usable",
			allowed:   []string{"https://partner.example.com/landing"},
			origins:   []string{"https://partner.example.com"},
			submitted: "https://partner.example.com/landing",
			assert:    resolvesTo("https://partner.example.com/landing"),
		},
		{
			name:    "a loopback origin over http is accepted",
			allowed: []string{"http://localhost:3000/landing"},
			origins: []string{"http://localhost:3000"},
			submitted: "http://localhost:3000/landing",
			assert:  resolvesTo("http://localhost:3000/landing"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newChain(t, httpsec.EnableMagicLink(testMagicLinkManager(t),
				httpsec.WithAllowedRedirects(tc.allowed...),
				httpsec.WithAllowedOrigins(tc.origins...),
			))

			if err != nil {
				tc.assert(t, "", err)
				return
			}

			tc.assert(t, resolveRedirect(t, c, tc.submitted), nil)
		})
	}
}
```

`resolveRedirect` drives a request through the request endpoint and reads the `next` the flow settled on — through the built link or the response — rather than reaching into unexported state.

- [ ] **Step 3: Run both and confirm the red step, then implement**

Run: `go test -run 'TestEnableMagicLink|TestMagicLinkRedirects' -count=1 ./httpsec/` → FAIL.

Build the allowlist with the helper that already exists:

```go
	// internal/origin already validates entries and declared origins, resolves
	// a requested target and falls back to "/". oidc-login will want the same
	// rules, and one implementation is how the two stay identical.
	allow, err := origin.NewAllowlist(cfg.allowedRedirects, cfg.allowedOrigins,
		"WithAllowedRedirects", "WithAllowedOrigins")
	if err != nil {
		return err
	}
```

Read `origin.NewAllowlist`'s real parameter order and error style first. If a rule the spec names is missing from it — userinfo, or the single-trailing-slash allowance — add it there with its own test in `internal/origin`, rather than layering a second check in `httpsec`.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -run 'TestEnableMagicLink|TestMagicLinkRedirects' -count=1 ./httpsec/ ./internal/origin/` → PASS.

```bash
git add httpsec/ internal/origin/
git commit -m "feat(httpsec): the magic-link interceptor, with redirect targets allowlisted exactly

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 31: The request endpoint and the binding cookie

**Implements:** tasks.md 12.3, 12.4, 12.5

**Files:**
- Modify: `httpsec/magiclink.go`
- Test: `httpsec/magiclinkrequest_test.go`

**Interfaces:**
- Produces: the request endpoint half of the magic-link interceptor.

- [ ] **Step 1: Write the failing tests**

```go
func TestMagicLinkRequestEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		body func() (contentType string, body io.Reader)
	}

	form := func(values url.Values) func() (string, io.Reader) {
		return func() (string, io.Reader) {
			return "application/x-www-form-urlencoded", strings.NewReader(values.Encode())
		}
	}

	cases := []testCase{
		{name: "a known address", body: form(url.Values{"email": {"ada@example.com"}, "next": {"/dashboard"}})},
		{name: "an unknown address", body: form(url.Values{"email": {"nobody@example.com"}})},
		{name: "no address at all", body: form(url.Values{})},
		{
			name: "a JSON body",
			body: func() (string, io.Reader) {
				return "application/json", strings.NewReader(`{"email":"ada@example.com","next":"/dashboard"}`)
			},
		},
		{
			name: "an unparsable body",
			body: func() (string, io.Reader) {
				return "application/json", strings.NewReader(`{{{not json`)
			},
		},
		{
			name: "an unparsable form body",
			body: func() (string, io.Reader) {
				return "application/x-www-form-urlencoded", strings.NewReader("%%%")
			},
		},
	}

	var (
		baselineStatus int
		baselineBody   string
		baselineCookie *http.Cookie
	)

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contentType, body := tc.body()
			rec := postTo(t, "/login/magic", contentType, body)

			assert.Equal(t, http.StatusAccepted, rec.Code)

			cookie := cookieNamed(t, rec, "magic_link_binding")
			require.NotNil(t, cookie, "the cookie is set whatever the outcome")

			if i == 0 {
				baselineStatus, baselineBody, baselineCookie = rec.Code, rec.Body.String(), cookie
				return
			}

			assert.Equal(t, baselineStatus, rec.Code)
			assert.Equal(t, baselineBody, rec.Body.String())
			assert.Equal(t, baselineCookie.Name, cookie.Name)
			assert.Equal(t, baselineCookie.Path, cookie.Path)
			assert.Equal(t, baselineCookie.MaxAge, cookie.MaxAge)
			assert.Equal(t, baselineCookie.HttpOnly, cookie.HttpOnly)
			assert.Equal(t, baselineCookie.Secure, cookie.Secure)
			assert.Equal(t, baselineCookie.SameSite, cookie.SameSite)
			assert.Len(t, cookie.Value, len(baselineCookie.Value),
				"a decoy is the same shape as the real thing")
		})
	}
}

func TestBindingCookieIsConstant(t *testing.T) {
	t.Parallel()

	known := postTo(t, "/login/magic", "application/x-www-form-urlencoded",
		strings.NewReader("email=ada@example.com"))
	unknown := postTo(t, "/login/magic", "application/x-www-form-urlencoded",
		strings.NewReader("email=nobody@example.com"))

	a := cookieNamed(t, known, "magic_link_binding")
	b := cookieNamed(t, unknown, "magic_link_binding")

	require.NotNil(t, a)
	require.NotNil(t, b)

	assert.Equal(t, a.Name, b.Name)
	assert.Len(t, b.Value, len(a.Value))
	assert.NotEqual(t, a.Value, b.Value, "the decoy is random, not a fixed string")

	assert.True(t, a.HttpOnly)
	assert.True(t, a.Secure)
	assert.Equal(t, http.SameSiteLaxMode, a.SameSite)
	assert.Equal(t, "/login/magic/consume", a.Path)
	assert.Equal(t, int(15*time.Minute/time.Second), a.MaxAge,
		"the lifetime comes from configuration, never from the result")
}

func TestBindingFollowsManager(t *testing.T) {
	t.Parallel()

	t.Run("with binding disabled no cookie is ever set and another device redeems", func(t *testing.T) {
		// Manager built WithSameDeviceBinding(false). The interceptor asks the
		// manager, so the two can never disagree.
	})

	t.Run("with binding enabled a redemption without the cookie fails", func(t *testing.T) {
		// → magiclink.ErrInvalidLink.
	})
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestMagicLinkRequestEndpoint|TestBindingCookieIsConstant|TestBindingFollowsManager' -count=1 ./httpsec/` → FAIL.

- [ ] **Step 3: Implement**

```go
// request handles a POST to the request path.
//
// It answers identically whatever happened, ends the chain, and never passes
// the request on: a later handler that could see the outcome would be a way to
// leak it.
//
// A body that will not parse degrades to empty values rather than an error.
// An error here would be a different response for a malformed request, and a
// scanner would use it.
func (i *magicLinkInterceptor) request(ex *Exchange) error {
	address, next := i.readRequestBody(ex)
	next = i.redirects.Resolve(next)

	result := i.manager.Request(ex.Context(), address, next)

	// Binding is read from the manager, never configured here. If the
	// interceptor could be told one thing and the manager another, a
	// deployment could emit cookies for links that carry no binding, or issue
	// bound links nothing ever answers.
	if i.manager.BindingEnabled() {
		value := result.BindingNonce
		if value == "" {
			// No link was issued. The cookie is still set, with a decoy of the
			// same shape, because a response that sometimes carries a cookie
			// and sometimes does not answers the question the whole endpoint
			// refuses to answer.
			var decoy [16]byte
			if _, err := io.ReadFull(i.random, decoy[:]); err != nil {
				return err
			}
			value = base64.RawURLEncoding.EncodeToString(decoy[:])
		}

		ex.ResponseWriter.SetCookie(Cookie{
			Name:     i.cookieName,
			Value:    value,
			Path:     i.consumePath,
			MaxAge:   int(i.manager.TTL().Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	ex.ResponseWriter.WriteHeader(http.StatusAccepted)
	_, _ = ex.ResponseWriter.Write(acceptedBody)

	return nil
}
```

The genuine nonce must be the same length as the decoy. Confirm `magiclink`'s nonce is 16 bytes in the same encoding; if it is not, make them agree and say so in a comment — a decoy of a different length is not a decoy.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -run 'TestMagicLinkRequestEndpoint|TestBindingCookieIsConstant|TestBindingFollowsManager' -count=1 ./httpsec/` → PASS.

```bash
git add httpsec/
git commit -m "feat(httpsec): the magic-link request endpoint answers identically every time

The binding cookie is always set, with a decoy of the same shape when no link
was issued, so its presence says nothing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 32: The consume endpoint and the policy check

**Implements:** tasks.md 12.6, 12.7

**Files:**
- Modify: `httpsec/magiclink.go`
- Test: `httpsec/magiclinkconsume_test.go`

**Interfaces:**
- Produces: the consume endpoint, and the `magiclink.Check` the interceptor supplies.

- [ ] **Step 1: Write the failing tests**

POST-only is what keeps a mail scanner's prefetch from spending a link before its owner ever sees it.

```go
func TestMagicLinkConsumeEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("a GET with a valid token in the query spends nothing", func(t *testing.T) {
		t.Parallel()

		// ...request a link, extract the token.
		var handlerCalled atomic.Bool

		rec := get(t, chain, "/login/magic/consume?token="+url.QueryEscape(token))

		assert.True(t, handlerCalled.Load(), "a GET passes through to the handler")

		// And the token is still good.
		err := postConsume(t, chain, token, nonce)
		assert.NoError(t, err, "a later POST succeeds")
		_ = rec
	})

	t.Run("a HEAD spends nothing", func(t *testing.T) { /* same shape as the GET case */ })

	t.Run("a successful redemption suppresses the referrer", func(t *testing.T) {
		t.Parallel()

		rec := postConsumeRecording(t, chain, token, nonce)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"),
			"the URL the browser came from carries the token")
	})
}

func TestMagicLinkPolicyCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		policy  policy.Policy
		assert  func(t *testing.T, err error, sessions *session.Manager, token string, chain *httpsec.Chain)
	}

	denyReason := errors.New("must enrol in MFA")

	cases := []testCase{
		{
			name:   "a deny refuses and leaves the link redeemable",
			policy: denyingPolicy(denyReason),
			assert: func(t *testing.T, err error, sessions *session.Manager, token string, chain *httpsec.Chain) {
				assert.ErrorIs(t, err, denyReason)
				assert.Zero(t, activeSessions(t, sessions), "no session is created")

				// The link survived, and works once the policy allows.
				assert.NoError(t, redeemWithAllowingChain(t, token))
			},
		},
		{
			name:   "a deny with no reason refuses with the generic one",
			policy: denyingPolicy(nil),
			assert: func(t *testing.T, err error, sessions *session.Manager, token string, chain *httpsec.Chain) {
				assert.ErrorIs(t, err, policy.ErrPolicyDenied)
				assert.Zero(t, activeSessions(t, sessions))
			},
		},
		{
			name:   "a challenge still spends the link and creates the session",
			policy: challengingPolicy(policy.ChallengeMFA),
			assert: func(t *testing.T, err error, sessions *session.Manager, token string, chain *httpsec.Chain) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)

				require.NotNil(t, ch.Session)
				assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.NotEmpty(t, ch.Token, "the credential the prompt will be answered with")

				// The link is spent: a second redemption fails.
				assert.Error(t, postConsume(t, chain, token, ""))
			},
		},
		{
			name:   "an allow creates the session with the magic-link first factor",
			policy: nil,
			assert: func(t *testing.T, err error, sessions *session.Manager, token string, chain *httpsec.Chain) {
				require.NoError(t, err)
				assert.Equal(t, 1, activeSessions(t, sessions))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// ...assemble with tc.policy, request a link, POST it, hand the
			// chain's error to tc.assert.
		})
	}
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestMagicLinkConsumeEndpoint|TestMagicLinkPolicyCheck' -count=1 ./httpsec/` → FAIL.

Confirm the deny-with-no-reason row fails for the right reason: a check returning nil would read as "no refusal" and spend the link, which is what the generic reason exists to prevent.

- [ ] **Step 3: Implement**

```go
// consume handles a POST to the consume path.
//
// Anything but a POST passes through untouched, token unread. Mail scanners
// and link previewers fetch with GET and HEAD, and a link they spent is a
// login its owner never got to make.
func (i *magicLinkInterceptor) consume(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost {
		return next(ex)
	}
	// ...source guard (Task 34), then redeem with the policy check below.
}

// policyCheck builds the refusal check the redemption runs, and the closure
// that reports what it decided.
//
// The decision has to escape the check, because the check's return value alone
// cannot distinguish "allowed" from "never ran" — and a redeemer that never
// ran the checks would otherwise look exactly like one whose checks passed.
// Task 33's guard reads both.
func (i *magicLinkInterceptor) policyCheck(ex *Exchange) (magiclink.Check, *policyOutcome) {
	out := &policyOutcome{}

	return func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		in := postAuthenticationInput(&p, factor.MagicLink, "", passwordChangedAt, i.now())

		d := policy.Decision{Outcome: policy.Allow}
		if i.engine != nil {
			d = i.engine.EvaluatePhase(ctx, policy.PostAuthentication, in)
		}

		out.evaluated = true
		out.decision = d

		if d.Outcome == policy.Deny {
			// Never nil for a refusal. A nil return reads as "no refusal" to
			// the redemption, which would then go on to spend the link — the
			// user loses their link and is refused anyway.
			reason := d.Reason
			if reason == nil {
				reason = policy.ErrPolicyDenied
			}

			out.denyErr = reason

			return reason
		}

		// A challenge is not a refusal. The link is spent, the session is
		// created with the challenge pending, and the caller is prompted.
		return nil
	}, out
}
```

`policy.Engine` already substitutes `ErrPolicyDenied` for a nil reason, so the fallback here is belt and braces for an engine-less chain — say so in the comment rather than implying the engine is untrustworthy.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -run 'TestMagicLinkConsumeEndpoint|TestMagicLinkPolicyCheck' -count=1 ./httpsec/` → PASS.

```bash
git add httpsec/
git commit -m "feat(httpsec): only a POST redeems a link, and a policy deny never spends one

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 33: The redeemer guard

**Implements:** tasks.md 12.8, 12.9

**Files:**
- Modify: `httpsec/magiclink.go`
- Test: `httpsec/magiclinkguard_test.go`

**Interfaces:**
- Produces: `httpsec.Redeemer` (the replaceable redemption port) and the post-success guard.

- [ ] **Step 1: Write the failing tests, and see them fail with the guard removed**

`Redeemer` is an interface, so a consumer's implementation cannot be trusted to have honoured the check it was handed. The guard is what makes the requirement true regardless.

```go
func TestRedeemerGuard(t *testing.T) {
	t.Parallel()

	denyReason := errors.New("must enrol in MFA")

	type testCase struct {
		name     string
		redeemer httpsec.Redeemer
		policy   policy.Policy
		assert   func(t *testing.T, err error, sessions *session.Manager, tokens *recordingTokenGenerator)
	}

	cases := []testCase{
		{
			name: "a redeemer that runs the check, sees the deny and reports success anyway",
			redeemer: redeemerFunc(func(ctx context.Context, token, nonce string, checks ...magiclink.Check) (magiclink.Redemption, error) {
				p := identity.Principal{ID: "u-1"}
				for _, check := range checks {
					_ = check(ctx, p, time.Time{}) // decision discarded
				}
				return magiclink.Redemption{Principal: p}, nil
			}),
			policy: denyingPolicy(denyReason),
			assert: func(t *testing.T, err error, sessions *session.Manager, tokens *recordingTokenGenerator) {
				assert.ErrorIs(t, err, denyReason, "the policy's own reason, not a generic one")
				assert.Zero(t, activeSessions(t, sessions), "no session is established")
				assert.Zero(t, tokens.Count(), "and no token is issued")
			},
		},
		{
			name: "a redeemer that never runs the checks",
			redeemer: redeemerFunc(func(ctx context.Context, token, nonce string, _ ...magiclink.Check) (magiclink.Redemption, error) {
				return magiclink.Redemption{Principal: identity.Principal{ID: "u-1"}}, nil
			}),
			policy: nil, // no policy registered at all
			assert: func(t *testing.T, err error, sessions *session.Manager, tokens *recordingTokenGenerator) {
				assert.ErrorIs(t, err, policy.ErrPolicyDenied,
					"a check that never ran is not an allow")
				assert.Zero(t, activeSessions(t, sessions))
				assert.Zero(t, tokens.Count())
			},
		},
		{
			name:     "the built-in redeemer with an allowing policy succeeds",
			redeemer: nil, // the default
			policy:   nil,
			assert: func(t *testing.T, err error, sessions *session.Manager, tokens *recordingTokenGenerator) {
				require.NoError(t, err)
				assert.Equal(t, 1, activeSessions(t, sessions))
				assert.Equal(t, 1, tokens.Count())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// ...assemble with tc.redeemer and tc.policy, POST a valid token.
		})
	}
}
```

**The red step here is explicit.** Write the guard's tests, then comment the guard out and run them: the first two rows must fail — a session established and a token issued for a user the policy denied. Read that output, then restore the guard. Record the failing output in the report; this is the one place a test that is never seen to fail would be worthless, because the guard exists precisely for implementations that lie.

Run: `go test -run TestRedeemerGuard -count=1 ./httpsec/`

- [ ] **Step 2: Implement**

```go
// Redeemer is the redemption step, replaceable by a consumer.
//
// The default is magiclink.Manager.Redeem. A consumer who replaces it takes on
// the ordering contract: run every check given, in order, and consume only
// after all of them pass.
//
// The endpoint does not rely on that. It checks afterwards what its own policy
// check actually decided, and refuses when the answer is "denied" or "never
// asked". What it cannot do is un-spend a link a non-conforming implementation
// already consumed: the refusal protects the session, not the link.
type Redeemer interface {
	Redeem(ctx context.Context, token, bindingNonce string, checks ...magiclink.Check) (magiclink.Redemption, error)
}

// guard refuses a redemption whose policy check was denied or skipped.
//
// "Never evaluated" is treated as a denial rather than an allow. A redeemer
// that did not run the checks has not shown the login is permitted, and the
// safe reading of "I don't know" is no.
func guard(out *policyOutcome) error {
	if !out.evaluated {
		return policy.ErrPolicyDenied
	}

	if out.decision.Outcome == policy.Deny {
		if out.denyErr != nil {
			return out.denyErr
		}
		return policy.ErrPolicyDenied
	}

	return nil
}
```

In the endpoint, call `guard` immediately after the redeemer reports success and before anything is created:

```go
	r, err := i.redeemer.Redeem(ctx, token, nonce, append([]magiclink.Check{check}, i.checks...)...)
	if err != nil {
		return err // recorded by Task 34
	}

	if err := guard(out); err != nil {
		return err
	}

	// Only now: session, challenge marking, token.
	tok, err := completeLogin(ex, i.loginDeps, postAuthenticationInput(
		&r.Principal, factor.MagicLink, "", r.PasswordChangedAt, i.now()))
	// ...
```

Reusing `completeLogin` is what keeps this flow's tail identical to form login's — the same phase, the same marking, the same ordering. Note that the policy is then evaluated twice on the success path; if that is unacceptable, pass the already-made decision into the tail rather than re-evaluating, and say so in a comment. Decide, implement one way, and record the choice for Task 38.

- [ ] **Step 3: Implement success and confirm green**

```go
func TestMagicLinkSuccess(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ...request a link, POST it.

	require.NoError(t, err)

	sessions := activeSessionList(t, manager)
	require.Len(t, sessions, 1)
	assert.Equal(t, factor.MagicLink, sessions[0].FirstFactor)
	assert.Equal(t, identity.UserID("u-1"), sessions[0].UserID)

	assert.Equal(t, 1, tokens.Count(), "an access token is issued")
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
}
```

Run: `go test -run 'TestRedeemerGuard|TestMagicLinkSuccess' -count=1 ./httpsec/` → PASS.

- [ ] **Step 4: Commit**

```bash
git add httpsec/
git commit -m "feat(httpsec): a redeemer that skipped or discarded the policy check establishes nothing

The guard cannot un-spend a link such an implementation consumed, and the
godoc says so.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 34: Magic-link rate-limit accounting

**Implements:** tasks.md 12.10, 12.11, 12.12

**Files:**
- Modify: `httpsec/magiclink.go`
- Test: `httpsec/magiclinkthrottle_test.go`

**Interfaces:**
- Consumes: the `sourceGuard` seam in `httpsec/throttle.go`.
- Produces: the source-accounting half of the consume endpoint.

- [ ] **Step 1: Write the failing tests**

D8: recording refused redemptions of a valid link is the default, and the opt-out restores the older accounting exactly.

```go
func TestMagicLinkSourceAccounting(t *testing.T) {
	t.Parallel()

	denyReason := errors.New("must enrol in MFA")

	t.Run("ten policy-denied redemptions throttle the eleventh", func(t *testing.T) {
		t.Parallel()

		// Chain with a denying policy, default accounting, default limit of
		// 10 per 15 minutes.
		var redeemed atomic.Int64

		for range 10 {
			err := postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce)
			require.ErrorIs(t, err, denyReason)
			redeemed.Add(1)
		}

		err := postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce)
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink,
			"the throttled source is refused with the uniform error")
		assert.Equal(t, int64(10), redeemer.Calls(),
			"and the eleventh never reaches the redeemer")
	})

	t.Run("an unattributable source is refused without redeeming", func(t *testing.T) {
		t.Parallel()

		err := postConsumeFrom(t, chain, "", validToken(t), nonce)
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
		assert.Zero(t, redeemer.Calls())
	})

	t.Run("another source is unaffected", func(t *testing.T) {
		t.Parallel()
		// Exhaust 203.0.113.7, then 198.51.100.4 still redeems.
	})
}

func TestMagicLinkCountRefusalsOptOut(t *testing.T) {
	t.Parallel()

	denyReason := errors.New("must enrol in MFA")
	consumerErr := errors.New("terms not accepted")

	t.Run("policy refusals stop counting", func(t *testing.T) {
		t.Parallel()

		// WithMagicLinkCountRefusals(false), a policy that denies ten times
		// and then allows.
		for range 10 {
			require.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce), denyReason)
		}

		allow.Store(true)

		assert.NoError(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce),
			"the source was never counted, so it is not throttled")
	})

	t.Run("consumer check refusals stop counting too", func(t *testing.T) {
		t.Parallel()
		// Ten refusals from a consumer Check returning consumerErr, then an
		// allowed redemption succeeds.
	})

	t.Run("invalid tokens still count", func(t *testing.T) {
		t.Parallel()

		// WithMagicLinkCountRefusals(false), ten wrong tokens.
		for range 10 {
			require.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", "wrong-token", nonce),
				magiclink.ErrInvalidLink)
		}

		assert.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce),
			magiclink.ErrInvalidLink, "the source is throttled")
	})

	t.Run("a redeemer that discarded the deny and failed otherwise still counts", func(t *testing.T) {
		t.Parallel()

		// WithMagicLinkCountRefusals(false), a redeemer that runs the check,
		// discards the deny and then returns a store error of its own.
		other := errors.New("dial tcp: connection refused")

		for range 10 {
			require.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce), other)
		}

		assert.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce),
			magiclink.ErrInvalidLink,
			"the opt-out exempts exactly the refusal the check produced, nothing else")
	})
}

func TestMagicLinkThrottleLogSampling(t *testing.T) {
	t.Parallel()

	// One throttled source, 500 attempts in a minute.
	assert.Equal(t, 1, strings.Count(buf.String(), "httpsec: source throttled"))

	logged := buf.String()
	assert.NotContains(t, logged, token)
	assert.NotContains(t, logged, nonce)
	assert.NotContains(t, logged, "ada@example.com")
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestMagicLinkSourceAccounting|TestMagicLinkCountRefusalsOptOut|TestMagicLinkThrottleLogSampling' -count=1 ./httpsec/` → FAIL.

- [ ] **Step 3: Implement**

```go
// recordRefusal decides whether this redemption failure counts against the
// source.
//
// By default every failure counts, including a policy denial and a consumer
// check refusal of a valid link. Without that, an attacker holding one link
// the policy refuses could replay it without limit for as long as it lives,
// and each attempt would cost a store read and a policy evaluation.
//
// The opt-out exempts exactly two things: the refusal this interceptor's own
// policy check produced, matched against the very error the closure recorded,
// and the consumer's own check errors. Everything else is still recorded —
// including a failure from a redeemer that discarded the deny and then failed
// for some other reason, which is not the refusal the consumer opted out of.
func (i *magicLinkInterceptor) recordRefusal(err error, out *policyOutcome) bool {
	if i.countRefusals {
		return true
	}

	if out.denyErr != nil && errors.Is(err, out.denyErr) {
		return false
	}

	return !i.isConsumerCheckError(err)
}
```

In the endpoint: check the guard before redeeming, and on any redeem error consult `recordRefusal` before `RecordFailure`.

```go
	src, err := i.guard.Check(ctx, ex.Request.ClientAddr())
	if err != nil {
		// Throttled, or an address that cannot key a bucket. Either way the
		// answer is the uniform one and the token is not read.
		return magiclink.ErrInvalidLink
	}

	r, redeemErr := i.redeemer.Redeem(ctx, token, nonce, checks...)
	if redeemErr != nil {
		if i.recordRefusal(redeemErr, out) {
			i.guard.RecordFailure(ctx, src)
		}
		return redeemErr
	}
```

Default the limiter to `ratelimit.NewMemoryLimiter(10, 15*time.Minute)` through a `ratelimit.NewSourceGuard("magic-link-redeem", limiter, ...)` so this flow's buckets are its own, and refuse a nil or typed-nil limiter at construction. Guards given the same limiter instance share the store and the limit, **not** the allowance: `NewSourceGuard`'s flow name is part of every key, so a source that exhausts one flow still has its own in another. Say that in `WithMagicLinkLimiter`'s godoc — and do not write the opposite, which an earlier draft of this plan did in two places.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -race -count=1 ./httpsec/` → PASS.

```bash
git add httpsec/
git commit -m "feat(httpsec): refused redemptions of a valid link count against the source by default

The opt-out exempts exactly the refusal the interceptor's own check produced,
so a redeemer that discarded a deny and failed otherwise is still counted.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 34A: The redemption response, made replaceable

**Implements:** tasks.md 12.13, 12.14

**Files:**
- Modify: `httpsec/magiclink.go`, `httpsec/options.go`
- Test: `httpsec/magiclinkresponder_test.go`

**Interfaces:**
- Consumes: the consume endpoint and its success path from Tasks 32–33; `internal/origin.Allowlist.Resolve` from Task 30; `loginDocument` from `httpsec/login.go`.
- Produces:

  ```go
  // MagicLinkResult is what a successful redemption produced, handed to
  // whatever writes the response.
  type MagicLinkResult struct {
      // Token is the access token issued for the new session.
      Token string

      // Session is the session the redemption opened.
      Session *session.Session

      // Next is the RESOLVED redirect target: an allowlisted entry, or "/".
      // It is never the target the caller submitted.
      Next string
  }

  type MagicLinkResponder func(ex *Exchange, result MagicLinkResult) error

  func WithMagicLinkResponder(fn MagicLinkResponder) MagicLinkOption
  ```

**Why this task exists.** The consume endpoint wrote a fixed document nothing could replace. `library-design.md` requires every default to be replaceable without forking, or the design to say why it is not — and there was no why, only an omission. `httpsec` already answers this shape twice: `EnableFormLogin` takes a `LoginResponder` and, after Task 29A, `EnableMFA` takes an `MFAResponder`, both because the endpoint is the library's own and the application has no route behind it. This is the third.

The one constraint that is not cosmetic: the responder receives the **resolved** target. Handing it the submitted one would let a consumer write `http.Redirect(w, r, result.Next, …)` and reopen the open redirect the allowlist exists to close — the library would have validated the target and then handed over the unvalidated one.

- [ ] **Step 1: Write the failing tests**

```go
func TestMagicLinkResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MagicLinkOption
		assert func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}

	cases := []testCase{
		{
			name: "the default document is unchanged",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)

				var got map[string]any
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
				assert.NotEmpty(t, got["access_token"])
				assert.Equal(t, "", got["refresh_token"], "present and empty, never absent")
				assert.NotEmpty(t, got["valid_until"])
				assert.Equal(t, "/", got["next"])
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
				func(*httpsec.Exchange, httpsec.MagicLinkResult) error { return errResponder },
			)},
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, err error) {
				require.ErrorIs(t, err, errResponder)
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(nil)},
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
	}

	// ...table body per the table-test skill's assert closure form: assemble the
	// harness with tc.opts, request a link, redeem it, then tc.assert.
}

func TestMagicLinkConsumerResponder(t *testing.T) {
	t.Parallel()

	var seen httpsec.MagicLinkResult

	h := newMagicLinkHarness(t, httpsec.WithMagicLinkResponder(
		func(ex *httpsec.Exchange, r httpsec.MagicLinkResult) error {
			seen = r
			http.SetCookie(ex.Writer, &http.Cookie{
				Name: "session", Value: r.Token, HttpOnly: true, Secure: true,
			})

			return nil
		},
	))

	// ...request and redeem a link.

	assert.Empty(t, rec.Body.String(), "the consumer's responder replaces the default entirely")
	require.NotNil(t, seen.Session)
	assert.Equal(t, factor.MagicLink, seen.Session.FirstFactor.Kind)
	require.Len(t, rec.Result().Cookies(), 1)
}

func TestMagicLinkResponderSeesResolvedTarget(t *testing.T) {
	t.Parallel()

	var seen httpsec.MagicLinkResult

	// No WithAllowedRedirects, so every submitted target resolves to "/".
	h := newMagicLinkHarness(t, httpsec.WithMagicLinkResponder(
		func(_ *httpsec.Exchange, r httpsec.MagicLinkResult) error { seen = r; return nil },
	))

	// ...request a link with next=/dashboard, redeem it with next=/dashboard.

	assert.Equal(t, "/", seen.Next,
		"a responder receives the resolved target; handing it the submitted one would "+
			"reopen the redirect the allowlist refused")
}
```

- [ ] **Step 2: Run them and confirm each fails for the intended reason**

Run: `go test -run 'TestMagicLinkResponder|TestMagicLinkConsumerResponder|TestMagicLinkResponderSeesResolvedTarget' -count=1 ./httpsec/`

Expected, against the endpoint as Tasks 32–33 left it:
- the nil-responder row: `An error is expected but got nil` — no option exists yet;
- the responder-error row: `Expected error with "…errResponder" in chain but got nil`;
- `TestMagicLinkConsumerResponder`: `Should be empty, but was {"access_token":…}` — the default still wrote;
- `TestMagicLinkResponderSeesResolvedTarget`: the responder never ran, so `seen.Next` is `""` and the assertion reports `expected: "/" actual: ""`.

The "default document is unchanged" row **passes** from the start, which is the point — it is a regression pin on behaviour that already shipped, not a new claim. Prove it has teeth by changing the default's `next` member to the submitted target and confirming it fails, then restore.

- [ ] **Step 3: Add the type, the option and the default**

In `options.go`, beside the other `MagicLinkOption`s:

```go
// WithMagicLinkResponder replaces the response written when a link is
// successfully redeemed.
//
// With none supplied, the library writes a JSON document carrying the access
// token, an empty refresh token field, the session's validity and the resolved
// redirect target — the same document a successful login answers with, plus
// that target.
//
// It is called instead of the downstream handler, because the consume endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
//
// The result's Next is the target the allowlist resolved, never the one the
// caller submitted: a responder that redirects to it cannot send a caller
// somewhere the allowlist refused.
func WithMagicLinkResponder(fn MagicLinkResponder) MagicLinkOption {
	return func(i *magicLinkInterceptor) error {
		if fn == nil {
			return newConfigError("httpsec: WithMagicLinkResponder was given no function")
		}

		i.respond = fn

		return nil
	}
}
```

In `magiclink.go`, replace the direct document write on the success path with `i.respond(ex, MagicLinkResult{Token: tok, Session: ex.Session, Next: resolved})`, where `resolved` is the value already computed by the allowlist — not the form value. Move the existing document into the default responder unchanged, so the shipped shape is preserved byte for byte:

```go
// writeMagicLinkResult is the response a redemption succeeds with when the
// consumer supplies no responder.
func writeMagicLinkResult(ex *Exchange, result MagicLinkResult) error {
	body := magicLinkDocument{
		loginDocument: loginDocument{AccessToken: result.Token},
		Next:          result.Next,
	}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	//nolint:gosec // G117: the access token is the document's purpose, not a leak of one
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(encoded)

	return err
}
```

Keep `Referrer-Policy: no-referrer` set **before** the responder runs, so a consumer's responder cannot forget it and leak the token through a referrer.

- [ ] **Step 4: Run them and confirm green**

Run the three tests → PASS. Then the whole magic-link suite unchanged: `go test -run TestMagicLink -count=1 ./httpsec/` → PASS. `TestMagicLinkSuccess` and `TestMagicLinkRedirects` still assert the shipped document and the resolved target, so they are the proof the default did not move.

- [ ] **Step 5: Full package run and commit**

Run: `go test -race -count=1 ./httpsec/` → PASS. `go vet ./httpsec/...`, `gofmt -l httpsec/` empty.

```bash
git add httpsec/
git commit -m "feat(httpsec): a consumer can write the magic-link success response

The third library-owned endpoint with no route behind it, and the last one
whose response could not be replaced. The responder is handed the resolved
redirect target, never the submitted one, so redirecting to it cannot
reintroduce what the allowlist refused.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 35: EnableAPIKey

**Implements:** tasks.md 13.1, 13.2, 13.3, 13.4, 13.5

**Files:**
- Create: `httpsec/apikey.go`
- Modify: `httpsec/options.go`
- Test: `httpsec/apikey_test.go`

**Interfaces:**
- Produces: `httpsec.EnableAPIKey(m *apikey.Manager, opts ...APIKeyOption) Option`; options `WithAPIKeyScheme`, `WithAPIKeyLimiter`.

- [ ] **Step 1: Write the failing construction and header-matching tests**

```go
func TestEnableAPIKey(t *testing.T) {
	t.Parallel()
	// defaults; nil manager; typed-nil manager; nil limiter; typed-nil
	// limiter; an empty scheme → construction error for every refusal row.
}

func TestAPIKeyHeaderMatching(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		scheme string
		req    func(t *testing.T, valid string) *http.Request
		assert func(t *testing.T, caller *authenticate.Authentication, err error, limiter *recordingLimiter)
	}

	passesThrough := func(t *testing.T, caller *authenticate.Authentication, err error, limiter *recordingLimiter) {
		require.NoError(t, err)
		assert.Nil(t, caller, "the request is unauthenticated")
		assert.Zero(t, limiter.Checks(), "and the limiter is not consulted")
	}

	cases := []testCase{
		{
			name: "no Authorization header",
			req:  func(t *testing.T, valid string) *http.Request { return httptest.NewRequest(http.MethodGet, "/", nil) },
			assert: passesThrough,
		},
		{
			name: "a key in the query string only",
			req: func(t *testing.T, valid string) *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?api_key="+url.QueryEscape(valid), nil)
			},
			assert: passesThrough,
		},
		{
			name: "a Bearer token",
			req: func(t *testing.T, valid string) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer "+valid)
				return r
			},
			assert: passesThrough,
		},
		{
			name: "the wrong case of the scheme",
			req: func(t *testing.T, valid string) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "apikey "+valid)
				return r
			},
			assert: passesThrough,
		},
		{
			name: "the default scheme",
			req: func(t *testing.T, valid string) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "ApiKey "+valid)
				return r
			},
			assert: func(t *testing.T, caller *authenticate.Authentication, err error, limiter *recordingLimiter) {
				require.NoError(t, err)
				require.NotNil(t, caller)
				assert.Equal(t, identity.UserID("svc-billing"), caller.Principal.ID)
			},
		},
		{
			name:   "a consumer scheme",
			scheme: "Service ",
			req: func(t *testing.T, valid string) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Service "+valid)
				return r
			},
			assert: func(t *testing.T, caller *authenticate.Authentication, err error, limiter *recordingLimiter) {
				require.NoError(t, err)
				require.NotNil(t, caller)
				assert.True(t, caller.Principal.IsService())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { t.Parallel() /* ...drive the chain */ })
	}
}
```

The query-string row is the important one: a credential in a URL reaches access logs, proxy logs and `Referer` headers, so it never authenticates — which is the same rule form login already applies to its body.

- [ ] **Step 2: Write the failing throttle and stateless-phase tests**

```go
func TestAPIKeyThrottle(t *testing.T) {
	t.Parallel()

	t.Run("twenty invalid keys from one source then a valid one is refused", func(t *testing.T) {
		t.Parallel()

		for range 20 {
			err := requestWithKey(t, chain, "203.0.113.7", "sk_"+freshID(t)+".bm9wZQ")
			assert.ErrorIs(t, err, httpsec.ErrAuthenticationFailed)
			assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		}

		before := manager.VerifyCalls()
		err := requestWithKey(t, chain, "203.0.113.7", valid)
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Equal(t, before, manager.VerifyCalls(), "a throttled source is not verified")
	})

	t.Run("an unattributable source is refused without verifying", func(t *testing.T) { /* ... */ })
}

func TestAPIKeyStateless(t *testing.T) {
	t.Parallel()

	denyReason := errors.New("outside office hours")

	t.Run("a valid key creates no session", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, requestWithKey(t, chain, "203.0.113.7", valid))
		assert.Zero(t, activeSessions(t, sessions))
	})

	t.Run("a stateless deny refuses with the policy's reason", func(t *testing.T) {
		t.Parallel()

		err := requestWithKey(t, chain, "203.0.113.7", valid)
		assert.ErrorIs(t, err, denyReason)
		assert.False(t, handlerCalled.Load(), "the principal does not reach later handlers")
	})

	t.Run("policy denials of a valid key are not counted", func(t *testing.T) {
		t.Parallel()

		for range 25 {
			require.ErrorIs(t, requestWithKey(t, chain, "203.0.113.7", valid), denyReason)
		}

		allow.Store(true)

		assert.NoError(t, requestWithKey(t, chain, "203.0.113.7", valid),
			"the credential was valid every time; only the policy refused")
	})
}

func TestAPIKeyConsumerLimiter(t *testing.T) { /* a shared limiter receives every check and failure */ }

func TestAPIKeyThrottleLogSampling(t *testing.T) {
	t.Parallel()
	// 300 keys from one throttled source in a minute → one record, containing
	// no presented key.
}
```

- [ ] **Step 3: Run them all and confirm the red steps, then implement**

Run: `go test -run 'TestEnableAPIKey|TestAPIKeyHeaderMatching|TestAPIKeyThrottle|TestAPIKeyStateless|TestAPIKeyConsumerLimiter|TestAPIKeyThrottleLogSampling' -count=1 ./httpsec/` → FAIL.

```go
// authenticate matches a key in the Authorization header and verifies it.
//
// The order matters at each step:
//
//  1. Match the scheme first. A request that carries no key is not an attempt,
//     so it must not consult the limiter — otherwise ordinary unauthenticated
//     traffic would fill the buckets that exist to catch guessing.
//  2. Check the source before verifying, so a throttled scanner costs one
//     bucket read rather than a store round trip.
//  3. Verify. A failure records against the source and returns the same error
//     a throttled source gets, so the two are indistinguishable.
//  4. The stateless phase. A deny here is not recorded: the credential was
//     valid, and counting it would let a policy misconfiguration lock out the
//     caller's own machines.
//  5. Publish the caller without a session. A machine has nobody to prompt and
//     nothing to keep between requests.
func (i *apiKeyInterceptor) authenticate(ex *Exchange, next Next) error {
	presented, ok := strings.CutPrefix(ex.Request.Header("Authorization"), i.scheme)
	if !ok {
		return next(ex)
	}

	ctx := ex.Context()

	src, err := i.guard.Check(ctx, ex.Request.ClientAddr())
	if err != nil {
		return errors.Join(ErrAuthenticationFailed, apikey.ErrVerificationFailed)
	}

	p, rec, err := i.keys.Verify(ctx, presented)
	if err != nil {
		i.guard.RecordFailure(ctx, src)
		return errors.Join(ErrAuthenticationFailed, apikey.ErrVerificationFailed)
	}

	auth := &authenticate.Authentication{
		Principal:   &p,
		FirstFactor: factor.APIKey,
		CredentialID: rec.ID.String(),
	}

	if i.engine != nil {
		d := i.engine.EvaluatePhase(ctx, policy.StatelessAuthentication,
			statelessInput(&p, factor.APIKey, i.now()))

		if d.Outcome == policy.Deny {
			return policyDenyReason(d)
		}
	}

	ex.Authentication = auth
	ex.SetContext(WithCaller(ctx, auth))

	return next(ex)
}
```

Read `authenticate.Authentication`'s real fields and whatever `httpsec` already uses to build a stateless policy input; match them rather than the sketch.

- [ ] **Step 4: Run them and confirm green, then commit**

Run: `go test -race -count=1 ./httpsec/` → PASS.

```bash
git add httpsec/
git commit -m "feat(httpsec): authenticate machine callers by API key, statelessly

A key in a query string never authenticates, a request without the scheme
never touches the limiter, and a policy refusal of a valid key is not counted
as a failed guess.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 36: The construction refusal http-security flagged

**Implements:** tasks.md 14.1, 14.2, 14.3

**Files:**
- Modify: `httpsec/chain.go`
- Test: `httpsec/chainmfa_test.go`, `test/httpsec_construction_test.go`

**Interfaces:**
- Produces: the assembly check that refuses a policy able to challenge for MFA when nothing enforces it.

- [ ] **Step 1: Write the failing test**

`http-security` recorded this as a dependency it could not enforce itself. The chain's per-request phase marks the challenge pending and continues, because the gate is what enforces it and the verify endpoint must stay reachable. With no gate, sessions are marked and nothing ever acts on the marker — the caller proceeds with an unsatisfied second factor and nothing reports it. A silent failure is why this is a construction error rather than a documented caution.

```go
func TestChainRefusesUnenforcedMFAChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	ok := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name: "a policy that can challenge for MFA with no interceptor",
			opts: []httpsec.Option{httpsec.WithPolicyEngine(engineWithMFAChallenge(t))},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names what is missing")
			},
		},
		{
			name: "the same policy with EnableMFA",
			opts: []httpsec.Option{
				httpsec.WithPolicyEngine(engineWithMFAChallenge(t)),
				httpsec.EnableMFA(&stubMethod{channel: factor.AuthenticatorApp}),
			},
			assert: ok,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := httpsec.NewChain(append(baseChainOptions(t), tc.opts...)...)
			tc.assert(t, c, err)
		})
	}
}

func TestChainMFAChallengeRefusalScope(t *testing.T) {
	t.Parallel()

	t.Run("a password-change challenge does not need EnableMFA", func(t *testing.T) {
		t.Parallel()
		c, err := httpsec.NewChain(append(baseChainOptions(t),
			httpsec.WithPolicyEngine(engineWithPasswordChangeChallenge(t)))...)
		require.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("no policy at all assembles", func(t *testing.T) {
		t.Parallel()
		c, err := httpsec.NewChain(baseChainOptions(t)...)
		require.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("EnableMFA without an MFA policy assembles", func(t *testing.T) {
		t.Parallel()
		// Enforcing a challenge nothing raises is harmless: the gate never
		// fires. Only the other direction is a hole.
	})
}
```

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestChainRefusesUnenforcedMFAChallenge|TestChainMFAChallengeRefusalScope' -count=1 ./httpsec/`
Expected: FAIL on the first row — the chain assembles happily.

- [ ] **Step 3: Implement**

The check needs to know whether any registered policy can raise `policy.ChallengeMFA`. `policy.Policy` exposes `Phases()`; if it exposes no way to ask what challenges it can raise, add one — a `Challenges() []ChallengeKind` on an optional interface that the MFA policies implement — with its own test in `policy`, and treat a policy that does not implement it as raising nothing.

```go
	// http-security ships the slot and the marking; this change ships the gate
	// that acts on the marker. A policy able to raise the challenge with
	// nothing registered at OrderMFAChallenge means every challenged session
	// is marked and then served anyway: the caller proceeds with an
	// unsatisfied second factor and no part of the request path says so.
	//
	// It is refused here rather than documented because the failure is
	// invisible. Nothing errors, nothing logs, and the only symptom is an
	// authorization that should not have happened.
	if c.engine != nil && c.engine.CanChallenge(policy.ChallengeMFA) && !c.registeredAt(OrderMFAChallenge) {
		return nil, errors.New(
			"httpsec: a registered policy can challenge for a second factor, " +
				"but nothing enforces it: add EnableMFA, or remove the policy")
	}
```

- [ ] **Step 4: Run them and confirm green**

Run: `go test -run 'TestChainRefusesUnenforcedMFAChallenge|TestChainMFAChallengeRefusalScope' -count=1 ./httpsec/ ./policy/` → PASS.

- [ ] **Step 5: Extend the adapter construction conformance table**

The same wiring mistake must fail the same way on net/http, gin and fiber. Add the case to the table `test/httpsec_construction_test.go` already holds — one row, three adapters, not three tests.

Run: `go test -run TestConformanceConstruction -count=1 ./...` in `test` → PASS.

- [ ] **Step 6: Commit**

```bash
git add httpsec/ policy/ test/
git commit -m "feat(httpsec): refuse a chain whose MFA challenge nothing enforces

http-security flagged this as a dependency it could not enforce itself. The
failure is silent, so it is a construction error rather than a caution.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 37: Integration across the methods

**Implements:** tasks.md 15.1, 15.2, 15.3

**Files:**
- Test: `httpsec/authmethods_integration_test.go`

**Interfaces:** none new. This task proves the three methods compose.

- [ ] **Step 1: Write the failing end-to-end test**

```go
func TestMagicLinkThenMFA(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// One chain: EnableMagicLink, EnableMFA, a policy that challenges for MFA,
	// a protected /invoices handler, a real TOTP method with a confirmed
	// enrolment for u-1.

	// 1. Request a link.
	reqRec := postTo(t, chain, "/login/magic", form("email=ada@example.com&next=/"))
	require.Equal(t, http.StatusAccepted, reqRec.Code)
	nonce := cookieNamed(t, reqRec, "magic_link_binding").Value
	token := tokenFromSentMessage(t, sender)

	// 2. Redeem it. The policy challenges, so the link is spent and the
	//    session is created with the challenge pending.
	err := postConsume(t, chain, token, nonce)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, err, &ch)
	assert.Equal(t, policy.ChallengeMFA, ch.Kind)
	require.NotNil(t, ch.Session)
	assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)

	pending := ch.Session.ID

	// 3. The gate refuses the protected route.
	var handlerCalled atomic.Bool
	err = get(t, chain, "/invoices", withSessionHandle(pending))
	require.ErrorAs(t, err, &ch)
	assert.False(t, handlerCalled.Load())

	// 4. The second factor is accepted, and the handle rotates.
	code := codeAt(t, secret, clock.Now(), 6, 30*time.Second)
	verifyRec := postTo(t, chain, "/mfa/totp", form("code="+code), withSessionHandle(pending))
	require.Equal(t, http.StatusOK, verifyRec.Code)

	rotated := sessionHandleFrom(t, verifyRec)
	assert.NotEqual(t, pending, rotated)

	_, err = sessions.Load(ctx, pending)
	assert.Error(t, err, "the pre-MFA handle is gone")

	// 5. The protected route now serves.
	require.NoError(t, get(t, chain, "/invoices", withSessionHandle(rotated)))
	assert.True(t, handlerCalled.Load())
}

func TestAPIKeyBypassesMFAGate(t *testing.T) {
	t.Parallel()

	// The same chain, plus EnableAPIKey. A machine caller presenting a valid
	// key reaches /invoices: factor.APIKey is MFA-exempt, and the gate only
	// looks at sessions, of which a key request has none.
	var handlerCalled atomic.Bool

	require.NoError(t, getWithKey(t, chain, "203.0.113.7", validKey, "/invoices"))
	assert.True(t, handlerCalled.Load())
	assert.Zero(t, activeSessions(t, sessions))
}

func TestFlowLimitersAreIndependent(t *testing.T) {
	t.Parallel()

	// Exhaust the magic-link source limit from 203.0.113.7.
	for range 10 {
		_ = postConsumeFrom(t, chain, "203.0.113.7", "wrong-token", "")
	}
	require.ErrorIs(t, postConsumeFrom(t, chain, "203.0.113.7", validToken(t), nonce),
		magiclink.ErrInvalidLink)

	// The same source still authenticates by key.
	assert.NoError(t, getWithKey(t, chain, "203.0.113.7", validKey, "/invoices"))

	// And the same user still verifies a code.
	assert.NoError(t, postVerify(t, chain, pendingHandle, validCode))
}
```

- [ ] **Step 2: Run them and confirm the red steps, then make them pass**

Run: `go test -run 'TestMagicLinkThenMFA|TestAPIKeyBypassesMFAGate|TestFlowLimitersAreIndependent' -race -count=1 ./httpsec/`

These exercise code every earlier task already made pass, so a failure here is an integration problem — a slot order, a context that does not carry the session, a handle the exchange does not publish. Fix the integration; do not weaken the test. If a failure reveals a genuine design gap, stop and report it rather than patching around it.

- [ ] **Step 3: Commit**

```bash
git add httpsec/
git commit -m "test(httpsec): a magic-link login challenged for MFA, end to end

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 38: Documentation, simplification and reconciling the artifacts

**Implements:** tasks.md 16.1, 16.2, 16.3, 16.4, 16.5, 16.6

**Files:**
- Modify: `notify/doc.go`, `mfa/doc.go`, `magiclink/doc.go`, `apikey/doc.go`, `httpsec/doc.go`
- Report (do not edit): `openspec/changes/auth-methods/design.md`, `openspec/specs/sessions/spec.md`, `openspec/specs/identity-model/spec.md`

- [ ] **Step 1: Simplify each package and re-run**

Invoke `/simplify` over `notify`, `mfa`, `apikey`, `magiclink` and the three new `httpsec` files, one at a time. It reviews for reuse, simplification, efficiency and altitude, and applies the fixes.

After each: `go test -race -count=1 ./<package>/`. A simplification that changes behaviour is a bug, and the suites are what say so.

Run at the end: `go test -race -count=1 ./notify/ ./mfa/ ./apikey/ ./magiclink/ ./httpsec/`

- [ ] **Step 2: Write the package godoc**

Each package's `doc.go` says what it does, what its defaults are and what its limits are. For every option, name the default it replaces. For every port, say what the library uses when the consumer supplies none.

State these limits explicitly, because the design commits to documenting them:

| Limit | Where it goes |
|---|---|
| The queued sender's send timeout bounds only an inner sender that honours cancellation | `notify`, on `WithQueueSendTimeout` |
| Messages still queued at a crash or a missed `Close` are lost | `notify`, on `QueuedSender` |
| An attacker holding a password can lock a user out of MFA verification for the window | `mfa`, on `WithVerifyLimiter` |
| A magic-link request still does store work only for real accounts, so a small timing difference remains | `magiclink`, on `Request` |
| An API key issued with a lifetime of zero or less never expires | `apikey`, on `Issue` |
| Rotation is two writes outside an attached transaction | `apikey`, on `Rotate` |
| Requiring MFA for all locks out unenrolled users until `mfa-enrolment-path` | `policy`, on the require-for-all option (Task 18) |

Verify: `go doc ./notify`, `go doc ./mfa`, `go doc ./magiclink`, `go doc ./apikey` — read each back and check every option names its default.

- [ ] **Step 3: Report the design corrections**

Write a report for the main session — do **not** edit `design.md`. It must record:

1. `factor.Channel` and `factor.Kind` in place of `identity.Channel`, and `factor.AuthenticatorApp`, `factor.MagicLink`, `factor.APIKey` as the constants used.
2. The existing `policy.MFAMethodLookup` in place of a new `mfa.EnrolmentLookup`. `mfa.Method` satisfies it structurally, so `LookupFor` is a validating adapter — the one place an empty channel is refused — rather than a translation. Decision 4's three-return `Enrolment(...)` signature does not exist.
3. `internal/origin.Allowlist` in place of a new unexported `httpsec` redirect helper. Decision 10 says the helper "lives unexported in `httpsec` and is shared"; it already lives in `internal/origin`, which `outbound` also uses, so `oidc-login` reuses it from there.
4. Whatever Task 33 decided about evaluating the post-authentication policy once or twice on the magic-link success path.

- [ ] **Step 4: Report the three prerequisite APIs**

Record, again as a report and not an edit:

- `Session.MFASatisfiedAt`, `session.Manager.Rotate` and `identity.UserLoader.LoadByUserID` were added by this change (Tasks 1 and 2), in the packages the `sessions` and `identity-model` capabilities own.
- The archived `openspec/specs/sessions/spec.md` and `openspec/specs/identity-model/spec.md` now understate those packages: `sessions` pins the second-factor *state* but not the satisfied *time* and not handle rotation, and `identity-model` pins no load-by-reference. The proposal's claim that `sessions` provides handle rotation was not true of the code.
- Each is additive and nothing is tagged, so no compatibility decision is owed — but the specs need amending or re-archiving, which is the main session's call.

- [ ] **Step 5: Report what durable-persistence must carry**

Record what this change needs from `durable-persistence`:

- `confirmed_at` and `last_step` columns on the MFA enrolment table, beyond the sealed secret. Squashing them into the initial migration is free before the first tag.
- An API key table matching `apikey.Key`, including the nullable `expires_at`, `revoked_at` and `last_used_at`.
- `store-conformance` scenarios for both ports: `AcceptStep`'s conditional write (concurrent acceptance of one step yields one success), `PutPending`'s already-enrolled decision made by the write, and **API key rotation's atomicity inside an attached transaction**, which Task 22 could not close here because no transactional store exists. That scenario stays `UNREPRODUCED` in this change's report, with that reason.

- [ ] **Step 6: Run the full gate**

```bash
make check
```

Every module, green: `fmt-check`, `vet`, `lint`, `test`, `vuln`, `generate-check`. Report the actual output. If anything fails, fix it before reporting — a gate that was not seen green has not been run.

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "docs: package godoc for the auth methods, with every default and limit named

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage.** Every requirement in the four specs maps to at least one task:

| Spec | Requirements | Tasks |
|---|---|---|
| `email-notification` | replaceable port; header refusal; faithful encoding; construction failures; one deadline; STARTTLS by default; queued sender; logs carry no body | 3, 4, 5, 6, 7, 8, 9, 10 |
| `multi-factor-auth` | constant non-empty channel; definitive enrolment answers; required issuer; RFC 6238; one step once; confirm before use; no silent replacement; lost enrolment never downgrades; require-for-all lockout; per-user throttle; same-channel refusal; verify resolves and rotates; the pending gate; logs carry no codes | 11, 12, 13, 14, 15, 16, 17, 18, 28, 29 |
| `magic-link` | uniform requests; replaceable resolver; bound to the user reference; issuance limit; absolute link base; neutral replaceable message; non-blocking delivery; check-then-consume ordering; checks unchanged; policy honoured; redeemer guard; uniform failures; source accounting; device binding; POST-only; exact redirects; sampled logs | 23, 24, 25, 26, 27, 30, 31, 32, 33, 34 |
| `api-keys` | shown once; prefix-recognisable; digest-only storage; bound to a service principal; expiry; uniform failures; immediate revocation; rotation; last use; Authorization header; stateless; per-source throttle; in-memory default; sampled logs | 19, 20, 21, 22, 35 |

The design's inbound dependency from `http-security` is Task 36. The three prerequisite APIs are Tasks 1 and 2. Every departure D1–D15 is named in the task that implements it: D1 in 11 and 28, D2 in 15, D3 in 13 and 16, D4 in 17, D5 in 1 and 28, D6 in 23, D7 in 24 and 26, D8 in 34, D9 and D10 in 20, D11 in 23, D12 in 7, D13 in 4, D14 in 8, D15 in 29.

**2. Placeholders.** Three tasks carry test bodies sketched as comments rather than written out — 28 step 5, 29's helper names, 32's `TestMagicLinkConsumeEndpoint`, 35's construction table and 37. Each states exactly what the case must assert and follows a fully written table in the same task, which is the pattern to copy. Everything else carries the code. No task says "add appropriate error handling" or "handle edge cases".

**3. Type consistency.** `mfa.Method` is used with the same four methods throughout (11, 13, 28). `magiclink.Check` has one signature everywhere (26, 27, 32, 33). `apikey.Key`'s field names are the same in 19, 21 and 22. `session.Manager.Rotate` returns `(*Session, error)` in 1 and is called that way in 28. `identity.UserLoader.LoadByUserID` is declared in 2 and called in 26. `notify.Sender` and `notify.NonBlocking` are consistent across 3, 10 and 23.

**Three places where the code must be read before writing**, because the plan works from a design that predates it: `identity.Details`' enabled and password-changed field names (Tasks 24, 26); `identity.Principal`'s field names and its mapping helper (Tasks 21, 26); and `httpsec`'s `Exchange` mechanism for publishing a new session handle (Task 28). Each task says so at the point it matters.

## Task 39: The two findings closed before archive

**Implements:** tasks.md 17.1, 17.2

**Files:**
- Modify: `notify/queuedoptions.go`, `notify/smtpoptions.go`, `notify/queued.go`, `notify/smtp.go`
- Modify: `mfa/throttle.go`
- Test: `notify/queued_test.go`, `mfa/throttle_test.go`

**Interfaces:**
- Consumes: nothing new. Both are corrections inside packages this change already built.
- Produces: no new exported symbol. Two defaults change; two godocs change with them.

These are independent packages and do not share a file, so they may be done in either order or at
the same time.

### 17.1 — `notify` reports by default

- [ ] **Step 1: Write the failing test**

```go
func TestQueuedSenderReportsDropsByDefault(t *testing.T) {
	t.Parallel()

	t.Run("a drop is reported with no logger configured", func(t *testing.T) {
		var buf bytes.Buffer

		// slog.Default() is process-global, so swap it for the duration of this
		// test rather than reading whatever the package was built with.
		restore := swapDefaultLogger(t, slog.New(slog.NewTextHandler(&buf, nil)))
		defer restore()

		// ...a queued sender with a queue of 1 and one worker held busy, no
		// WithQueueLogger, then two sends so the second is dropped.

		require.ErrorIs(t, err, notify.ErrQueueFull)
		assert.Contains(t, buf.String(), "queue",
			"a dropped sign-in message is reported without configuration")
		assert.NotContains(t, buf.String(), body,
			"and the record still carries no message body")
	})

	t.Run("silence is available but must be asked for", func(t *testing.T) {
		var buf bytes.Buffer
		restore := swapDefaultLogger(t, slog.New(slog.NewTextHandler(&buf, nil)))
		defer restore()

		// ...same again, but with notify.WithQueueLogger(slog.New(slog.DiscardHandler)).

		require.ErrorIs(t, err, notify.ErrQueueFull)
		assert.Empty(t, buf.String(), "a supplied discarding logger writes nothing")
	})
}
```

`swapDefaultLogger` sets `slog.SetDefault` and returns a restore func; keep it in the test file and
do not run these two subtests in parallel with each other, because they share process state.

- [ ] **Step 2: Run it and confirm it fails for the intended reason**

Run: `go test -run TestQueuedSenderReportsDropsByDefault -count=1 ./notify/`

Expected: the first subtest fails on `Should contain "queue"` with an empty buffer — the sender is
writing to its discarding default, not to `slog.Default()`. The second subtest passes already, which
is correct: it pins the behaviour that must survive the change.

- [ ] **Step 3: Change both defaults**

In `notify/queuedoptions.go` and `notify/smtpoptions.go`, the unset logger becomes `slog.Default()`.
Rewrite both godocs to name the new default and to say that a consumer wanting silence supplies a
discarding handler explicitly. Keep every existing sentence about what the records do **not**
contain — the body and subject stay out of them, and `TestSMTPSenderLogsCarryNoBody` must stay green
untouched.

- [ ] **Step 4: Run and confirm green**

Run: `go test -race -count=1 ./notify/` → PASS, including `TestSMTPSenderLogsCarryNoBody` and the
queued sender's existing drop, panic and close tests.

### 17.2 — the throttle charges a guess whose caller hung up

- [ ] **Step 1: Write the reproducing test**

```go
func TestVerifyThrottleChargesAHangUp(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)

	var recordedWithLiveCancel bool

	// DoAndReturn, not Do: the mock is generated with --typed, so its Do takes
	// func(context.Context, string) error and a void closure will not compile.
	limiter.EXPECT().
		RecordFailure(gomock.Any(), mfa.VerifyThrottleKey("u-1")).
		DoAndReturn(func(ctx context.Context, _ string) error {
			recordedWithLiveCancel = ctx.Err() != nil

			return nil
		})

	throttle, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(limiter))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the client hung up before the answer was written

	throttle.RecordFailure(ctx, "u-1")

	assert.False(t, recordedWithLiveCancel,
		"a guess that was made is charged even when the caller has gone; the limiter "+
			"must not be handed a context that is already cancelled")
}
```

- [ ] **Step 2: Run it and confirm it fails for the intended reason**

Run: `go test -run TestVerifyThrottleChargesAHangUp -count=1 ./mfa/`

Expected: `Should be false` — the limiter received a context whose `Err()` is non-nil. That is the
defect: with the in-memory limiter nothing shows, but a networked limiter would decline the write and
the guess would go uncounted, which is a free retry against the throttle D4 exists to impose.
**REPRODUCED.**

- [ ] **Step 3: Strip the cancellation**

In `mfa/throttle.go`, `RecordFailure` passes `context.WithoutCancel(ctx)` to the limiter. Values
survive, cancellation does not. Say why in a comment, citing the limiter contract rather than
restating it. Leave `Check` alone: refusing a check whose caller has gone is correct, and only the
*recording* of a failure already made must outlive the request.

- [ ] **Step 4: Run and confirm green, then the whole package**

Run: `go test -run TestVerifyThrottleChargesAHangUp -count=1 ./mfa/` → PASS.
Then `go test -race -count=1 ./mfa/` → PASS, with the existing throttle, sampling and log-hygiene
tests untouched.

- [ ] **Step 5: Commit**

```bash
git add notify/ mfa/
git commit -m "fix(mfa,notify): charge a guess whose caller hung up, and report dropped mail

A networked limiter would have declined to record an MFA failure whose request
context was already cancelled, handing back a free retry. A dropped queued
message was reported to a discarding logger, so a sign-in link that never
arrived was invisible at both ends.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---
