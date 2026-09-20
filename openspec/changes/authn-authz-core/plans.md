# authn-authz-core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build scrty's framework-free security core — who a caller is, whether they may act, whether their session still holds, what a deployment rule decides, how often a source may fail, and how a single-use credential is spent exactly once.

**Architecture:** Six packages in the core module, each a plain constructor with functional options over a port the consumer may replace: `authenticate` (ordered providers), `authorize` (ordered authorizers plus a generic rule set), `session` (record, store, manager, sealing decorator), `policy` (phase engine plus built-in policies), `ratelimit` (limiter, source keyer, guard), `onetime` (issue, check, consume). Nothing here imports net/http, a driver, a scheduler or a DI container; every decision is testable without them.

**Tech Stack:** Go 1.27, standard library, `log/slog`, `pkg/id`, `pkg/logsample`, `testing/synctest`, testify, uber-go/mock.

**Spec:** `openspec/changes/authn-authz-core/proposal.md`, `design.md`, and `specs/{authentication,authorization,sessions,security-policy,rate-limiting,one-time-tokens}/spec.md`. The plan argues from those; read them alongside it.

## Global Constraints

- **Test-first, always.** Write the failing test, run it, confirm it fails for the intended reason, then implement. A compile error is not a red step (`.claude/rules/golang-tdd.md`).
- **Table tests use the `assert` closure form**, never `want`/`wantErr` fields, with a `ctx` modifier where context matters and `t.Context()` over `context.Background()` (`.claude/skills/table-test/SKILL.md`).
- **Mocks come from `mockgen`** via `//go:generate`, placed by who consumes them, never in a production build (`.claude/skills/use-mockgen/SKILL.md`).
- **Opinionated defaults, full consumer control.** Every behaviour has a safe default needing no configuration; every default is replaceable through an option or a port; a limit on flexibility is stated, never silently relaxed; a contradictory configuration is an error from the constructor, before traffic (`.claude/rules/library-design.md`).
- **A defect claim needs a failing test as proof** (`.claude/rules/defect-claims.md`). The "verify red against X" steps below are that proof for each departure.
- **Core module only.** No framework, driver, scheduler or DI dependency. Go 1.27 floor.
- **Consumer data is opaque.** Stored, filtered where promised, returned unchanged; its meaning belongs to the consumer.
- **Options are named after what they govern.** One option never silently governs two subsystems.
- **Refusal logs are sampled** with `pkg/logsample`, always with a reporter, and never carry a secret.
- **Library-owned records use `pkg/id`.** Tokens, secrets and session identifiers come from `crypto/rand`.
- **Never cite or copy the reference implementation** in code, comments, commits or artifacts (`.claude/rules/legacy-reference.md`).

---

## Task 1: Package scaffolding and shared conventions

**Implements:** tasks.md 1.1–1.4 — design.md decision 1.

**Files:**
- Create: `authenticate/doc.go`, `authorize/doc.go`, `session/doc.go`, `policy/doc.go`, `ratelimit/doc.go`, `onetime/doc.go`
- Create: `internal/nilcheck/nilcheck.go`, `internal/nilcheck/nilcheck_test.go`

**Interfaces:**
- Produces: `nilcheck.IsNil(v any) bool`, used by every construction check in Tasks 2–7. It is internal so it never reaches the public surface.

**Why an internal package.** Six packages each need the same check and none of them should export it. A shared `internal/` package is the one place it can live without becoming API.

- [ ] **Step 1.1a: Create the six package docs**

One file per package, each naming what the package holds, in the voice of the existing packages (read `signingkey/alg.go`'s package doc first). No types yet.

```go
// Package authenticate decides who a caller is.
//
// A Manager runs ordered providers and returns the first answer that is not a
// refusal to handle the credentials. Providers for a username and password, and
// for a bearer token, ship here; a consumer adds their own by implementing
// Authenticator.
package authenticate
```

Run: `go build ./...`
Expected: success, with the root layout guard test still green and no new requirement in `go.mod`.

- [ ] **Step 1.1b: Verify the layout gate**

Run: `go test . -count=1`
Expected: PASS. The guard fails if a new package pulled in a forbidden module.

- [ ] **Step 1.2a: Write the failing test for nil detection**

```go
func TestIsNil(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  any
		assert func(t *testing.T, got bool)
	}

	var nilPointer *bytes.Buffer
	var nilMap map[string]string
	var nilFunc func()

	cases := []testCase{
		{
			name:  "an untyped nil interface",
			value: nil,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			// What an unchecked constructor error hands over: the interface is
			// not nil, so `if v == nil` misses it, and the first call panics.
			name:  "a non-nil interface holding a nil pointer",
			value: nilPointer,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:  "a nil map",
			value: nilMap,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:  "a nil func",
			value: nilFunc,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:  "a live value",
			value: &bytes.Buffer{},
			assert: func(t *testing.T, got bool) { assert.False(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, nilcheck.IsNil(tc.value))
		})
	}
}
```

- [ ] **Step 1.2b: Run it and watch it fail**

Run: `go test -run 'TestIsNil' -count=1 ./internal/nilcheck/`
Expected: FAIL — the package does not exist yet, so create `nilcheck.go` with `func IsNil(any) bool { return false }` first, then re-run and see the four true cases fail on their assertions. A missing package is not a red step.

- [ ] **Step 1.2c: Implement**

```go
// IsNil reports whether v is nil, including an interface holding a nil pointer.
//
// A constructor that only writes `if v == nil` accepts the second shape, which
// is exactly what an unchecked constructor error hands over: the caller passes
// the nil result of a failed New, the interface is non-nil because it carries a
// type, and the first method call panics on a request instead of failing at
// wiring time.
func IsNil(v any) bool {
	if v == nil {
		return true
	}

	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
```

- [ ] **Step 1.2d: Run to verify it passes**

Run: `go test -run 'TestIsNil' -count=1 ./internal/nilcheck/`
Expected: PASS, all five cases.

- [ ] **Step 1.3: Pin the clock convention where it is first used**

The clock has no home of its own; it is a convention each package repeats. Pin it in `session` (Task 4), where it is first load-bearing, with this shape:

```go
// WithClock replaces the time source. The default is time.Now.
//
// A nil clock is a configuration error rather than a silent fallback: a caller
// passing one meant to inject a clock, and falling back to the wall clock would
// make a test that never advances look like one that does.
func WithClock(now func() time.Time) ManagerOption {
	return func(m *Manager) { m.now = now }
}
```

Verification for this step is the session manager's construction table (Step 4.4b), which must include a nil-clock row.

- [ ] **Step 1.4: Pin the logger convention the same way**

```go
// WithSessionLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger has
// an obvious safe reading — the caller does not want this component's logs —
// and refusing it would make logging mandatory.
```

Verified by the same construction table: a nil logger constructs and logs, a nil clock does not construct.

---

## Task 2: authenticate — manager, providers and result

**Implements:** tasks.md 2.1–2.12 — design.md decisions 2, 3, 4, and `specs/authentication/spec.md`.

**Files:**
- Create: `authenticate/authenticate.go` (port, sentinels, `Authentication`), `authenticate/manager.go`, `authenticate/password.go`, `authenticate/jwt.go`, `authenticate/context.go`
- Create: `authenticate/manager_test.go`, `authenticate/password_test.go`, `authenticate/jwt_test.go`, `authenticate/context_test.go`, `authenticate/sampling_test.go`
- Create: `authenticate/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do) (mockgen output, test build only)

**Interfaces:**
- Consumes: `identity.Credentials`, `identity.Principal`, `identity.UserLoader`, `identity.Details` (identity-model); `password.Encoder` (password-encoding); `token.Verifier` (token-issuance); `id.Generator` (id-generation); `logsample.Sampler` (log-sampling).
- Produces: `Authenticator` (the port every later change wires), `NewManager(delegates ...Authenticator) (*Manager, error)`, `NewUsernamePasswordAuthenticator`, `NewJwtAuthenticator`, `Authentication`, `WithAuthentication`/`AuthenticationFromContext`, and the sentinels `ErrUnsupportedCredentials`, `ErrAuthenticationFailed`, `ErrNoEligibleAuthenticator`.

- [ ] **Step 2.1a: Write the failing test for ordered delegation**

```go
func TestManagerAuthenticate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, got *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the first delegate that answers decides, and later ones are never asked",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				// No EXPECT: asking it at all is the failure.
				second := NewMockAuthenticator(ctrl)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := authenticate.NewManager(tc.delegates(t, ctrl)...)
			require.NoError(t, err)

			got, err := m.Authenticate(t.Context(), credentials(t))
			tc.assert(t, got, err)
		})
	}
}
```

- [ ] **Step 2.1b: Run it and watch it fail**

Run: `go test -run 'TestManagerAuthenticate' -count=1 ./authenticate/`
Expected: FAIL on the assertion once the package compiles. Generate the mock first (`//go:generate mockgen -source=authenticate.go -package=authenticate_test -destination=mocks_test.go -typed`) and stub `NewManager` returning an empty manager, so the failure is behavioural.

- [ ] **Step 2.2: Add the skip and exhaustion rows to the same table**

```go
		{
			name: "ErrUnsupportedCredentials skips to the next delegate",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				first := NewMockAuthenticator(ctrl)
				first.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(nil, authenticate.ErrUnsupportedCredentials)
				second := NewMockAuthenticator(ctrl)
				second.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: principal(t)}, nil)

				return []authenticate.Authenticator{first, second}
			},
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
		{
			name: "any other error is returned unchanged",
			// ... first returns errBackendDown; assert require.ErrorIs(t, err, errBackendDown)
		},
		{
			name: "every delegate skipping is reported as such",
			// ... both return ErrUnsupportedCredentials
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				require.ErrorIs(t, err, authenticate.ErrNoEligibleAuthenticator)
				assert.Nil(t, got)
			},
		},
```

Run: `go test -run 'TestManagerAuthenticate' -count=1 ./authenticate/`
Expected: each new row FAILs, then passes once the evaluation loop is implemented.

- [ ] **Step 2.3a: Prove a nil delegate panics (departure a, red)**

Before adding the construction check, build a manager with a typed-nil delegate and call it:

```go
func TestZTmpNilDelegatePanics(t *testing.T) {
	var missing authenticate.Authenticator // typed nil after an unchecked New
	m, err := authenticate.NewManager(missing)
	require.NoError(t, err) // the shape being replaced accepts it
	_, _ = m.Authenticate(t.Context(), credentials(t))
}
```

Run: `go test -run 'TestZTmpNilDelegatePanics' -count=1 ./authenticate/`
Expected: PANIC — `runtime error: invalid memory address or nil pointer dereference`. Record the output. This is the wiring mistake that must move to construction.

- [ ] **Step 2.3b: Refuse it at construction**

```go
func NewManager(delegates ...Authenticator) (*Manager, error) {
	if len(delegates) == 0 {
		return nil, fmt.Errorf("%w: a manager with no delegates authenticates nobody", ErrConfig)
	}
	for i, d := range delegates {
		if nilcheck.IsNil(d) {
			return nil, fmt.Errorf("%w: delegate %d is nil", ErrConfig, i)
		}
	}

	return &Manager{delegates: slices.Clone(delegates)}, nil
}
```

Delete the throwaway test and add its cases as rows in a `TestNewManager` construction table: no delegates, an untyped nil, a typed nil.

Run: `go test -run 'TestNewManager' -count=1 ./authenticate/`
Expected: PASS, and no panic is reachable.

- [ ] **Step 2.4: The nil-principal choke point**

```go
		{
			name: "a nil result becomes a failure, not a nil-principal success",
			// delegate returns (nil, nil)
			assert: func(t *testing.T, got *authenticate.Authentication, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, got)
			},
		},
		{
			name: "a result with a nil principal becomes a failure",
			// delegate returns (&Authentication{Principal: nil}, nil)
			// same assertion
		},
```

This is the one place that protects every caller reading the principal after a nil error. Implement by checking both shapes in the manager, not in each provider.

Run: `go test -run 'TestManagerAuthenticate' -count=1 ./authenticate/` — both rows PASS.

- [ ] **Step 2.5: `Authentication` and its identifier**

```go
// Authentication is what a successful authentication produced.
type Authentication struct {
	// ID identifies this authentication event. It comes from a replaceable
	// id.Generator so a consumer can correlate it with their own records.
	ID                id.ID
	Credentials       identity.Credentials
	Principal         *identity.Principal
	Time              time.Time
	PasswordChangedAt time.Time
}
```

Test both the default generator (sortable, unique across calls) and `WithIDGenerator` replacing it.

Run: `go test -run 'TestAuthenticationIdentifier' -count=1 ./authenticate/`

- [ ] **Step 2.6: The context carrier**

```go
func TestAuthenticationContext(t *testing.T) {
	t.Parallel()

	t.Run("round trips", func(t *testing.T) {
		t.Parallel()

		want := &authenticate.Authentication{Principal: principal(t)}
		got, ok := authenticate.AuthenticationFromContext(
			authenticate.WithAuthentication(t.Context(), want))
		require.True(t, ok)
		assert.Same(t, want, got)
	})

	t.Run("reports absence rather than a zero value", func(t *testing.T) {
		t.Parallel()

		got, ok := authenticate.AuthenticationFromContext(t.Context())
		assert.False(t, ok)
		assert.Nil(t, got, "a caller that ignores ok must not get a usable empty principal")
	})
}
```

Use an unexported context key type, so no other package can collide with it.

- [ ] **Step 2.7: Password provider construction**

```go
func NewUsernamePasswordAuthenticator(users identity.UserLoader, opts ...PasswordOption) (Authenticator, error) {
	if nilcheck.IsNil(users) {
		return nil, fmt.Errorf("%w: a user loader is required", ErrConfig)
	}
	p := &passwordAuthenticator{users: users, logEvery: time.Minute}
	// The default encoder is password.NewArgon2idEncoder(); there is no password.Default().
	// Its own construction error is reported here as a configuration error.
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	// The dummy must come from the configured encoder. A literal in another
	// algorithm's format would be rejected before any work happened, which is
	// the timing gap this exists to close.
	dummy, err := p.enc.Encode(dummyPassword)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding the timing-equalisation hash failed: %w", ErrConfig, err)
	}
	p.dummy = dummy

	return p, nil
}
```

Test rows: nil loader; an encoder whose `Encode` fails; success leaves a dummy in the configured encoder's format.

- [ ] **Step 2.8a: The failing test for indistinguishable refusals**

```go
func TestPasswordAuthenticatorDoesNotRevealWhyItFailed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		users  func(t *testing.T, ctrl *gomock.Controller) identity.UserLoader
		assert func(t *testing.T, err error, enc *countingEncoder)
	}

	cases := []testCase{
		{
			name: "an unknown user still costs a password comparison",
			users: func(_ *testing.T, ctrl *gomock.Controller) identity.UserLoader {
				users := NewMockUserLoader(ctrl)
				users.EXPECT().Load(gomock.Any(), gomock.Any()).
					Return(nil, identity.ErrUserNotFound)

				return users
			},
			assert: func(t *testing.T, err error, enc *countingEncoder) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, 1, enc.matches,
					"the unknown-user path skipped the comparison, so it is faster than a wrong password")
			},
		},
		{
			name: "a wrong password returns the same bare sentinel",
			// loader returns a real user; encoder reports no match
		},
		{
			name: "a loader failure returns the same bare sentinel",
			// loader returns errBackendDown; assert the error does NOT wrap it
		},
	}
	// ... loop as canonical
}
```

- [ ] **Step 2.8b: Watch it fail, then implement the order of operations**

Run: `go test -run 'TestPasswordAuthenticatorDoesNotRevealWhyItFailed' -count=1 ./authenticate/`
Expected: FAIL on `enc.matches` being 0 for the unknown user until the dummy comparison is added.

- [ ] **Step 2.9: Active checked only after the password**

```go
		{
			name: "an inactive account with a wrong password is indistinguishable from an active one",
			// assert both rows return the bare sentinel AND enc.matches == 1
		},
		{
			name: "an inactive account with the right password is still refused",
		},
```

Implement by checking `Active` after `Match` succeeds, never before.

- [ ] **Step 2.10: Credentials are wiped on success**

```go
func TestPresentedSecretsAreWipedAfterSuccess(t *testing.T) {
	t.Parallel()

	secret := []byte("correct-horse")
	creds := identity.NewPasswordCredentials("ada", secret)

	_, err := auth.Authenticate(t.Context(), creds)
	require.NoError(t, err)

	assert.NotContains(t, string(secret), "correct-horse",
		"the presented password survived in the caller's buffer")
}
```

- [ ] **Step 2.11: The bearer-token provider**

Construction refuses a missing verifier. On `Authenticate`, a verification failure returns `errors.Join(ErrAuthenticationFailed, err)` so both the sentinel and the cause stay matchable:

```go
	claims, err := a.verifier.Verify(ctx, presented)
	if err != nil {
		return nil, errors.Join(ErrAuthenticationFailed, err)
	}
```

Test rows: no verifier is a configuration error; a valid token yields a principal built from the subject and a result ID taken from the token's own identifier; an invalid token matches both `ErrAuthenticationFailed` and the verifier's cause.

- [ ] **Step 2.12: Sampled refusal logs that never carry the password**

```go
func TestRefusalLogsAreBoundedAndCarryNoPassword(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var buf bytes.Buffer
		auth := authenticatorLoggingTo(t, &buf, authenticate.WithPasswordAuthenticatorLogInterval(time.Minute))

		for range 50 {
			_, _ = auth.Authenticate(t.Context(), identity.NewPasswordCredentials("ada", []byte("hunter2")))
		}
		synctest.Wait()

		assert.Equal(t, 1, strings.Count(buf.String(), `"msg":"authentication refused"`),
			"the sampler let more than one record through inside its window")
		assert.NotContains(t, buf.String(), "hunter2", "a refusal log carried the presented password")

		require.NoError(t, auth.FlushRefusalLogs())
		assert.Contains(t, buf.String(), `"suppressed":49`,
			"the suppressed count was dropped rather than reported")
	})
}
```

Run: `go test -race -run 'TestRefusalLogs' -count=1 ./authenticate/`
Expected: PASS. The reporter is what keeps the count from being lost.

---

## Task 3: authorize — managers, authorizers and centralized rules

**Implements:** tasks.md 3.1–3.12 — design.md decisions 5 and 6, and `specs/authorization/spec.md`.

**Files:**
- Create: `authorize/authorize.go` (port, sentinels, attributes), `authorize/manager.go`, `authorize/privilege.go`, `authorize/ownership.go`, `authorize/rules.go`, `authorize/requirements.go`
- Create: `authorize/manager_test.go`, `authorize/privilege_test.go`, `authorize/ownership_test.go`, `authorize/rules_test.go`, `authorize/requirements_test.go`, `authorize/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do)

**Interfaces:**
- Consumes: `identity.Principal`, `identity.AssignedRole`, `identity.RoleLoader` (identity-model); `nilcheck.IsNil` (Task 1).
- Produces: `Authorizer`, `NewManager(...Authorizer) (*Manager, error)`, `NewPrivilegeAuthorizer`, `NewOwnershipAuthorizer`, `Requirement func(context.Context) error`, `Rule[R]`, `NewRules[R any](...Rule[R]) (*Rules[R], error)`, the requirement constructors, and `ErrUnsupportedAttributes`, `ErrInvalidAttributes`, `ErrAccessDenied`, `ErrAuthenticationRequired`. `http-security` instantiates `Rules[R]` with its own request type.

- [ ] **Step 3.1: Write the failing test for ordered authorization**

```go
func TestManagerAuthorize(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		authorizers func(t *testing.T, ctrl *gomock.Controller) []authorize.Authorizer
		assert      func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the first authorizer that does not skip decides",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				first := NewMockAuthorizer(ctrl)
				first.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)
				second := NewMockAuthorizer(ctrl) // no EXPECT: asking it is the failure

				return []authorize.Authorizer{first, second}
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "all skipping denies",
			// both return ErrUnsupportedAttributes
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
	}
	// ... canonical loop, constructing with authorize.NewManager
}
```

Run: `go test -run 'TestManagerAuthorize' -count=1 ./authorize/` — FAIL, then implement the loop.

- [ ] **Step 3.2: Construction refuses absent authorizers**

A nil authorizer must not be silently filtered: a filtered nil produces fewer checks than the consumer wrote, which is the wiring mistake that belongs at construction.

```go
func NewManager(authorizers ...Authorizer) (*Manager, error) {
	if len(authorizers) == 0 {
		return nil, fmt.Errorf("%w: a manager with no authorizers denies everything", ErrConfig)
	}
	for i, a := range authorizers {
		if nilcheck.IsNil(a) {
			return nil, fmt.Errorf("%w: authorizer %d is nil", ErrConfig, i)
		}
	}
	return &Manager{authorizers: slices.Clone(authorizers)}, nil
}
```

Table rows: none; untyped nil; typed nil. Run `go test -run 'TestNewManager' -count=1 ./authorize/`.

- [ ] **Step 3.3: Invalid and unsupported attributes are distinct**

```go
		{
			name: "attributes of a shape this authorizer does not handle are a skip",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrUnsupportedAttributes)
				assert.NotErrorIs(t, err, authorize.ErrInvalidAttributes)
			},
		},
		{
			name: "attributes of the right shape but unusable content are a refusal",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
			},
		},
```

The distinction matters because the manager skips one and stops on the other.

- [ ] **Step 3.4: A subject without an active role denies without touching the loader**

```go
		{
			name: "a nil subject denies without consulting the role loader",
			roles: func(_ *testing.T, ctrl *gomock.Controller) identity.RoleLoader {
				return NewMockRoleLoader(ctrl) // no EXPECT
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name: "a subject with no active role denies without consulting the role loader",
		},
```

Both must deny rather than panic; the mock controller fails the test if the loader is called.

- [ ] **Step 3.5: Privilege matching**

```go
func TestPrivilegeAuthorizerMatching(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		granted  []string
		required []string
		mode     authorize.MatchMode
		assert   func(t *testing.T, err error)
	}

	allowed := func(t *testing.T, err error) { require.NoError(t, err) }
	denied := func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) }

	cases := []testCase{
		{name: "any-of matches one", granted: []string{"read", "write"}, required: []string{"write"}, mode: authorize.AnyOf, assert: allowed},
		{name: "any-of with none granted denies", granted: []string{"read"}, required: []string{"write"}, mode: authorize.AnyOf, assert: denied},
		{name: "all-of needs every one", granted: []string{"read"}, required: []string{"read", "write"}, mode: authorize.AllOf, assert: denied},
		{name: "names match case-insensitively", granted: []string{"Write"}, required: []string{"write"}, mode: authorize.AnyOf, assert: allowed},
		{name: "names match after trimming", granted: []string{"  write  "}, required: []string{"write"}, mode: authorize.AnyOf, assert: allowed},
		{name: "a denied privilege never counts", granted: nil, required: []string{"write"}, mode: authorize.AnyOf, assert: denied},
	}
	// ... canonical loop
}
```

- [ ] **Step 3.6: The super role short-circuits**

Give the loader an `EXPECT` that would deny, and assert the super role allows anyway. That proves the bypass happens before matching.

- [ ] **Step 3.7: Loader errors are wrapped, not collapsed**

```go
		{
			name: "privileges not found denies",
			// loader returns identity.ErrPrivilegesNotFound
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) },
		},
		{
			name: "any other loader error stays matchable",
			// loader returns errBackendDown
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown, "the cause was collapsed into a denial")
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"an outage was reported as a decision about this caller")
			},
		},
```

- [ ] **Step 3.8: The name comparer override**

```go
		{
			name: "a consumer comparer replaces the default without changing it",
			comparer: func(a, b string) bool { return a == b }, // exact, case-sensitive
			granted:  []string{"Write"},
			required: []string{"write"},
			assert:   denied,
		},
```

The default row (case-insensitive, allowed) and this override row sit in the same table, which is what `library-design.md` requires of every replaceable default.

- [ ] **Step 3.9: Ownership**

Resolver and check are consumer functions; their errors wrap with `%w` and stay matchable. Rows: owner allows; non-owner denies; resolver error wraps; check error wraps.

- [ ] **Step 3.10: `NewRules` refuses half-built rules**

```go
	for i, r := range rules {
		if r.Match == nil {
			return nil, fmt.Errorf("%w: rule %d has no matcher, so it can never fire", ErrConfig, i)
		}
		if r.Require == nil {
			return nil, fmt.Errorf("%w: rule %d has no requirement, so a match decides nothing", ErrConfig, i)
		}
	}
```

- [ ] **Step 3.11: First match decides; the empty set abstains**

```go
		{
			name:  "the first matching rule decides, later matches are not consulted",
		},
		{
			name:  "a non-empty set with no match denies",
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) },
		},
		{
			name:  "an empty set makes no central decision",
			assert: func(t *testing.T, err error) {
				require.NoError(t, err, "an empty set must leave the decision to per-endpoint guards")
			},
		},
		{
			name:  "a trailing permit-all rule is the documented override for the deny default",
		},
```

- [ ] **Step 3.12: Every requirement, including its empty case**

```go
func TestRequirements(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		req    authorize.Requirement
		ctx    func(ctx context.Context) context.Context // nil means an anonymous caller
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "PermitAll allows anonymously", req: authorize.PermitAll(), assert: allowed},
		{name: "DenyAll denies an authenticated caller", req: authorize.DenyAll(), ctx: withPrincipal, assert: denied},
		{name: "Authenticated refuses anonymously with the anonymous sentinel", req: authorize.Authenticated(),
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAuthenticationRequired)
			}},
		{name: "HasAnyScope with an empty set denies", req: authorize.HasAnyScope(), ctx: withPrincipal, assert: denied},
		{name: "HasAllScopes with an empty set denies", req: authorize.HasAllScopes(), ctx: withPrincipal, assert: denied},
		{name: "AnyOf with no members denies", req: authorize.AnyOf(), ctx: withPrincipal, assert: denied},
		{name: "AnyOf reports anonymous only when every member did", req: authorize.AnyOf(authorize.Authenticated(), authorize.Authenticated()),
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAuthenticationRequired)
			}},
		// The spec's own scenario: a known caller who meets neither member is
		// denied rather than sent to log in. Do NOT write this as
		// AnyOf(Authenticated(), DenyAll()) with a principal — Authenticated()
		// succeeds there, so the row allows and proves nothing.
		{name: "AnyOf denies a known caller who meets no member",
			req:  authorize.AnyOf(authorize.HasAnyRole("admin"), authorize.HasAnyScope("orders:read")),
			ctx:  withPrincipalHavingNeither, assert: denied},
		// The privilege requirement names a group and a resource, because the
		// spec's scenario is "read on billing/invoice". A single-string form
		// cannot express it.
		{name: "HasPrivilege denies with no authorizer in context",
			req: authorize.HasPrivilege("billing", "invoice", "read"), ctx: withPrincipal, assert: denied},
		{name: "HasPrivilege delegates to the authorizer in context",
			req: authorize.HasPrivilege("billing", "invoice", "read"), ctx: withPrincipalAndAuthorizer, assert: allowed},
	}
	// ... canonical loop, applying tc.ctx to t.Context()
}
```

The empty-set rows are the point: an empty scope list that allowed would turn a typo into an open endpoint.

---

## Task 4: session — record, store port, manager and stores

**Implements:** tasks.md 4.1–4.15 — design.md decisions 7, 8, 9, 10, and `specs/sessions/spec.md`.

**Files:**
- Create: `session/session.go` (the record, `MFAState`), `session/store.go` (port, sentinels), `session/manager.go`, `session/memory.go`, `session/encrypted.go`, `session/options.go`
- Create: `session/manager_test.go`, `session/memory_test.go`, `session/encrypted_test.go`, `session/resurrection_test.go`, `session/housekeeping_test.go`, `session/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do)

**Interfaces:**
- Consumes: `identity.UserID`, `identity.FactorKind` (identity-model); `secrets.Cipher` (secrets-at-rest); `nilcheck.IsNil`.
- Produces: `Session`, `MFAState`, `Store`, `NewManager(...ManagerOption) (*Manager, error)`, `NewMemoryStore`, `NewEncryptedStore(inner Store, c secrets.Cipher) (Store, error)`, `ErrSessionNotFound`, `ErrSessionExpired`, `ErrSessionUnreadable`. `security-state-stores` implements `Store` durably against this contract.

- [ ] **Step 4.1: Unguessable identifiers**

```go
func TestSessionIdentifiers(t *testing.T) {
	t.Parallel()

	t.Run("are 32 random bytes, base64url encoded", func(t *testing.T) {
		t.Parallel()

		m := managerFor(t)
		s, err := m.Create(t.Context(), identity.UserID("u1"))
		require.NoError(t, err)

		raw, err := base64.RawURLEncoding.DecodeString(s.ID)
		require.NoError(t, err, "the identifier is not unpadded base64url")
		assert.Len(t, raw, 32)
	})

	t.Run("never repeat", func(t *testing.T) {
		t.Parallel()

		seen := make(map[string]struct{}, 1000)
		m := managerFor(t)
		for range 1000 {
			s, err := m.Create(t.Context(), identity.UserID("u1"))
			require.NoError(t, err)
			_, dup := seen[s.ID]
			require.False(t, dup, "a session identifier repeated")
			seen[s.ID] = struct{}{}
		}
	})

	t.Run("a failing entropy source is an error, never a weak identifier", func(t *testing.T) {
		t.Parallel()

		m := managerWithReader(t, iotest.ErrReader(errNoEntropy))
		_, err := m.Create(t.Context(), identity.UserID("u1"))
		require.ErrorIs(t, err, errNoEntropy)
	})
}
```

- [ ] **Step 4.2: The record keeps library state out of consumer data**

```go
func TestLibraryStateIsNotInConsumerData(t *testing.T) {
	t.Parallel()

	s := sessionWith(t, func(s *session.Session) {
		s.FirstFactor = identity.FactorPassword
		s.MFA = session.MFASatisfied
		s.PasswordChangePending = true
	})

	assert.Empty(t, s.Data,
		"library state was written into the consumer's map, where a key collision could forge it")
}
```

A consumer key must never be able to forge or erase a challenge state, which is only true while these are fields.

- [ ] **Step 4.3: Consumer data survives a round trip byte-for-byte**

```go
	data := map[string]string{
		"tenant":  "acme",
		"empty":   "",
		"unicode": "héllo → 世界",
		"numeric": "0042",          // must not come back as 42
		"float":   "1.0",           // must not come back as 1
	}
```

Store, load, and `assert.Equal(t, data, loaded.Data)`. The numeric rows are why `Data` is `map[string]string` rather than `map[string]any`.

- [ ] **Step 4.4a: Manager defaults and construction errors**

```go
func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.ManagerOption
		assert func(t *testing.T, m *session.Manager, err error)
	}

	cases := []testCase{
		{
			name: "defaults to an in-memory store, 30m idle and 12h absolute",
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, 30*time.Minute, m.IdleTimeout())
				assert.Equal(t, 12*time.Hour, m.AbsoluteTimeout())
			},
		},
		{
			name: "a zero idle timeout is refused, because it expires every session on creation",
			opts: []session.ManagerOption{session.WithIdleTimeout(0)},
			assert: configError,
		},
		{name: "a negative idle timeout is refused", opts: []session.ManagerOption{session.WithIdleTimeout(-time.Second)}, assert: configError},
		{name: "a zero absolute timeout is refused", opts: []session.ManagerOption{session.WithAbsoluteTimeout(0)}, assert: configError},
		{name: "a nil clock is refused", opts: []session.ManagerOption{session.WithClock(nil)}, assert: configError},
		{
			name: "a nil logger is ignored rather than refused",
			opts: []session.ManagerOption{session.WithSessionLogger(nil)},
			assert: func(t *testing.T, m *session.Manager, err error) { require.NoError(t, err) },
		},
	}
	// ... canonical loop
}
```

- [ ] **Step 4.4b: Run and implement**

Run: `go test -run 'TestNewManager' -count=1 ./session/` — each row FAILs before its check exists. This table is also what verifies Steps 1.3 and 1.4.

- [ ] **Step 4.5: `Touch` extends, capped at the absolute deadline**

```go
	{
		name: "Touch moves the idle deadline to now plus idle",
	},
	{
		name: "Touch never moves it past the absolute deadline",
		// clock set to absoluteExpiresAt - 1m, idle 30m
		assert: func(t *testing.T, s *session.Session, err error) {
			require.NoError(t, err)
			assert.Equal(t, s.AbsoluteExpiresAt, s.IdleExpiresAt,
				"the idle deadline was allowed past the absolute one")
		},
	},
```

- [ ] **Step 4.6: `Load` enforces existence and expiry distinctly**

Rows: a live session loads; a missing one is `ErrSessionNotFound`; an idle-expired one is `ErrSessionExpired`; an absolute-expired one is `ErrSessionExpired`. The two sentinels must not collapse: a caller distinguishes "log in again" from "no such session".

- [ ] **Step 4.7a: Prove resurrection (departure b, red)**

```go
func TestZTmpUpsertingSaveResurrectsADeletedSession(t *testing.T) {
	m := managerFor(t) // built over the upsert-shaped Save being replaced
	ctx := t.Context()

	s, err := m.Create(ctx, identity.UserID("u1"))
	require.NoError(t, err)

	// The revocation a concurrent request races.
	require.NoError(t, m.Delete(ctx, s.ID))

	// Touch is load-then-save: exactly the path a live request takes.
	require.NoError(t, m.Touch(ctx, s))

	_, err = m.Load(ctx, s.ID)
	require.ErrorIs(t, err, session.ErrSessionNotFound,
		"a revoked session came back to life through Touch")
}
```

Run: `go test -run 'TestZTmpUpsertingSave' -count=1 ./session/`
Expected: FAIL — `Load` succeeds, so the revoked session is live again. Record the output.

- [ ] **Step 4.7b: Split `Create` from `Save`**

`Create` inserts. `Save` updates only, returning `ErrSessionNotFound` when the row is gone. Keep the whole-record save — only the insert half is removed.

Rename the throwaway to `TestSaveNeverRecreatesADeletedSession`, keep it permanently, and re-run: PASS.

- [ ] **Step 4.8: The first factor is in the creating write**

```go
	store := NewMockStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, s *session.Session) error {
			assert.Equal(t, identity.FactorPassword, s.FirstFactor,
				"the first factor was applied after the create write, so a crash could lose it")
			assert.Equal(t, "iss", s.ExternalIssuer)
			return nil
		})
	// No EXPECT for Save: a second write is the failure this pins.
```

- [ ] **Step 4.9: Deletion and counting**

Rows: `Delete` removes; deleting what does not exist is not an error; `DeleteByUser` removes every session of one user and none of another; `CountActiveByUser` excludes expired; `DeleteExpired` returns the number removed.

- [ ] **Step 4.10: Federated deletes, including the empty-argument cases**

```go
	{name: "DeleteByExternalSession ends the matching session", want: 1},
	{name: "an empty issuer deletes nothing and is not an error", issuer: "", want: 0},
	{name: "an empty external session id deletes nothing and is not an error", sessionID: "", want: 0},
	{name: "DeleteByUserAndExternalIssuer ends every session of that user at that issuer"},
```

An empty issuer that matched everything would let one provider's logout end sessions from another.

- [ ] **Step 4.11: The in-memory store copies both ways**

```go
	s := sessionWith(t, func(s *session.Session) { s.Data = map[string]string{"k": "v"} })
	require.NoError(t, store.Create(ctx, s))
	s.Data["k"] = "mutated-after-store"          // the caller keeps writing

	loaded, err := store.Load(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, "v", loaded.Data["k"], "the store aliased the caller's map on write")

	loaded.Data["k"] = "mutated-after-load"
	again, err := store.Load(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, "v", again.Data["k"], "the store aliased its own record on read")
```

Run under `-race`.

- [ ] **Step 4.12: Housekeeping start and stop**

```go
	synctest.Test(t, func(t *testing.T) {
		store := session.NewMemoryStore(session.WithHousekeepingInterval(time.Minute))
		require.NoError(t, store.Start(t.Context()))
		require.NoError(t, store.Start(t.Context()), "Start is idempotent")

		// ... insert an expired session ...
		time.Sleep(90 * time.Second)
		synctest.Wait()

		assert.Zero(t, store.Len(), "housekeeping did not run")

		require.NoError(t, store.Stop())
		require.NoError(t, store.Stop(), "Stop is idempotent")
	})
```

Also assert the ticker goroutine exits when the context ends, with `goleak` or an explicit wait. Run under `-race`.

- [ ] **Step 4.13: The unstarted store's stated limit**

An expired session in an unstarted store is never served, but is still held:

```go
	_, err := store.Load(ctx, expired.ID)
	require.ErrorIs(t, err, session.ErrSessionExpired)
	assert.Equal(t, 1, store.Len(),
		"the record is still held; that is the documented limit of not calling Start")
```

The godoc must say this. A test asserting the limit is what stops someone "fixing" it into a surprise purge.

- [ ] **Step 4.14: The sealing store seals exactly one field**

```go
	{name: "a nil inner store is a configuration error"},
	{name: "a nil cipher is a configuration error"},
	{
		name: "only ExternalIDToken is sealed, with its own AAD",
		assert: func(t *testing.T, stored *session.Session) {
			assert.NotContains(t, stored.ExternalIDToken, plaintextToken)
			assert.Equal(t, "iss", stored.ExternalIssuer, "a field that should pass through was sealed")
			assert.Equal(t, "u1", string(stored.UserID))
		},
	},
	{name: "an empty token is left unsealed", /* stored.ExternalIDToken stays "" */},
```

The AAD is `"scrty/session:external-id-token:" + ID`, so an envelope moved to another session will not open.

- [ ] **Step 4.15: Copies, distinct unreadable errors, and no re-seal on load**

```go
	t.Run("the caller keeps plaintext", func(t *testing.T) {
		s := sessionWith(t, func(s *session.Session) { s.ExternalIDToken = plaintextToken })
		require.NoError(t, store.Create(ctx, s))
		assert.Equal(t, plaintextToken, s.ExternalIDToken, "the caller's record was sealed in place")
	})

	t.Run("an open failure is distinct from not-found", func(t *testing.T) {
		// inner holds an envelope the retired cipher cannot open
		_, err := store.Load(ctx, id)
		require.ErrorIs(t, err, session.ErrSessionUnreadable)
		assert.NotErrorIs(t, err, session.ErrSessionNotFound,
			"a retired-key mistake was hidden as a missing session")
	})

	t.Run("Load issues no write", func(t *testing.T) {
		inner := NewMockStore(ctrl)
		inner.EXPECT().Load(gomock.Any(), gomock.Any()).Return(sealed, nil)
		// No EXPECT for Create or Save: a write on read is the resurrection race.
		_, err := session.MustEncrypted(t, inner).Load(ctx, id)
		require.NoError(t, err)
	})
```

---

## Task 5: policy — engine, phases and the built-in policies

**Implements:** tasks.md 5.1–5.22 — design.md decisions 11, 12, 13, 14, 15, 16, and `specs/security-policy/spec.md`.

**Files:**
- Create: `policy/policy.go` (`Phase`, `Outcome`, `Decision`, `Policy`, `Input`), `policy/engine.go`, `policy/lockout.go`, `policy/attempts.go`, `policy/idle.go`, `policy/passwordage.go`, `policy/concurrent.go`, `policy/mfa.go`, `policy/mfarequirement.go`, `policy/options.go`
- Create: one `_test.go` beside each, plus `policy/reasonless_deny_test.go` and `policy/samechannel_test.go` for the two departures, and `policy/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do)

**Interfaces:**
- Consumes: `identity.UserID`, `identity.FactorKind`, `identity.FactorChannel`, `identity.MFARequirementLookup` (identity-model); `session.Session` (Task 4); `logsample.Sampler`; `nilcheck.IsNil`.
- Produces: `Phase` (`PreAuthentication`, `PostAuthentication`, `PerRequest`, `PostHandler`, `StatelessAuthentication`), `Outcome` (`Allow`, `Deny`, `Challenge`), `Decision`, `Policy`, `Input`, `NewEngine(...Policy) (*Engine, error)`, `(*Engine).Add`, `(*Engine).EvaluatePhase`, `AttemptStore`, `AttemptReaper`, `MFAMethodLookup`, the six policy constructors, and the sentinels `ErrPolicyDenied`, `ErrAccountLocked`, `ErrSessionIdle`, `ErrTooManySessions`, `ErrSecondFactorSameChannel`, `ErrMFARequired`, `ErrMFAEnrollmentRequired`, `ErrReapUnsupported`, `ErrRetainSinceRequired`, `ErrMFARequirementLookupMissing`, `ErrMFARequirementUnsatisfiable`. `http-security` registers policies and maps these sentinels to statuses.

- [ ] **Step 5.1: Policies run only in their declared phases**

```go
func TestEngineRunsOnlyDeclaredPhases(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	p := NewMockPolicy(ctrl)
	p.EXPECT().Name().Return("test").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	// No EXPECT for Evaluate: being asked in another phase is the failure.

	e, err := policy.NewEngine(p)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.PreAuthentication, &policy.Input{})
	assert.Equal(t, policy.Allow, d.Outcome, "an empty phase must allow")
}
```

Add a subtest asserting `Phase.String()` returns each constant's name, since logs read it.

- [ ] **Step 5.2: Precedence — deny, then the first held challenge, then allow**

```go
	cases := []testCase{
		{name: "an empty phase allows", outcomes: nil, want: policy.Allow},
		{name: "a single allow allows", outcomes: []policy.Outcome{policy.Allow}, want: policy.Allow},
		{name: "deny outranks allow", outcomes: []policy.Outcome{policy.Allow, policy.Deny}, want: policy.Deny},
		{name: "deny outranks challenge whatever the order",
			outcomes: []policy.Outcome{policy.Challenge, policy.Deny}, want: policy.Deny},
		{name: "challenge outranks allow", outcomes: []policy.Outcome{policy.Allow, policy.Challenge}, want: policy.Challenge},
		{name: "the first held challenge is the one returned",
			// two challenges of different kinds; assert the first policy's kind survives
		},
	}
```

- [ ] **Step 5.3a: Prove a reasonless deny lets a stateless request through (departure b, red)**

```go
func TestZTmpReasonlessDenyLetsAStatelessRequestThrough(t *testing.T) {
	// A stateless first factor refuses by returning the Deny's reason as its
	// error. A Deny carrying no reason therefore returns nil — success.
	reasonless := stubPolicy{
		phases:   []policy.Phase{policy.StatelessAuthentication},
		decision: policy.Decision{Outcome: policy.Deny}, // Reason left nil
	}
	e, err := policy.NewEngine(reasonless)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.StatelessAuthentication, &policy.Input{})
	require.Equal(t, policy.Deny, d.Outcome)
	require.Error(t, d.Reason, "a deny with no reason is indistinguishable from success to its caller")
}
```

Run: `go test -run 'TestZTmpReasonlessDeny' -count=1 ./policy/`
Expected: FAIL — `d.Reason` is nil, so the caller proceeds. Record the output.

- [ ] **Step 5.3b: Substitute the reason in the engine**

Fixing it in the engine closes it for every caller, rather than asking each policy to remember:

```go
	// A Deny must always carry a reason. A caller that reports the reason as its
	// error returns nil for a reasonless Deny, so the request it was refusing
	// proceeds. Substituting here closes that for every policy at once.
	if d.Outcome == Deny && d.Reason == nil {
		d.Reason = ErrPolicyDenied
	}
```

Rename the test to `TestADenyAlwaysCarriesAReason`, keep it, re-run: PASS.

- [ ] **Step 5.4: Nil policies are configuration errors at both entry points**

Rows for `NewEngine(nil)`, `NewEngine(typedNilPolicy)`, `e.Add(nil)`, `e.Add(typedNilPolicy)`. The godoc for `Add` states it is for use before serving and is not safe concurrently with `EvaluatePhase`.

- [ ] **Step 5.5: `Input` reaches the policy intact**

One policy that records the `*Input` it was handed; assert each field of decision 11 arrived — user, username, principal, session, first factor, password-changed time, MFA-satisfied flag and now.

- [ ] **Step 5.6: Lockout defaults and the threshold boundary**

```go
	{name: "defaults are a threshold of 5 over 15 minutes"},
	{name: "below the threshold allows", failures: 4, want: policy.Allow},
	{name: "at the threshold denies", failures: 5,
		assert: func(t *testing.T, d policy.Decision) {
			require.Equal(t, policy.Deny, d.Outcome)
			require.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
		}},
	{name: "a failure exactly at the window edge does not count", /* at == now-window */ want: policy.Allow},
	{name: "a failure just inside the window counts", /* at == now-window+1ns */ want: policy.Deny},
```

The window is strict: `at` must be strictly after `now - window`.

- [ ] **Step 5.7a: Prove the evaluation-only shape disarms itself (departures a and b, red)**

```go
func TestZTmpNonPositiveLockoutConfigIsAcceptedAndBreaks(t *testing.T) {
	t.Run("a zero window silently disables lockout", func(t *testing.T) {
		p := lockoutWith(t, policy.WithLockoutWindow(0), policy.WithLockoutThreshold(1))
		recordFailures(t, p, "ada", 100)
		d := p.Evaluate(t.Context(), inputFor("ada"))
		require.Equal(t, policy.Deny, d.Outcome, "100 failures did not lock the account")
	})

	t.Run("a zero threshold locks everyone out", func(t *testing.T) {
		p := lockoutWith(t, policy.WithLockoutThreshold(0))
		d := p.Evaluate(t.Context(), inputFor("never-failed"))
		require.Equal(t, policy.Allow, d.Outcome, "an account with no failures was locked")
	})
}
```

Run: both FAIL — the first because no failure counts inside a zero window, the second because zero is always "at or above". Record both.

- [ ] **Step 5.7b: Refuse at construction**

A constructor for a new type can return an error, so nothing forces the check onto the request path. Convert the two throwaways into construction-table rows and confirm the configurations are now unreachable.

- [ ] **Step 5.8: A store error denies, wrapping**

```go
	d := p.Evaluate(ctx, in)
	require.Equal(t, policy.Deny, d.Outcome)
	require.ErrorIs(t, d.Reason, errBackendDown, "the cause was collapsed")
```

Failing open here would let an attacker disable lockout by breaking the store.

- [ ] **Step 5.9: Purging cannot disarm lockout**

```go
	t.Run("the cutoff comes from the policy's own window", func(t *testing.T) {
		// a failure 5 minutes old, window 15 minutes
		_, err := p.PurgeExpired(ctx)
		require.NoError(t, err)
		d := p.Evaluate(ctx, in)
		assert.Equal(t, policy.Deny, d.Outcome, "a purge freed a failure the window still counts")
	})

	t.Run("PurgeExpired takes no caller window", func(t *testing.T) {
		// asserted by the signature: PurgeExpired(ctx) (int, error)
	})

	t.Run("the in-memory store reports unsupported rather than a silent zero", func(t *testing.T) {
		n, err := memoryBacked(t).PurgeExpired(ctx)
		require.ErrorIs(t, err, policy.ErrReapUnsupported)
		assert.Zero(t, n)
	})

	t.Run("a zero retain-since is refused", func(t *testing.T) {
		_, err := reaper.DeleteAttemptsBefore(ctx, time.Time{})
		require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
	})
```

- [ ] **Step 5.10: Idle timeout policy**

Rows: within idle allows; past idle denies `ErrSessionIdle`; exactly at idle allows (the rule is strictly greater); a zero `LastAccessedAt` allows. Plus a subtest that `Thresholds(createdAt, now)` returns the idle and absolute deadlines a new session gets.

- [ ] **Step 5.11: Password age policy, default and override**

```go
	{name: "a fresh password allows", age: 30 * 24 * time.Hour, want: policy.Allow},
	{name: "a password older than 90 days is challenged", age: 91 * 24 * time.Hour,
		assert: func(t *testing.T, d policy.Decision) {
			require.Equal(t, policy.Challenge, d.Outcome)
			assert.Equal(t, policy.ChallengePasswordChange, d.Challenge)
		}},
	{name: "a zero change time allows by default", changedAt: time.Time{}, want: policy.Allow},
	{name: "WithUnknownPasswordAge challenges instead",
		opts: []policy.PasswordAgeOption{policy.WithUnknownPasswordAge(policy.ChallengeUnknown)},
		changedAt: time.Time{},
		assert: func(t *testing.T, d policy.Decision) { require.Equal(t, policy.Challenge, d.Outcome) }},
```

The godoc must state that the policy enforces nothing for users whose change time is never written, say who owns that column, and warn against refreshing it from every federated login — a refresh would make the policy never fire.

- [ ] **Step 5.12: Concurrent session policy**

Rows: under `max` allows; at `max` denies `ErrTooManySessions`; above denies; a counter error denies. `max` is a positional argument with no default, so the policy is opt-in and cannot be half-configured.

- [ ] **Step 5.13: Construction errors for all three policies of decision 14**

One row per option: non-positive idle, non-positive absolute, non-positive max password age, non-positive `max`. Each makes the policy either always fire or never fire, which is never what the caller meant.

- [ ] **Step 5.14: The enrolment lookup fails closed**

```go
	{name: "a confirmed enrolment whose secret opens is enrolled", enrolled: true, want: true},
	{name: "an unconfirmed enrolment is not enrolled", want: false},
	{name: "a store failure is an error, never not-enrolled",
		assert: func(t *testing.T, enrolled bool, err error) {
			require.ErrorIs(t, err, errBackendDown)
			assert.False(t, enrolled, "a failure was reported as a usable answer")
		}},
	{name: "a secret that will not decrypt is an error, never not-enrolled"},
```

Then assert the policies refuse on that error: losing or corrupting an enrolment must not downgrade a user.

- [ ] **Step 5.15: The MFA challenge policy's five outcomes**

```go
	{name: "an MFA-satisfied login allows", want: policy.Allow},
	{name: "an exempt first factor allows", want: policy.Allow},
	{name: "a lookup error denies", want: policy.Deny},
	{name: "enrolled on a different channel challenges",
		assert: func(t *testing.T, d policy.Decision) {
			require.Equal(t, policy.Challenge, d.Outcome)
			assert.Equal(t, policy.ChallengeMFA, d.Challenge)
		}},
	{name: "not enrolled allows", want: policy.Allow},
```

Plus a construction row: a nil method lookup is a configuration error.

- [ ] **Step 5.16a: Prove a same-channel login completes silently (departure a, red)**

```go
func TestZTmpSameChannelLoginCompletesSilently(t *testing.T) {
	// The user enrolled a second factor on the very channel their first factor
	// arrived on. Two factors on one channel are one factor, so the enrolment
	// cannot count — but completing anyway lowers the assurance the user chose,
	// and leaves no record that it happened.
	p := mfaPolicyWith(t, methodOnChannel(identity.ChannelEmail))
	in := inputWithFirstFactor(identity.FactorEmailLink) // also ChannelEmail

	d := p.Evaluate(t.Context(), in)

	require.Equal(t, policy.Deny, d.Outcome,
		"an enrolled user completed on one channel with no second factor and no record")
}
```

Run: FAIL — the outcome is Allow. Record it.

- [ ] **Step 5.16b: Default to refusal**

`SameChannelRefuse` denies with `ErrSecondFactorSameChannel` plus a sampled WARN. Keep the test as `TestSameChannelEnrolmentIsRefusedByDefault`. Re-run: PASS.

- [ ] **Step 5.17: The override, and what it cannot change**

```go
	t.Run("SameChannelCompleteOnFirstFactor allows and still warns", func(t *testing.T) {
		d := evaluate(t, policy.WithSameChannelEnrolment(policy.SameChannelCompleteOnFirstFactor))
		assert.Equal(t, policy.Allow, d.Outcome)
		assert.False(t, d.MFASatisfied, "the override recorded a second factor that never happened")
		assert.Contains(t, logs.String(), "same-channel", "the override stopped warning")
	})

	t.Run("a required user is unaffected by the override", func(t *testing.T) {
		// required lookup says yes; same-channel enrolment; override set
		d := requirementPolicy(t).Evaluate(ctx, in)
		require.Equal(t, policy.Deny, d.Outcome)
		require.ErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
	})
```

That second subtest is the documented line the override may not cross.

- [ ] **Step 5.18: The exemption override**

Default row: `identity-model`'s rule exempts what it exempts. Override row: `WithMFAExemption(func(identity.FactorKind) bool { return false })` makes a normally-exempt kind non-exempt. Both in one table.

- [ ] **Step 5.19: Requirement policy construction**

```go
	{name: "a nil lookup without for-all is unsatisfiable",
		assert: func(t *testing.T, _ policy.Policy, err error) {
			require.ErrorIs(t, err, policy.ErrMFARequirementLookupMissing)
		}},
	{name: "for-all with a nil method can never be satisfied",
		opts: []policy.MFARequirementOption{policy.WithMFARequiredForAll()},
		assert: func(t *testing.T, _ policy.Policy, err error) {
			require.ErrorIs(t, err, policy.ErrMFARequirementUnsatisfiable)
		}},
	{name: "for-all with a method constructs"},
	{name: "a lookup without for-all constructs"},
```

Catching this at construction rather than only at chain assembly is the departure.

- [ ] **Step 5.20: The evaluation order, one row per step**

```go
	{name: "1 an exempt first factor allows", want: policy.Allow},
	{name: "2 for-all answers required without consulting the lookup" /* lookup mock has no EXPECT */},
	{name: "2 a lookup error denies with the error"},
	{name: "3 not required allows", want: policy.Allow},
	{name: "4 the stateless phase denies ErrMFARequired", phase: policy.StatelessAuthentication},
	{name: "4 no method denies ErrMFARequired"},
	{name: "5 per-request and satisfied allows", phase: policy.PerRequest, satisfied: true, want: policy.Allow},
	{name: "6 no usable enrolment denies ErrMFAEnrollmentRequired"},
	{name: "6 a same-channel enrolment is no usable enrolment"},
	{name: "7 per-request challenges", phase: policy.PerRequest, want: policy.Challenge},
	{name: "8 post-authentication allows, because NewMFAPolicy issues the login challenge",
		phase: policy.PostAuthentication, want: policy.Allow},
	{name: "9 any other phase denies ErrMFARequired", phase: policy.PostHandler},
```

The godoc must require both policies to be registered together; row 8 is meaningless without it.

- [ ] **Step 5.21: Lookup-failure logging**

```go
	{name: "a cancelled context logs at DEBUG, unsampled",
		ctx: cancelled, wantLevel: slog.LevelDebug, wantSampled: false},
	{name: "any other lookup failure logs at ERROR under lookup-failed",
		wantLevel: slog.LevelError, wantKey: "lookup-failed"},
```

A cancelled request is the caller leaving, not an outage, so it must not flood ERROR.

- [ ] **Step 5.22: Sampling is per subsystem**

```go
	synctest.Test(t, func(t *testing.T) {
		// Both policies refuse repeatedly inside one interval.
		assert.Equal(t, 1, records(mfaLogs, "second factor"), "the MFA policy over-logged")
		assert.Equal(t, 1, records(reqLogs, "mfa required"), "the requirement policy over-logged")

		// The intervals are independent options, so advancing one does not reset the other.
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 2, records(mfaLogs, "second factor"))
		assert.Equal(t, 1, records(reqLogs, "mfa required"),
			"one interval option governed both subsystems")
	})
```

Then `FlushRefusalLogs` on each, asserting each reports its own suppressed count.

---

## Task 6: ratelimit — limiter, source keys and the guard

**Implements:** tasks.md 6.1–6.12 — design.md decision 17, and `specs/rate-limiting/spec.md`.

**Files:**
- Create: `ratelimit/limiter.go` (port), `ratelimit/memory.go`, `ratelimit/keyer.go`, `ratelimit/guard.go`, `ratelimit/options.go`
- Create: `ratelimit/memory_test.go`, `ratelimit/keyer_test.go`, `ratelimit/guard_test.go`, `ratelimit/concurrency_test.go`, `ratelimit/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do)

**Interfaces:**
- Consumes: `logsample.Sampler`; `nilcheck.IsNil`.
- Produces: `Limiter`, `NewMemoryLimiter(limit int, window time.Duration, ...MemoryOption) (*MemoryLimiter, error)`, `NewSourceKeyer(...KeyerOption) (*SourceKeyer, error)`, `NewSourceGuard(flow string, l Limiter, ...GuardOption) (*SourceGuard, error)`, `Source`, `ErrSourceUnattributable`, `ErrThrottled`. `shared-rate-limiting` later implements `Limiter` across replicas; `http-security` supplies the client address and maps the errors.

- [ ] **Step 6.1: Failures are counted, requests are not**

```go
func TestLimitsCountFailuresNotRequests(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(3, time.Minute)
	require.NoError(t, err)

	for range 100 {
		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		require.False(t, exceeded, "checking tripped the limit without a single failure")
	}
}
```

- [ ] **Step 6.2: The window slides, strictly**

```go
	{name: "a failure inside the window counts", at: now.Add(-30 * time.Second), want: true},
	{name: "a failure exactly at the window edge does not count", at: now.Add(-time.Minute), want: false},
	{name: "a failure one instant inside the edge counts", at: now.Add(-time.Minute).Add(time.Nanosecond), want: true},
	{name: "a failure older than the window does not count", at: now.Add(-2 * time.Minute), want: false},
```

Strictly-after is what makes "a 1-minute window" mean the same thing at every call site.

- [ ] **Step 6.3: A limiter that cannot trip, or always trips, is refused**

Rows: limit 0, limit -1, window 0, window -1. A zero limit throttles everyone; a zero window counts nothing. Both are configuration errors, not runtime surprises.

- [ ] **Step 6.4: Limiter errors fail closed**

```go
	l := NewMockLimiter(ctrl)
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errBackendDown)

	g := guardOver(t, l)
	_, err := g.Check(t.Context(), "198.51.100.7")
	require.ErrorIs(t, err, ratelimit.ErrThrottled,
		"a limiter outage let the request through, which is how an attacker disables the limit")
```

- [ ] **Step 6.5: Bounded memory that does not disarm the limit**

```go
	t.Run("at most limit stamps are kept per key", func(t *testing.T) {
		for range 1000 {
			require.NoError(t, l.RecordFailure(ctx, "k"))
		}
		assert.LessOrEqual(t, l.StampsFor("k"), 3, "the limiter grew without bound")
	})

	t.Run("pruning never drops a key whose newest stamp is still inside the window", func(t *testing.T) {
		require.NoError(t, l.RecordFailure(ctx, "k"))
		clock.Advance(30 * time.Second) // half a 1-minute window
		l.Prune()
		exceeded, err := l.Exceeded(ctx, "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "pruning freed a key the window still counts")
	})

	t.Run("pruning runs at most once per window", func(t *testing.T) {
		// count prune passes over many calls inside one window; expect 1
	})
```

`Prune` accepts no window, so no caller can shorten a limit by sweeping.

- [ ] **Step 6.6: The per-replica WARN, once**

```go
	for range 50 {
		_, _ = l.Exceeded(ctx, "k")
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "counts only this replica"),
		"the per-replica warning repeated on every call")
```

The godoc states the same limit: behind N replicas every per-source limit is effectively N times higher.

- [ ] **Step 6.7: Source canonicalisation**

```go
	{name: "IPv4 keys per address", addr: "198.51.100.7", want: "198.51.100.7"},
	{name: "an IPv4-mapped address is unmapped", addr: "::ffff:198.51.100.7", want: "198.51.100.7"},
	{name: "IPv6 keys by its /64 prefix", addr: "2001:db8:1:2:3:4:5:6", want: "2001:db8:1:2::/64"},
	{name: "the IPv6 zone is dropped", addr: "fe80::1%eth0", want: "fe80::/64"},
	{name: "a custom prefix is honoured", opts: []KeyerOption{WithIPv6SourcePrefix(48)}, want: "2001:db8:1::/48"},
	{name: "a prefix of 0 is a configuration error"},
	{name: "a prefix of 129 is a configuration error"},
```

Keying IPv6 per address would let one allocation spend an unbounded number of keys.

- [ ] **Step 6.8: Unattributable sources are refused under distinct reasons**

```go
	{name: "an empty address", addr: "", wantReason: "empty"},
	{name: "a host:port that is not a single IP", addr: "example.com:443", wantReason: "not-an-ip"},
	{name: "the unspecified address", addr: "0.0.0.0", wantReason: "unspecified"},
```

Each returns `ErrSourceUnattributable` with its own log reason — pooling them under one key would let an attacker share a bucket with every unattributable caller.

- [ ] **Step 6.9: Check and record share a key, and recording survives cancellation**

```go
	t.Run("the key Check reads is the key RecordFailure writes", func(t *testing.T) {
		l := NewMockLimiter(ctrl)
		var checked, recorded string
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, k string) (bool, error) { checked = k; return false, nil })
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, k string) error { recorded = k; return nil })

		g := guardOver(t, l)
		src, err := g.Check(ctx, "198.51.100.7")
		require.NoError(t, err)
		g.RecordFailure(ctx, src)

		assert.Equal(t, checked, recorded, "the guard recorded against a different key than it checked")
	})

	t.Run("recording survives a cancelled caller context", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string) error {
				assert.NoError(t, ctx.Err(), "the guard passed on the caller's cancellation")
				return nil
			})
		g.RecordFailure(cancelled, src) // context.WithoutCancel inside
	})

	t.Run("a record failure is logged, not returned", func(t *testing.T) {
		// RecordFailure has no error return; assert the log carries the cause
	})
```

- [ ] **Step 6.10: Guards refuse a missing limiter and keep flows apart**

Rows: a nil limiter and a typed-nil limiter are configuration errors; an empty flow name is a configuration error; two guards with different flows over one limiter do not share counts; two guards with the same flow and limiter do, deliberately.

- [ ] **Step 6.11: Throttle WARNs are sampled per flow and source**

```go
	synctest.Test(t, func(t *testing.T) {
		for range 20 {
			_, _ = guardA.Check(ctx, "198.51.100.7")
			_, _ = guardA.Check(ctx, "198.51.100.8")
			_, _ = guardB.Check(ctx, "198.51.100.7")
		}
		synctest.Wait()

		assert.Equal(t, 3, warnCount(logs), "sampling did not key on both flow and source")
	})
```

Then assert `WithSourceGuardLogInterval` governs this guard alone: advancing past it produces another guard WARN while the MFA policy's sampler is untouched. One refusal-log option must not govern two subsystems.

- [ ] **Step 6.12: Concurrency and the stated overshoot**

```go
	t.Run("is safe under concurrent use", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = l.RecordFailure(ctx, "k") }()
		}
		wg.Wait()
		assert.LessOrEqual(t, l.StampsFor("k"), 3)
	})

	t.Run("check-then-record overshoots by at most the concurrency, as documented", func(t *testing.T) {
		// N concurrent Check calls against a limit of 3 may all pass before any
		// records. Assert the documented bound, not an exact count.
		assert.LessOrEqual(t, passed, 3+concurrency)
	})
```

Run: `go test -race -count=1 ./ratelimit/`

---

## Task 7: onetime — issuance, checking and consumption

**Implements:** tasks.md 7.1–7.12 — design.md decision 18, and `specs/one-time-tokens/spec.md`.

**Files:**
- Create: `onetime/onetime.go` (`Token`, `Checked`, `Check`, sentinels), `onetime/store.go` (port, `Reaper`), `onetime/memory.go`, `onetime/manager.go`, `onetime/options.go`
- Create: `onetime/manager_test.go`, `onetime/check_test.go`, `onetime/consume_test.go`, `onetime/memory_test.go`, `onetime/<interface>_mock_test.go` (one destination per interface, as `signingkey` and `token` already do)

**Interfaces:**
- Consumes: `id.ID`, `id.Generator` (id-generation); `nilcheck.IsNil`.
- Produces: `Store`, `Reaper`, `Token`, `Checked`, `Check func(context.Context, Token) error`, `NewManager(purpose string, ...Option) (*Manager, error)`, `Issue`, `Check`, `Consume`, `Redeem`, `IssuedCount`, `PurgeExpired`, `ErrInvalidToken`, `ErrTokenNotFound`, `ErrReapUnsupported`. `magic-link` and `api-keys` build on this; the refused-redemption counting rule belongs to them, not here.

- [ ] **Step 7.1: Construction**

Rows: an empty purpose is a configuration error; `WithTTL(0)` and a negative TTL are errors; `WithIssuanceWindow(0)` and a negative window are errors; the defaults are 15 minutes and 1 hour. A purposeless manager would let a password-reset token redeem as a magic link.

- [ ] **Step 7.2: Format and unguessability**

```go
	t.Run("is id.secret with 32 random bytes", func(t *testing.T) {
		presented, tok, err := m.Issue(ctx, "ada")
		require.NoError(t, err)

		rawID, secret, ok := strings.Cut(presented, ".")
		require.True(t, ok, "the presented token is not <id>.<secret>")
		assert.Equal(t, tok.ID.String(), rawID)

		decoded, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("the record identifier is a pkg/id value", func(t *testing.T) {
		// sortable, and replaceable through the generator option
	})

	t.Run("two issues never collide", func(t *testing.T) { /* 1000 issues, no duplicate */ })
```

- [ ] **Step 7.3: Hashed at rest, compared in constant time**

```go
	presented, tok, err := m.Issue(ctx, "ada")
	require.NoError(t, err)

	stored := store.Record(tok.ID)
	_, secret, _ := strings.Cut(presented, ".")
	assert.NotContains(t, string(stored.SecretHash), secret, "the secret itself was stored")
	assert.Equal(t, sha256.Sum256([]byte(secret)), [32]byte(stored.SecretHash))
```

Add a source assertion that comparison uses `crypto/subtle`, and the same for the binding hash.

- [ ] **Step 7.4: Expiry**

Rows: inside the TTL checks; exactly at expiry is refused; past expiry is refused. Use the injected clock.

- [ ] **Step 7.5: Uniform refusals with no side effects**

```go
	{name: "a wrong purpose", want: onetime.ErrInvalidToken},
	{name: "an already-consumed token", want: onetime.ErrInvalidToken},
	{name: "an expired token", want: onetime.ErrInvalidToken},
	{name: "a binding mismatch", want: onetime.ErrInvalidToken},
	{name: "a secret mismatch", want: onetime.ErrInvalidToken},
	{name: "a malformed token", want: onetime.ErrInvalidToken},
	{name: "a store error is refused the same way and logged at ERROR", want: onetime.ErrInvalidToken},
```

Every row additionally asserts the store recorded zero writes — `Check` must be side-effect free, because it can run once per racing caller. Uniform errors are what stop the refusal becoming an oracle for which tokens exist.

- [ ] **Step 7.6: Optional binding**

Rows: an unbound token checks with an empty binding; a bound token refuses a wrong binding; a bound token accepts its binding; and an unbound token presented with a binding **ignores it**. That last row is the spec's (`Binding is optional`: "A token issued without one SHALL ignore any presented binding", and the scenario "the binding does not affect the outcome"). Refusing instead would make an unbound token behave as though it were bound to the empty string, which is a different contract from the one the capability states.

- [ ] **Step 7.7: Atomic consumption**

```go
	t.Run("exactly one of many racing consumers spends the token", func(t *testing.T) {
		presented, _, err := m.Issue(ctx, "ada")
		require.NoError(t, err)

		var succeeded atomic.Int64
		var wg sync.WaitGroup
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := m.Redeem(t.Context(), presented, ""); err == nil {
					succeeded.Add(1)
				}
			}()
		}
		wg.Wait()

		assert.Equal(t, int64(1), succeeded.Load(), "the token was spent more than once")
	})
```

Run under `-race`. The store's `Consume` is a compare-and-set on `consumed_at IS NULL`, returning `ErrTokenNotFound` otherwise.

- [ ] **Step 7.8: `Checked` cannot be forged**

```go
	// Compile-time: Checked's fields are unexported and it has no exported
	// constructor, so consumption cannot precede a check. Assert structurally.
	typ := reflect.TypeOf(onetime.Checked{})
	for i := range typ.NumField() {
		assert.False(t, typ.Field(i).IsExported(),
			"Checked.%s is exported, so a caller can consume without checking", typ.Field(i).Name)
	}
```

This makes the settled check-then-consume rule structural rather than a convention a caller can forget.

- [ ] **Step 7.9: A refusal between check and consume spends nothing**

```go
	t.Run("a caller check error is returned unchanged and spends nothing", func(t *testing.T) {
		presented, _, err := m.Issue(ctx, "ada")
		require.NoError(t, err)

		_, err = m.Redeem(ctx, presented, "", func(context.Context, onetime.Token) error {
			return errRateLimited
		})
		require.ErrorIs(t, err, errRateLimited, "the caller's reason was replaced")

		// The holder can still fix the problem and use their token.
		_, err = m.Redeem(ctx, presented, "")
		require.NoError(t, err, "a refusal spent the token")
	})

	t.Run("a Consume failure returns ErrInvalidToken and no token", func(t *testing.T) {
		tok, err := m.Redeem(ctx, presented, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Zero(t, tok)
	})
```

- [ ] **Step 7.10: Issuance counting**

Rows: no issues counts zero; three inside the window count three; an issue older than the window does not count; counting is per subject and per purpose.

- [ ] **Step 7.11: Purging cannot free quota or break live tokens**

```go
	t.Run("the cutoff is the manager's own issuance window", func(t *testing.T) {
		// issue, advance less than the window, purge
		n, err := m.IssuedCount(ctx, "ada")
		require.NoError(t, err)
		assert.Equal(t, 1, n, "a purge freed quota IssuedCount still counts")
	})

	t.Run("a live token still redeems after a purge", func(t *testing.T) {
		_, err := m.PurgeExpired(ctx)
		require.NoError(t, err)
		_, err = m.Redeem(ctx, presented, "")
		require.NoError(t, err, "the purge broke a live token")
	})

	t.Run("a consumer store that cannot purge says so rather than reporting zero", func(t *testing.T) {
		// The in-memory store implements purging: the spec requires it to
		// ("it SHALL implement purging"). The unsupported error is for a
		// consumer's store that does not, and it must never be a silent zero,
		// which would read as "nothing needed purging".
		_, err := managerOver(t, storeWithoutReaper(t)).PurgeExpired(ctx)
		require.ErrorIs(t, err, onetime.ErrReapUnsupported)
	})

	t.Run("a zero retain-since is refused", func(t *testing.T) { /* ErrRetainSinceRequired */ })
```

- [ ] **Step 7.12: The in-memory store isolates records**

Mutate what was inserted and what was returned; the stored record is unchanged both ways. Run under `-race`.

---

## Task 8: Final verification

**Implements:** tasks.md 8.1–8.5.

This task writes no production code. It is the gate that the six packages together satisfy the six capabilities, and that the departures were each proven rather than asserted.

- [ ] **Step 8.1: Mocks are generated, placed and current**

Run:
```sh
rg -n 'go:generate mockgen' authenticate authorize session policy ratelimit onetime
go generate ./... && git diff --stat
make generate-check
```
Expected: every mock has a directive, `git diff` is empty after regeneration, and `generate-check` exits 0. Confirm by reading `go list -deps` that no mock package reaches a production build.

- [ ] **Step 8.2: The four departures each have a test that was seen to fail**

| Departure | Test | Proven in |
|---|---|---|
| `Save` resurrecting a deleted session | `TestSaveNeverRecreatesADeletedSession` | Step 4.7a |
| A reasonless Deny letting a stateless request through | `TestADenyAlwaysCarriesAReason` | Step 5.3a |
| A nil delegate panicking on the first request | `TestNewManager` (nil-delegate rows) | Step 2.3a |
| A same-channel login completing silently | `TestSameChannelEnrolmentIsRefusedByDefault` | Step 5.16a |

For each, record the test name, the command, and the failing output actually seen. A departure whose test has never been seen to fail is not proven, and the claim must be withdrawn or the departure reverted.

- [ ] **Step 8.3: Every requirement maps to a named test**

Build the table below by walking each `specs/*/spec.md` and naming the test that pins each requirement. Where a requirement carries a documented override, name two tests: one for the default, one for the override (`library-design.md`).

```sh
for f in openspec/changes/authn-authz-core/specs/*/spec.md; do
  printf '%s\n' "$f"; grep '^### Requirement:' "$f"
done
```
Expected: 71 requirements, none unmapped. Any gap is a missing test, not a missing row.

- [ ] **Step 8.4: The whole-project gate**

Run:
```sh
make check
go test -race -count=1 ./...
```
Expected: `fmt-check`, `vet`, `lint` with no new suppressions, `test`, `vuln` and `generate-check` all green across the core and `test` modules, and the race detector clean.

- [ ] **Step 8.5: Stated limits appear in the godoc of the type they constrain**

Run: `go doc ./ratelimit MemoryLimiter`, `go doc ./session MemoryStore`, `go doc ./policy AttemptStore`, `go doc ./ratelimit SourceGuard`, and `openspec validate authn-authz-core --strict`.

Expected: valid, and each of the design's stated limits is visible where a consumer meets it —

- the in-memory limiter and stores are per replica;
- an unstarted in-memory session store retains expired records, which are never served;
- the in-memory attempt store cannot be purged and grows with submitted identifiers;
- check-then-record overshoots by at most the concurrency;
- lockout by submitted identifier lets an attacker lock a victim, so pair it with the per-source guard.

A limit that is real but undocumented is the failure this step exists to catch.

---

## Self-Review

**Spec coverage.** Every requirement of the six capabilities maps to at least one task: `authentication` → Task 2; `authorization` → Task 3; `sessions` → Task 4; `security-policy` → Task 5; `rate-limiting` → Task 6; `one-time-tokens` → Task 7. Step 8.3 is the check that this held once the code exists, rather than a claim made here.

**Placeholders.** None. Every step names a command, a file, or carries the code it asks for. Where a table is abbreviated with `// ...`, the omitted part is the canonical loop given in full in Step 2.1a and in `.claude/skills/table-test/SKILL.md`.

**Type consistency.** `Authenticator`, `Authorizer`, `Policy`, `Limiter`, `Store` (session) and `Store` (onetime) are each defined once, in the task that produces them, and referenced by the same name everywhere after. The two `Store` types live in different packages and are never used in the same signature. `nilcheck.IsNil` is produced in Task 1 and consumed in Tasks 2–7.

**Ordering.** Tasks 1–4 have no dependency on 5–7. Task 5 consumes `session.Session` from Task 4 and `identity`'s kinds; Tasks 6 and 7 depend only on Task 1. So 2, 3, 6 and 7 can proceed in parallel once 1 has landed, 4 before 5. That is the split to use when delegating (`.claude/rules/subagent-delegation.md`), remembering that ownership follows the call graph: whoever changes a port owns its callers.
