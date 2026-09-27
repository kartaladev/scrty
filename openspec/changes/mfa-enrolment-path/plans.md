# MFA Enrolment Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code: every task is dispatched to a subagent under `.claude/rules/subagent-delegation.md`, and the subagent reports; it never commits and never edits anything under `openspec/`.

**Goal:** Let a user who is required to use MFA, and has no usable enrolment, bind a second factor through the library from a confined, short-lived enrolment-only session. By default this needs an emailed code and a notification, and the path is off unless the consumer turns it on.

**Architecture:** The MFA requirement policy raises a new `ChallengeMFAEnrolment` where it used to deny. The login completion step and the bearer interceptor mark the session enrolment-pending, which lowers its existing absolute deadline. A new enrolment interceptor at `OrderMFAEnrolment` (599) confines that session to three enrolment endpoints and logout. Device proof and completion are generation-bound conditional writes on a separate store port. Verification through the existing verify endpoint restores the deadline and rotates. Two shared chain rules are generalised on the way: an enforcer check for every declared challenge kind, and logout through the password-change gate.

**Tech Stack:** Go 1.27, the core module `github.com/kartaladev/scrty` (`policy`, `session`, `mfa`, `httpsec`, `notify`, `ratelimit`, `pkg/id`, `pkg/logsample`), the `test` module for framework conformance and durable suites, and uber-go/mock (`mockgen --typed`).

**Spec:** `openspec/changes/mfa-enrolment-path/`: `proposal.md`, `design.md` (decisions 1–17), `specs/{multi-factor-auth,security-policy,sessions,http-security-chain,http-error-propagation,oidc-login,security-state-stores,secrets-at-rest}/spec.md`, `tasks.md`. Plan task numbers are `tasks.md` numbers.

## Global Constraints

- Test-first on every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, see it pass (`.claude/rules/golang-tdd.md`).
- Table tests use the `table-test` skill's `assert` closure form, a `ctx` modifier where context matters, and `t.Context()`; mocks come from the `use-mockgen` skill (`//go:generate mockgen ... -typed`), placed as that skill says; PostgreSQL through `test.RunTestPostgres` (`use-testcontainers`).
- Library design: every option's godoc names the default it replaces; every wiring mistake is a construction error from `httpsec.New` or the relevant constructor; no option silently governs two subsystems.
- Defect claims: the three reproductions (tasks 3.3, 4.1, 4.3) are the first red step of their task. Group 6 adds two, both `UNREPRODUCED` in design decision 10: the sealing wrapper passes the emailed code through unsealed (task 6.4 step 2), and a zero generation matches an enrolment stored without one (task 6.3's "nil generation" row, then each adapter's run of it in 6.4–6.6). If the reproduction passes on unchanged code, stop and report; do not implement the departure.
- Never log a presented code, the emailed code, a TOTP secret, a provisioning URI or a contact address.
- New exported names spell "Enrolment". `policy.ErrMFAEnrollmentRequired` keeps its spelling.
- Append new enum values (`policy.ChallengeMFAEnrolment`, `session.MFAEnrolmentPending`); never insert, because durable stores keep ordinals.
- Core module tests never import the `test` module.
- Nothing is copied from, or cites, the predecessor in `.claude/.legacy`.
- Defaults (design): path off; email confirmation on; notification on; enrolment session lifetime 15 min; emailed code 6 digits, 10 min, void at 5 wrong; begin limit 5/hour (every call); confirmation limit 5 failures/15 min; enrolment log interval 1 min; allowlist `password`, `magic-link`, unrecorded; paths `/mfa/enrol/begin`, `/mfa/enrol/confirm`, `/mfa/enrol/confirm-email`; contact address and account label default to the username.
- Verification commands a subagent runs before reporting: the task's focused `go test -run ... -count=1`, then `go test -count=1 ./<pkg>/`, `go vet ./<pkg>/`, `gofmt -l <pkg>` (empty).

## Review Focus

1. **A second begin in the same session.** A user who begins, proves their device, then begins again in the same session must have the first emailed code refused. The session's recorded generation moves with every begin, so the old code's generation no longer matches. Test added to task 5.5.
2. **A user no longer required while enrolment-only.** An operator removes the requirement from a user holding an enrolment-only session. The session stays confined until it expires or logs out (the gate reads session state, not policy), and a fresh login gets a full session. Test added to task 5.8.
3. **A malformed emailed code** (spaces, 5 or 7 digits, non-ASCII digits) is refused as the invalid-code error and counted as a wrong code. It is never trimmed or normalised into a match. Test added to task 5.5.
4. **Option order.** `EnableMFAEnrolment` is given before `EnableLogout`, or a logout path is set after it. The gate still exempts the final logout path, because it is handed over at assembly as the MFA gate's is. Test added to task 5.2.
5. **A username containing `:`** under the default label resolver. Begin fails with TOTP's label error and stores nothing; it never produces a half-made enrolment. The godoc of the default resolver says so. Test added to task 5.3.
6. **An enrolment with no generation on a durable store.** A consumer's out-of-band `PutPending` with `id.Nil`, then any of the three writes with `id.Nil`. `id.ID.Value()` writes the all-zero UUID, so a naive `generation = $2` matches it; every write must refuse. Row "nil generation" in task 6.3's suite, which every adapter runs.
7. **A zeroing update through gorm.** gorm skips zero fields in a struct update, so a device proof or a new begin that must write `email_code_attempts = 0` or `email_code = NULL` would silently keep the old values. The "A new pending enrolment starts a new generation" row fails for such a store; task 6.6 writes with maps.
8. **A key rotation while an emailed code is outstanding.** The code is not re-sealed on read. A read under a retired key still in the keyring opens it and leaves it unchanged; a removed key fails closed, and the user begins again, since begin does not read the enrolment. Rows in task 6.4 step 1.

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `policy/policy.go` | `ChallengeKind` gains `ChallengeMFAEnrolment` and its `String` | 1.1 |
| `policy/mfarequirement.go` | `Challenges()` conditional; no-usable-enrolment branch | 1.1, 1.2, 1.5 |
| `policy/enrolmentpath.go` (new) | `EnrolmentPathOption`, `WithMFAEnrolmentPath`, `WithEnrolmentFirstFactors`, `WithEnrolmentPathUntil`, the path's decision helper | 1.2–1.4 |
| `policy/enrolmentpath_test.go`, `policy/mfarequirement_test.go` | tables | 1.1–1.5 |
| `policy/engine.go` | `(*Engine).DeclaredChallenges()` | 4.2 |
| `session/session.go` | `MFAEnrolmentPending`, `EnrolmentOriginDeadline`, `EnrolmentGeneration`; `clone` copies them | 2.1 |
| `session/enrolment.go` (new) | `(*Manager).MarkEnrolmentPending`, `(*Manager).RestoreEnrolmentDeadlines`, `(*Manager).AbsoluteTimeout` | 2.2, 2.3 |
| `session/enrolment_test.go` (new) | tables under an injected clock | 2.1–2.4 |
| `mfa/store.go` | `Enrolment` fields | 3.1 |
| `mfa/mfa.go` | `ErrEnrolmentThrottled`, `ErrEmailCodeInvalid` | 3.4 |
| `mfa/store.go` | `DeviceProofStore` port | 3.2 |
| `mfa/memory.go` | `PutPending` generation; the port's writes | 3.1, 3.2 |
| `mfa/enroller.go` (new) | `Enroller`, `TOTP.ProveDevice`, `TOTP.CompleteEnrolment`, `TOTP.SupportsEnrolmentPath` | 3.4 |
| `mfa/resolvers.go` (new) | `ContactResolver`, `LabelResolver`, `UsernameAsAddress` | 3.4 |
| `mfa/reset.go` (new) | `ResetEnrolment`, `ResetDeps`, `ResetOption` | 3.5 |
| `httpsec/passwordchange.go`, `httpsec/options.go` (password-change wiring) | logout exemption | 4.1 |
| `httpsec/chain.go`, `httpsec/options.go` (`WithChallengeEnforcer`) | generalised check | 4.2 |
| `httpsec/status.go` | new rows | 4.3 |
| `httpsec/order.go`, `httpsec/logincomplete.go`, `httpsec/bearer.go` | slot, `challengeMarker` | 4.4 |
| `httpsec/mfaenrol.go` (new) | enrolment interceptor: gate, begin, confirm, emailed code | 5.1–5.5, 5.7 |
| `httpsec/mfaenroloptions.go` (new) | `EnableMFAEnrolment`, `EnrolmentDeps`, `EnrolmentOption`s | 5.1 |
| `httpsec/mfaverify.go` | restore before rotate | 5.6 |
| `httpsec/mfaenrol*_test.go` (new) | per-task tests | 5.1–5.8 |
| `test/httpsecconformance/enrolment_scenarios.go` (new), `scenarios.go` | framework scenarios | 5.9 |
| `migrate/securitystate/20260926000000_security_state.sql`, `test/migrate_securitystate_test.go` | enrolment and session columns | 6.2 |
| `test/storetest/` (`deviceproof_suite.go` new, `race.go`, suites, broken variants), `test/internal/storefix/races.go` | durable conformance | 6.3 |
| `seal/aad.go`, `seal/mfa.go` | emailed code sealed, bound to generation and user | 6.4 |
| `internal/pgschema/{mfa,sessions}.go`, `sqlstore/{mfa,session}.go`, `test/sqlstore/`, `test/internal/storefix/sealed.go` | `database/sql` side | 6.4 |
| `pgx/{mfa,session}.go`, `test/pgxstore/` | pgx side | 6.5 |
| `gorm/{models,mfa,session}.go`, `test/gormstore/`, `test/crossbackend/crossbackend_test.go` | gorm side, cross-backend row | 6.6 |

## Dispatch Lanes (for the main session)

The lanes follow file ownership and the call graph. Lanes A, B and C are separate packages that nothing else in this change edits at the same time. They run **in parallel** as the first wave. Lane D consumes all three, so it starts after them.

| Lane | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| A | 1.1–1.5 | `policy/policy.go`, `policy/mfarequirement.go`, `policy/enrolmentpath*.go`, their tests | `policy/engine.go`, `session/`, `mfa/`, `httpsec/` | Opus | security-critical refusal logic in a table where a wrong row passes tests |
| B | 2.1–2.4 | `session/` | everything else | Opus | deadline arithmetic that must fail early, never late |
| C | 3.1–3.5 (two dispatches: 3.1–3.3, then 3.4–3.5) | `mfa/` | everything else | Opus | conditional writes, the race, check-then-consume |
| D1 | 4.1–4.4 | `httpsec/passwordchange.go`, `chain.go`, `status.go`, `order.go`, `logincomplete.go`, `bearer.go`, `options.go` (their sections), `policy/engine.go` (+ test), and every existing test chain the new check breaks | `httpsec/mfaenrol*`, `mfaverify.go` | Opus | changes an interface other lanes compile against |
| D2 | 5.1–5.4 | `httpsec/mfaenrol.go`, `mfaenroloptions.go`, their tests | files of D1 | Opus | security gate and wiring checks |
| D3 | 5.5–5.9 | `httpsec/mfaenrol.go` (emailed code, logs), `mfaverify.go`, `test/httpsecconformance/` | files of D1 | Opus | check-then-consume and upgrade |
| E1 | 6.2 ∥ 6.3 (two agents, parallel) | 6.2: the migration and its schema test; 6.3: `test/storetest/`, `test/internal/storefix/races.go` | adapters, `seal/` | 6.2 Sonnet, 6.3 Opus | 6.2 is a pinned schema edit; 6.3 is race suites and broken variants |
| E2 | 6.4 | `seal/aad.go`, `seal/mfa.go`, `internal/pgschema/`, `sqlstore/`, `test/sqlstore/`, `test/internal/storefix/sealed.go` | `pgx/`, `gorm/`, `test/storetest/` | Opus | sealing binding and conditional writes every later adapter reuses |
| E3 | 6.5 ∥ 6.6 (two agents, parallel) | 6.5: `pgx/`, `test/pgxstore/`; 6.6: `gorm/`, `test/gormstore/`, `test/crossbackend/` | `internal/pgschema/`, `seal/`, `sqlstore/` | Opus | the same writes on two drivers with different NULL rules |
| F | 7.1 | godoc and README | code | Sonnet | documentation against stated limits |

D1, D2 and D3 are sequential dispatches of one lane. E1, E2 and E3 are sequential waves (E2 needs 6.2's columns and 6.3's suites; E3 needs 6.4's statements and seal wrapper); within E1 and E3 the two agents run in parallel. After each dispatch, the main session runs the listed verification commands, then a fresh reviewer checks the diff against the requirements the dispatch covers.

---

### Task 1.1: `ChallengeMFAEnrolment` and its declaration

**Files:**
- Modify: `policy/policy.go:214-235`
- Modify: `policy/mfarequirement.go` (`Challenges`)
- Test: `policy/challenger_test.go`, `policy/mfarequirement_test.go`

**Interfaces:**
- Produces: `const ChallengeMFAEnrolment ChallengeKind` (value 3); `mfaRequirementPolicy.enrolment *enrolmentPath` (nil when off; defined in 1.2 as an empty struct for now).

- [ ] **Step 1: Write the failing test**

```go
func TestChallengeKind(t *testing.T) {
	tests := []struct {
		name   string
		kind   policy.ChallengeKind
		assert func(t *testing.T, kind policy.ChallengeKind)
	}{
		{name: "existing values are stable", kind: policy.ChallengePasswordChange,
			assert: func(t *testing.T, k policy.ChallengeKind) { require.Equal(t, policy.ChallengeKind(2), k) }},
		{name: "enrolment is appended", kind: policy.ChallengeMFAEnrolment,
			assert: func(t *testing.T, k policy.ChallengeKind) {
				require.Equal(t, policy.ChallengeKind(3), k)
				require.Equal(t, "ChallengeMFAEnrolment", k.String())
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.assert(t, tt.kind) })
	}
}

func TestMFARequirementChallenges(t *testing.T) {
	tests := []struct {
		name   string
		opts   []policy.MFARequirementOption
		assert func(t *testing.T, kinds []policy.ChallengeKind)
	}{
		{name: "path off declares MFA only", opts: nil,
			assert: func(t *testing.T, k []policy.ChallengeKind) {
				require.Equal(t, []policy.ChallengeKind{policy.ChallengeMFA}, k)
			}},
		{name: "path on also declares enrolment", opts: []policy.MFARequirementOption{policy.WithMFAEnrolmentPath()},
			assert: func(t *testing.T, k []policy.ChallengeKind) {
				require.ElementsMatch(t, []policy.ChallengeKind{policy.ChallengeMFA, policy.ChallengeMFAEnrolment}, k)
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := policy.NewMFARequirementPolicy(nil, newTOTPLookup(t),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, tt.opts...)...)
			require.NoError(t, err)
			tt.assert(t, p.(policy.Challenger).Challenges())
		})
	}
}
```

(`newTOTPLookup` is the existing helper or a typed mock of `MFAMethodLookup` with `Channel()` returning `factor.AuthenticatorApp`; reuse what `mfarequirement_test.go` already uses.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test -run 'TestChallengeKind|TestMFARequirementChallenges' -count=1 ./policy/`
Expected: to get past compilation, first add `WithMFAEnrolmentPath` as a stub returning an option that does nothing, and the constant with no `String` case. Then expect FAIL: `"ChallengeKind(3)"` is not `"ChallengeMFAEnrolment"`, and the path-on row lacks `ChallengeMFAEnrolment`.

- [ ] **Step 3: Implement**

```go
	// ChallengeMFAEnrolment asks a user who must use a second factor, and has
	// none they can use, to enrol one before going any further. Only the
	// enrolment path raises it, and only when the consumer turned that on.
	ChallengeMFAEnrolment
```
Add `case ChallengeMFAEnrolment: return "ChallengeMFAEnrolment"` to `String`, and:

```go
func (p *mfaRequirementPolicy) Challenges() []ChallengeKind {
	if p.enrolment == nil {
		return []ChallengeKind{ChallengeMFA}
	}
	return []ChallengeKind{ChallengeMFA, ChallengeMFAEnrolment}
}
```

- [ ] **Step 4: Run to verify it passes.** Same command, then `go test -count=1 ./policy/`. Expected: PASS.

- [ ] **Step 5: Report** the files, the test names and the red output to the main session.

### Task 1.2: The no-usable-enrolment branch

**Files:**
- Create: `policy/enrolmentpath.go`, `policy/enrolmentpath_test.go`
- Modify: `policy/mfarequirement.go` (struct field `enrolment *enrolmentPath`, step 6 of `Evaluate`, package doc's evaluation order)

**Interfaces:**
- Produces:

```go
type EnrolmentPathOption interface{ applyEnrolmentPath(*enrolmentPath) }
func WithMFAEnrolmentPath(opts ...EnrolmentPathOption) MFARequirementOption

type enrolmentPath struct {
	firstFactors map[factor.Kind]bool // 1.3
	until        time.Time            // 1.4; zero = open
}
// admits reports whether a required user with no usable enrolment is challenged for enrolment.
func (e *enrolmentPath) admits(in *Input, phase Phase, method MFAMethodLookup) bool
```

- [ ] **Step 1: Write the failing test.** Run one table over `path` ∈ {off, on} × rows. Each path-off row expects today's outcome:

```go
func TestMFARequirementEnrolmentPath(t *testing.T) {
	type row struct {
		name     string
		pathOn   bool
		phase    policy.Phase
		first    factor.Kind
		enrolled bool
		channel  factor.Channel // method channel
		lookup   error
		stateless bool
		satisfied bool
		assert   func(t *testing.T, d policy.Decision)
	}
	deny := func(reason error) func(*testing.T, policy.Decision) {
		return func(t *testing.T, d policy.Decision) {
			require.Equal(t, policy.Deny, d.Outcome)
			require.ErrorIs(t, d.Reason, reason)
		}
	}
	enrol := func(t *testing.T, d policy.Decision) {
		require.Equal(t, policy.Challenge, d.Outcome)
		require.Equal(t, policy.ChallengeMFAEnrolment, d.Challenge)
	}
	tests := []row{
		{name: "off, not enrolled, login", phase: policy.PostAuthentication, first: factor.Password, channel: factor.AuthenticatorApp, assert: deny(policy.ErrMFAEnrollmentRequired)},
		{name: "on, not enrolled, login", pathOn: true, phase: policy.PostAuthentication, first: factor.Password, channel: factor.AuthenticatorApp, assert: enrol},
		{name: "on, not enrolled, per request", pathOn: true, phase: policy.PerRequest, first: factor.Password, channel: factor.AuthenticatorApp, assert: enrol},
		{name: "on, enrolled only on first factor's channel", pathOn: true, phase: policy.PostAuthentication, first: factor.MagicLink, enrolled: true, channel: factor.Email, assert: deny(policy.ErrMFAEnrollmentRequired)},
		{name: "on, lookup failure", pathOn: true, phase: policy.PostAuthentication, first: factor.Password, channel: factor.AuthenticatorApp, lookup: errors.New("down"),
			assert: func(t *testing.T, d policy.Decision) { require.Equal(t, policy.Deny, d.Outcome) }},
		{name: "on, stateless", pathOn: true, phase: policy.StatelessAuthentication, first: factor.Basic, channel: factor.AuthenticatorApp, assert: deny(policy.ErrMFARequired)},
		{name: "on, usable enrolment at login", pathOn: true, phase: policy.PostAuthentication, first: factor.Password, enrolled: true, channel: factor.AuthenticatorApp,
			assert: func(t *testing.T, d policy.Decision) { require.Equal(t, policy.Allow, d.Outcome) }},
		{name: "on, satisfied per request", pathOn: true, phase: policy.PerRequest, first: factor.Password, satisfied: true, enrolled: true, channel: factor.AuthenticatorApp,
			assert: func(t *testing.T, d policy.Decision) { require.Equal(t, policy.Allow, d.Outcome) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := NewMockMFAMethodLookup(ctrl)
			m.EXPECT().Channel().Return(tt.channel).AnyTimes()
			m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(tt.enrolled, tt.lookup).AnyTimes()
			opts := []policy.MFARequirementOption{policy.WithMFARequiredForAll(),
				policy.WithMFARequirementPhaseSource(func(context.Context, *policy.Input) (policy.Phase, bool) { return tt.phase, true })}
			if tt.pathOn {
				opts = append(opts, policy.WithMFAEnrolmentPath())
			}
			p, err := policy.NewMFARequirementPolicy(nil, m, opts...)
			require.NoError(t, err)
			tt.assert(t, p.Evaluate(t.Context(), &policy.Input{User: "u-1", FirstFactor: tt.first, MFASatisfied: tt.satisfied}))
		})
	}
}
```

Also add a row for "no method configured, path on", built with `NewMFARequirementPolicy(lookupMock, nil, WithMFAEnrolmentPath())` and expecting `deny(policy.ErrMFARequired)`.

- [ ] **Step 2: Run to verify it fails.** `go test -run TestMFARequirementEnrolmentPath -count=1 ./policy/`. Expected: FAIL on the "on, not enrolled" rows (`Deny` where `Challenge` was expected). Every "off" row passes, which confirms they pin today's behaviour.

- [ ] **Step 3: Implement.** In `Evaluate` step 6:

```go
	if !usable {
		if p.enrolment != nil && p.enrolment.admits(in, phase, p.method) {
			return Decision{Outcome: Challenge, Challenge: ChallengeMFAEnrolment}
		}
		return p.denyEnrolment(ctx, in, phaseName(phase, known))
	}
```

and in `enrolmentpath.go`:

```go
func WithMFAEnrolmentPath(opts ...EnrolmentPathOption) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) {
		e := &enrolmentPath{firstFactors: defaultEnrolmentFirstFactors()}
		for _, o := range opts {
			if o != nil {
				o.applyEnrolmentPath(e)
			}
		}
		p.enrolment = e
	})
}

func (e *enrolmentPath) admits(in *Input, phase Phase, method MFAMethodLookup) bool {
	if phase != PostAuthentication && phase != PerRequest {
		return false
	}
	if !e.until.IsZero() && !in.Now.Before(e.until) {
		return false
	}
	if !e.firstFactors[in.FirstFactor] {
		return false
	}
	return method.Channel() != in.FirstFactor.Channel()
}
```

For now `defaultEnrolmentFirstFactors()` returns `{factor.Password: true, factor.MagicLink: true, "": true}`. Godoc for `WithMFAEnrolmentPath` states: default off; what the path gives a password holder; that it must be paired with `httpsec.EnableMFAEnrolment` or the chain refuses to assemble. Update the numbered evaluation order in `NewMFARequirementPolicy`'s godoc, step 6.

- [ ] **Step 4: Run to verify it passes.** Same command, then `go test -count=1 ./policy/`.
- [ ] **Step 5: Report.**

### Task 1.3: The first-factor allowlist

**Files:** Modify `policy/enrolmentpath.go`; Test `policy/enrolmentpath_test.go`.

**Interfaces:** Produces `func WithEnrolmentFirstFactors(kinds ...factor.Kind) EnrolmentPathOption`; construction error from `NewMFARequirementPolicy` wrapping `ErrConfig` when an ineligible kind is listed or the list is empty.

- [ ] **Step 1: Write the failing test**

```go
func TestEnrolmentFirstFactors(t *testing.T) {
	tests := []struct {
		name   string
		list   []factor.Kind // nil = default
		first  factor.Kind
		assert func(t *testing.T, d policy.Decision, err error)
	}{
		{name: "password on default list", first: factor.Password, assert: challenged},
		{name: "oidc off default list", first: factor.OIDC, assert: deniedEnrolment},
		{name: "consumer admits oidc", list: []factor.Kind{factor.Password, factor.MagicLink, factor.OIDC}, first: factor.OIDC, assert: challenged},
		{name: "consumer drops magic link", list: []factor.Kind{factor.Password}, first: factor.MagicLink, assert: deniedEnrolment},
		{name: "api key cannot be listed", list: []factor.Kind{factor.APIKey}, first: factor.Password,
			assert: func(t *testing.T, _ policy.Decision, err error) { require.ErrorIs(t, err, policy.ErrConfig) }},
		{name: "basic cannot be listed", list: []factor.Kind{factor.Basic}, first: factor.Password,
			assert: func(t *testing.T, _ policy.Decision, err error) { require.ErrorIs(t, err, policy.ErrConfig) }},
		// A path that admits nothing still declares ChallengeMFAEnrolment and demands an
		// enforcer no login can reach.
		{name: "empty list", list: []factor.Kind{}, first: factor.Password,
			assert: func(t *testing.T, _ policy.Decision, err error) { require.ErrorIs(t, err, policy.ErrConfig) }},
	}
	// build with WithMFAExemption(func(factor.Kind) bool { return false }) so OIDC is not exempt,
	// phase PostAuthentication, not enrolled, method channel AuthenticatorApp;
	// pass WithEnrolmentFirstFactors(tt.list...) only when tt.list != nil (an empty, non-nil list is passed);
	// on construction error call tt.assert(t, policy.Decision{}, err) and return.
}
```

`challenged` and `deniedEnrolment` are package-level assert helpers in the test file.

- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentFirstFactors -count=1 ./policy/`. Expected, once the option compiles as a no-op: FAIL on "consumer admits oidc" (denied) and the three construction rows (no error).
- [ ] **Step 3: Implement.** The option stores a fresh set, replacing the default. In `NewMFARequirementPolicy`, after the options are applied, validate:

```go
	if p.enrolment != nil {
		if len(p.enrolment.firstFactors) == 0 {
			return nil, fmt.Errorf("%w: the enrolment path admits no first factor, so no login "+
				"could reach the enrolment endpoints it demands", ErrConfig)
		}
		for k := range p.enrolment.firstFactors {
			if k == factor.APIKey || k == factor.Basic {
				return nil, fmt.Errorf("%w: the enrolment path cannot admit the %q first factor: it "+
					"authenticates statelessly and has no session to confine", ErrConfig, k)
			}
		}
	}
```

Godoc: the default list; that the option replaces it; the OIDC limit (a stolen provider account usually includes its mailbox); that the list governs only entry to the path and not `WithMFAExemption`.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 1.4: Closing the path at a set time

**Files:** Modify `policy/enrolmentpath.go`; Test `policy/enrolmentpath_test.go`.

**Interfaces:** Produces `func WithEnrolmentPathUntil(t time.Time) EnrolmentPathOption`. The decision instant is the request's `Input.Now`, as `idle`, `passwordage` and `lockout` judge time, not the policy's log-sampling clock (`WithMFARequirementClock`). A zero instant means no cutoff.

- [ ] **Step 1: Write the failing test.** A table with `until = 2027-01-01T00:00:00Z` and `Input.Now` of 2026-12-31 (challenged), 2027-01-02 (denied with `ErrMFAEnrollmentRequired`) and exactly the instant (denied), plus no `until` at 2030 (challenged), plus a zero `until` at 2030 (challenged). Build the policy with `WithMFARequirementClock` pinned to a time before the cutoff, so a row after the cutoff shows the check reads `Input.Now` and not that clock.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentPathUntil -count=1 ./policy/`. Expected: FAIL on the after and at-instant rows.
- [ ] **Step 3: Implement.** `func WithEnrolmentPathUntil(t time.Time) EnrolmentPathOption { return enrolmentPathOption(func(e *enrolmentPath) { e.until = t }) }`. The `admits` check already exists from 1.2 and is `!e.until.IsZero() && !in.Now.Before(e.until)`. Godoc: default none; a zero instant means none; compared with the request's time; use it for a require-for-all rollout.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 1.5: Mid-session enrolment challenge

**Files:** Test `policy/mfarequirement_test.go`.

- [ ] **Step 1: Write the test.** Phase `PerRequest`, first factor `Password`, not enrolled, `MFASatisfied: false`. With the path on, expect `Challenge`/`ChallengeMFAEnrolment`; with it off, expect `Deny`/`ErrMFAEnrollmentRequired`.
- [ ] **Step 2: Run.** `go test -run TestMFARequirementMidSessionEnrolment -count=1 ./policy/`. This is expected to pass at once, because 1.2 covered the phase. To make it red, temporarily return `false` from `admits` for `PerRequest`, see the path-on row fail, then restore.
- [ ] **Step 3: Report**, including the inverted-implementation red output.

---

### Task 2.1: The enrolment-pending state and its fields

**Files:** Modify `session/session.go` (`MFAState`, `Session`, `clone`); Test `session/enrolment_test.go`.

**Interfaces:** Produces `session.MFAEnrolmentPending` (value 3), `Session.EnrolmentOriginDeadline time.Time`, and `Session.EnrolmentGeneration id.ID`. `EnrolmentOriginDeadline` is the enrolment-origin marker: non-zero means the session entered the second-factor flow through the enrolment path, and its value is the absolute deadline the session held immediately before it was marked, the most the upgrade may restore (design decision 7).

- [ ] **Step 1: Write the failing test**

```go
func TestEnrolmentStateRoundTrip(t *testing.T) {
	store := session.NewMemoryStore()
	m, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)
	s, err := m.Create(t.Context(), "u-1")
	require.NoError(t, err)
	gen := id.MustParse("0192f0a0-0000-7000-8000-000000000001")
	origin := s.AbsoluteExpiresAt
	s.MFA, s.EnrolmentOriginDeadline, s.EnrolmentGeneration = session.MFAEnrolmentPending, origin, gen
	s.Data = map[string]string{"mfa": "none"}
	require.NoError(t, m.Save(t.Context(), s))

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	require.Equal(t, session.MFAEnrolmentPending, got.MFA)
	require.True(t, origin.Equal(got.EnrolmentOriginDeadline))
	require.Equal(t, gen, got.EnrolmentGeneration)
}

func TestMFAState(t *testing.T) {
	require.Equal(t, session.MFAState(2), session.MFASatisfied)
	require.Equal(t, session.MFAState(3), session.MFAEnrolmentPending)
}
```

- [ ] **Step 2: Run to verify it fails.** `go test -run 'TestMFAState|TestEnrolmentStateRoundTrip' -count=1 ./session/`. Adding only the constant and the fields makes it compile, and then it must fail on the loaded `EnrolmentGeneration` only if `clone` or the memory store drops fields. If it passes at once, the memory store copies the whole struct. In that case make it red by temporarily zeroing the new fields in `clone`, record the output, and restore.
- [ ] **Step 3: Implement.** Append the constant with godoc: "a first factor was accepted for a user who must use a second factor and has none; the session reaches only the enrolment endpoints and logout". Add both fields as library-owned, with godoc (the marker's godoc says a zero value means "not marked" and what the value bounds), and copy them in `clone`. Update the godoc of `AbsoluteExpiresAt`, which says nothing extends it: marking lowers it, and the upgrade restores it to no later than creation plus the absolute timeout and the deadline held before the mark.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 2.2: Marking lowers the deadline

**Files:** Create `session/enrolment.go`; Test `session/enrolment_test.go`.

**Interfaces:**

```go
// MarkEnrolmentPending records on s, in memory, that it may reach only enrolment,
// and lowers its deadlines so it ends no later than lifetime from now. The caller saves.
func (m *Manager) MarkEnrolmentPending(s *Session, lifetime time.Duration)
// AbsoluteTimeout is the manager's configured absolute timeout.
func (m *Manager) AbsoluteTimeout() time.Duration
```

- [ ] **Step 1: Write the failing test**

```go
func TestMarkEnrolmentPending(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 9, 26, h, m, 0, 0, time.UTC) }
	tests := []struct {
		name     string
		created  time.Time
		absolute time.Time // zero = manager default
		markAt   time.Time
		touchAt  time.Time // zero = no touch
		assert   func(t *testing.T, s *session.Session)
	}{
		{name: "at login", created: at(9, 0), markAt: at(9, 0), assert: func(t *testing.T, s *session.Session) {
			require.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
			require.Equal(t, at(9, 15), s.IdleExpiresAt)
			require.Equal(t, at(21, 0), s.EnrolmentOriginDeadline) // the deadline held before the mark
			require.Equal(t, session.MFAEnrolmentPending, s.MFA)
		}},
		{name: "near the end keeps the earlier deadline", created: at(9, 0), absolute: at(21, 0), markAt: at(20, 55),
			assert: func(t *testing.T, s *session.Session) { require.Equal(t, at(21, 0), s.AbsoluteExpiresAt) }},
		{name: "activity cannot extend", created: at(9, 0), markAt: at(9, 0), touchAt: at(9, 14),
			assert: func(t *testing.T, s *session.Session) { require.Equal(t, at(9, 15), s.IdleExpiresAt) }},
	}
	// a settable clock drives session.WithClock; create at tt.created; if tt.absolute set, overwrite
	// s.AbsoluteExpiresAt; move the clock to tt.markAt; m.MarkEnrolmentPending(s, 15*time.Minute);
	// m.Save; if touchAt set, move the clock and m.Touch(ctx, s); reload with m.Load and
	// tt.assert(t, loaded), so every assertion is on the persisted value and lives in assert.
}
```

- [ ] **Step 2: Run to verify it fails.** `go test -run TestMarkEnrolmentPending -count=1 ./session/`. With a stub that only sets the state: FAIL on the deadlines.
- [ ] **Step 3: Implement**

```go
func (m *Manager) MarkEnrolmentPending(s *Session, lifetime time.Duration) {
	if s.EnrolmentOriginDeadline.IsZero() {
		// Marking twice keeps the first deadline: the second mark's "before" is already lowered.
		s.EnrolmentOriginDeadline = s.AbsoluteExpiresAt
	}
	capAt := m.now().Add(lifetime)
	if capAt.Before(s.AbsoluteExpiresAt) {
		s.AbsoluteExpiresAt = capAt
	}
	if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
		s.IdleExpiresAt = s.AbsoluteExpiresAt
	}
	s.MFA = MFAEnrolmentPending
}

func (m *Manager) AbsoluteTimeout() time.Duration { return m.absoluteTimeout }
```

The godoc explains why the existing deadline is lowered rather than a new field added: every store already enforces this deadline, so the cap holds even in a consumer's own store.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 2.3: The upgrade restores the deadline

**Files:** Modify `session/enrolment.go`; Test `session/enrolment_test.go`.

**Interfaces:** Produces `func (m *Manager) RestoreEnrolmentDeadlines(s *Session) error`. It does nothing, and returns nil, for a session whose `EnrolmentOriginDeadline` is zero. It returns `ErrSessionExpired` and leaves `s` unchanged for a session already past either lowered deadline, so a caller that saves rather than rotates cannot revive it. The verify endpoint calls it just before `Rotate` (5.6) and treats an error as the session having ended.

- [ ] **Step 1: Write the failing test.** A table under a 12-hour absolute and 30-minute idle timeout:
  - created 09:00, marked 09:00, restored at 09:09 → absolute 21:00, idle 09:39, marker zero, generation zero;
  - created 08:00, marked 10:00, restored 10:10 → absolute 20:00;
  - created 09:00, absolute lowered to 10:00 before the mark, marked 09:30, restored 09:35 → absolute 10:00 (the deadline held before the mark, not 21:00);
  - created 09:00, absolute timeout raised to 24 hours on a second manager over the same store, marked 09:00, restored 09:09 by that manager → absolute 21:00 (the recorded deadline caps it);
  - marked 09:00 with a 15-minute lifetime, restored 09:20 → `ErrSessionExpired`, deadlines and marker unchanged;
  - no marker, absolute 21:00 → unchanged, nil error;
  - restore then `Rotate` → the rotated session carries 21:00.
- [ ] **Step 2: Run to verify it fails.** `go test -run 'TestSatisfyRestoresEnrolmentDeadline|TestManagerRotate' -count=1 ./session/`. Against the earlier restore to `CreatedAt` plus the timeout with no expiry check: FAIL on the lowered-before-mark row (21:00 instead of 10:00), the raised-timeout row, and the expired row (nil error).
- [ ] **Step 3: Implement**

```go
func (m *Manager) RestoreEnrolmentDeadlines(s *Session) error {
	if s.EnrolmentOriginDeadline.IsZero() {
		return nil
	}
	now := m.now()
	if s.expired(now) {
		return ErrSessionExpired
	}
	absolute := s.CreatedAt.Add(m.absoluteTimeout)
	if s.EnrolmentOriginDeadline.Before(absolute) {
		absolute = s.EnrolmentOriginDeadline
	}
	idle := now.Add(m.idleTimeout)
	if idle.After(absolute) {
		idle = absolute
	}
	s.AbsoluteExpiresAt, s.IdleExpiresAt = absolute, idle
	s.EnrolmentOriginDeadline = time.Time{}
	s.EnrolmentGeneration = id.ID{}
	return nil
}
```

The godoc states that the restored deadline is never later than creation plus the absolute timeout nor than the deadline held before the mark, that an expired session is refused rather than revived, and that a fault here can only end a session early.
- [ ] **Step 4: Run to verify it passes**, with `go test -count=1 ./session/`.
- [ ] **Step 5: Report.**

### Task 2.4: Enrolment-only sessions in the count

**Files:** Test `session/enrolment_test.go`.

- [ ] **Step 1: Write the test.** A session marked at 09:00 with a 15-minute lifetime. `CountActive` for the user (the memory store's count, whatever it is called) returns 1 at 09:10 and 0 at 09:16.
- [ ] **Step 2: Run.** `go test -run TestEnrolmentSessionCountsUntilExpiry -count=1 ./session/`. This is expected to pass by construction. To make it red, temporarily have the count ignore `AbsoluteExpiresAt`, see the 09:16 row fail, restore, and report that the requirement holds by construction.
- [ ] **Step 3: Report.**

---

### Task 3.1: Generations on the enrolment

**Files:** Modify `mfa/store.go` (`Enrolment`), `mfa/memory.go` (`PutPending`, `copyEnrolment`), `mfa/totp.go` (new field `ids id.Generator`, default `id.NewV7Generator()`, option `WithTOTPIDGenerator`); Test `mfa/memory_test.go`.

**Interfaces:** `Enrolment` gains `Generation id.ID`, `DeviceProvenAt time.Time`, `EmailCode []byte`, `EmailCodeUntil time.Time` and `EmailCodeFails int`. `TOTP.BeginEnrolment` sets `Generation` from its generator before `PutPending`. `PutPending` stores the generation it is given, and clears `DeviceProvenAt`, `EmailCode`, `EmailCodeUntil` and `EmailCodeFails`.

- [ ] **Step 1: Write the failing test.** `PutPending` with generation g1, then set a proof by hand through a second `PutPending` carrying a non-zero `DeviceProvenAt` and `EmailCode`, which must be cleared on store. `Get` shows g1 replaced by g2 and a zero proof and code. A confirmed enrolment still returns `ErrAlreadyEnrolled`. Also: `BeginEnrolment` twice yields two different generations.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestPutPendingStartsGeneration -count=1 ./mfa/`. Expected: FAIL because the proof fields survive `PutPending`.
- [ ] **Step 3: Implement.** In `PutPending`, next to `stored.LastStep = 0`: `stored.DeviceProvenAt, stored.EmailCode, stored.EmailCodeUntil, stored.EmailCodeFails = time.Time{}, nil, time.Time{}, 0`. `copyEnrolment` also clones `EmailCode`. `BeginEnrolment` draws `gen, err := t.ids.NewID()` before writing, returning the error with nothing stored. Keep `BeginEnrolment`'s signature: the generation is read back with `Get` by the caller in 5.3. Instead, add `func (t *TOTP) BeginEnrolmentGeneration(ctx, user, label) (Provisioning, id.ID, error)`, and have `BeginEnrolment` delegate to it and drop the generation.
- [ ] **Step 4: Run to verify it passes**, then `go test -count=1 ./mfa/`.
- [ ] **Step 5: Report.**

### Task 3.2: The device-proof port

**Files:** Modify `mfa/store.go`, `mfa/memory.go`; Test `mfa/memory_test.go`.

**Interfaces:**

```go
// DeviceProofStore is what the enrolment path needs beyond EnrolmentStore.
// Each method decides by its write, never by a preceding read.
type DeviceProofStore interface {
	// ProveDevice records step, at and the sealed-at-rest emailed code (nil when
	// email confirmation is off) only where the pending enrolment's generation
	// is gen, its device is not yet proven, and step is later than LastStep.
	ProveDevice(ctx context.Context, user identity.UserID, gen id.ID, step int64, code []byte, codeUntil, at time.Time) (bool, error)
	// Complete confirms the enrolment at at only where its generation is gen,
	// its device is proven and it is not confirmed. It clears the emailed code.
	Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error)
	// FailEmailCode counts a wrong emailed code on generation gen and reports
	// the count after the write; at five the code is cleared.
	FailEmailCode(ctx context.Context, user identity.UserID, gen id.ID) (int, error)
}
```

- [ ] **Step 1: Write the failing test.** A table per method:
  - `ProveDevice`: wrong generation, already proven, confirmed, step not later → false; happy path → true with the fields set.
  - `Complete`: wrong generation, not proven, already confirmed → false; happy path → true, `ConfirmedAt` set, `EmailCode` nil.
  - `FailEmailCode`: counts 1..5, and the fifth clears the code. (Superseded in 3.4 by `ChargeEmailCode`.)

  Then `TestCompleteRace`: 8 goroutines released from a `sync.WaitGroup` barrier complete the same generation, and exactly one returns true.
- [ ] **Step 2: Run to verify it fails.** `go test -race -run 'TestDeviceProofPort|TestCompleteRace' -count=1 ./mfa/`. Before the methods exist, the test file does not compile. Add stubs returning `false, nil` first; then expect FAIL on every happy-path row.
- [ ] **Step 3: Implement** each under `s.mu.Lock()`, following the pattern of `Confirm`, with every condition in one guarded block. Add `var _ DeviceProofStore = (*MemoryEnrolmentStore)(nil)`.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 3.3: Reproduce the two-session race

**Files:** Test `mfa/memory_test.go` (a broken variant type lives in the test file).

- [ ] **Step 1: Write the test against a generation-blind variant.** `blindStore` embeds `*MemoryEnrolmentStore` and overrides `Complete` to ignore `gen`, reading the current generation instead. The sequence runs through the `TOTP` path:
  1. begin → g1, then prove in "session B" with g1;
  2. begin again → g2 (the attacker's secret);
  3. prove with g2;
  4. `Complete(user, g1)`.

  The test asserts that completion fails and that `u-1` is not enrolled.
- [ ] **Step 2: Run against `blindStore`.** `go test -run TestNewerBeginInvalidatesEarlierProof -count=1 ./mfa/`. Expected: FAIL, because the blind store confirms g2's secret. This is the reproduction; record the output.
- [ ] **Step 3: Switch the test to the real store** (keep the blind run as a sub-test named `broken variant is caught`, which asserts that the scenario *does* confirm, proving the test is load-bearing). Run again: PASS.
- [ ] **Step 4: Report** both outputs, labelled `REPRODUCED against the generation-blind variant`.

### Task 3.4: `Enroller` on TOTP, and the resolvers

**Files:** Create `mfa/enroller.go`, `mfa/resolvers.go`; Modify `mfa/mfa.go` (errors), `mfa/store.go` (`EmailCodeFails` → `EmailCodeAttempts`; `FailEmailCode` → `ChargeEmailCode`), `mfa/memory.go` (`ChargeEmailCode`; `Confirm` clears the emailed code); Test `mfa/enroller_test.go`, `mfa/memory_test.go`.

**Port change (charge before compare, design decision 5):**

```go
	// ChargeEmailCode charges one attempt against the emailed code of generation
	// gen at time at, and reports the attempt count after the write. It charges
	// only where the enrolment is pending on gen, its device is proven, its code
	// is outstanding and not expired at at, and fewer than MaxEmailCodeFailures
	// attempts have been charged; otherwise it reports false and writes nothing.
	ChargeEmailCode(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (int, bool, error)
```

It replaces `FailEmailCode`. A correct code charged fifth still completes; the sixth attempt is refused. The single-call `Confirm` also sets `EmailCode = nil` when it confirms.

**Interfaces:**

```go
var ErrEmailCodeInvalid = errors.New("mfa: invalid or expired emailed code")
var ErrEnrolmentThrottled = errors.New("mfa: too many enrolment attempts for this user")

type Enroller interface {
	Method
	BeginEnrolmentGeneration(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, id.ID, error)
	// ProveDevice proves code against the pending secret of gen. With emailCode
	// true it returns a fresh 6-digit code, stored on the enrolment for
	// emailCodeTTL; otherwise it returns "".
	ProveDevice(ctx context.Context, user identity.UserID, gen id.ID, code string, emailCode bool, emailCodeTTL time.Duration) (string, error)
	CompleteEnrolment(ctx context.Context, user identity.UserID, gen id.ID) error
	// RedeemEmailCode charges an attempt (ChargeEmailCode), compares in
	// constant time, then calls Complete last.
	RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error
	// SupportsEnrolmentPath reports whether the store implements DeviceProofStore.
	SupportsEnrolmentPath() bool
}

type ContactResolver func(ctx context.Context, d *identity.Details) (string, error)
type LabelResolver func(ctx context.Context, d *identity.Details) (string, error)
// UsernameAsAddress is the default of both: the username, unchanged.
func UsernameAsAddress(_ context.Context, d *identity.Details) (string, error)
```

- [ ] **Step 1: Write the failing test.** First the store: `TestChargeEmailCode`, a table (wrong generation, unproven, no code outstanding, expired, five already charged → false with nothing written; happy path → true and count+1), and a barrier test in which 20 goroutines charge one code and exactly five report true (`-race`). A `Confirm` row in the existing confirm table: confirming a proven enrolment clears `EmailCode`. Then, on TOTP: `CompleteEnrolment` completes only when its read shows the device proven on the generation with `EmailCodeUntil` zero (no code issued), and `ConfirmEnrolment` refuses any enrolment with `DeviceProvenAt` set; each refusal is `ErrInvalidCode` with the enrolment still pending, covering a code outstanding, expired, out of attempts, a store that reports an exhausted code as nil, and a proof landing between `CompleteEnrolment`'s read and its write (a store wrapper that proves right after `Get`); with a scripted `io.Reader` feeding `rand.Int`, the emailed code for a draw of 42 is `"000042"` and for the top draw `"999999"`. Then a table over a TOTP with a fixed clock and a scripted `io.Reader`:
  - a valid device code with `emailCode` true → a 6-digit string, stored, not enrolled;
  - a wrong code → `ErrInvalidCode`, nothing proven;
  - a random-source failure while drawing the emailed code → error, nothing proven;
  - `emailCode` false → `""`, proven;
  - `CompleteEnrolment` → enrolled;
  - `RedeemEmailCode`: correct code → enrolled; wrong → `ErrEmailCodeInvalid` and attempts 1; four wrong then correct → enrolled; five wrong then correct → `ErrEmailCodeInvalid`, not enrolled; after TTL → `ErrEmailCodeInvalid`; generation mismatch → `ErrEmailCodeInvalid` and nothing completed; `" 12345"`, `"1234567"` and `"١٢٣٤٥٦"` → `ErrEmailCodeInvalid` (Review Focus 3);
  - a TOTP over a store implementing only `EnrolmentStore` → `SupportsEnrolmentPath()` false.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestTOTPEnroller -count=1 ./mfa/`. With stubs: FAIL on every behavioural row.
- [ ] **Step 3: Implement.** Draw the code as `n, err := rand.Int(t.random, big.NewInt(1_000_000))`, formatted `%06d`. `RedeemEmailCode` order: `ChargeEmailCode` (false → `ErrEmailCodeInvalid`) → `Get` → reject a presented code that is not exactly six ASCII digits as `ErrEmailCodeInvalid` (already charged) → `subtle.ConstantTimeCompare` → `Complete`. A false `Complete` returns `ErrEmailCodeInvalid`. Verify: `go test -race -run 'TestTOTPEnroller|TestChargeEmailCode|TestDeviceProofPort|TestCompleteRace' -count=1 ./mfa/`. Logging is through `t.record` with no code; the emailed code gets a new message constant `msgEnrolmentDeviceProven`.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 3.5: Operator reset

**Files:** Create `mfa/reset.go`; Test `mfa/reset_test.go`.

**Interfaces:**

```go
type SessionRevoker interface{ DeleteByUser(ctx context.Context, user identity.UserID) error }
type EnrolmentRemover interface{ RemoveEnrolment(ctx context.Context, user identity.UserID) error }
type ResetDeps struct {
	Enrolments EnrolmentRemover
	Sessions   SessionRevoker        // required unless WithoutSessionRevocation
	Users      identity.UserLoader   // required unless WithoutResetNotification
	Sender     notify.Sender         // required unless WithoutResetNotification
	Contact    ContactResolver       // nil = UsernameAsAddress
}
type ResetOption func(*resetConfig)
func WithoutSessionRevocation() ResetOption
func WithoutResetNotification() ResetOption
// WithResetMessage replaces the default subject and body. The library still sets
// To from the contact resolver. A nil builder is ErrConfig.
func WithResetMessage(build func(at time.Time) (subject, body string)) ResetOption
func WithResetClock(now func() time.Time) ResetOption // default time.Now; the time the body names
func ResetEnrolment(ctx context.Context, user identity.UserID, deps ResetDeps, opts ...ResetOption) error
```

- [ ] **Step 1: Write the failing test.** A table with typed mocks (`use-mockgen`: `//go:generate mockgen -destination=reset_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/mfa SessionRevoker`, and a sender mock):
  - full reset → remove, delete and send, in that order (`gomock.InOrder`), with the message to the username and no secret;
  - failing deleter → error returned, remove already called, no send;
  - `WithoutSessionRevocation` → no delete;
  - `WithoutResetNotification` → no send, nil `Users` accepted;
  - notification on with a nil `Sender` → `errors.Is(err, ErrConfig)`, and nothing removed;
  - a failing user load, address resolution or send → error returned, enrolment and sessions already gone;
  - `WithResetMessage` → the sent message carries the builder's subject and body and `To` from the contact resolver; a nil builder → `ErrConfig`, nothing removed.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestResetEnrolment -count=1 ./mfa/`.
- [ ] **Step 3: Implement** in the order the spec gives. Validate the dependencies and options before any write. The sender is used as given (no non-blocking check: an operator-named reset reveals nothing through timing, design decision 11). Default subject `"Your sign-in verification was reset"` and a body naming the time, as the default builder; godoc on `WithResetMessage` names it.
- [ ] **Step 4: Run to verify it passes**, then `go test -count=1 ./mfa/ && go vet ./mfa/`.
- [ ] **Step 5: Report.**

---

### Task 4.1: Logout through the password-change gate

**Files:** Modify `httpsec/passwordchange.go`, and the option that registers the gate, so it gets `logoutPath` at assembly (as `wireMFA` does); Test `httpsec/passwordchange_test.go`.

- [ ] **Step 1: Write the reproduction.** A chain with logout, the password-change gate and a session whose `PasswordChangePending` is true. A POST to `/logout` must delete the session.
- [ ] **Step 2: Run on unchanged code.** `go test -run TestPasswordChangeGateLogout -count=1 ./httpsec/`. Expected: FAIL with a `*ChallengeError` of kind `ChallengePasswordChange`. **This is the reproduction of the `UNREPRODUCED` claim.** If it passes, stop and report.
- [ ] **Step 3: Extend to a table.** Default logout path; consumer path `/auth/sign-out`; `GET /invoices` still refused; the resolve endpoint still clears the marker.
- [ ] **Step 4: Implement.** Add the field `logoutPath string` and a `wirePasswordChange` handed `c.logoutPath` at assembly. In `Intercept`, after the resolve check: `if pending && g.isLogoutRequest(ex.Request) { return next(ex) }`. Reuse the MFA gate's shape; consider extracting `isLogoutRequest(logoutPath string, r Request) bool` as a package function both gates call.
- [ ] **Step 5: Run to verify it passes**, then `go test -count=1 ./httpsec/`.
- [ ] **Step 6: Report**, including the reproduction output as `REPRODUCED`.

### Task 4.2: Every declared challenge needs an enforcer

**Files:** Modify `policy/engine.go` (+ `policy/engine_test.go`), `httpsec/chain.go` (`refuseUnenforcedChallenges`), `httpsec/options.go` (`WithChallengeEnforcer`), and every existing `httpsec` test chain that registers a password-age policy without the gate; Test `httpsec/chain_test.go`.

**Interfaces:**

```go
// policy
func (e *Engine) DeclaredChallenges() []ChallengeKind // distinct, in first-declared order
// httpsec
func WithChallengeEnforcer(kind policy.ChallengeKind) Option
```

The built-in map, in `chain.go`:

```go
var builtInEnforcers = map[policy.ChallengeKind]Order{
	policy.ChallengeMFA:            OrderMFAChallenge,
	policy.ChallengePasswordChange: OrderPasswordChange,
}
```

Task 4.4 adds the `policy.ChallengeMFAEnrolment: OrderMFAEnrolment` entry together with the constant, so 4.4's slot test is a genuine red step.

- [ ] **Step 1: Write the failing test**

```go
func TestUnenforcedChallenges(t *testing.T) {
	const terms policy.ChallengeKind = 100
	tests := []struct {
		name     string
		policies []policy.Policy
		opts     []httpsec.Option
		assert   func(t *testing.T, err error)
	}{
		{name: "password age without its gate", policies: []policy.Policy{passwordAgePolicy(t)},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig); require.ErrorContains(t, err, "ChallengePasswordChange") }},
		{name: "mfa policy without interceptor", policies: []policy.Policy{mfaChallengePolicy(t)},
			assert: func(t *testing.T, err error) { require.ErrorContains(t, err, "ChallengeMFA") }},
		{name: "consumer kind declared", policies: []policy.Policy{declaring(terms)}, opts: []httpsec.Option{httpsec.WithChallengeEnforcer(terms)},
			assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "consumer kind undeclared", policies: []policy.Policy{declaring(terms)},
			assert: func(t *testing.T, err error) { require.ErrorContains(t, err, "ChallengeKind(100)") }},
		{name: "policy declaring nothing", policies: []policy.Policy{silentPolicy{}},
			assert: func(t *testing.T, err error) { require.NoError(t, err) }},
	}
	// build an engine with tt.policies registered in their phases, then
	// httpsec.New(append([]httpsec.Option{httpsec.WithPolicyEngine(engine)}, tt.opts...)...)
}
```

- [ ] **Step 1b: Runtime refusal (review finding, reproduced).** `TestUnenforcedChallengeAtRuntime`: build the chain with an empty engine, then `e.Add` a per-request policy that declares and raises `ChallengePasswordChange`; a bearer request is refused with an error wrapping the chain's configuration error, the session is not marked, and the handler does not run. Implement: wherever a raised challenge is marked (the login tail and the bearer), check the kind against the chain's enforcer set (built-in enforcers registered plus `WithChallengeEnforcer` kinds) first. Godoc on `WithPolicyEngine` and `Engine.Add`: register every policy before the chain is built.
- [ ] **Step 1c: Enforcement means the built-in gate (review findings, reproduced).** Replace slot occupancy with a set built from the gates actually enabled (`EnableMFA` → `ChallengeMFA`, the password-change gate → `ChallengePasswordChange`, `EnableMFAEnrolment` → `ChallengeMFAEnrolment`) plus `WithChallengeEnforcer` kinds, used by both the assembly check and `refuseUnenforced`. Tests: a consumer interceptor at `Before(OrderMFAChallenge)` with the enrolment path on and no enrolment interceptor fails assembly; a pre-authentication policy raising an unenforced kind refuses form login and basic with the configuration error; a magic-link and an OIDC redemption raising an unenforced kind refuse before the credential is consumed (the store's consume is not called); a declared consumer kind raised per request is readable from the exchange (an exported accessor, e.g. `(*Exchange).RaisedChallenge() policy.ChallengeKind`) by the next interceptor, and the request continues.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestUnenforcedChallenges -count=1 ./httpsec/`. Expected: FAIL on "password age without its gate" and the consumer rows. The MFA row passes today; that is the existing check.
- [ ] **Step 3: Implement**

```go
func (c *config) refuseUnenforcedChallenges() error {
	if c.engine == nil {
		return nil
	}
	for _, kind := range c.engine.DeclaredChallenges() {
		if at, ok := builtInEnforcers[kind]; ok && c.registeredAt(at) {
			continue
		}
		if c.consumerEnforced[kind] {
			continue
		}
		return newConfigError("a registered policy can raise %s, but nothing on this chain "+
			"enforces it: enable its gate, declare your own with WithChallengeEnforcer, or remove the policy", kind)
	}
	return nil
}
```

`WithChallengeEnforcer` records into `c.consumerEnforced map[policy.ChallengeKind]bool`. Its godoc says it is for a kind the library does not know, and that there is no switch to disable the check.
- [ ] **Step 4: Fix the existing test chains** that now fail to assemble. Run `go test -count=1 ./httpsec/` and give each failing chain the gate it was missing, never `WithChallengeEnforcer` for a built-in kind. Report each file touched.
- [ ] **Step 5: Run to verify all pass.** `go test -run TestUnenforcedChallenges -count=1 ./httpsec/ && go test -count=1 ./httpsec/ ./policy/`, plus `cd test && go test -count=1 .`.
- [ ] **Step 6: Report.**

### Task 4.3: Status rows

**Files:** Modify `httpsec/status.go`; Test `httpsec/status_test.go`.

- [ ] **Step 1: Write the reproduction.** Add rows to the existing `StatusForError` table expecting `mfa.ErrInvalidCode` → 401, `mfa.ErrVerifyThrottled` → 401, `mfa.ErrSameChannel` → 403 and `mfa.ErrAlreadyEnrolled` → 403.
- [ ] **Step 2: Run on unchanged code.** `go test -run TestStatusForError -count=1 ./httpsec/`. Expected: FAIL with 500 for each. **This reproduces the `UNREPRODUCED` status claim;** record it. If any row already passes, report which one and drop that part of the claim.
- [ ] **Step 3: Add the remaining rows:** `&ChallengeError{Kind: policy.ChallengeMFAEnrolment}` → 403, `mfa.ErrEmailCodeInvalid` → 401, `mfa.ErrEnrolmentThrottled` → 401.
- [ ] **Step 4: Implement**

```go
	if errors.As(err, &ch) {
		switch ch.Kind {
		case policy.ChallengePasswordChange, policy.ChallengeMFAEnrolment:
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	}
```

`mfa.ErrEmailCodeInvalid` wraps `mfa.ErrInvalidCode` (`errors.Is` finds both), so an emailed-code refusal is identifiable as the invalid second-factor code refusal, as `http-error-propagation` requires, and maps through its row. Add to `statusTable`: `{mfa.ErrInvalidCode, 401}`, `{mfa.ErrVerifyThrottled, 401}`, `{mfa.ErrEnrolmentThrottled, 401}`, `{mfa.ErrSameChannel, 403}`, `{mfa.ErrAlreadyEnrolled, 403}`.
- [ ] **Step 5: Run to verify it passes.**
- [ ] **Step 6: Report**, with the reproduction output labelled `REPRODUCED`.

### Task 4.4: The slot and the marker

**Files:** Modify `httpsec/order.go`, `httpsec/logincomplete.go` (`markChallengePending` → `challengeMarker`; `loginTailDeps` gains `marker challengeMarker`), `httpsec/bearer.go`, the three `loginTailDeps{...}` literals (`login.go:135`, `magiclink.go:361`, `oidc_redeem.go:65`), and `export_seams_test.go:50`; Test `httpsec/logincomplete_test.go`, `httpsec/bearer_test.go`, `httpsec/order_test.go`.

**Interfaces:**

```go
// OrderMFAEnrolment is the enrolment gate and its endpoints, immediately outside the second-factor gate.
const OrderMFAEnrolment = OrderMFAChallenge - 1 // == Before(OrderMFAChallenge)

type challengeMarker struct {
	sessions          *session.Manager
	enrolmentLifetime time.Duration // set by EnableMFAEnrolment at assembly; > 0 whenever the kind can be raised (4.2)
}
func (m challengeMarker) mark(s *session.Session, kind policy.ChallengeKind)
```

`config` gains `enrolmentLifetime time.Duration`. The chain hands `challengeMarker{sessions: c.sessions, enrolmentLifetime: c.enrolmentLifetime}` to every login tail and to the bearer interceptor at wiring time, not at option time.

- [ ] **Step 1: Write the failing tests.**
  - `TestOrderMFAEnrolment`: `require.Equal(t, httpsec.Before(httpsec.OrderMFAChallenge), httpsec.OrderMFAEnrolment)`.
  - `TestCompleteLoginEnrolment`: the tail, with an engine whose post-authentication phase challenges `ChallengeMFAEnrolment` and a lifetime of 15 minutes, returns a `*ChallengeError` of that kind with a token. The session loaded from the store is `MFAEnrolmentPending`, with `AbsoluteExpiresAt` 15 minutes after creation, and the store's `Save` happened before `Generate` (use `gomock.InOrder` on the session store mock and the token generator mock).
  - `TestBearerMarksEnrolment`: a per-request enrolment challenge leaves `ex.Session.MFA == MFAEnrolmentPending` and continues, and the stored session shows the state and the lowered deadline even when a gate at `OrderMFAEnrolment` refuses before the session-touch step; a session already in the state is not saved again. `TestBearerMarksEnrolmentSaveFails`: a failing save refuses the request.
- [ ] **Step 2: Run to verify it fails.** `go test -run 'TestOrderMFAEnrolment|TestCompleteLoginEnrolment|TestBearerMarksEnrolment' -count=1 ./httpsec/`. Expected: FAIL, the state is `MFANone`, because `markChallengePending` marks nothing for an unknown kind.
- [ ] **Step 3: Implement.** Add the constant, and the `builtInEnforcers` entry `policy.ChallengeMFAEnrolment: OrderMFAEnrolment` in `chain.go`. Then:

```go
func (m challengeMarker) mark(s *session.Session, kind policy.ChallengeKind) {
	switch kind {
	case policy.ChallengeMFA:
		s.MFA = session.MFAPending
	case policy.ChallengePasswordChange:
		s.PasswordChangePending = true
	case policy.ChallengeMFAEnrolment:
		m.sessions.MarkEnrolmentPending(s, m.enrolmentLifetime)
	case policy.ChallengeNone:
	}
}
```

Replace both call sites and update the three literals and the seam export.
- [ ] **Step 4: Run to verify it passes**, then `go test -count=1 ./httpsec/`.
- [ ] **Step 5: Report.**

---

### Task 5.1: `EnableMFAEnrolment` and its construction checks

**Files:** Create `httpsec/mfaenroloptions.go`, `httpsec/mfaenrol.go` (interceptor struct only); Test `httpsec/mfaenroloptions_test.go`.

**Interfaces:**

```go
type EnrolmentDeps struct {
	Users  identity.UserLoader // loads Details for the resolvers
	Sender notify.Sender       // required while notification or email confirmation is on
}
type EnrolmentOption func(*enrolmentInterceptor) error
func EnableMFAEnrolment(d EnrolmentDeps, opts ...EnrolmentOption) Option

func WithEnrolmentBeginPath(p string) EnrolmentOption        // default DefaultEnrolmentBeginPath "/mfa/enrol/begin"
func WithEnrolmentConfirmPath(p string) EnrolmentOption      // default "/mfa/enrol/confirm"
func WithEnrolmentEmailConfirmPath(p string) EnrolmentOption // default "/mfa/enrol/confirm-email"
func WithEnrolmentSessionTTL(d time.Duration) EnrolmentOption // default 15 * time.Minute
func WithEnrolmentBeginLimiter(l ratelimit.Limiter) EnrolmentOption   // default NewMemoryLimiter(5, time.Hour)
func WithEnrolmentConfirmLimiter(l ratelimit.Limiter) EnrolmentOption // default NewMemoryLimiter(5, 15*time.Minute)
func WithoutEmailConfirmation() EnrolmentOption
func WithoutEnrolmentNotification() EnrolmentOption
func WithEnrolmentSynchronousDelivery() EnrolmentOption
func WithContactResolver(r mfa.ContactResolver) EnrolmentOption // default mfa.UsernameAsAddress
func WithLabelResolver(r mfa.LabelResolver) EnrolmentOption     // default mfa.UsernameAsAddress
```

Two more options belong to this file but are added by the task that gives them behaviour: `WithEnrolmentMessages(r EnrolmentMessages)` in 5.4 (default: the plain-text renderer) and `WithEnrolmentLogInterval(d time.Duration)` in 5.7 (default: one minute).

The interceptor registers at `OrderMFAEnrolment`. The checks that need the assembled chain run at wiring (`wireMFAEnrolment`): the enabled MFA interceptor's method, and `c.sessions`.

- [ ] **Step 1: Write the failing test.** One row per construction error, each asserting `errors.Is(err, httpsec.ErrConfig)` and the option name in the message:
  1. no policy declares `ChallengeMFAEnrolment`;
  2. no `EnableMFA`;
  3. an `EnableMFA` method that is not an `mfa.Enroller` (a typed `mfa.Method` mock);
  4. TOTP over a store without `DeviceProofStore`: construction fails; the same TOTP still begins and confirms out of band (spec scenario);
  5. a nil begin limiter, and a nil confirm limiter;
  6. no sender with defaults;
  7. a synchronous sender (a plain `notify.Sender` mock) without `WithEnrolmentSynchronousDelivery`;
  8. TTL 0;
  9. TTL longer than `sessions.AbsoluteTimeout()`;
  10. a nil `Users`.

  Plus the "policy side only" row: `WithMFAEnrolmentPath` on the policy, no `EnableMFAEnrolment`, which fails through 4.2 naming `ChallengeMFAEnrolment`. Plus one passing row with every default satisfied.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnableMFAEnrolmentConstruction -count=1 ./httpsec/`.
- [ ] **Step 3: Implement.** The defaults are set in `EnableMFAEnrolment`, then options applied, then option-time checks (nil limiter, TTL ≤ 0, nil `Users`, sender presence and non-blocking via a `requireNonBlocking`-style helper). Assembly-time checks go in `wireMFAEnrolment`, which also sets `c.enrolmentLifetime`. Write a godoc per option naming its default. `WithoutEmailConfirmation` states that a password alone then binds a second factor. `WithoutEnrolmentNotification` states that nothing then tells the user.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 5.2: The gate

**Files:** Modify `httpsec/mfaenrol.go` (`Intercept`, `gate`, `isEnrolmentRequest`, `logoutPath` wired at assembly); Test `httpsec/mfaenrolgate_test.go`.

- [ ] **Step 1: Write the failing test.** Build a full chain: bearer, `EnableMFA`, `EnableMFAEnrolment`, the password-change gate with a resolve endpoint, logout, a consumer interceptor at `After(OrderPasswordChange)` that records it ran, an authorizer, and a handler that records it ran. The session is marked enrolment-pending. The table:
  - `POST /invoices`, `POST /mfa/totp`, `POST /account/password` and `GET /mfa/enrol/begin` → each an enrolment `*ChallengeError` carrying the session, with no handler, consumer interceptor or authorizer run;
  - `POST /logout` → the session is deleted;
  - `WithEnrolmentBeginPath("/account/2fa/start")` and a POST there → reaches begin (assert the begin limiter was consulted);
  - Review Focus 4: `EnableMFAEnrolment` given before `EnableLogout(WithLogoutPath("/session/end"))`, and `POST /session/end` → the session is deleted.

  Each refused row must be seen to fail once, by building the chain without `EnableMFAEnrolment` (a `withoutGate` sub-test asserting the handler *does* run).
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentGate -count=1 ./httpsec/`.
- [ ] **Step 3: Implement**

```go
func (i *enrolmentInterceptor) Intercept(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil || s.MFA != session.MFAEnrolmentPending {
		return next(ex)
	}
	switch {
	case i.is(ex.Request, i.beginPath):
		return i.begin(ex)
	case i.is(ex.Request, i.confirmPath):
		return i.confirm(ex)
	case i.emailConfirmation && i.is(ex.Request, i.emailPath):
		return i.redeemEmailCode(ex)
	case isLogoutRequest(i.logoutPath, ex.Request):
		return next(ex)
	}
	return &ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: s}
}
```

`begin`, `confirm` and `redeemEmailCode` return `errNotImplemented` until 5.3–5.5; the gate tests do not reach them except for the consumer-path row, which asserts only the limiter call.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 5.3: Begin

**Files:** Modify `httpsec/mfaenrol.go` (`begin`); Test `httpsec/mfaenrolbegin_test.go`.

- [ ] **Step 1: Write the failing test.** A table:
  - provisioning JSON returned, `u-1` not enrolled, and `ex.Session.EnrolmentGeneration` saved non-zero;
  - a `label=attacker@example.com` form field → the URI contains the username, not the attacker's address;
  - `WithLabelResolver` returning `ana.work@example.com` → used;
  - a magic-link session with an email-channel method mock implementing `Enroller` → `mfa.ErrSameChannel`, and `BeginEnrolmentGeneration` never called;
  - an enrolled user → `mfa.ErrAlreadyEnrolled`;
  - a sixth begin in an hour → `mfa.ErrEnrolmentThrottled`, with nothing generated;
  - a limiter `Exceeded` error → refused;
  - Review Focus 5: username `ana:x` → an error, nothing stored.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentBegin -count=1 ./httpsec/`.
- [ ] **Step 3: Implement**, in order:
  1. the limiter `Exceeded(user)` check, refusing on true or on error;
  2. `RecordFailure(context.WithoutCancel(ctx), user)`, recorded on every call as the design states;
  3. the same-channel check: `enroller.Channel() == s.FirstFactor.Channel()` → `mfa.ErrSameChannel`;
  4. `Users.LoadByUserID`, then the label resolver;
  5. `BeginEnrolmentGeneration`;
  6. `s.EnrolmentGeneration = gen`, then `i.sessions.Save`;
  7. write `{"secret":…, "uri":…}` with `Cache-Control: no-store`.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 5.4: Confirm

**Files:** Modify `httpsec/mfaenrol.go` (`confirm`, `EnrolmentMessages` with the default code message); Test `httpsec/mfaenrolconfirm_test.go`.

**Interfaces:** `type EnrolmentMessages interface { Code(code string, at time.Time) (subject, body string); Bound(method string, at time.Time) (subject, body string) }` with a default plain-text implementation, replaceable through `WithEnrolmentMessages(r EnrolmentMessages) EnrolmentOption`, whose godoc names the default; a nil renderer is a configuration error. The code message carries the code; the bound message carries none.

- [ ] **Step 1: Write the failing test.** A table:
  - a valid code with email confirmation on → proven, not enrolled, and one message queued to the username whose body contains the 6-digit code;
  - a wrong code → `mfa.ErrInvalidCode`, and the confirm limiter records one failure;
  - a cancelled request context with a wrong code → the failure still recorded (the limiter mock asserts its context has no cancellation: `require.NoError(t, ctx.Err())`);
  - five wrong codes, then a valid one → `mfa.ErrEnrolmentThrottled`;
  - the sender returns a queue-full error → the request fails, and a later email-code request cannot complete that proof;
  - `WithoutEmailConfirmation` → enrolled, and the session state is `MFAPending` and saved.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentConfirm -count=1 ./httpsec/`.
- [ ] **Step 3: Implement**, in order:
  1. the limiter check;
  2. read `code`;
  3. `ProveDevice(user, s.EnrolmentGeneration, code, i.emailConfirmation, 10*time.Minute)`;
  4. on `ErrInvalidCode`, record a failure under `context.WithoutCancel` and return;
  5. with email confirmation on, resolve the contact and `Sender.Send` the code message; a send error is returned as the refusal;
  6. with it off, `CompleteEnrolment`, then `s.MFA = session.MFAPending`, then `Save`, then the notification (5.5's helper).

  Respond 204 with no body.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

*Order, as implemented and accepted:* with email confirmation on, confirm resolves the contact address before `ProveDevice`, so an unresolvable address leaves no device proof behind.

### Task 5.5: The emailed code and the notification

**Files:** Modify `httpsec/mfaenrol.go` (`redeemEmailCode`, `notifyBound`); Test `httpsec/mfaenrolemail_test.go`.

- [ ] **Step 1: Write the failing test.** A table:
  - the correct code within 10 minutes → enrolled, the session is `MFAPending` and saved, and one notification is queued whose body contains neither the code, the secret nor the URI;
  - 11 minutes later → `mfa.ErrEmailCodeInvalid`, still pending;
  - the fifth wrong code, then the correct one → refused;
  - a session whose `EnrolmentGeneration` is older → refused and nothing completed;
  - Review Focus 1: a same-session begin, proof, begin again → the first code is refused;
  - Review Focus 3: `" 123456"` and `"12345"` → `ErrEmailCodeInvalid` and counted;
  - `WithoutEnrolmentNotification` → nothing queued;
  - the notification queue refusing → the enrolment stays confirmed, and one sampled record is written.
- [ ] **Step 2: Run to verify it fails.** `go test -run 'TestEnrolmentEmailCode|TestEnrolmentNotification' -count=1 ./httpsec/`.
- [ ] **Step 3: Implement.** The limiter check comes first, then `RedeemEmailCode(user, s.EnrolmentGeneration, code)`. On `ErrEmailCodeInvalid`, record a limiter failure under `WithoutCancel` and return. On success, set `s.MFA = MFAPending`, `Save`, then `notifyBound` (whose errors are logged through the sampler and never returned), and respond 204.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 5.6: Upgrade at verify

**Files:** Modify `httpsec/mfaverify.go` (`verify`, just before `Rotate`); Test `httpsec/mfaenrolupgrade_test.go`.

- [ ] **Step 1: Write the failing test.** A session created at 09:00 is marked enrolment-pending at 09:00 (from the enrolment path), confirmed at 09:08, and moves to `MFAPending`. A valid TOTP code at 09:09 → the rotated session has `MFASatisfied`, `AbsoluteExpiresAt` 21:00 and no marker, and the old handle no longer loads. The second test, `TestConfirmationIsNotASecondFactor`: the same session at 09:08 requesting `/invoices` gets a `ChallengeMFA` error.
- [ ] **Step 2: Run to verify it fails.** `go test -run 'TestVerifyUpgradesEnrolmentSession|TestConfirmationIsNotASecondFactor' -count=1 ./httpsec/`. Expected: FAIL, the absolute deadline is still 09:15.
- [ ] **Step 3: Implement.** In `verify`, where `s.MFA`/`s.MFASatisfiedAt` are set: capture the deadline fields, the marker (`EnrolmentOriginDeadline`) and the generation for rollback, call `i.sessions.RestoreEnrolmentDeadlines(s)` and, if it returns an error (`ErrSessionExpired`), roll back the state and refuse as the session having ended, without rotating; on a `Rotate` error restore the captured values alongside the existing `state, satisfiedAt` rollback.
- [ ] **Step 4: Run to verify it passes**, then `go test -count=1 ./httpsec/`.
- [ ] **Step 5: Report.**

### Task 5.7: Enrolment logs

**Files:** Modify `httpsec/mfaenrol.go` (sampler built at wiring with `logsample.New(interval, logsample.WithReporter(...))`, keyed by reason); Test `httpsec/mfaenrollogs_test.go`.

- [ ] **Step 1: Write the failing test.** A capturing `slog.Handler` records every record and its attributes, serialised to a string. Run begin → proof → a wrong emailed code → throttle. Assert that no record contains the secret, the URI, the emailed code or the contact address. With `WithEnrolmentLogInterval(0)`, 20 throttled begins give 20 records. Verification throttle records stay sampled under their own interval.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestEnrolmentLogs -count=1 ./httpsec/`. With no logging yet, the count assertion fails.
- [ ] **Step 3: Implement** a `refuse(ctx, reason string, user identity.UserID)` helper, used by every refusal, that writes only the endpoint, the reason and, where relevant, the limiter: never a code, secret, URI, address or user reference. Sampled per endpoint and reason.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 5.8: End to end

**Files:** Test `httpsec/mfaenrole2e_test.go`.

- [ ] **Step 1: Write the test.** A real chain over the in-memory session, enrolment and user stores, a real TOTP with a fixed clock, a capturing sender, form login, magic link and a stubbed OIDC redeemer (the existing `oidc_redeem_test` helpers). Sub-tests:
  1. password login → 403 enrolment challenge with a token → begin → a TOTP code for the returned secret → confirm → read the emailed code from the sender → redeem → advance 30 s → verify → `/invoices` 200 with the rotated token;
  2. the same with `WithoutEmailConfirmation`;
  3. magic-link login → enrolment challenge;
  4. OIDC with the exemption removed and the default list → 403 enrolment-required, and the handoff not consumed; with `WithEnrolmentFirstFactors(Password, MagicLink, OIDC)` → consumed, and an enrolment challenge;
  5. a login after `WithEnrolmentPathUntil` → 403 enrolment-required;
  5a. an enrolled required user whose enrolment is removed with `mfa.ResetEnrolment` logs in → enrolment challenge (spec `multi-factor-auth`, scenario "Enrolment deleted with the path on");
  6. Review Focus 2: an enrolment-only session whose user is then unflagged → still confined; a fresh login → a full session.
- [ ] **Step 2: Run.** `go test -run TestEnrolmentPathEndToEnd -count=1 ./httpsec/`. Every sub-test must have been seen to fail. For the ones already green from earlier tasks, disable the gate or the marker temporarily and record the failure.
- [ ] **Step 3: Report.**

### Task 5.9: Framework conformance scenarios

**Files:** Create `test/httpsecconformance/enrolment_scenarios.go`; Modify `test/httpsecconformance/scenarios.go` (append `enrolmentScenarios()...` to the list `Run` iterates).

- [ ] **Step 1: Write the scenarios** in the existing `Scenario` shape, as in `oidc_scenarios.go`: "enrolment gate refuses a protected route" (403), "enrolment-only session logs out" (200, then the token is refused), and "enrolment completes and verify grants access".
- [ ] **Step 2: See them fail.** Temporarily build the scenarios' chain without `EnableMFAEnrolment` and run `cd test && go test -run 'TestConformance' -count=1 .`: expect the gate scenario to fail with 200. Restore.
- [ ] **Step 3: Run all adapters.** `cd test && go test -run 'TestConformance' -count=1 .`. Expected: PASS.
- [ ] **Step 4: Report.**

---

### Task 6.1: Durable deltas (main session) — done

`durable-persistence` is archived (`openspec/changes/archive/2026-09-27-durable-persistence`) and its specs are promoted. This change now carries `specs/security-state-stores/spec.md` and `specs/secrets-at-rest/spec.md`, and `openspec validate mfa-enrolment-path --strict` passes. Tasks 6.2–6.6 below implement those two deltas. Their requirements, by name:

- `security-state-stores`: "MFA enrolment confirmation is recorded once" (modified: new generation on `PutPending`, proof and code cleared; `Confirm` clears the code and never lowers the step), "Enrolment device proof, completion and emailed-code attempts are decided by the write" (added), "Enrolment-path session state survives a durable store" (added).
- `secrets-at-rest`: "Long-lived secrets are stored sealed", "A sealed value is bound to its row", "A value that cannot be opened fails closed", "Retired-key values are re-sealed on read without disturbing concurrent writes" (all modified for the emailed code).

#### Group 6 facts every dispatch needs

Two items below are `UNREPRODUCED` claims (design decision 10), not established defects: **Sealing** (the wrapper passes the code through) and **The nil generation**. Each is proven only by the red step named for it. A dispatch whose red step passes on unchanged code stops and reports, and the main session removes or narrows the claim instead of implementing the fix.

- **Schema:** one file, `migrate/securitystate/20260926000000_security_state.sql`, edited in place (no tag yet). Its pin is `TestSecurityStateMigrations_Schema` in `test/migrate_securitystate_test.go`.
- **Shared SQL:** `internal/pgschema/mfa.go` and `internal/pgschema/sessions.go` hold the statement text that `sqlstore` and `pgx` both use. `gorm` builds its own in `gorm/mfa.go`, `gorm/session.go`, with its models in `gorm/models.go`.
- **Sealing:** every durable enrolment store is `seal.NewEnrolmentStore(inner, inner, c, ...)` over an unsealed inner store. The wrapper already exposes `mfa.DeviceProofStore` when the inner store has it (`provingEnrolmentStore` in `seal/mfa.go`), but **passes `ProveDevice`'s code through unsealed, and `Get` returns `EmailCode` as stored**. Sealing the code is therefore the wrapper's job, done once in the `seal` package, not three times in the adapters. The session side is `session.NewEncryptedStore(inner, seal.SessionCipher(c))`; the new session fields are not secrets and are not sealed.
- **Text encoding:** sealed values sit in `text` columns base64url-encoded, through `storekit.SecretText` / `storekit.SecretFromText` (`internal/storekit`). The emailed code follows the secret: `email_code text NULL`, NULL meaning none.
- **The nil generation.** `id.ID.Value()` writes `id.Nil` as the all-zero UUID string, not NULL. A WHERE clause `generation = $2` would then match an enrolment stored with no generation when the caller also passes none, which breaks "an absent generation matches no enrolment". Every adapter therefore writes a zero `id.ID` as SQL NULL (column nullable) and passes a zero generation to the three writes as NULL, so `generation = NULL` matches nothing. `id.ID.Scan(nil)` returns an error, so scan the nullable uuid columns through `sql.Null[id.ID]` (or the driver's equivalent) and use `id.Nil` when not valid, as `sqlstore` does after 6.4.
- **After 6.4 (landed):** `internal/pgschema` statements are widened (`EnrolmentPutPending` takes `$5`; the session insert and update take the marker and generation), so `test/pgxstore` and `test/crossbackend` fail until 6.5 lands. `internal/storekit.CheckSession` still refuses a session carrying the marker or generation; `sqlstore/session.go` works around it by judging a copy with those two fields cleared. Task 6.5 owns removing that refusal and the workaround. The nil-generation subtest path is `TestEnrolmentStore/<backend>_device_proofs/nil_generation`; the pattern `TestEnrolmentStore/.*nil_generation` does not reach it.
- **Suites** live in the `test` module: `test/storetest/{mfa_suite,session_suite,race,sealed}.go`, broken variants in `test/storetest/broken_*_test.go` and `test/internal/storefix/`, and memory runs in `test/storetest/memory_test.go`. Each adapter wires them in `test/{sqlstore,pgxstore,gormstore}/{mfa,session,broken}_test.go`. Cross-backend cases are the table in `test/crossbackend/crossbackend_test.go` (`TestCrossBackend`).
- **Existing suite gaps, deliberate:** `session_suite.go` and `mfa_suite.go` each carry a comment saying the enrolment-path fields are "asserted by the enrolment-path suite extension, not here". 6.3 writes that extension and removes those comments.

### Task 6.2: Migration columns

**Model:** Sonnet — a well-specified schema edit with a pinning test.

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (`mfa_enrolments`, `sessions`)
- Test: `test/migrate_securitystate_test.go` (`TestSecurityStateMigrations_Schema`)

**Interfaces — Produces** (every later task reads these names):

| Table | Column | Type |
|---|---|---|
| `mfa_enrolments` | `generation` | `uuid NULL` (NULL = no generation; never matched) |
| `mfa_enrolments` | `device_proven_at` | `timestamptz NULL` |
| `mfa_enrolments` | `email_code` | `text NULL` (base64url sealed envelope; NULL = none) |
| `mfa_enrolments` | `email_code_until` | `timestamptz NULL` |
| `mfa_enrolments` | `email_code_attempts` | `integer NOT NULL DEFAULT 0` |
| `sessions` | `enrolment_origin_deadline` | `timestamptz NULL` (NULL = not marked) |
| `sessions` | `enrolment_generation` | `uuid NULL` |

`sessions.mfa_state smallint` is unchanged; `session.MFAEnrolmentPending` is ordinal 3, after `MFASatisfied`.

- [ ] **Step 1: Write the failing test.** Extend the column table `TestSecurityStateMigrations_Schema` already checks with the seven rows above: type, nullability, and the default of `email_code_attempts`. Add a row asserting `mfa_state`'s type is still `smallint`.
- [ ] **Step 2: Run to verify it fails.** `cd test && go test -run TestSecurityStateMigrations_Schema -count=1 .` Expected: FAIL, naming the first missing column (for example `mfa_enrolments.generation`). A Docker or compile error is not the red step.
- [ ] **Step 3: Implement.** Add the columns to the two `CREATE TABLE` statements, each with a one-line comment matching the file's style:

```sql
    -- Enrolment path. NULL generation = none, and matches no conditional write.
    generation          uuid NULL,
    device_proven_at    timestamptz NULL,
    email_code          text NULL, -- base64url envelope, NULL = none
    email_code_until    timestamptz NULL,
    email_code_attempts integer NOT NULL DEFAULT 0,
```

```sql
    -- The absolute deadline held before an enrolment mark; NULL = not marked.
    enrolment_origin_deadline timestamptz NULL,
    enrolment_generation      uuid NULL,
```

  The down migration drops tables, so it needs nothing.
- [ ] **Step 4: Run to verify it passes.** Same command, then `cd test && go test -run 'TestSecurityStateMigrations|TestGooseDirect|TestPopulatedMigrationAddsNotNullColumn' -count=1 . ./crossbackend/`. Expected: PASS.
- [ ] **Step 5: Report** the columns added and the failing line seen in step 2.

### Task 6.3: Conformance suites

**Model:** Opus — race suites and broken variants whose failure must name the defect, and a mistake here would pass every store.

**Files:**
- Create: `test/storetest/deviceproof_suite.go` (`RunDeviceProofSuite`)
- Modify: `test/storetest/race.go` (add `RunCompleteRace`, `RunChargeRace`; give `runRace` a wins-per-record parameter, default 1)
- Modify: `test/storetest/mfa_suite.go` (the modified confirmation requirement's rows; remove the "not here" comment)
- Modify: `test/storetest/session_suite.go` (the enrolment fields; remove the "not here" comment)
- Modify: `test/storetest/memory_test.go`, `test/storetest/broken_mfa_test.go`, `test/storetest/broken_session_test.go`, `test/storetest/broken_race_test.go`
- Modify: `test/internal/storefix/races.go` (`CompleteRace`, `ChargeRace`)
- Must not touch: any adapter (`sqlstore/`, `pgx/`, `gorm/`, `seal/`), `test/{sqlstore,pgxstore,gormstore}/` (6.4–6.6 wire the suites there), the migration (6.2).

**Interfaces — Produces:**

```go
// RunDeviceProofSuite holds a store implementing mfa.DeviceProofStore to the
// security-state-stores requirement "Enrolment device proof, completion and
// emailed-code attempts are decided by the write". newStore returns an
// isolated store; now is the fixed time the rows are written against.
func RunDeviceProofSuite(t *testing.T, newStore func(t *testing.T) DeviceProofEnrolmentStore)

// DeviceProofEnrolmentStore is what the suite needs: both ports on one store.
type DeviceProofEnrolmentStore interface {
	mfa.EnrolmentStore
	mfa.DeviceProofStore
}

// RunCompleteRace: Racers completions of one proven generation per record; exactly one wins.
func RunCompleteRace[S any](t *testing.T, h DurableHarness[S], r Race[S])
// RunChargeRace: Racers charges of one outstanding code per record; exactly
// mfa.MaxEmailCodeFailures win. Racers defaults to 20 for this race.
func RunChargeRace[S any](t *testing.T, h DurableHarness[S], r Race[S])
```

`storefix.CompleteRace[S DeviceProofEnrolmentStore]()` and `storefix.ChargeRace[S ...]()` return the `Race` inputs (Seed: `PutPending` on a fresh generation, then `ProveDevice`; Attempt: `Complete` or `ChargeEmailCode`), as `storefix.StepRace` does for steps.

- [ ] **Step 1: Write the device-proof suite** as one table in the `table-test` skill's `assert` form, each row seeding with `PutPending` and the port's writes, then asserting the returned `bool` and the enrolment `Get` returns. The rows (each named after its spec scenario where there is one):
  - proof on the current generation: true; `DeviceProvenAt`, `LastStep`, `EmailCode`, `EmailCodeUntil` recorded, attempts 0;
  - "Device proof on a stale generation": false, no proof time;
  - "Device proven twice": second false, step stays 1000;
  - proof at a step not later than the recorded one: false;
  - proof on a confirmed enrolment: false;
  - **nil generation** (reproduces the `UNREPRODUCED` zero-generation claim; the memory store is expected to pass it, the `nilGenerationMatches` variant to fail it, and each adapter to fail it until its NULL binding lands — an adapter that passes it before is reported, not changed): an enrolment stored by `PutPending` with `Generation: id.Nil`, then `ProveDevice`, `Complete` and `ChargeEmailCode` each passing `id.Nil`: all false, nothing changed;
  - "Completion before device proof": false, unconfirmed;
  - "A newer begin invalidates an earlier proof": proof on G1, `PutPending` G2, `Complete(G1)`: false, unconfirmed;
  - completion on the proven generation: true, `ConfirmedAt` set, `EmailCode` nil, `EmailCodeUntil` **kept**;
  - charge: true with count 1, 2, … 5, then false with count 0 and the code still stored ("Concurrent charges" in its sequential form);
  - "Expired code is not charged": false; code and expiry still stored;
  - charge with no code issued (proof with nil code): false;
  - "A new pending enrolment starts a new generation" (modified requirement): after proof with a code, `PutPending` G2 reads generation G2, zero proof time, nil code, zero expiry, attempts 0;
  - "Confirmation keeps a later device-proof step": proof at step 1001, then `Confirm(step 1000)`: true, `LastStep` 1001, `EmailCode` nil; then `AcceptStep(1001)` false.

  Put the last two rows in `RunEnrolmentStoreSuite` only when the store implements `mfa.DeviceProofStore` (they need `ProveDevice` to seed); leave the rest of that suite unchanged.
- [ ] **Step 2: Extend the session suite.** A round-trip row saving a session with `MFA: session.MFAEnrolmentPending`, `EnrolmentOriginDeadline: suiteStart.Add(12*time.Hour)` and a fixed `EnrolmentGeneration`, asserting all three back ("Enrolment-only session round trip"); an unmarked session reading zero marker and `id.Nil` ("Unmarked session"); a marked session saved again with both cleared reading them cleared ("Marker cleared on upgrade"). Remove the "not here" comments in both suites.
- [ ] **Step 3: Add the races.** Generalise `runRace` with the expected wins per record (the existing three pass 1, unchanged). `RunCompleteRace` expects 1; `RunChargeRace` expects `mfa.MaxEmailCodeFailures` and defaults `Racers` to 20. Add `storefix.CompleteRace` and `storefix.ChargeRace`.
- [ ] **Step 4: Add broken variants and see each new case fail.** In `broken_mfa_test.go`, beside the existing variants, wrap `mfa.NewMemoryEnrolmentStore()`:
  - `generationBlindComplete`: `Complete` ignores `gen`;
  - `stepOverwritingConfirm`: `Confirm` sets `LastStep = step`;
  - `chargeWithoutCap`: `ChargeEmailCode` never refuses on the count;
  - `nilGenerationMatches`: treats `id.Nil` as a match.

  In `broken_session_test.go`, a memory session store that drops `EnrolmentOriginDeadline` on save. Wire them into `TestSuitesCatchBrokenStores` so each is expected to fail. Run `cd test && go test -run 'TestSuitesCatchBrokenStores|TestBrokenStoreConformance' -count=1 ./storetest/`. Expected: each variant reported caught, with the failing assertion naming the row (for example "A newer begin invalidates an earlier proof: Complete must report false"). Record that output.
- [ ] **Step 5: Run against the memory stores.** Add `RunDeviceProofSuite` to `TestMemoryEnrolmentStore`. Run `cd test && go test -race -run 'TestMemory(Enrolment|Session)Store|TestSuitesCatchBrokenStores|TestRaceInputs' -count=1 ./storetest/`. Expected: PASS. Then `cd test && go vet ./storetest/ ./internal/... && gofmt -l storetest internal`.
- [ ] **Step 6: Report** the suite and race names, the broken-variant output from step 4, and the final run.

### Task 6.4: `seal` wrapper and `database/sql` stores

**Model:** Opus — sealing binding, fail-closed reads and single-statement conditional writes.

**Dispatch:** one agent, two parts in order: the `seal` part (core module) first, then `sqlstore`.

**Files:**
- Modify: `seal/aad.go` (constant and function), `seal/mfa.go` (`provingEnrolmentStore.ProveDevice` seals; `enrolmentStore.Get` opens the code), tests in `seal/aad_test.go`, `seal/mfa_test.go`
- Modify: `internal/pgschema/mfa.go`, `internal/pgschema/sessions.go`
- Modify: `sqlstore/mfa.go`, `sqlstore/session.go`
- Modify: `test/internal/storefix/sealed.go` (`SealedEmailCodes`), `test/sqlstore/mfa_test.go`, `test/sqlstore/session_test.go`, `test/sqlstore/broken_test.go`
- Must not touch: `pgx/`, `gorm/`, `test/pgxstore/`, `test/gormstore/`, `test/storetest/` (6.3's), the migration.

**Interfaces — Produces:**

```go
// seal/aad.go
// AADMFAEmailCodePrefix is followed by the generation, in its canonical
// 36-character text form, a ':' and the user reference, byte for byte.
AADMFAEmailCodePrefix = "scrty/mfa:email-code:"

// MFAEmailCodeAAD returns the additional data an emailed enrolment code is
// sealed against. The fixed-length generation precedes the free-form user
// reference, so no two (generation, user) pairs share additional data.
func MFAEmailCodeAAD(gen id.ID, user identity.UserID) []byte
```

`internal/pgschema` gains `EnrolmentProveDevice`, `EnrolmentComplete`, `EnrolmentChargeEmailCode`, and widened `EnrolmentPutPending`, `EnrolmentGet`, `EnrolmentConfirm`, plus the session statements' two new columns. 6.5 reuses them verbatim.

- [ ] **Step 1: Seal — write the failing tests** in `seal/mfa_test.go`, table form with the package's existing mocks: `ProveDevice` hands the inner store a code that is not the plaintext and opens only with `MFAEmailCodeAAD(gen, user)`; `ProveDevice` with a nil code hands nil and calls no cipher; `Get` returns the plaintext code; `Get` of a code that will not open returns an error and `found == false` ("Emailed code unreadable"); `Get` never re-seals the code, even with re-seal on and a retired key ("Emailed code is not rewritten on read"); a cipher failure sealing the code stores nothing. In `seal/aad_test.go`, a `TestAADGolden` row for `MFAEmailCodeAAD` and a row showing it differs from `MFASecretAAD` for the same user.
- [ ] **Step 2: Run to verify it fails (reproduces the `UNREPRODUCED` sealing claim).** `go test -run 'TestEnrolmentStore_|TestNewEnrolmentStore|TestAADGolden' -count=1 ./seal/`. If the plaintext-code rows pass on the unchanged wrapper, stop and report: the claim was wrong. Expected: FAIL because the code reaches the inner store in plaintext (the assertion names it), not because of a compile error. Add the function signature first if needed, so the red step is behavioural.
- [ ] **Step 3: Implement the seal part.**

```go
func (s provingEnrolmentStore) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID,
	step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	if code != nil {
		sealed, err := s.cipher.Seal(code, MFAEmailCodeAAD(gen, user))
		if err != nil {
			return false, diag.Wrap(err, "seal: the emailed MFA code could not be sealed")
		}
		code = sealed
	}
	ok, err := s.proofs.ProveDevice(ctx, user, gen, step, code, codeUntil, at)
	return ok, enrolmentFailed(err, "seal: the inner store could not record the device proof")
}
```

  In `Get`, after the secret opens: when `e.EmailCode != nil`, open it with `MFAEmailCodeAAD(e.Generation, user)`; failure returns the zero enrolment, `false` and a wrapped error with fixed text; no re-seal. Update the `NewEnrolmentStore` godoc: the emailed code is sealed too, bound to generation and user, never re-sealed on read. Run `go test -count=1 ./seal/ && go vet ./seal/`.
- [ ] **Step 4: sqlstore — see the suites fail.** Wire in `test/sqlstore/mfa_test.go`: `RunDeviceProofSuite` inside `TestEnrolmentStore`, `TestEnrolmentStore_CompleteRace` and `TestEnrolmentStore_ChargeRace` beside `TestEnrolmentStore_StepAcceptRace`, and a second `RunSealedColumns` run with `storefix.SealedEmailCodes(...)` in `TestEnrolmentStore_SealedColumns`. `SealedEmailCodes` seeds through `PutPending` plus `ProveDevice` on a fixed generation, reads and copies the `email_code` column, and adds two out-of-band copies of its own: into the owner's `secret` column ("Emailed code copied into the secret column"), and back onto the same user after a `PutPending` on a new generation ("Emailed code carried into a new generation"). Run `cd test && go test -run 'TestEnrolmentStore|TestSessionStore' -count=1 ./sqlstore/`. Expected: FAIL. The device-proof suite fails because the store lacks the port (the suite's type assertion names `mfa.DeviceProofStore`), and the session row fails with `EnrolmentOriginDeadline` zero.
- [ ] **Step 5: Implement sqlstore.** Statements in `internal/pgschema/mfa.go` (`$` numbering as below; every condition is in the WHERE clause, never in a preceding read):

```sql
-- EnrolmentPutPending: $1 id, $2 user_id, $3 secret, $4 created_at, $5 generation (NULL for id.Nil)
INSERT INTO mfa_enrolments (id, user_id, secret, confirmed_at, last_step, created_at, generation)
VALUES ($1, $2, $3, NULL, 0, $4, $5)
ON CONFLICT (user_id) DO UPDATE
   SET secret = EXCLUDED.secret, last_step = 0, created_at = EXCLUDED.created_at,
       generation = EXCLUDED.generation, device_proven_at = NULL,
       email_code = NULL, email_code_until = NULL, email_code_attempts = 0
 WHERE mfa_enrolments.confirmed_at IS NULL
-- EnrolmentConfirm: clears the code, never lowers the step
UPDATE mfa_enrolments SET confirmed_at = $3, last_step = GREATEST(last_step, $2), email_code = NULL
 WHERE user_id = $1 AND confirmed_at IS NULL
-- EnrolmentProveDevice: $1 user, $2 gen, $3 step, $4 code, $5 until, $6 at
UPDATE mfa_enrolments
   SET last_step = $3, device_proven_at = $6, email_code = $4, email_code_until = $5, email_code_attempts = 0
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NULL AND last_step < $3
-- EnrolmentComplete: $1 user, $2 gen, $3 at
UPDATE mfa_enrolments SET confirmed_at = $3, email_code = NULL
 WHERE user_id = $1 AND generation = $2 AND device_proven_at IS NOT NULL AND confirmed_at IS NULL
-- EnrolmentChargeEmailCode: $1 user, $2 gen, $3 at, $4 cap (mfa.MaxEmailCodeFailures)
UPDATE mfa_enrolments SET email_code_attempts = email_code_attempts + 1
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NOT NULL AND email_code IS NOT NULL
   AND email_code_until > $3 AND email_code_attempts < $4
RETURNING email_code_attempts
```

  **Zero-generation red step, in order:** first bind the generation as the plain `id.ID` value and run `cd test && go test -run 'TestEnrolmentStore/.*nil_generation' -count=1 ./sqlstore/`. Expected: FAIL, a write reporting true for `id.Nil`. Record the output; if it passes, stop and report. Only then bind NULL as below and re-run.

  Keep `PutPending`'s existing already-enrolled detection as it is today. A zero `id.ID` is bound as `nil` (NULL) in every statement; a NULL `generation` scans to `id.Nil`. `EnrolmentGet` selects the five new columns; `email_code` goes through `storekit.SecretFromText`/`SecretText` as `secret` does. `ChargeEmailCode` maps `sql.ErrNoRows` to `(0, false, nil)`. Session statements in `internal/pgschema/sessions.go` read and write `enrolment_origin_deadline` (NULL for zero time) and `enrolment_generation` (NULL for `id.Nil`). Add `_ mfa.DeviceProofStore = (*enrolmentStore)(nil)` beside the existing assertions. Each method runs through the store's existing exec helper, so it joins an attached transaction as `Confirm` does.
- [ ] **Step 6: Run to verify it passes.** `cd test && go test -race -run 'TestEnrolmentStore|TestSessionStore|TestSuitesCatchBrokenSQLStores' -count=1 ./sqlstore/`, then `cd test && go test -count=1 ./sqlstore/ ./storetest/`, then in the root `go test -count=1 ./seal/ ./sqlstore/ ./internal/... && go vet ./... && gofmt -l .`. Expected: PASS, empty gofmt.
- [ ] **Step 7: Report** files changed, test names, the red output at steps 2 and 4, and the final runs.

### Task 6.5: `pgx` stores

**Model:** Opus — the same conditional writes on another driver, where NULL binding differs.

**Runs in parallel with 6.6**, after 6.4 lands: no shared files.

**Files:**
- Modify: `pgx/mfa.go`, `pgx/session.go`
- Modify: `test/pgxstore/mfa_test.go`, `test/pgxstore/session_test.go`, `test/pgxstore/broken_test.go`
- Must not touch: `internal/pgschema/` (use 6.4's statements verbatim; if one does not fit pgx, stop and report), `seal/`, `sqlstore/`, `gorm/`, `test/gormstore/`, `test/crossbackend/`.

- [ ] **Step 1: See the suites fail.** Wire the device-proof suite, the two races and the `SealedEmailCodes` run into `test/pgxstore/mfa_test.go`, as 6.4 step 4 did for `sqlstore`. Run `cd test && go test -run 'TestEnrolmentStore|TestSessionStore' -count=1 ./pgxstore/`. Expected: FAIL for the missing port and the dropped session marker.
- [ ] **Step 2: Implement** `ProveDevice`, `Complete` and `ChargeEmailCode` on the pgx enrolment store with the `internal/pgschema` statements. Do the zero-generation red step first, as 6.4 step 5 describes: bind the plain `id.ID`, see `cd test && go test -run 'TestEnrolmentStore/pgx_device_proofs/nil_generation' -count=1 ./pgxstore/` fail (or stop and report if it passes), then bind NULL. Add the new columns in `Get`, `PutPending` and the session statements. pgx binds `id.ID` through `driver.Valuer`, so pass a zero generation as an untyped `nil`, and scan the nullable uuid into a `*id.ID` or a `pgtype.UUID` and convert. `ChargeEmailCode` maps `pgx.ErrNoRows` to `(0, false, nil)`. Add the compile-time port assertion.
- [ ] **Step 3: Run to verify it passes.** `cd test && go test -race -run 'TestEnrolmentStore|TestSessionStore|TestSuitesCatchBroken' -count=1 ./pgxstore/`, then `cd pgx && go vet ./... && gofmt -l .`.
- [ ] **Step 4: Report** as 6.4 step 7.

### Task 6.6: `gorm` stores and the cross-backend row

**Model:** Opus — gorm's zero-value update rules make a silent partial write easy.

**Runs in parallel with 6.5**, after 6.4 lands.

**Files:**
- Modify: `gorm/models.go`, `gorm/mfa.go`, `gorm/session.go`
- Modify: `test/gormstore/mfa_test.go`, `test/gormstore/session_test.go`, `test/gormstore/broken_test.go`, `test/crossbackend/crossbackend_test.go`
- Must not touch: `internal/pgschema/`, `seal/`, `sqlstore/`, `pgx/`, `test/pgxstore/`.

- [ ] **Step 1: See the suites fail.** Wire the suites into `test/gormstore/` as in 6.4 step 4. Add a `TestCrossBackend` row "enrolment fields shared across backends": save an enrolment-pending session with a marker and a generation through each backend and load it through each other ("Backends share the enrolment fields"); prove a device with a sealed code through one backend's enrolment store and charge it through another's. Run `cd test && go test -run 'TestEnrolmentStore|TestSessionStore' -count=1 ./gormstore/ && go test -run TestCrossBackend -count=1 ./crossbackend/`. Expected: FAIL. The cross-backend row fails at least on gorm; once 6.5 has landed, pgx and sqlstore already agree.
- [ ] **Step 2: Implement.** Zero-generation red step first, as 6.4 step 5 describes: write the conditions with the plain `id.ID`, see `cd test && go test -run 'TestEnrolmentStore/gorm_device_proofs/nil_generation' -count=1 ./gormstore/` fail (or stop and report if it passes), then pass a zero generation as `nil`. Add the fields to the models, with `*time.Time` and `*id.ID` (or a nullable wrapper) for the nullable columns, so that a zero value is written as NULL. Each conditional write is `Model(&enrolmentModel{}).Where("user_id = ? AND generation = ? AND ...", ...).Updates(map[string]any{...})`, using a **map**, never a struct, so that zeroing columns (`email_code_attempts: 0`, `email_code: nil`) is written. It reports `RowsAffected == 1`. A zero generation is passed as `nil`. `ChargeEmailCode` uses `gorm.Expr("email_code_attempts + 1")` with `Clauses(clause.Returning{Columns: []clause.Column{{Name: "email_code_attempts"}}})`. `Confirm` gains `email_code: nil` and `last_step: gorm.Expr("GREATEST(last_step, ?)", step)`. Add the port assertion.
- [ ] **Step 3: Run to verify it passes.** `cd test && go test -race -run 'TestEnrolmentStore|TestSessionStore|TestSuitesCatchBroken' -count=1 ./gormstore/ && go test -run TestCrossBackend -count=1 ./crossbackend/`, then `cd gorm && go vet ./... && gofmt -l .`.
- [ ] **Step 4: Report** as 6.4 step 7.

---

### Task 7.1: Documentation

**Files:** godoc across `policy/enrolmentpath.go`, `httpsec/mfaenroloptions.go`, `mfa/enroller.go`, `mfa/reset.go`, `session/enrolment.go`; `README.md` (a "Letting required users enrol" section).

- [ ] **Step 1:** Write the godoc and the README section. They must name every default and every stated limit: the emailed code adds nothing after magic-link or federated logins; OIDC is off the allowlist and why; a password holder can burn a user's begin budget for an hour; enrolment-only sessions count toward the concurrent cap; the limiters are per replica; the contact defaults to the username; consumer interceptors in 500–599 see the principal; there is no route allowlist; the path pairs with `WithMFAEnrolmentPath`. Remove the "until it lands" paragraph from `WithMFARequiredForAll`'s godoc and point it at the path instead.
- [ ] **Step 2:** Verify with `go doc -all ./httpsec | grep -n Enrolment`, `go doc -all ./policy | grep -n Enrolment` and `go vet ./...` clean.
- [ ] **Step 3: Report.**

### Task 7.2: Final gate and whole-branch review (main session)

- [ ] **Step 0: Whole-branch review findings.** Test-first: a sender refusing to queue the emailed code voids it (charge its remaining attempts via `ChargeEmailCode` until refused), so a later emailed-code request with that code is refused and the enrolment stays pending; `TestEnrolmentConfirm` still passes. A test that u-1's exhausted confirmation limiter does not stop u-2 verifying. Godoc: the fixed emailed-code bounds (6 digits, 10 minutes, 5 attempts) on `EnableMFAEnrolment`/`WithoutEmailConfirmation`; the same-method requirement on `WithMFAEnrolmentPath` and `EnableMFAEnrolment`; the idle-deadline limit on `WithEnrolmentSessionTTL`; `OrderMFAEnrolment` no longer claims nothing runs between the gates; `ConcurrentSessionPolicy` notes that enrolment-only sessions count.
- [ ] **Step 1:** In every module of `go.work`, run `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` (empty) and `golangci-lint run ./...`, with Docker available.
- [ ] **Step 2:** Dispatch a fresh reviewer against every requirement in `specs/`, `design.md` decisions 1–17 and this plan's Review Focus. Every defect it claims needs a failing test, or is labelled `UNREPRODUCED`.
- [ ] **Step 3:** Findings go back to a fresh dispatch of the owning lane. Re-run step 1.
- [ ] **Step 4:** Tick the tasks in `tasks.md` (the main session only), then `/opsx:archive`.
