# MFA Enrolment Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code: every task is dispatched to a subagent under `.claude/rules/subagent-delegation.md`, and the subagent reports; it never commits and never edits anything under `openspec/`.

**Goal:** Let a user who is required to use MFA, and has no usable enrolment, bind a second factor through the library from a confined, short-lived enrolment-only session. By default this needs an emailed code and a notification, and the path is off unless the consumer turns it on.

**Architecture:** The MFA requirement policy raises a new `ChallengeMFAEnrolment` where it used to deny. The login completion step and the bearer interceptor mark the session enrolment-pending, which lowers its existing absolute deadline. A new enrolment interceptor at `OrderMFAEnrolment` (599) confines that session to three enrolment endpoints and logout. Device proof and completion are generation-bound conditional writes on a separate store port. Verification through the existing verify endpoint restores the deadline and rotates. Two shared chain rules are generalised on the way: an enforcer check for every declared challenge kind, and logout through the password-change gate.

**Tech Stack:** Go 1.27, the core module `github.com/kartaladev/scrty` (`policy`, `session`, `mfa`, `httpsec`, `notify`, `ratelimit`, `pkg/id`, `pkg/logsample`), the `test` module for framework conformance and durable suites, and uber-go/mock (`mockgen --typed`).

**Spec:** `openspec/changes/mfa-enrolment-path/`: `proposal.md`, `design.md` (decisions 1–17), `specs/{multi-factor-auth,security-policy,sessions,http-security-chain,http-error-propagation,oidc-login}/spec.md`, `tasks.md`. Plan task numbers are `tasks.md` numbers.

## Global Constraints

- Test-first on every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, see it pass (`.claude/rules/golang-tdd.md`).
- Table tests use the `table-test` skill's `assert` closure form, a `ctx` modifier where context matters, and `t.Context()`; mocks come from the `use-mockgen` skill (`//go:generate mockgen ... -typed`), placed as that skill says; PostgreSQL through `test.RunTestPostgres` (`use-testcontainers`).
- Library design: every option's godoc names the default it replaces; every wiring mistake is a construction error from `httpsec.New` or the relevant constructor; no option silently governs two subsystems.
- Defect claims: the three reproductions (tasks 3.3, 4.1, 4.3) are the first red step of their task. If the reproduction passes on unchanged code, stop and report; do not implement the departure.
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
| durable adapters (paths as `durable-persistence` archives them) | columns, port, suites | 6.x |

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
| E | 6.2–6.6 | durable adapters, `storetest` | core packages | Opus | durable conditional writes and sealing |
| F | 7.1 | godoc and README | code | Sonnet | documentation against stated limits |

D1, D2 and D3 are sequential dispatches of one lane. After each dispatch, the main session runs the listed verification commands, then a fresh reviewer checks the diff against the requirements the dispatch covers.

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

### Task 6.1: Durable deltas (main session)

- [ ] **Step 1:** Confirm `openspec/changes/archive/*-durable-persistence` exists and that `openspec/specs/security-state-stores/spec.md` and `openspec/specs/secrets-at-rest/spec.md` are promoted.
- [ ] **Step 2:** Run `/opsx:update mfa-enrolment-path` to add:
  - a `security-state-stores` ADDED requirement "Device proof and completion are recorded once per generation", with scenarios for each write's conditions and the 8-racer completion;
  - a `security-state-stores` MODIFIED "MFA enrolment confirmation is recorded once", where a new pending enrolment also clears the device proof and the emailed code;
  - a `secrets-at-rest` ADDED "The emailed enrolment code is sealed with its own binding", with scenarios for the code copied into the secret column, and into another user's row, failing to open.
- [ ] **Step 3:** Update this plan's group 6 with the file paths the archived tree actually has.
- [ ] **Step 4:** `openspec validate mfa-enrolment-path --strict`.

### Task 6.2: Migration columns

**Files:** the initial security-state migration (from 6.1), and its schema-pinning test.

- [ ] **Step 1: Write the failing schema test.** Assert the columns:
  - `mfa_enrolments`: `generation uuid NOT NULL`, `device_proven_at timestamptz NULL`, `email_code bytea NULL`, `email_code_until timestamptz NULL`, `email_code_attempts smallint NOT NULL DEFAULT 0`;
  - `sessions`: `enrolment_origin boolean NOT NULL DEFAULT false`, `enrolment_generation uuid NULL`.
- [ ] **Step 2: Run to verify it fails.** `cd test && go test -run TestSecurityStateSchema -count=1 ./...`. Expected: FAIL, column not found.
- [ ] **Step 3: Implement** by editing the initial migration in place (free before a tag). Keep `mfa_state`'s ordinals.
- [ ] **Step 4: Run to verify it passes. Report.**

### Task 6.3: Conformance suites

**Files:** `storetest` MFA enrolment and session suites (from 6.1).

- [ ] **Step 1:** Add `RunDeviceProofSuite(t, harness)`. It covers the rows of 3.2, the race of 3.3, a forward-only step (device proof at step N, then the single-call `Confirm` at step N-1, then `AcceptStep(N)` must report false, as `TestTOTPProvingCodeNotReplayableAfterConfirm` pins for the memory store), and `RunCompleteRace` (8 racers × 50 records, exactly one success each). For stores implementing `mfa.DeviceProofStore` it runs; others are skipped with a message naming the missing port. Add the enrolment state, marker and generation to the session round-trip case.
- [ ] **Step 2:** Run against broken variants kept beside the suite (a generation-blind `Complete`; a `Confirm` that overwrites the step; a session store that drops `EnrolmentOriginDeadline`). Expected: FAIL, naming the case.
- [ ] **Step 3:** Run against the memory stores. `cd test && go test -run 'TestMFAEnrolmentSuite|TestSessionSuite' -count=1 ./storetest/...`. Expected: PASS.
- [ ] **Step 4: Report.**

### Task 6.4: `database/sql` stores

- [ ] **Step 1:** Run the extended suites and the new sealed-column case against the `sqlstore` enrolment and session stores. Expected: the proof suite skipped or failing (port missing), the session round trip failing (marker dropped), and the sealed-code case failing.
- [ ] **Step 2: Implement.** Each write is one conditional UPDATE:

```sql
-- ProveDevice
UPDATE mfa_enrolments
   SET device_proven_at = $4, last_step = $5, email_code = $6, email_code_until = $7, email_code_attempts = 0
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NULL AND last_step < $5;
-- Complete
UPDATE mfa_enrolments SET confirmed_at = $3, email_code = NULL
 WHERE user_id = $1 AND generation = $2 AND device_proven_at IS NOT NULL AND confirmed_at IS NULL;
-- ChargeEmailCode
UPDATE mfa_enrolments
   SET email_code_attempts = email_code_attempts + 1
 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL
   AND device_proven_at IS NOT NULL AND email_code IS NOT NULL
   AND email_code_until > $3 AND email_code_attempts < 5
RETURNING email_code_attempts;
```

`PutPending`'s upsert sets `generation` and nulls the proof columns. The emailed code is sealed with an AAD distinct from the secret's, for example the constant `scrty/mfa:email-code:` plus the user reference, added beside the existing AAD constants with a golden test. Session columns are read and written with the rest of the row.
- [ ] **Step 3: Run to verify it passes.** `cd test && go test -run 'TestSQLStore.*(MFA|Session)' -count=1 ./...`.
- [ ] **Step 4: Report.**

### Task 6.5: `pgx` stores

- [ ] **Steps 1–4:** As in 6.4, using the shared SQL text in `internal/pgschema`. Run `cd test && go test -run 'TestPgx.*(MFA|Session)' -count=1 ./...`.

### Task 6.6: `gorm` stores

- [ ] **Steps 1–4:** As in 6.4, with the conditional updates as `Where(...).Updates(...)` checking `RowsAffected == 1`, and the fail counter through `gorm.Expr`. Run `cd test && go test -run 'TestGorm.*(MFA|Session)' -count=1 ./...`.

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
