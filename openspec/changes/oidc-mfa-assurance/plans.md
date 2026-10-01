# oidc-mfa-assurance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An OIDC login meets a user's MFA requirement only when the provider's verified ID token asserts accepted assurance (`amr`/`acr`, per provider). Otherwise a required user is challenged for scrty's own second factor (default), refused (option) or exempted (explicit option). The asserted values travel through the handoff into the session and are re-matched on every request.

**Architecture:**
- `oidc` owns per-provider `Assurance` configuration, claim extraction from the verified ID token, `acr_values` on the authorize URL, and the `AMR`/`ACR` fields on the callback result, handoff record and handoff result. `oidc.Manager` implements `policy.FederatedAssuranceSource`, optionally through a consumer `AssuranceEvaluator`.
- `policy` owns the evidence type `policy.FederatedAssurance`, minted only through `internal/assurance`, the source port, the requirement policy's federated-assurance mode, the challenge policy's opt-in, and `policy.LoginAdmission` for the way-back check.
- `session` holds `FederatedAMR`/`FederatedACR` as library-owned fields. `httpsec` mints the evidence at redemption (from `oidc.RedeemCandidate`) and per request (from the session), and refuses to assemble a chain whose MFA policy needs a source and has none.
- The durable stores add `jsonb`/`text` columns in place to the security-state migration.

**Tech Stack:** Go 1.27, `github.com/lestrrat-go/jwx/v4/jwt` (already used by `oidc`), testify, mockgen (`use-mockgen`), testcontainers PostgreSQL 15 and 18 (`use-testcontainers`, the `test` module), gopls.

**Spec:** `openspec/changes/oidc-mfa-assurance/`:
- `proposal.md`;
- `design.md` (decisions 1–10);
- `specs/oidc-login`, `specs/security-policy`, `specs/identity-model`, `specs/sessions`, `specs/http-security-chain`, `specs/account-recovery`, `specs/security-state-stores`, `specs/schema-migrations`;
- `tasks.md`.

Task numbers below (`1.1`…`8.3`) are `tasks.md`'s.

## Prerequisite

`passkey-authentication` is applied and archived first (design.md, decision 8). This plan consumes what that change produces:
- `factor.Passkey` and `factor.PublicKey`;
- `internal/assurance.Proof` and `assurance.New`;
- `policy.SecondFactorProof`, `policy.Input.SecondFactorAtLogin`, and `policy.MintProofForTest` in `policy/export_test.go`;
- `session.Session.MFAAtFirstFactor` and `session.WithSecondFactorAtLogin()`;
- the `mfa_at_first_factor` column, and `recovery.UsableLister` in `recovery/wayback.go`.

Line numbers below are from the tree before passkey lands. Re-find each site with gopls before editing.

## Global Constraints

- **Vocabulary:** `factor.OIDC` reports `factor.Federated` and is **not** exempt. `factor.APIKey` is the only kind exempt by `factor.Kind.MFAExempt`.
- **Assurance defaults:**
  - `AcceptedAMR = ["mfa"]`, no accepted `acr`, no `acr_values`, `MatchAny`;
  - values matched exactly and case-sensitively;
  - a configured empty set accepts nothing.
- **Claim reading:**
  - `amr` is an array of strings, kept in order with duplicates removed;
  - `acr` is a non-empty string;
  - anything else means not asserted, plus a sampled warning keyed `oidc.callback:malformed-assurance-claim:<provider>` with attributes `provider` and `claim`, never the value. The token stays valid.
- **Mode:** `policy.FederatedAssuranceChallenge` (default), `FederatedAssuranceRefuse`, `FederatedAssuranceExempt`. The refusal sentinel is `policy.ErrFederatedAssuranceNotMet`, mapped to 403.
- **Evidence:** `policy.FederatedAssurance` has no public constructor, and its zero value asserts nothing. It is minted only in `httpsec`, through `internal/assurance`. With no source wired, nothing is met.
- **Session:** provider assurance never sets `MFA = MFASatisfied` or `MFAAtFirstFactor`.
- **Storage:** `amr` as `jsonb NOT NULL DEFAULT '[]'` and `acr` as `text NOT NULL DEFAULT ''`, on both `oidc_handoffs` and `sessions` (`federated_amr`, `federated_acr`), unsealed. Columns are added in place to `migrate/securitystate/20260926000000_security_state.sql`.
- **Logs:** no record or error text carries an `amr`/`acr` value, a code, a token or a claim value.
- **Godoc:** every option names the default it replaces (`library-design.md`). Every port says what the library uses when none is supplied.
- **Test-first** (`golang-tdd.md`): red for the intended reason, where a compile error is not red. Tables follow `table-test` (the `assert` closure, `t.Context()`). Mocks come from mockgen per `use-mockgen`. PostgreSQL comes through the `test` module's helper per `use-testcontainers`. Nothing outside `test/` imports `test`.
- **No git command that discards work. No edit under `openspec/`.** The established behaviour this change departs from is described in design.md.

## Review Focus

1. **A required user's live federated session after the provider's `AcceptedAMR` is tightened**, while the user has *no* usable enrolment and the enrolment path is off. Expected: the next per-request evaluation denies with enrolment-required, and does not allow on the stale login. Pinned in 2.4.
2. **An `amr` containing a non-string element** (`["mfa", 1]`). Expected: the whole claim is treated as not asserted, with a sampled warning. It is never read as `["mfa"]`. Pinned in 4.2.
3. **A consumer `HandoffRedeemer` that returns `AMR: ["mfa"]` for a record whose check saw no `amr`.** Expected: `guardRedemption` refuses with the policy-denied error, and no session is created. Pinned in 6.2.
4. **A session rotated by the MFA verify endpoint, where the rotated copy shares the `FederatedAMR` backing array with the original.** Expected: mutating one does not change the other. `clone` copies the slice. Pinned in 3.1.
5. **Exempt mode combined with a requirement lookup that fails.** Expected: allow, without calling the lookup, because exempt mode is decided at step 1 like the exemption rule. Pinned in 2.3.

---

## Dispatch map

Lanes run in parallel where they own disjoint files and compile independently. Within a lane, dispatches run in order. After each dispatch, the main session runs the verification commands and a fresh reviewer checks the dispatch against its spec requirements (`subagent-delegation.md`).

| Dispatch | Tasks | Owns | Must not touch | Starts after | Model | Why |
|---|---|---|---|---|---|---|
| R0 | 1.1 | a scratch copy only; reports the failing output | the tree | — | Sonnet | One well-specified test over existing helpers |
| P1 | 2.1–2.3 | `factor/**`, `internal/assurance/**`, `policy/{policy,mfa,mfarequirement,federated}*.go` and their tests, every `_test.go` in the workspace that relied on OIDC being exempt | `oidc/**`, `session/**`, `httpsec/*.go` (non-test) | R0 | Opus | Security-critical decision order, and an interface other lanes compile against |
| S1 | 3.1 | `session/**` | everything else | R0 (parallel with P1, O1) | Sonnet | One option and a clone along an existing pattern |
| O1 | 4.1–4.3 | `oidc/{assurance,options_manager,manager,verify,authorize,callback}*.go` and tests | `oidc/handoff*.go`, `oidc/ports.go`, `policy/**`, `httpsec/**` | R0 (parallel with P1, S1) | Opus | Claim parsing that decides trust |
| P2 | 2.4–2.6 | `policy/**`, `httpsec/status.go` and its test | `oidc/**`, `session/**` | P1 | Opus | Per-request re-matching and the opt-in on the challenge policy |
| O2 | 4.4–4.5 | `oidc/{ports,handoff,handoffstore_memory,assurance_source}*.go` and tests, `httpsec/redemption.go`, `httpsec/oidc_redeem.go` (signature move only), `httpsec/oidc_callback.go` | `policy/**`, `session/**` | P1, O1 (parallel with P2) | Opus | A public signature change across packages, and the evaluator port |
| E1 | 5.1–5.2 | `migrate/securitystate/*.sql`, `internal/pgschema/{sessions,oidc}.go`, `sqlstore/{session,oidc}*.go`, `pgx/{session,oidc}*.go`, `gorm/{session,oidc,models}*.go`, `test/storetest/session_suite.go`, `test/oidc/handoffstore_suite.go`, `test/migrate_securitystate_test.go`, `test/crossbackend/**` | `oidc/*.go`, `session/*.go`, `httpsec/**` | S1, O2 | Sonnet | Column threading along an existing pattern |
| H1 | 6.1–6.5 | `httpsec/{logincomplete,bearer,oidc_redeem,redemption,oidc_options,chain,options}*.go` and tests, `policy/engine.go` (one method) | `oidc/**`, `session/**`, `policy/mfa*.go` | P2, O2, S1 | Opus | Evidence minting, guard comparisons, assembly checks |
| R1 | 7.1 | `recovery/wayback*.go` and tests, `policy/admission*.go` and test | `httpsec/**`, `policy/mfa*.go` | P2 (parallel with H1, E1) | Opus | Fail-closed way-back logic across two packages |
| G1 | 8.1–8.2 | `README.md`, `oidc/example_test.go`, `policy/example_test.go`, `ginsec`/`fibersec` parity tests | everything else | H1, E1, R1 | Sonnet | Documentation and parity plumbing over a finished API |
| — | 8.3 | main session | — | G1 | — | Final gate and whole-branch review |

**Why P1 and P2 are one lane split in two:** both write `policy/mfarequirement.go`. The seam is "decision at login" versus "re-matching, the challenge policy and docs".

**Why O2 waits for P1:** `oidc.Manager` implements `policy.FederatedAssuranceSource`, which P1 defines (2.2).

**Why 2.1 owns other packages' tests:** changing `MFAExempt` changes every caller's observable outcome. Ownership follows the call graph, so tests that assumed OIDC was exempt are restated in the same dispatch, and the tree stays green.

---

### Task 1.1: Reproduce the departure

**Files:**
- Test (scratch copy, not the tree): `httpsec/oidc_assurance_repro_test.go`

**Interfaces:**
- Consumes: the existing helpers in `httpsec/oidc_redeem_session_test.go` and `httpsec/oidc_mfa_test.go` (`oidcMFAEngine` and the handoff fixtures). Find them with gopls `references` from `TestOIDCRedeemMFAExemptionRemoved`.
- Produces: the test text, handed to H1 for 6.2.

- [ ] **Step 1: Copy the module to the scratchpad.** Use `rsync -a --exclude .claude ./ <scratch>/repro/`, and do the remaining steps there.
- [ ] **Step 2: Write the test** with the default classification, MFA required for all, TOTP configured and the user not enrolled. A handoff record carries no assurance, which is all today's records can carry:

```go
func TestOIDCRedeem_RequiredUserWithoutAssuranceIsRefused(t *testing.T) {
	t.Parallel()
	h := newOIDCRedeemHarness(t, oidcRedeemConfig{ // existing harness; name per gopls
		engine: oidcMFAEngine(t, false /* default classification */, false /* not enrolled */),
	})
	code := h.issue(t, "u-1")

	rec := h.redeem(t, code)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.ErrorIs(t, h.lastErr, policy.ErrMFAEnrollmentRequired)
	require.Zero(t, h.sessions.Count(t.Context()), "no session may be created")
	require.True(t, h.redeemable(t, code), "the code stays redeemable")
}
```

- [ ] **Step 3: Run** `go test -run TestOIDCRedeem_RequiredUserWithoutAssuranceIsRefused -count=1 ./httpsec/` in the copy. **Expected:** FAIL with status 200 and a session created. That failure is the defect. Report the failing lines verbatim.
- [ ] **Step 4: If it passes**, stop and report. The main session removes the departure from design.md.

### Task 2.1: `oidc` is no longer exempt by kind

**Files:**
- Modify: `factor/factor.go` (`MFAExempt`), `factor/factor_test.go` (the case `"oidc is federated and exempt"`)
- Modify, tests only: every test found by gopls `references` on `factor.Kind.MFAExempt` and on `factor.OIDC` whose expected outcome assumed exemption. Known ones: `policy/mfa_test.go:442`, `TestMFAExemptionRule`, `policy/enrolmentpath_test.go:293-312`, `httpsec/oidc_redeem_session_test.go:229-245`, `httpsec/oidc_mfa_test.go`, `httpsec/mfaenrole2e_test.go:385,494`, `recovery/wayback_test.go`.

**Interfaces:**
- Produces: `factor.OIDC.MFAExempt() == false`. Godoc: "Only `APIKey` is exempt. A federated login's MFA treatment is decided by the federated-assurance rules of `policy`."

- [ ] **Step 1: Write the failing test.** Change the factor table row to `"oidc is federated and not exempt"`, asserting `factor.OIDC.Channel() == factor.Federated` and `!factor.OIDC.MFAExempt()`.
- [ ] **Step 2: Run** `go test -run TestKind -count=1 ./factor/`. **Expected:** FAIL, `MFAExempt` is true.
- [ ] **Step 3: Implement.** In `MFAExempt`, `return k == APIKey`.
- [ ] **Step 4: Restate dependent tests.** Each test that meant "the default exemption" gains `policy.WithMFAExemption(func(k factor.Kind) bool { return k == factor.OIDC || k == factor.APIKey })`, so it keeps testing what it tested. Each test that meant "the exemption removed" drops that option. `recovery/wayback_test.go`'s linked-provider case passes `Exempt: func(k factor.Kind) bool { return k == factor.OIDC }` until 7.1 replaces the field. No assertion is weakened.
- [ ] **Step 5: Run** `go test -race ./factor/... ./policy/... ./httpsec/... ./recovery/...`. **Expected:** PASS.

### Task 2.2: Federated evidence and the source port

**Files:**
- Modify: `internal/assurance/assurance.go` (add the federated value)
- Create: `policy/federated.go`, `policy/federated_test.go`
- Modify: `policy/policy.go` (`Input.FederatedAssurance`), `policy/export_test.go` (`MintFederatedForTest`)

**Interfaces:**
- Produces:

```go
package assurance
type Federated struct{ provider, issuer string; amr []string; acr string }
func NewFederated(provider, issuer string, amr []string, acr string) Federated // empty provider → zero value; amr cloned
func (f Federated) Asserted() bool // provider != ""
func (f Federated) Provider() string
func (f Federated) Issuer() string
func (f Federated) AMR() []string  // a copy
func (f Federated) ACR() string

package policy
type FederatedAssurance = assurance.Federated
// Input gains:
FederatedAssurance FederatedAssurance // zero value asserts nothing; only library code mints one

type FederatedAssuranceSource interface {
	// MeetsAssurance reports whether the evidence meets the configured assurance for user.
	// An error fails closed: the caller denies with it as the reason.
	MeetsAssurance(ctx context.Context, user identity.UserID, ev FederatedAssurance) (bool, error)
}
type FederatedAssuranceSourceOption struct{ src FederatedAssuranceSource } // implements MFAOption and MFARequirementOption
func WithFederatedAssuranceSource(src FederatedAssuranceSource) FederatedAssuranceSourceOption
```

- A shared, unexported helper, `federatedMet(ctx, src, in) (bool, error)`, returns `false, nil` when `src` is nil, when the first factor's channel is not `Federated`, or when the evidence is not asserted. Otherwise it returns `src.MeetsAssurance(...)`.
- `policy/export_test.go`: `var MintFederatedForTest = assurance.NewFederated`.
- Mock: `//go:generate mockgen -source=federated.go -package=policy_test -destination=federated_mock_test.go -typed -exclude_interfaces=` (per `use-mockgen`; the consumer is `policy_test`).

- [ ] **Step 1: Write the failing tests.**
  - `internal/assurance` gets a table over zero, empty provider, and valid (asserted). It also mutates the `amr` slice passed to `NewFederated` and the slice returned by `AMR()`, and asserts the stored value is unchanged.
  - `policy/federated_test.go` holds a table over `federatedMet`, reached through the requirement policy only after 2.3, so here it is tested through the exported surface: a mock source must not be called for zero evidence, for a non-federated first factor, or with no source.

```go
func TestFederatedMet_ZeroEvidenceNeverAsksTheSource(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	src := NewMockFederatedAssuranceSource(ctrl) // no EXPECT: any call fails the test
	met, err := policy.FederatedMetForTest(t.Context(), src, &policy.Input{User: "u-1", FirstFactor: factor.OIDC})
	require.NoError(t, err)
	require.False(t, met)
}
```

  (`FederatedMetForTest = federatedMet` in `export_test.go`.)
- [ ] **Step 2: Run** `go test -run 'TestFederated' -count=1 ./policy/... ./internal/assurance/...`. **Expected:** after declaring the types with a `federatedMet` that returns `true, nil` unconditionally, the zero and no-source rows fail.
- [ ] **Step 3: Implement** the helper as specified, and the godoc on the field and the option. The option's godoc says: "the default is no source, under which no federated login meets assurance".
- [ ] **Step 4: Run** `go test -race ./policy/... ./internal/assurance/...`. **Expected:** PASS.

### Task 2.3: The requirement policy's federated branch

**Files:**
- Modify: `policy/mfarequirement.go` (option, fields, `Evaluate`, `Challenges`, godoc's evaluation order)
- Modify: `policy/errors.go`, or wherever `ErrMFARequired` is declared (`ErrFederatedAssuranceNotMet`)
- Test: `policy/mfarequirement_federated_test.go`

**Interfaces:**
- Produces:

```go
type FederatedAssuranceMode int
const (
	FederatedAssuranceChallenge FederatedAssuranceMode = iota // default
	FederatedAssuranceRefuse
	FederatedAssuranceExempt
)
func (m FederatedAssuranceMode) String() string
func WithFederatedAssurance(mode FederatedAssuranceMode) MFARequirementOption // unknown mode → ErrConfig at construction
var ErrFederatedAssuranceNotMet = errors.New("policy: the provider did not assert the assurance this login requires")
```

- **New evaluation order** (godoc and code):
  1. an exempt first factor, **or** a `federated` first factor in Exempt mode: allow;
  2. required?
  3. not required: allow;
  4. unknown phase or stateless: deny `ErrMFARequired`;
  5. per-request phase with the second factor satisfied: allow;
  6. a `federated` first factor: `federatedMet`. An error denies (diag-wrapped, fixed text). Met allows. Not met in Refuse mode denies `ErrFederatedAssuranceNotMet`;
  7. no method configured: deny `ErrMFARequired`;
  8. post-authentication with the passkey proof holding: allow (from passkey);
  9. no usable enrolment: enrolment path or deny `ErrMFAEnrollmentRequired`;
  10. per-request: challenge MFA;
  11. post-authentication: challenge MFA for a `federated` first factor, otherwise allow;
  12. otherwise: deny `ErrMFARequired`.
- `Challenges()` is unchanged in content (`ChallengeMFA` is already declared). Its godoc adds the federated post-authentication challenge.

- [ ] **Step 1: Write the failing table** `TestMFARequirementPolicy_Federated`, with one row per ADDED-requirement scenario and the federated MODIFIED scenarios. Each row builds the policy with a mock lookup and a mock source, sets the phase with `WithMFARequirementPhaseSource`, and asserts in the `assert` closure:

| Row | Mode | Required | Enrolled | Source answer | Phase | Expected |
|---|---|---|---|---|---|---|
| met | default | yes | no | met | post-auth | Allow |
| not met, enrolled | default | yes | TOTP | not met | post-auth | Challenge MFA |
| not met, unenrolled (required for all) | default | all | no | not met | post-auth | Deny `ErrMFAEnrollmentRequired` |
| refuse | Refuse | yes | TOTP | not met | post-auth | Deny `ErrFederatedAssuranceNotMet` |
| exempt | Exempt | lookup fails (mock returns error, `.Times(0)`) | — | `.Times(0)` | post-auth | Allow |
| consumer rule | default + `WithMFAExemption(oidc)` | yes | no | `.Times(0)` | post-auth | Allow |
| source error | default | yes | TOTP | error | post-auth | Deny wrapping the error |
| zero evidence | default | yes | TOTP | `.Times(0)` | post-auth | Challenge MFA |
| no source | default, no source option | yes | TOTP | — | post-auth | Challenge MFA |
| path admits OIDC | default + path allowlist incl. OIDC | yes | no | not met | post-auth | Challenge enrolment |
| OIDC off path | default + path on | yes | no | not met | post-auth | Deny `ErrMFAEnrollmentRequired` |
| unknown mode | `FederatedAssuranceMode(9)` | — | — | — | — | construction error `ErrConfig` |

  The evidence for asserted rows is `policy.MintFederatedForTest("corp", "https://idp.example", []string{"pwd"}, "")`.
- [ ] **Step 2: Run** `go test -run TestMFARequirementPolicy_Federated -count=1 ./policy/`. **Expected:** with the option and sentinel declared and `Evaluate` unchanged, the rows "met", "not met, enrolled", "refuse", "exempt", "source error" and "unknown mode" fail. Today the policy allows or denies by the old order, and does not validate the mode.
- [ ] **Step 3: Implement** the order above. Do not restructure the existing steps beyond inserting 1's clause, splitting step 4 into 4 and 7, and adding 6 and 11's clause.
- [ ] **Step 4: Run** `go test -race ./policy/...`. **Expected:** PASS, including every pre-existing requirement test.

### Task 2.4: Per-request re-matching

**Files:**
- Test: `policy/mfarequirement_federated_test.go` (a second table)
- Modify: `policy/mfarequirement.go` (only if the table fails for a reason 2.3 did not cover)

**Interfaces:**
- Consumes: 2.3's order, where step 6 runs in both phases.

- [ ] **Step 1: Write the failing table** `TestMFARequirementPolicy_FederatedPerRequest`. Each row uses the per-request phase, a session with `FirstFactor: factor.OIDC`, and the evidence minted from the session's values:
  - **tightened:** the source now answers not met, and the user is enrolled on TOTP. Expect Challenge MFA.
  - **removed provider:** the source answers not met. Expect Challenge MFA.
  - **satisfied locally:** `MFASatisfied: true`. Expect Allow, with the source `.Times(0)`.
  - **Review Focus 1, tightened with no enrolment and the path off:** expect Deny `ErrMFAEnrollmentRequired`.
- [ ] **Step 2: Run** `go test -run TestMFARequirementPolicy_FederatedPerRequest -count=1 ./policy/`. If every row already passes, prove the rows test something: invert step 5 temporarily (drop the `MFASatisfied` check) and watch "satisfied locally" fail. Then restore it and record both runs.
- [ ] **Step 3: Implement** only what fails.
- [ ] **Step 4: Run** `go test -race ./policy/...`. **Expected:** PASS.

### Task 2.5: The challenge policy

**Files:**
- Modify: `policy/mfa.go` (`mfaPolicy` fields, `WithFederatedChallengeWhenUnmet`, `NewMFAPolicy` check, `Evaluate`)
- Modify: the passkey proof godoc on `policy.Input.SecondFactorAtLogin`, adding "federated evidence is never this proof"
- Test: `policy/mfa_federated_test.go`

**Interfaces:**
- Produces:

```go
func WithFederatedChallengeWhenUnmet(on bool) MFAOption // default false; true without WithFederatedAssuranceSource → ErrConfig
```

- `Evaluate`: after the satisfied, proof and exempt allows, add:

```go
if in.FirstFactor.Channel() == factor.Federated {
	if !p.challengeUnmetFederated {
		return Decision{Outcome: Allow}
	}
	met, err := federatedMet(ctx, p.source, in)
	if err != nil {
		return Decision{Outcome: Deny, Reason: diag.Wrap(err, "policy: whether the provider's assurance is met could not be decided")}
	}
	if met {
		return Decision{Outcome: Allow}
	}
}
```

- [ ] **Step 1: Write the failing table** `TestMFAPolicy_Federated`:
  - default, OIDC, enrolled on TOTP: Allow, and the lookups `.Times(0)`;
  - opt-in and not met: Challenge MFA;
  - opt-in and met: Allow;
  - opt-in without a source: construction `ErrConfig`;
  - opt-in with a source error: Deny wrapping it;
  - a passkey proof plus OIDC evidence: the proof decides, and the evidence is not consulted.
- [ ] **Step 2: Run** `go test -run TestMFAPolicy_Federated -count=1 ./policy/`. **Expected:** after 2.1 the default row fails (it challenges, because OIDC is no longer exempt), and so do the opt-in rows.
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run** `go test -race ./policy/...`. **Expected:** PASS.

### Task 2.6: Godoc and the status mapping

**Files:**
- Modify: `policy/mfarequirement.go`, `policy/mfa.go`, `policy/federated.go` (godoc)
- Modify: `httpsec/status.go` (map `policy.ErrFederatedAssuranceNotMet` to 403 beside the other MFA policy errors, around lines 73–77), `httpsec/status_test.go`

- [ ] **Step 1: Write the failing row** in the status table test: `policy.ErrFederatedAssuranceNotMet` maps to 403.
- [ ] **Step 2: Run** `go test -run TestStatus -count=1 ./httpsec/`. **Expected:** FAIL, mapped to 500.
- [ ] **Step 3: Implement** the mapping. Write the godoc:
  - `WithFederatedAssurance` names the default (Challenge) and states that Exempt "lets a required user in on the provider's word alone, whatever it asserted".
  - `WithMFAExemption` states that marking `oidc` exempt equals `FederatedAssuranceExempt`.
  - `NewMFARequirementPolicy` lists the new defaults.
- [ ] **Step 4: Run** `go test -race ./httpsec/... ./policy/...` and `go doc ./policy WithFederatedAssurance`. **Expected:** PASS, and the doc names the default.

### Task 3.1: Session fields

**Files:**
- Modify: `session/session.go` (fields and `clone`), `session/options.go` (`WithFederatedAssurance`), `session/memory.go` (copy on save and load)
- Test: `session/federated_test.go`

**Interfaces:**
- Produces:

```go
// Session gains, library-owned:
FederatedAMR []string
FederatedACR string
func WithFederatedAssurance(amr []string, acr string) CreateOption // clones amr
```

- [ ] **Step 1: Write the failing table** `TestFederatedAssurance`:
  - **recorded at creation:** one store write (count with the existing write-counting store wrapper in `session` tests); the loaded values are equal; `MFA == MFANone`; `!MFAAtFirstFactor`;
  - **rotation keeps them:** rotate after setting `MFASatisfied`; the values are equal on the rotated session;
  - **Review Focus 4:** after rotation, `rotated.FederatedAMR[0] = "x"` leaves the original's value unchanged;
  - **consumer data cannot forge:** `Data["amr"] = []any{"mfa"}`; `FederatedAMR` is empty;
  - **not recorded:** a session created without the option reports an empty `amr` and `acr`.
- [ ] **Step 2: Run** `go test -run TestFederatedAssurance -count=1 ./session/`. **Expected:** with the fields and an empty option body, the creation and rotation rows fail on empty values, and the aliasing row fails once the option assigns without cloning.
- [ ] **Step 3: Implement.** Use `slices.Clone` in the option and in `clone`, and in the memory store's copy.
- [ ] **Step 4: Run** `go test -race ./session/...` and `go build ./...` in every module. **Expected:** PASS.

### Task 4.1: Per-provider configuration

**Files:**
- Create: `oidc/assurance.go`, `oidc/assurance_test.go`
- Modify: `oidc/options_manager.go` (`WithProviderAssurance`), `oidc/manager.go` (`NewManager` checks, a resolved `map[string]Assurance`)

**Interfaces:**
- Produces:

```go
type AssuranceMatch int
const (
	MatchAny AssuranceMatch = iota
	MatchAll
)
type Assurance struct {
	AcceptedAMR []string
	AcceptedACR []string
	RequestACR  []string
	Match       AssuranceMatch
}
func WithProviderAssurance(provider string, a Assurance) ManagerOption
func (m *Manager) assuranceFor(provider string) (Assurance, bool)    // configured or default; false for an unregistered provider
func matchAssurance(a Assurance, amr []string, acr string) bool       // unexported, pure
```

- **Matching rule:**
  - The `amr` criterion holds when any asserted value is in `AcceptedAMR`. The `acr` criterion holds when the asserted `acr` is non-empty and in `AcceptedACR`.
  - A criterion with an empty accepted set is "not configured": under `MatchAny` it cannot hold, and under `MatchAll` it is skipped.
  - `MatchAll` with both sets empty never holds.
- **Default** (no option): `Assurance{AcceptedAMR: []string{"mfa"}}`. A provider configured with an empty `AcceptedAMR` keeps it empty, which is the comma-ok distinction: the default applies only when the map has no entry.

- [ ] **Step 1: Write the failing table** `TestMatchAssurance`, one row per scenario of ADDED "Each provider has an assurance configuration with a safe default":
  - default with `["pwd","otp"]`: false;
  - default with `["pwd","mfa"]`: true;
  - `acr` accepted and asserted: true;
  - `["MFA"]`: false;
  - `MatchAll` with `["mfa"]` and `silver`: false;
  - empty sets with `["mfa"]`: false.

  Add `TestNewManager_AssuranceConfig`:
  - an unknown provider: `ErrConfig` naming `corpp`;
  - `"mfa"` and `""` in a list: `ErrConfig`;
  - `Match: 7`: `ErrConfig`;
  - `RequestACR` with no `AcceptedACR`: valid.
- [ ] **Step 2: Run** `go test -run 'TestMatchAssurance|TestNewManager_AssuranceConfig' -count=1 ./oidc/`. **Expected:** with `matchAssurance` returning false and no checks, the true rows and every error row fail.
- [ ] **Step 3: Implement.** The godoc on `AcceptedAMR` explains RFC 8176 `mfa` versus single-method values. `WithProviderAssurance` names the default it replaces.
- [ ] **Step 4: Run** `go test -race ./oidc/...`. **Expected:** PASS.

### Task 4.2: Claim extraction

**Files:**
- Modify: `oidc/verify.go` (`idClaims` gains `AMR []string`, `ACR string`, `malformedAMR`, `malformedACR bool`; read after the subject check)
- Modify: `oidc/callback.go` (one sampled warning per malformed claim, through `logCallbackRefusal`'s sampler, with key `oidc.callback:malformed-assurance-claim:<provider>`, no error text and no value)
- Test: `oidc/verify_assurance_test.go`

**Interfaces:**
- Produces: `func readAssurance(tok jwt.Token) (amr []string, acr string, badAMR, badACR bool)`, unexported.

- [ ] **Step 1: Write the failing table** `TestReadAssurance`. Sign tokens with the existing test signer in `oidc` tests:
  - absent;
  - `[]`;
  - `["pwd","mfa","mfa"]` → `["pwd","mfa"]`;
  - `"mfa"` (string): bad;
  - **Review Focus 2:** `["mfa", 1]`: bad, nothing asserted;
  - `acr` `""`: not asserted and not bad;
  - `acr` `2`: bad;
  - `acr` `"urn:corp:loa:2"`.

  Add a callback test: a malformed `amr` leaves the login successful with empty `AMR`, and the captured log record has `provider=corp`, `claim=amr` and no `mfa` substring anywhere in the record.
- [ ] **Step 2: Run** `go test -run 'TestReadAssurance|TestCallback_MalformedAssurance' -count=1 ./oidc/`. **Expected:** with a stub returning zero values, the asserted rows and the warning test fail.
- [ ] **Step 3: Implement.** Use `tok.Field("amr")`. The decoded type from jwx is `[]any` (confirm with a test print, then delete it). Every element must be a `string`, or the whole claim is bad.
- [ ] **Step 4: Run** `go test -race ./oidc/...`. **Expected:** PASS.

### Task 4.3: `acr_values` on the authorize URL

**Files:**
- Modify: `oidc/authorize.go:73-82`
- Test: `oidc/authorize_test.go` (new rows)

- [ ] **Step 1: Write the failing rows:**
  - configured `["urn:corp:loa:2","urn:corp:loa:3"]`: `q.Get("acr_values") == "urn:corp:loa:2 urn:corp:loa:3"`;
  - unconfigured: `!q.Has("acr_values")`.
- [ ] **Step 2: Run** `go test -run TestAuthorize -count=1 ./oidc/`. **Expected:** the configured row fails.
- [ ] **Step 3: Implement.** `if a, _ := m.assuranceFor(p.Name); len(a.RequestACR) > 0 { q.Set("acr_values", strings.Join(a.RequestACR, " ")) }`.
- [ ] **Step 4: Run** `go test -race ./oidc/...`. **Expected:** PASS.

### Task 4.4: Records, results and the redemption candidate

**Files:**
- Modify: `oidc/ports.go` (`CallbackResult`, `HandoffRecord` fields), `oidc/handoff.go` (`Issue` writes them; `RedeemCandidate`; `RedeemCheck`; `HandoffResult`; `Redeem` passes the candidate), `oidc/callback.go` (fills `CallbackResult.AMR/ACR`), `oidc/handoffstore_memory.go` (clone on insert and find)
- Modify (signature move only): `httpsec/redemption.go` (`redemptionPolicyCheck`'s closure takes `oidc.RedeemCandidate`), `httpsec/oidc_redeem.go`, and every other `RedeemCheck` caller gopls finds
- Test: `oidc/handoff_assurance_test.go`

**Interfaces:**
- Produces:

```go
type RedeemCandidate struct {
	Principal         identity.Principal
	PasswordChangedAt time.Time
	Provider, Issuer  string
	AMR               []string // a copy
	ACR               string
}
type RedeemCheck func(ctx context.Context, c RedeemCandidate) error
// HandoffRecord, HandoffResult and CallbackResult gain: AMR []string; ACR string
```

- [ ] **Step 1: Write the failing tests:**
  - **issue then find:** the record carries `AMR ["pwd","mfa"]` and `ACR "urn:corp:loa:2"`;
  - **the check receives** the record's provider, issuer, `AMR` and `ACR`;
  - **the result carries** the same values;
  - **a copy:** mutating the check's `AMR` does not change the result's.
- [ ] **Step 2: Run** `go test -run TestHandoff_Assurance -count=1 ./oidc/`. **Expected:** with the fields declared and not written, the equality assertions fail.
- [ ] **Step 3: Implement.** Move `httpsec`'s closure to the new signature, reading `c.Principal` and `c.PasswordChangedAt`, with no other behaviour change. Godoc on `CallbackResult.AMR`: "a consumer whose callback success handler creates the session records these with `session.WithFederatedAssurance`, or the session carries no assurance and required users are challenged or refused".
- [ ] **Step 4: Run** `go test -race ./oidc/... ./httpsec/...` and `go build ./...` in every module. **Expected:** PASS.

### Task 4.5: The manager as assurance source, and the evaluator

**Files:**
- Create: `oidc/assurance_source.go`, `oidc/assurance_source_test.go`
- Modify: `oidc/options_manager.go` (`WithAssuranceEvaluator`)

**Interfaces:**
- Consumes: `policy.FederatedAssuranceSource`, `policy.FederatedAssurance` (2.2).
- Produces:

```go
type AssuranceInput struct {
	User             identity.UserID
	Provider, Issuer string
	AMR              []string
	ACR              string
}
type AssuranceEvaluator interface {
	MeetsAssurance(ctx context.Context, in AssuranceInput) (bool, error)
}
func WithAssuranceEvaluator(e AssuranceEvaluator) ManagerOption // nil, typed nil included → ErrConfig
func (m *Manager) MeetsAssurance(ctx context.Context, user identity.UserID, ev policy.FederatedAssurance) (bool, error)
var _ policy.FederatedAssuranceSource = (*Manager)(nil)
```

- `MeetsAssurance`:
  - an unregistered provider, or an issuer different from the registered one, is `false, nil`;
  - with an evaluator, its answer and error are returned unchanged;
  - otherwise `matchAssurance` decides.
- The evaluator mock is placed per `use-mockgen`, consumed by `oidc_test`.

- [ ] **Step 1: Write the failing table** `TestManager_MeetsAssurance`:
  - every 4.1 matching scenario, run through `MeetsAssurance`;
  - an unknown provider: false;
  - a wrong issuer: false;
  - the evaluator's per-user rule: `u-1` not met without `hwk`;
  - the evaluator's error returned unchanged (`errors.Is`);
  - zero evidence: false, with the evaluator `.Times(0)`.
- [ ] **Step 2: Run** `go test -run TestManager_MeetsAssurance -count=1 ./oidc/`. **Expected:** with a stub returning `false, nil`, the met rows and the error row fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./oidc/...`. **Expected:** PASS.

### Task 5.1: The migration

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (`sessions` and `oidc_handoffs` columns, and their down section if it lists columns)
- Test: `test/migrate_securitystate_test.go`

- [ ] **Step 1: Write the failing test.** For PostgreSQL 15 and 18 through the existing helper, assert:
  - `sessions.federated_amr` is `jsonb NOT NULL DEFAULT '[]'::jsonb`;
  - `sessions.federated_acr` is `text NOT NULL DEFAULT ''::text`;
  - `oidc_handoffs.amr` and `oidc_handoffs.acr` likewise.
- [ ] **Step 2: Run** `go test -run TestSecurityStateMigration -count=1 ./...` in `test`. **Expected:** FAIL, the columns are missing.
- [ ] **Step 3: Implement** the DDL in place.
- [ ] **Step 4: Run** the same command, then `go test -race ./...` in `test`. **Expected:** PASS. Full rollback still leaves nothing behind.

### Task 5.2: Drivers and suites

**Files:**
- Modify: `internal/pgschema/sessions.go` (the positional list at lines 13–41), `internal/pgschema/oidc.go` (lines 43–60), `sqlstore`, `pgx` and `gorm` session and handoff stores, `gorm/models.go` (`sessionRow`, `handoffRow`)
- Test: `test/storetest/session_suite.go` (fixture `federatedSession` at :63 gains values; `assertSession` compares them), `test/oidc/handoffstore_suite.go` (`handoffSuiteRecord` at :49 and `assertHandoffRecord` at :69), `test/crossbackend/**`

- [ ] **Step 1: Write the failing suite cases:**
  - **handoff round trip:** `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2`;
  - **session round trip:** `["mfa"]` and `urn:corp:loa:2`;
  - **nothing asserted:** a password session loads with an empty `amr` (compare with `assert.Empty`, so nil and empty are both accepted) and `""`;
  - a crossbackend case for each round trip.
- [ ] **Step 2: Run** `go test -race -count=1 ./...` in `test`. **Expected:** the in-memory stores pass after 3.1 and 4.4, and every SQL backend fails on empty values.
- [ ] **Step 3: Implement.** Encode `amr` with `encoding/json`, as the `scopes` column does in `internal/pgschema/apikeys.go`.
- [ ] **Step 4: Run** `go test -race ./...` in `test`, `pgx` and `gorm`. **Expected:** PASS.

### Task 6.1: Completion and per-request evidence

**Files:**
- Modify: `httpsec/logincomplete.go` (`loginTailDeps` or `postAuthenticationInput` gains the evidence; `completeLogin` passes `session.WithFederatedAssurance`), `httpsec/bearer.go:142-151` (mint from the session when `s.FirstFactor.Channel() == factor.Federated`)
- Create: `httpsec/federated.go` (`mintFederated(provider, issuer string, amr []string, acr string) policy.FederatedAssurance`, the only call to `assurance.NewFederated` in `httpsec`)
- Test: `httpsec/federated_completion_test.go`

- [ ] **Step 1: Write the failing tests:**
  - **at login:** a required user enrolled on nothing, evidence `["mfa"]`, and a source that accepts `mfa`. The token is returned without a challenge, and the session has `FederatedAMR ["mfa"]` and `MFA == MFANone`.
  - **per request:** a federated session holding `["mfa"]` reaches the handler. After the source is switched to not met, the next request is marked for the MFA challenge.
- [ ] **Step 2: Run** `go test -run TestFederatedCompletion -count=1 ./httpsec/`. **Expected:** the login row fails on enrolment-required, because no evidence reaches policy, and the per-request row is challenged.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.

### Task 6.2: Redemption

**Files:**
- Modify: `httpsec/redemption.go` (mint the evidence from `RedeemCandidate` in the check; keep the candidate's values on `policyOutcome`; `guardRedemption` compares provider, issuer, `amr` and `acr`), `httpsec/oidc_redeem.go` (pass the result's values to completion)
- Test: `httpsec/oidc_assurance_test.go` (the 1.1 test, committed here as the red step, plus the rows below)

- [ ] **Step 1: Write the failing tests**, one row per oidc-login scenario covered by 6.2, end to end through the `net/http` chain:
  - `TestOIDCRedeem_RequiredUserWithoutAssuranceIsRefused` from 1.1, unchanged;
  - "Challenge redeems";
  - "A policy lookup failure does not spend the code";
  - "Session carries the asserted assurance";
  - "Value presented at redemption is ignored": the body carries `"amr":["mfa"]`, and the outcome is the same as without it;
  - "Evaluator failure denies": the code is not consumed;
  - refuse mode: a refused valid code is counted against the source (11th request throttled);
  - **Review Focus 3:** a consumer redeemer returning `AMR ["mfa"]` where the check saw none is refused with `policy.ErrPolicyDenied`, and no session is created.
- [ ] **Step 2: Run** `go test -run 'TestOIDCRedeem_' -count=1 ./httpsec/`. **Expected:** the 1.1 test fails exactly as recorded in 1.1 if 2.x has not landed, and otherwise fails because no evidence reaches the check (the challenge and met rows). The Review Focus 3 row fails because the guard does not compare.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.

### Task 6.3: The callback success handler

**Files:**
- Modify: `httpsec/oidc_callback.go` (no code change is expected, because `CallbackResult` already carries the values after 4.4)
- Test: `httpsec/oidc_callback_test.go` (new row)

- [ ] **Step 1: Write the failing row:** a handler receives `res.AMR == ["mfa"]` for a token asserting it.
- [ ] **Step 2: Run** `go test -run TestOIDCCallback -count=1 ./httpsec/`. If it passes at once, prove it: blank `AMR` in `callback.go` temporarily, watch it fail, restore, and record both runs.
- [ ] **Step 3: Implement** only what fails.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.

### Task 6.4: Assembly refuses an unwired source

**Files:**
- Modify: `policy/federated.go` (`FederatedAssuranceUser` interface), `policy/mfarequirement.go` and `policy/mfa.go` (implement it), `policy/engine.go` (`UnwiredFederatedAssurance() []string`, mirroring `DeclaredChallenges`)
- Modify: `httpsec/oidc_options.go` (`oidcInterceptor.check` at :134 calls it when OIDC login is enabled)
- Test: `httpsec/oidc_options_test.go`, `policy/engine_test.go`

**Interfaces:**
- Produces:

```go
type FederatedAssuranceUser interface {
	// NeedsFederatedAssuranceSource reports whether the policy decides federated
	// logins on provider assurance and was given no source.
	NeedsFederatedAssuranceSource() bool
}
func (e *Engine) UnwiredFederatedAssurance() []string // names of such policies
```

- A requirement policy needs a source unless it is in Exempt mode. A challenge policy needs one only with the opt-in on, which construction already refuses without a source.

- [ ] **Step 1: Write the failing tests:**
  - an engine reports `["mfa-requirement"]` for a default requirement policy with no source;
  - a chain with OIDC login and that engine fails with `ErrConfig`, naming the policy;
  - the same chain with `WithFederatedAssuranceSource(manager)` assembles;
  - a chain without OIDC login assembles with the unwired policy.
- [ ] **Step 2: Run** `go test -run 'TestUnwiredFederatedAssurance|TestOIDCOptions_AssuranceSource' -count=1 ./policy/ ./httpsec/`. **Expected:** FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./policy/... ./httpsec/...`. **Expected:** PASS.

### Task 6.5: Re-matching end to end

**Files:**
- Test: `httpsec/oidc_assurance_test.go` (`TestFederatedRematch`)

- [ ] **Step 1: Write the table** over the three ADDED security-policy scenarios ("Provider configuration tightened", "Provider removed", "Locally satisfied session"). Each row builds a real `oidc.Manager` (registry with `corp`) as the source, redeems a code asserting `["mfa"]`, then:
  - **tightened:** rebuilds the manager with `AcceptedAMR: ["hwk"]` and swaps it in through the test's source indirection;
  - **removed:** registers a manager without `corp`;
  - **locally satisfied:** resolves the challenge through the verify endpoint.

  The next request's outcome is asserted.
- [ ] **Step 2: Run** `go test -run TestFederatedRematch -count=1 ./httpsec/`. **Expected:** if it passes at once, invert the per-request mint in `bearer.go` temporarily (pass zero evidence), watch "tightened" stay challenged but the baseline met request fail, then restore and record both runs.
- [ ] **Step 3: Implement** only what fails.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.

### Task 7.1: The way-back check

**Files:**
- Create: `policy/admission.go`, `policy/admission_test.go`
- Modify: `policy/mfarequirement.go` (implement `LoginAdmission`), `recovery/wayback.go` (`WayBackDeps.Admits` replaces `Exempt`; `HasWayBack` asks it per linked kind), `recovery/wayback_test.go`

**Interfaces:**
- Produces:

```go
package policy
type LoginAdmission interface {
	// AdmitsWithoutLocalSecondFactor reports whether a login of kind for user would be
	// admitted without a local second factor whatever its provider asserts.
	AdmitsWithoutLocalSecondFactor(ctx context.Context, user identity.UserID, kind factor.Kind) (bool, error)
}

package recovery
// WayBackDeps: Exempt is removed, and gains:
Admits func(ctx context.Context, user identity.UserID, kind factor.Kind) (bool, error) // nil → kind.MFAExempt()
```

- **Requirement policy answer**, in order:
  1. the exemption rule marks the kind: true;
  2. a federated kind in Exempt mode: true;
  3. look up the requirement: on error, return it; not required: true;
  4. otherwise false.

- [ ] **Step 1: Write the failing tables.** `TestAdmitsWithoutLocalSecondFactor`:
  - exempt mode: true;
  - a rule marking OIDC: true;
  - not required: true;
  - required and default: false;
  - lookup error: error.

  `TestHasWayBack_LinkedProvider`, one row per MODIFIED account-recovery scenario:
  - "Linked provider under the default exemption", meaning exempt mode: yes;
  - "required user, default mode": no;
  - "user not required": yes;
  - "Requirement lookup failure": error;
  - no `Admits` with an OIDC link: no.
- [ ] **Step 2: Run** `go test -run 'TestAdmitsWithoutLocalSecondFactor|TestHasWayBack_LinkedProvider' -count=1 ./policy/ ./recovery/`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** The `Admits` godoc tells the consumer to pass the requirement policy's method: `adm, _ := reqPolicy.(policy.LoginAdmission); deps.Admits = adm.AdmitsWithoutLocalSecondFactor`.
- [ ] **Step 4: Run** `go test -race ./recovery/... ./policy/...` and `go build ./...` in every module. **Expected:** PASS.

### Task 8.1: Documentation

**Files:**
- Modify: `README.md` (OIDC section)
- Create: `oidc/example_test.go` (`ExampleWithProviderAssurance`, `ExampleWithAssuranceEvaluator`), `policy/example_test.go` (`ExampleWithFederatedAssurance`)

- [ ] **Step 1: Write the examples first** with `// Output:` lines. Each one prints the outcome of matching or of a policy decision, so it fails until it compiles and runs correctly.
- [ ] **Step 2: Run** `go test -run Example -count=1 ./oidc/ ./policy/`. **Expected:** FAIL until the output matches.
- [ ] **Step 3: Write** the README section:
  - the default (`mfa` only) and the Challenge mode;
  - how to choose Refuse or Exempt, and what Exempt gives up;
  - `acr_values` is a request, not evidence;
  - the evaluator for per-user rules;
  - the freshness limit;
  - required users of providers without `amr` must enrol locally, or OIDC must be admitted to the enrolment path;
  - the callback success handler must pass the values on.

  Every code sample is one of the compiled examples.
- [ ] **Step 4: Run** `go test ./...` and `go vet ./...`. **Expected:** PASS.

### Task 8.2: Adapter parity

**Files:**
- Test: the existing parity tests in `ginsec` and `fibersec` (find them with gopls `references` on the `net/http` parity helper)

- [ ] **Step 1: Add rows** for met, unmet-challenge and refuse redemptions, and for a per-request challenge after tightening, comparing status, headers and body with `net/http`.
- [ ] **Step 2: Run** `go test -race ./...` in `ginsec` and `fibersec`. **Expected:** the rows fail only if an adapter maps `ErrFederatedAssuranceNotMet` differently. If every row passes at once, mutate the `net/http` side's expected status for one row in the test, watch it fail, restore it, and record both runs.
- [ ] **Step 3: Fix** only what fails.
- [ ] **Step 4: Run** the same commands. **Expected:** PASS.

### Task 8.3: Close out (main session)

- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` (empty) and `go test -race ./...` in every workspace module.
- [ ] `openspec validate oidc-mfa-assurance --strict`: no errors. The `security-policy` "not found" note must be gone now that passkey is archived.
- [ ] A whole-branch review by a fresh agent against every requirement in `specs/`, with defect claims labelled per `defect-claims.md`.
- [ ] Tick the tasks in `tasks.md` and commit.
