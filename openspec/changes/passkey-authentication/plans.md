# passkey-authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Passkeys (WebAuthn) for scrty: registration and management, passwordless login with a user-verified passkey meeting both factors, the passkey as an MFA challenge method, clone suspension, attestation off by default, and recovery integration, including registration from enrolment-only and recovery-pending sessions.

**Architecture:**
- A new core package, `passkey`, owns:
  - the ceremonies (`Manager`), the credential and handle store ports with in-memory defaults;
  - pending reasons, clone handling and notices;
  - the MFA method and the recovery kind.
- WebAuthn parsing and verification sit behind one port, `passkey.Verifier`, implemented in the nested module `github.com/kartaladev/scrty/passkey/webauthn` over `github.com/go-webauthn/webauthn` v0.18.2. Its test-double package `passkey/webauthn/webauthntest` is a software authenticator.
- `internal/assurance` mints the one proof that a login's second factor was met at the first. `policy` honours it, and `httpsec.completeLogin` records it on the session in its creating write.
- `httpsec` parses, gates and responds:
  - authenticated endpoints at `OrderPasskeys` (660);
  - passwordless login at `OrderPasskeyLogin` (380).
- The durable stores are `sqlstore`, `pgx` and `gorm`, over shared SQL in `internal/pgschema`. The tables are added in place to the security-state migration.

**Tech Stack:** Go 1.27 (module floor 1.26), go-webauthn v0.18.2 (adapter module only), `onetime`, `ratelimit`, `notify`, `seal`, `outbound`, `pkg/clock` with clockwork fakes in tests, testify, mockgen (`use-mockgen`), testcontainers PostgreSQL (`use-testcontainers`, the `test` module), gopls.

**Spec:** `openspec/changes/passkey-authentication/`:
- `proposal.md`;
- `design.md` (D1–D20);
- `specs/passkey-authentication`, `specs/identity-model`, `specs/sessions`, `specs/security-policy`, `specs/multi-factor-auth`, `specs/http-security-chain`, `specs/http-error-propagation`, `specs/account-recovery`, `specs/security-state-stores`, `specs/schema-migrations`, `specs/store-conformance`, `specs/module-layout`, `specs/rate-limiting`, `specs/email-notification`;
- `tasks.md`.

Task numbers below (`1.1`…`9.3`) are `tasks.md`'s.

## Global Constraints

- **Vocabulary:** kind `factor.Passkey = "passkey"`, channel `factor.PublicKey = "public-key"`, not exempt. MFA method name `passkey`.
- **One-time purposes:**
  - `passkey-registration`: subject the user reference, binding the session handle;
  - `passkey-login`: subject the constant `"passkey-login"`, binding the 32-byte ceremony cookie value, base64url-encoded;
  - the MFA slot's own purpose, unchanged.
- **The challenge** is the token string's UTF-8 bytes, and `clientDataJSON.challenge` is their base64url (RawURLEncoding) form.
- **Defaults:**
  - challenge TTL 5 minutes;
  - registration issuance 10 per hour;
  - passkey limit 25 per user;
  - management freshness 15 minutes;
  - user verification `required`;
  - resident key `required`;
  - attestation `none`;
  - clone response: refuse and suspend;
  - passwordless off; passwordless begin source guard 30 per 15 minutes, flow `passkey-login`;
  - emailed code: 6 digits, 10 minutes, 5 attempts;
  - user handle: 64 random bytes;
  - body caps: 64 KiB for registration, 16 KiB for an assertion;
  - default name `Passkey <YYYY-MM-DD>`; names trimmed, at most 64 characters, no control characters.
- **Default paths:**
  - `/passkey/register/{begin,finish,confirm,confirm-email}`;
  - `/passkey/credentials` (GET), `/passkey/credentials/{rename,remove}`;
  - `/passkey/login/{begin,finish}`;
  - the MFA slot's `/mfa/begin/passkey` and `/mfa/verify/passkey`.
- **Ceremony cookie:** `passkey_ceremony`; `HttpOnly; Secure; SameSite=Strict; Path=<finish path>; Max-Age=<TTL seconds>`. It is cleared (`Max-Age=0`, same path) on every finish response.
- **Sentinels** (`passkey/errors.go`), each wrapping and mapping as below:

  | Sentinel | Wraps | Status |
  |---|---|---|
  | `ErrConfig` | — | — |
  | `ErrCloneSuspected` | `mfa.ErrAuthenticatorRefused` | 403 |
  | `ErrSuspended` | `mfa.ErrAuthenticatorRefused` | 403 |
  | `ErrPending` | — | 403 |
  | `ErrAttestationRefused` | — | 403 |
  | `ErrLimitReached` | — | 403 |
  | `ErrReauthenticationRequired` | — | 403 |
  | `ErrNotFound` | — | 404 |
  | `ErrRegistrationThrottled` | `ratelimit.ErrThrottled` | 401 |
  | `ErrMalformedResponse` | — | 401: an unreadable ceremony response; `httpsec` maps it to `ErrCredentialsMissing` (there is no core `authenticate.ErrMissingCredentials`) |
  | `ErrDuplicateCredential` (store) | — | — (finish maps it to `authenticate.ErrAuthenticationFailed`) |

  A refused ceremony is `authenticate.ErrAuthenticationFailed`, or `mfa.ErrInvalidCode` as a second factor. `mfa.ErrAuthenticatorRefused` maps to 403 by itself.
- **The core module** must not require `github.com/go-webauthn/webauthn`, `github.com/fxamacker/cbor` or `github.com/google/go-tpm`. No exported identifier of `passkey/webauthn` refers to a go-webauthn type.
- **Logs:** no log record or error text carries a challenge, emailed or saved code, user handle, public key, attestation statement, credential ID or contact address. A credential is named only by its library `id.ID`.
- **Godoc:** every option names the default it replaces (`library-design.md`). Every in-memory default states its single-process limit.
- **Test-first** (`golang-tdd.md`): red for the intended reason, where a compile error is not red. Tables follow `table-test` (the `assert` closure, `t.Context()`). Mocks come from mockgen per `use-mockgen`. PostgreSQL comes through the `test` module's helper per `use-testcontainers`. Nothing outside `test/` imports `test`.
- **No git command that discards work. No edit under `openspec/`.** The legacy reference has no WebAuthn; do not consult or cite it for this change.

## Review Focus

1. **A finish body whose `clientDataJSON.challenge` decodes to a token string with a different purpose's prefix,** for example a registration challenge replayed at the passwordless finish. Expected: `authenticate.ErrAuthenticationFailed`, with no credential lookup and no counter write. Pinned in 4.5.
2. **The same authenticator answering two concurrent passwordless begins** with the same next counter, from two tabs. Expected: one login, and one `ErrCloneSuspected` with suspension. This is the spec's choice, and the test documents it so it is not "fixed" later. Pinned in 3.2 (store) and 4.6 (manager).
3. **A registration finish whose response `name` is 200 characters or contains `\n`.** Expected: stored with the default date name, never truncated mid-rune and never refused. Pinned in 4.2.
4. **A recovery-pending session that registers a passkey which lands pending, awaiting saved codes, and then expires before confirming.** Expected: the credential stays pending and unusable, and a later full session's registration deletes and replaces it. Pinned in 4.3.
5. **A passwordless finish posted with two `passkey_ceremony` cookies** (path shadowing). Expected: refused as authentication failed unless the first matching cookie binds. The library reads `Request.Cookie(name)` only, so it never tries each value in turn. Pinned in 8.5.

---

## Dispatch map

Lanes run in parallel where they own disjoint files and compile independently. Within a lane, dispatches run in order. After each dispatch, the main session runs the verification commands and a fresh reviewer checks the dispatch against its spec requirements (`subagent-delegation.md`).

| Dispatch | Tasks | Owns | Must not touch | Starts after | Model | Why |
|---|---|---|---|---|---|---|
| A1 | 1.1–1.3 | `factor/**`, `internal/assurance/**`, `policy/policy.go`, `policy/mfa.go`, `policy/mfarequirement.go`, their tests, `session/**` | `httpsec/**`, `passkey/**`, drivers | — | Opus | Security-critical proof semantics other lanes compile against |
| B1 | 2.1–2.2 | `mfa/errors` (new sentinel in `mfa/mfa.go`), `httpsec/mfaverify.go` and its tests, `recovery/reset.go`, `recovery/wayback.go`, their tests | `policy/**`, `session/**`, `passkey/**` | — (parallel with A1) | Opus | Throttle counting and fail-closed way-back logic |
| C1 | 3.1–3.3 | `passkey/{doc,errors,types,relyingparty,verifier,store,memstore,handles}*.go` and tests | everything outside `passkey/` | A1, B1 | Opus | Conditional-write contracts later drivers must match |
| D1 | 6.1–6.2 | `passkey/webauthn/go.mod`, `go.sum`, `passkey/webauthn/webauthntest/**`, `go.work`, `layout_guard_test.go`, `layout_test.go` | `passkey/*.go` | C1 (parallel with C2) | Opus | CBOR and COSE encoding by hand, module plumbing |
| C2 | 4.1–4.3 | `passkey/{manager,options,register,pending}*.go` and tests | `passkey/webauthn/**` | C1 | Opus | Admission (AAL, freshness), check-order, pending reasons |
| E1 | 7.1–7.2 | `migrate/securitystate/*.sql`, `internal/pgschema/sessions.go`, `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`, `gorm/models.go`, `test/migrate_securitystate_test.go`, `test/storetest/session_suite.go`, `test/crossbackend/**` | `passkey/**`, `httpsec/**` | A1 (parallel with C1) | Sonnet | Column threading along an existing pattern; the passkey tables' DDL is fully given here |
| F1 | 8.1 | `httpsec/logincomplete.go` and its tests | everything else | A1 (parallel with C1) | Opus | Login tail ordering of proof versus challenge marks |
| D2 | 6.3–6.4 | `passkey/webauthn/*.go` and tests | `passkey/*.go` | C1, D1 | Opus | Verification and attestation trust decisions |
| C3 | 4.4–4.6 | `passkey/{messages,login,clone,logs}*.go` and tests | `passkey/webauthn/**` | C2 | Opus | Clone rule, proof minting, uniform refusals |
| E2 | 7.3–7.5 | `internal/pgschema/passkey*.go`, `seal/aad.go` (append `PasskeyEmailCodeAAD`), `sqlstore/passkey*.go`, `pgx/passkey*.go`, `gorm/passkey*.go`, `gorm/models.go` (append only), `test/storetest/passkey*`, `test/storetest/memory_test.go` (append only), `test/storetest/broken_passkey_test.go`, `test/internal/storefix/passkey.go`, `test/{sqlstore,pgxstore,gormstore}/passkey*_test.go`, `test/crossbackend/**` (append only) | `passkey/**` | C1, E1 | Opus | Conditional SQL, sealing, races on three drivers |
| C4 | 5.1–5.3 | `passkey/{mfamethod,recoverykind,manage}*.go` and tests | `passkey/webauthn/**` | C3 | Opus | MFA contract and reset semantics |
| F2 | 8.2–8.3 | `httpsec/passkey{,register,confirm,options}*.go`, `httpsec/order.go`, `httpsec/mfaenrol.go`, `httpsec/mfaenroloptions.go`, `httpsec/recoverygate.go`, `httpsec/recoveryoptions.go`, `httpsec/options.go`, `policy/enrolmentpath_test.go` (scenario only), their tests | `passkey/**` | C4, D2, F1 | Opus | Gate exemptions and assembly checks across slots |
| F3 | 8.4–8.6 | `httpsec/passkey{manage,login,status}*.go`, `httpsec/status.go`, `httpsec/mfa*.go` tests, `fibersec`/`ginsec` tests if affected | `passkey/**` | F2 | Opus | Cookie binding, unauthenticated writes, status table |
| G1 | 9.1 | `test/httpsecconformance/**`, `test/httpsec_*_test.go`, `test/go.mod` (require the adapter) | everything else | E2, F3 | Sonnet | Scenario plumbing over a finished API |
| G2 | 9.2 | `README.md`, `passkey/example_test.go`, `passkey/webauthn/example_test.go` | everything else | F3 (parallel with G1) | Sonnet | Documentation plus compiled examples |
| — | 9.3 | main session | — | G1, G2 | — | Final gate and whole-branch review |

**Why C is one sequential lane split four ways:** every dispatch writes the `passkey` package. A half-written file would break the next one's `go test`. Each split sits at a seam (stores, registration, login, method and kind) of at most three tasks.

**Why D1 can run beside C2:** D1 only creates the nested module's scaffold and `webauthntest`, which depend on nothing in `passkey` beyond C1's port types.

**Why F1 runs early:** `completeLogin` needs only A1's proof, and `httpsec` is otherwise untouched until F2.

---

### Task 1.1: `factor.Passkey` and `factor.PublicKey`

**Files:**
- Modify: `factor/factor.go` (kinds const block, channels const block, `Channel()`)
- Modify: `factor/export_test.go` (`AllKinds` gains `Passkey`)
- Test: `factor/factor_test.go`

**Interfaces:**
- Produces: `const Passkey Kind = "passkey"`, `const PublicKey Channel = "public-key"`, `Passkey.Channel() == PublicKey`, `Passkey.MFAExempt() == false`.

- [ ] **Step 1: Write the failing test.** Add a row to the kind table in `factor/factor_test.go`:

```go
{
	name: "passkey reports public-key and is not exempt", kind: factor.Passkey,
	assert: func(t *testing.T, k factor.Kind) {
		assert.Equal(t, factor.PublicKey, k.Channel())
		assert.Equal(t, factor.Channel("public-key"), k.Channel())
		assert.False(t, k.MFAExempt())
	},
},
```

- [ ] **Step 2: Run** `go test -run 'TestKind' -count=1 ./factor/...`. **Expected:** with `Passkey` and `PublicKey` declared but `Channel()` unchanged, the test fails on `"" != "public-key"`.
- [ ] **Step 3: Implement.** Add `case Passkey: return PublicKey` to `Channel()`. The godoc of `PublicKey` says "credentials an authenticator holds as a key pair and proves by signing a challenge; also the channel of the passkey second factor". Add `Passkey` to `AllKinds`.
- [ ] **Step 4: Run** `go test -race ./factor/... ./identity/...`. **Expected:** PASS. The `kinds_guard_test.go` vocabulary walk includes the new kind.
- [ ] **Step 5: Commit** `feat(factor): passkey kind and public-key channel`

### Task 1.2: The proof, and both MFA policies honouring it

**Files:**
- Create: `internal/assurance/assurance.go`, `internal/assurance/assurance_test.go`
- Modify: `policy/policy.go` (alias and `Input.SecondFactorAtLogin`)
- Modify: `policy/mfa.go:338-341` (`Evaluate`), `policy/mfarequirement.go` (a step before 6, in post-authentication)
- Test: `policy/proof_test.go`, `policy/export_test.go` (a test-only minting hook, see below)

**Interfaces:**
- Produces:
  ```go
  package assurance
  type Proof struct{ kind factor.Kind; at time.Time }
  func New(kind factor.Kind, at time.Time) Proof // non-empty kind and non-zero at, or the zero Proof
  func (p Proof) Holds() bool                    // kind != "" && !at.IsZero()
  func (p Proof) Kind() factor.Kind
  func (p Proof) At() time.Time

  package policy
  type SecondFactorProof = assurance.Proof
  // Input gains, documented as the only post-authentication second-factor fact a policy honours:
  SecondFactorAtLogin SecondFactorProof
  ```
- Tests outside the core cannot mint. `policy/export_test.go` exposes `MintProofForTest = assurance.New`, which is visible to `policy_test` only.

- [ ] **Step 1: Write the failing tests.** `internal/assurance/assurance_test.go` holds a table over zero, empty kind, zero time and valid. Only valid has `Holds() == true`. `policy/proof_test.go`:

```go
func TestMFAPolicies_HonourSecondFactorProof(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	type testCase struct {
		name   string
		build  func(t *testing.T) policy.Policy
		in     policy.Input
		assert func(t *testing.T, d policy.Decision)
	}
	totpEnrolled := enrolledLookup("totp", factor.AuthenticatorApp, true)  // existing test helper in mfa_test.go
	passkeyOnly := enrolledLookup("passkey", factor.PublicKey, true)
	cases := []testCase{
		{
			name:  "challenge policy allows on a holding proof",
			build: func(t *testing.T) policy.Policy { return mustMFAPolicy(t, totpEnrolled) },
			in:    policy.Input{User: "u-1", FirstFactor: factor.Passkey, SecondFactorAtLogin: policy.MintProofForTest(factor.Passkey, at), Now: at},
			assert: func(t *testing.T, d policy.Decision) { assert.Equal(t, policy.Allow, d.Outcome) },
		},
		{
			name:  "challenge policy challenges on a zero proof",
			build: func(t *testing.T) policy.Policy { return mustMFAPolicy(t, totpEnrolled) },
			in:    policy.Input{User: "u-1", FirstFactor: factor.Passkey, Now: at},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name:  "requirement policy allows a required passkey-only user on the proof in post-authentication",
			build: func(t *testing.T) policy.Policy { return mustRequiredForAll(t, passkeyOnly) },
			in:    policy.Input{User: "u-1", FirstFactor: factor.Passkey, SecondFactorAtLogin: policy.MintProofForTest(factor.Passkey, at), Now: at},
			assert: func(t *testing.T, d policy.Decision) { assert.Equal(t, policy.Allow, d.Outcome) },
		},
		{
			name:  "requirement policy denies the same user without it",
			build: func(t *testing.T) policy.Policy { return mustRequiredForAll(t, passkeyOnly) },
			in:    policy.Input{User: "u-1", FirstFactor: factor.Passkey, Now: at},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
			},
		},
		{
			name: "an exemption rule exempting nothing does not hide the proof",
			build: func(t *testing.T) policy.Policy {
				return mustRequiredForAll(t, passkeyOnly, policy.WithMFAExemption(func(factor.Kind) bool { return false }))
			},
			in:    policy.Input{User: "u-1", FirstFactor: factor.Passkey, SecondFactorAtLogin: policy.MintProofForTest(factor.Passkey, at), Now: at},
			assert: func(t *testing.T, d policy.Decision) { assert.Equal(t, policy.Allow, d.Outcome) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := policy.NewEngine(tc.build(t))
			require.NoError(t, err)
			tc.assert(t, e.EvaluatePhase(t.Context(), policy.PostAuthentication, &tc.in))
		})
	}
}
```

  If `enrolledLookup`, `mustMFAPolicy` and `mustRequiredForAll` do not exist under those names, use the existing helpers in `mfa_test.go` and `mfarequirement_test.go`. Add a small helper only where none exists.
- [ ] **Step 2: Run** `go test -run 'TestMFAPolicies_HonourSecondFactorProof' -count=1 ./policy/... ./internal/assurance/...`. **Expected:** after declaring the type, the alias and the field, rows 1, 3 and 5 fail (outcomes Challenge and Deny instead of Allow).
- [ ] **Step 3: Implement.**
  - In `mfaPolicy.Evaluate`: `if in.MFASatisfied || in.SecondFactorAtLogin.Holds() || p.exempt(in.FirstFactor) { return Allow }`.
  - In the requirement policy, right after step 5: `if phase == PostAuthentication && in.SecondFactorAtLogin.Holds() { return Allow }`.
  - Godoc on both policies: "a consumer who wants a separate second factor after a user-verified passkey login sets `passkey.WithoutSecondFactorAtLogin`". Godoc on the field: zero value proves nothing, only library code mints one, and a copied value is the consumer's own act.
- [ ] **Step 4: Run** `go test -race ./policy/... ./internal/assurance/...` and `go build ./...` in every workspace module. **Expected:** PASS.
- [ ] **Step 5: Refactor.** Consider `/simplify` on the two policy edits, then re-run.
- [ ] **Step 6: Commit** `feat(policy): honour the library's proof of a second factor met at login`

### Task 1.3: The session marker

**Files:**
- Modify: `session/session.go` (field `MFAAtFirstFactor bool`, documented library-owned)
- Modify: `session/options.go` (add `WithSecondFactorAtLogin`)
- Modify: `session/manager.go` (`Create` applies options after setting `CreatedAt`; `Rotate` copies the field)
- Modify: `session/memory.go` if its copy is field-by-field
- Test: `session/secondfactoratlogin_test.go`

**Interfaces:**
- Produces: `func WithSecondFactorAtLogin() CreateOption`, which sets `MFA = MFASatisfied`, `MFASatisfiedAt = s.CreatedAt` and `MFAAtFirstFactor = true`.

- [ ] **Step 1: Write the failing table test** on a clockwork fake at 09:00, with rows:
  - **"created satisfied in one write":** use a store spy counting `Create` calls, then assert state, satisfied time and marker, and exactly one write;
  - **"rotation keeps it":**  `Rotate` then assert the same three fields;
  - **"consumer data cannot claim it":** `Data["mfa_at_first_factor"]="true"` on a password session; the marker stays false after save and load;
  - **"verify-resolved sessions are not marked":** set `MFA=MFASatisfied` the way the verify endpoint does, then assert the marker is false.
- [ ] **Step 2: Run** `go test -run 'TestSecondFactorAtLogin' -count=1 ./session/...`. **Expected:** with an empty option body, rows 1 and 2 fail on `MFANone != MFASatisfied`.
- [ ] **Step 3: Implement.** Make sure `CreatedAt` is set before options run. Check `Create`, and if options run before `CreatedAt`, set the satisfied time inside `Create` after options when the marker is set. Copy the field in `Rotate` and the memory store.
- [ ] **Step 4: Run** `go test -race ./session/...` and `go build ./... && go vet ./...` in every workspace module. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(session): sessions created with the second factor met at login`

### Task 2.1: `mfa.ErrAuthenticatorRefused` is not counted

**Files:**
- Modify: `mfa/mfa.go` (sentinel)
- Modify: `httpsec/mfaverify.go:266-270`
- Modify: `httpsec/status.go` (403 row) and its sentinel-coverage test
- Test: `httpsec/mfaverify_uncounted_test.go`, using the existing `challengeStub` (`httpsec/mfachallenge_stub_test.go`)

**Interfaces:**
- Produces: `var ErrAuthenticatorRefused = errors.New("mfa: the authenticator itself was refused")`. Its godoc says a method returns an error wrapping it when it refuses the authenticator, not the response, and the verify endpoint does not count it.

- [ ] **Step 1: Write the failing test.** It is a table with two rows over a pending session and the stub's `Verify` returning:
  - `fmt.Errorf("%w: clone", mfa.ErrAuthenticatorRefused)`. Assert the error is returned unchanged (`errors.Is`), the limiter mock receives no `RecordFailure`, the challenge stays pending, and the handle is unchanged.
  - `mfa.ErrInvalidCode`. Assert that one failure is recorded.
- [ ] **Step 2: Run** `go test -run 'TestMFAVerify_AuthenticatorRefusedUncounted' -count=1 ./httpsec/...`. **Expected:** row 1 fails with "unexpected call to RecordFailure".
- [ ] **Step 3: Implement:**

```go
if err := method.Verify(ctx, user, response); err != nil {
	if !errors.Is(err, mfa.ErrAuthenticatorRefused) {
		i.throttle.RecordFailure(ctx, user)
	}
	return err
}
```

  Add the status row: `mfa.ErrAuthenticatorRefused` → 403.
- [ ] **Step 4: Run** `go test -race ./mfa/... ./httpsec/...`. **Expected:** PASS, including `TestStatusForErrorCoversEverySentinel`.
- [ ] **Step 5: Commit** `feat(mfa): refusals of the authenticator itself are not counted as guesses`

### Task 2.2: `recovery.UsableLister` in the way-back check

**Files:**
- Modify: `recovery/reset.go` (interface next to `AuthenticatorKind`), `recovery/wayback.go`
- Test: `recovery/wayback_usable_test.go`

**Interfaces:**
- Produces:
  ```go
  // UsableLister is implemented by a kind that holds authenticators which cannot
  // authenticate now. The way-back check counts Usable; the reset keeps using Held.
  type UsableLister interface {
      Usable(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)
  }
  ```

- [ ] **Step 1: Write the failing test.** It is a table with issued codes enabled, a user without a password, and a stub kind whose `Held` returns one ref:
  - **"usable empty":** the stub implements `Usable` returning none → `HasWayBack` false;
  - **"usable one":** → true;
  - **"usable error":** → error;
  - **"no UsableLister":** → true, from `Held`.
- [ ] **Step 2: Run** `go test -run 'TestWayBack_Usable' -count=1 ./recovery/...`. **Expected:** rows 1 and 3 fail, because `Held` is consulted.
- [ ] **Step 3: Implement.** In the per-kind loop: `refs, err := k.Held(...)`. If `u, ok := k.(UsableLister); ok`, call `u.Usable` instead.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): kinds report usable authenticators to the way-back check`

### Task 3.1: `passkey` types, relying party and the verifier port

**Files:**
- Create: `passkey/doc.go`, `passkey/errors.go`, `passkey/relyingparty.go`, `passkey/types.go`, `passkey/verifier.go`
- Test: `passkey/relyingparty_test.go`, `passkey/types_test.go`

**Interfaces:**
- Produces:
  ```go
  type RelyingParty struct{ ID, Name string; Origins []string }
  func (rp RelyingParty) Validate() error // ErrConfig naming the field

  type State uint8
  const ( StateActive State = iota + 1; StatePending; StateSuspended )
  type PendingReason uint8
  const ( AwaitingSavedCodes PendingReason = 1 << iota; AwaitingEmailCode )
  type UserVerification uint8
  const ( UVRequired UserVerification = iota + 1; UVPreferred )
  type ResidentKey uint8
  const ( ResidentKeyRequired ResidentKey = iota + 1; ResidentKeyPreferred )

  type EmailCode struct{ Code string; ExpiresAt time.Time; Attempts int }
  type Credential struct {
      ID id.ID; User identity.UserID
      CredentialID, PublicKey []byte; SignCount uint32
      BackupEligible, BackupState bool; Transports []string; AAGUID []byte
      AttestationFormat string; AttestationStatement []byte
      Name string; CreatedAt, LastUsedAt time.Time
      State State; Pending PendingReason; EmailCode *EmailCode
  }
  type Descriptor struct{ ID []byte; Transports []string }
  type CreationInput struct {
      UserHandle []byte; UserName, DisplayName, Challenge string; Timeout time.Duration
      Exclude []Descriptor; UV UserVerification; ResidentKey ResidentKey
  }
  type RequestInput struct{ Challenge string; Timeout time.Duration; Allow []Descriptor; UV UserVerification }
  type RegistrationExpectation struct{ Challenge string; UV UserVerification }
  type AssertionExpectation struct{ Challenge string; UV UserVerification }
  type NewCredential struct {
      CredentialID, PublicKey []byte; SignCount uint32
      UserVerified, BackupEligible, BackupState bool; Transports []string; AAGUID []byte
      AttestationFormat string; AttestationStatement []byte; AttestationTrusted bool
  }
  type AssertionResult struct{ SignCount uint32; UserVerified, BackupEligible, BackupState bool }
  type ParsedRegistration interface{ Challenge() string; CredentialID() []byte; Name() string }
  type ParsedAssertion interface{ Challenge() string; CredentialID() []byte; UserHandle() []byte }
  type Verifier interface { /* exactly design D1 */ }

  func NormaliseName(raw string, created time.Time) string // trims; >64 runes or any control rune → "Passkey 2006-01-02"
  func DecodeChallenge(clientDataChallenge string) (string, error) // RawURLEncoding → token string
  ```
- Sentinels: the Global Constraints table, plus `ErrConfig`.

- [ ] **Step 1: Write the failing tests.**
  - `relyingparty_test.go` is a table over every spec scenario: missing ID; ID with a scheme, port, path or trailing dot; empty name; empty origins; `https://example.org` for `example.com`; `https://login.example.com` passes; `http://example.com` fails; `http://localhost:8080` for `localhost` passes; `http://127.0.0.1:3000` for ID `127.0.0.1`.
  - Decide and pin the last case: WebAuthn needs a domain, so an IP ID is `ErrConfig`.
  - `types_test.go` pins `NormaliseName`: `" Work laptop "` gives `"Work laptop"`; 64 runes are kept; 65 runes and `"a\nb"` give the date name; an empty name gives the date name.
  - It also pins `DecodeChallenge` round trips with `base64.RawURLEncoding`, and refuses padded or standard-alphabet input.
- [ ] **Step 2: Run** `go test -count=1 ./passkey/...`. **Expected:** with stub functions returning nil and `""`, the rows fail on their asserted values.
- [ ] **Step 3: Implement.** Origin parsing uses `net/url`. The host compare is case-insensitive and exact or suffixed with `.`+ID. Loopback is `localhost` or `*.localhost`; the origin host must still equal the ID or end in `.`+ID, so a loopback IP origin is refused for ID `localhost` (the spec's rule, which browsers also enforce). An origin must equal its serialised form (`scheme://host[:port]`): no path (not even `/`), query, fragment, user info, empty port or default port.
- [ ] **Step 4: Run** `go test -race ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): types, relying party and the verifier port`

### Task 3.2: `CredentialStore` and the in-memory store

**Files:**
- Create: `passkey/store.go` (interface and godoc), `passkey/memstore.go`
- Test: `passkey/memstore_test.go`

**Interfaces:**
- Produces:
  ```go
  type CredentialStore interface {
      Insert(ctx context.Context, c *Credential) error                       // ErrDuplicateCredential
      FindByCredentialID(ctx context.Context, credID []byte) (*Credential, error) // ErrNotFound
      Find(ctx context.Context, user identity.UserID, cid id.ID) (*Credential, error)
      List(ctx context.Context, user identity.UserID) ([]*Credential, error) // by CreatedAt
      Count(ctx context.Context, user identity.UserID) (int, error)
      RecordAssertion(ctx context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time) (bool, error)
      Suspend(ctx context.Context, cid id.ID) (bool, error)                  // active → suspended
      ClearReason(ctx context.Context, user identity.UserID, cid id.ID, r PendingReason) (State, bool, error)
      ChargeEmailAttempt(ctx context.Context, user identity.UserID, cid id.ID, at time.Time) (*EmailCode, bool, error)
      Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) (bool, error)
      Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error)
      DeleteAwaitingSavedCodes(ctx context.Context, user identity.UserID) (int, error)
      DeleteUser(ctx context.Context, user identity.UserID) (int, error)
  }
  var ErrDuplicateCredential = errors.New("passkey: credential ID already registered")
  func NewMemoryCredentialStore() *MemoryCredentialStore
  ```
- **Write semantics.** These are what every driver later matches:
  - `RecordAssertion` succeeds only when `State==Active && (stored < new || (stored == 0 && new == 0))`.
  - `ClearReason` takes exactly one reason (any other value is refused); it succeeds only when that bit is set and the state is pending, clears the emailed code with `AwaitingEmailCode`, and returns the resulting state.
  - `ChargeEmailAttempt` succeeds only when the state is pending, the `AwaitingEmailCode` bit is set, the code is non-nil, `at < ExpiresAt`, and `Attempts < 5`. It increments `Attempts` and returns the stored code to compare.
  - `DeleteAwaitingSavedCodes` deletes the user's credentials with the bit set.

- [ ] **Step 1: Write the failing tests.** These are tables per operation, over every scenario of ADDED "Passkey credentials are unique…":
  - duplicate across users;
  - 8 goroutines recording 43 over 42, where exactly one wins;
  - 41 over 42 refused, with the stored value still 42;
  - 0 over 0 accepted with `LastUsedAt` moved;
  - suspended not recorded;
  - 20 goroutines charging, where exactly 5 succeed;
  - two reasons cleared one by one: pending, then active;
  - mutating the inserted struct after `Insert` does not change the stored copy.

  Use `sync.WaitGroup` with a start gate channel for the concurrent rows.
- [ ] **Step 2: Run** `go test -run 'TestMemoryCredentialStore' -count=1 ./passkey/...`. **Expected:** with methods returning zero values, every row fails on its assertion.
- [ ] **Step 3: Implement** the store behind one `sync.Mutex`, keyed by `id.ID`, with a `credentialID → id` index. Deep-copy byte slices in and out. The godoc states the single-process limit.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): credential store contract and in-memory default`

### Task 3.3: `HandleStore` and the in-memory store

**Files:**
- Create: `passkey/handles.go`
- Test: `passkey/handles_test.go`

**Interfaces:**
- Produces:
  ```go
  type HandleStore interface {
      Assign(ctx context.Context, user identity.UserID, offered []byte) ([]byte, error)
      UserFor(ctx context.Context, handle []byte) (identity.UserID, bool, error)
  }
  func NewMemoryHandleStore() *MemoryHandleStore
  const HandleSize = 64
  ```

- [ ] **Step 1: Write the failing test.**
  - 8 goroutines `Assign` different 64-byte offers for `u-1`. All results are equal and equal one of the offers.
  - `UserFor` on that handle returns `u-1, true`.
  - An unknown handle returns `"", false, nil`.
  - An offer of the wrong length is refused with `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestMemoryHandleStore' -count=1 ./passkey/...`. **Expected:** the stub returns the offer unchanged, so the equality row fails.
- [ ] **Step 3: Implement** with a mutex and two maps, copying bytes.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): user-handle store and in-memory default`

### Task 4.1: `passkey.New` and `BeginRegistration`

**Files:**
- Create: `passkey/manager.go`, `passkey/options.go`, `passkey/register.go`
- Create: `passkey/verifier_mock_test.go` (`//go:generate mockgen -destination=verifier_mock_test.go -package=passkey_test -typed github.com/kartaladev/scrty/passkey Verifier`), `passkey/sender_mock_test.go` for `notify.Sender`
- Test: `passkey/manager_test.go`, `passkey/register_begin_test.go`

**Interfaces:**
- Consumes: Tasks 1.1–1.3 and 3.1–3.3.
- Produces:
  ```go
  type RecoveryDeps struct{ Codes *recovery.Codes; WayBack *recovery.WayBackCheck }
  type Deps struct {
      Verifier    Verifier                  // required
      Credentials CredentialStore           // default NewMemoryCredentialStore()
      Handles     HandleStore               // default NewMemoryHandleStore()
      Challenges  onetime.Store             // default onetime.NewMemoryStore()
      Users       identity.UserLoader       // required (name resolver, contact resolver)
      MFAMethods  []policy.MFAMethodLookup  // for the assurance rule; may be empty
      Sender      notify.Sender             // required
      Recovery    *RecoveryDeps             // optional
  }
  func New(deps Deps, opts ...Option) (*Manager, error)
  // Options (each godoc names its default):
  func WithChallengeTTL(d time.Duration) Option               // 5m
  func WithRegistrationChallengeLimit(n int) Option           // 10 per issuance window (1h)
  func WithPasskeyLimit(n int) Option                         // 25
  func WithManagementFreshness(d time.Duration) Option        // 15m
  func WithUserVerification(uv UserVerification) Option       // UVRequired
  func WithResidentKey(rk ResidentKey) Option                 // ResidentKeyRequired
  func WithNameResolver(fn func(ctx context.Context, d *identity.Details) (name, display string, err error)) Option // username, username
  func WithRepudiationContact(s string) Option                // required, no default
  func WithSynchronousDelivery() Option
  func WithClock(clk clock.Clock) Option
  func WithRandom(r io.Reader) Option
  func WithIDGenerator(g id.Generator) Option
  func WithLogger(l *slog.Logger) Option
  func (m *Manager) BeginRegistration(ctx context.Context, s *session.Session) (json.RawMessage, error)
  func (m *Manager) admit(ctx context.Context, s *session.Session) error // shared with Remove (5.3)
  ```

- [ ] **Step 1: Write the failing tests.**
  - `manager_test.go` is a construction table:
    - nil verifier, nil users, nil sender, and missing repudiation contact each give `ErrConfig`;
    - an invalid `Verifier.RelyingParty()` gives `ErrConfig`;
    - a synchronous sender (one not implementing `notify.NonBlocking`) gives `ErrConfig`, and `WithSynchronousDelivery()` accepts it;
    - a TTL, freshness, limit or passkey limit of ≤ 0 gives `ErrConfig`;
    - valid input succeeds.
  - `register_begin_test.go` is a table on a fake clock at 09:00 with a mock verifier capturing `CreationInput`. It covers every scenario of "Registration admits a session…" and the begin scenarios of "Registration is a begin and finish ceremony…":
    - a fresh full session at 09:10 → options returned, with `UV=UVRequired`, `ResidentKey=ResidentKeyRequired`, a 64-byte handle, `Timeout=5m`, and `Exclude` listing two existing credentials;
    - 09:16 → `ErrReauthenticationRequired`;
    - satisfied at 09:20 and beginning at 09:30 → OK;
    - a usable TOTP lookup on a session with `MFANone` → `ErrReauthenticationRequired`;
    - recovery-pending and enrolment-pending sessions at +14m → OK;
    - an 11th begin within the hour → `ErrRegistrationThrottled`;
    - the same handle for two begins a day apart;
    - the handle contains neither `u-1` nor the username;
    - the consumer name resolver's email used.
- [ ] **Step 2: Run** `go test -run 'TestNew|TestBeginRegistration' -count=1 ./passkey/...`. **Expected:** with `New` returning a bare manager and `BeginRegistration` returning `nil, nil`, the rows fail on their assertions.
- [ ] **Step 3: Implement.**
  - **Admission.**
    - A full session is `s.MFA ∈ {MFANone, MFASatisfied}` and `s.EnrolmentOriginDeadline.IsZero()`.
    - If `policy.UsableMFAMethods(ctx, m.methods, s.UserID, s.FirstFactor)` returns any method and `s.MFA != MFASatisfied`, return `ErrReauthenticationRequired`. A lookup error is returned behind fixed text with `diag.Wrap`.
    - Freshness: `now.Sub(max(s.CreatedAt, s.MFASatisfiedAt)) > m.fresh` gives `ErrReauthenticationRequired`.
    - Sessions in `MFAEnrolmentPending` or `MFARecoveryPending` pass.
    - Anything else (`MFAPending`) gives `ErrReauthenticationRequired`.
  - **Handle.** `Handles.Assign(user, random 64)`.
  - **Throttle.** `IssuedCount(user) >= limit` gives `ErrRegistrationThrottled`.
  - **Token.** `Issue(user, WithBinding(s.ID))`.
  - **Exclusions.** `List(user)` → `Exclude`.
  - **Options.** `Verifier.CreationOptions`.
- [ ] **Step 4: Run** `go test -race ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): manager construction and registration begin`

### Task 4.2: `FinishRegistration` — verification and storage

**Files:**
- Modify: `passkey/register.go`
- Test: `passkey/register_finish_test.go`

**Interfaces:**
- Produces:
  ```go
  type RegistrationContext struct {
      EmailConfirmation bool                 // the enrolment path's setting, for an enrolment-pending session
      ContactResolver   mfa.ContactResolver  // nil: the manager's
  }
  type RegistrationResult struct {
      Credential       *Credential
      Activated        bool
      RecoveryCodes    []string
      BackupEligible   bool
      NoSyncedPasskey  bool
      RecoveryNotSetUp bool
  }
  type RegistrationFacts struct {
      User identity.UserID; AAGUID []byte; BackupEligible, BackupState bool
      AttestationFormat string; AttestationTrusted bool
  }
  func WithRegistrationCheck(fn func(ctx context.Context, f RegistrationFacts) error) Option // none
  func (m *Manager) FinishRegistration(ctx context.Context, s *session.Session, body []byte, rc RegistrationContext) (*RegistrationResult, error)
  ```

- [ ] **Step 1: Write the failing tests.** This is a table with a mock verifier whose `ParseRegistration` returns a stub `ParsedRegistration` carrying the challenge from a real begin. Rows:
  - **Happy path:** the stored record carries the flags, transports, counter and `CreatedAt`, and `Activated` is true.
  - **Parse error:** `authenticate.ErrMissingCredentials`, or the existing "missing credentials" sentinel the MFA readers use. Find it with gopls references on `postedJSON`'s error.
  - **Spent challenge reused:** the second finish is `ErrAuthenticationFailed` and `VerifyRegistration` is not called.
  - **Challenge from another session:** `ErrAuthenticationFailed`, nothing stored.
  - **Expired at +6m:** `ErrAuthenticationFailed`.
  - **Verify error:** `ErrAuthenticationFailed`, nothing stored.
  - **`UserVerified=false` under `UVRequired`:** `ErrAuthenticationFailed`.
  - **Consumer check error:** returned unchanged, nothing stored.
  - **25 existing:** `ErrLimitReached`.
  - **Duplicate credential ID** (pre-insert for `u-2`): `ErrAuthenticationFailed`, and `u-2`'s record is unchanged.
  - **8 concurrent finishes presenting one challenge:** the verify mock is called at most once.
  - **Names:** a 200-character name and `"a\nb"` give the date name (Review Focus 3); `"Work laptop"` is kept.
- [ ] **Step 2: Run** `go test -run 'TestFinishRegistration' -count=1 ./passkey/...`. **Expected:** the stub returns `nil, nil`, so the rows fail.
- [ ] **Step 3: Implement** design D7 steps 1–5 and step 10:
  1. parse;
  2. `DecodeChallenge`, then `Check(challenge, s.ID)`, requiring the token subject to equal `s.UserID`, then `Consume`;
  3. `VerifyRegistration`;
  4. the UV check;
  5. the consumer check;
  6. the limit;
  7. build the `Credential` (`State: StateActive` for now; pending reasons come in 4.3);
  8. insert, mapping `ErrDuplicateCredential` to `authenticate.ErrAuthenticationFailed`.

  Every refusal reason before the insert stores nothing.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): registration finish verifies once and stores once`

### Task 4.3: Pending reasons and the confirm operations

**Files:**
- Create: `passkey/pending.go`
- Modify: `passkey/register.go` (D7 steps 6–9)
- Test: `passkey/pending_test.go`

**Interfaces:**
- Produces:
  ```go
  func WithOptionalRecoveryCodes() Option
  func (m *Manager) ConfirmSavedCode(ctx context.Context, s *session.Session, code string) (activated *Credential, err error)
  func (m *Manager) ConfirmEmailCode(ctx context.Context, s *session.Session, code string, rc RegistrationContext) (activated *Credential, err error)
  // The email-confirm limiter is passed in by httpsec for enrolment-pending sessions:
  type RegistrationContext struct { EmailConfirmation bool; ContactResolver mfa.ContactResolver; ConfirmLimiter ratelimit.Limiter }
  ```
  `RegistrationContext` gains `ConfirmLimiter`. A nil limiter uses the manager's own: 5 per 15 minutes under `httpsec.EnrolmentConfirmThrottleKey`'s format, duplicated as a `passkey` constant with the same value. The `passkey` package cannot import `httpsec`.

- [ ] **Step 1: Write the failing tests.** The way-back check uses a real `recovery.NewWayBackCheck` over in-memory stores and a stub user loader. Rows:
  - **Passwordless first passkey:** pending `AwaitingSavedCodes`, 10 codes returned, and `Authenticate` (4.5) is not yet available, so assert `State==StatePending` and `MFAMethod` reports not enrolled in 5.1.
  - **Confirm with one of the codes:** active, and that code is still unspent (`Codes.Remaining == 10`).
  - **Wrong code:** still pending.
  - **Abandoned then re-registered:** the old credential is gone, and the new one is pending with a new set.
  - **User with 3 saved codes:** active, no codes.
  - **Optional mode:** active and `RecoveryNotSetUp`.
  - **Way-back check error:** refused, nothing stored.
  - **Email code:** `RegistrationContext{EmailConfirmation:true}` on an enrolment-pending session.
    - Pending `AwaitingEmailCode`; the sender mock receives one message whose body contains a 6-digit code.
    - The code within 10 minutes activates.
    - At 11 minutes it is refused.
    - Five wrong codes and then the right one: refused.
    - 20 concurrent wrong codes and then the right one: still pending, with at most 5 compared. Count with a compare hook exposed via `export_test.go`.
    - A sender returning `notify.ErrQueueFull`: the finish fails and nothing is stored.
  - **Both reasons:** active only after both confirms, in either order.
  - **A full session:** no emailed code.
  - **Review Focus 4:** a recovery-pending session's pending credential is left. A later full-session finish for the same user deletes it and stores the new one pending.
- [ ] **Step 2: Run** `go test -run 'TestPending' -count=1 ./passkey/...`. **Expected:** rows asserting pending fail, because 4.2 stores everything active.
- [ ] **Step 3: Implement** design D7 steps 6–9 in order:
  - generate codes before the insert;
  - queue the email code before the insert;
  - store the email code with `ExpiresAt = now + 10m`.

  Then the confirm operations:
  - `ConfirmSavedCode`: find the user's credential with the `AwaitingSavedCodes` bit (none → `mfa.ErrInvalidCode`), `Codes.Confirm` (its error mapped to `mfa.ErrInvalidCode`, throttled error unchanged), then `ClearReason`.
  - `ConfirmEmailCode`: limiter check, then `ChargeEmailAttempt`, then `subtle.ConstantTimeCompare`, then `ClearReason`. A failure records on the limiter with `context.WithoutCancel`.
  - When the resulting state is active, return the credential so the caller runs activation, which is the notice in 4.4 and the session move in 8.2.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): pending passkeys await saved codes or the emailed code`

### Task 4.4: Notices

**Files:**
- Create: `passkey/messages.go`
- Modify: `passkey/register.go`, `passkey/pending.go` (call `m.activated(ctx, c, rc)`)
- Test: `passkey/messages_test.go`

**Interfaces:**
- Produces:
  ```go
  type Notice struct{ Name string; At time.Time; Repudiation string }
  type Messages interface {
      Registered(n Notice) (subject, body string)
      Removed(n Notice) (subject, body string)
      Suspended(n Notice) (subject, body string)
      EmailCode(code string, until time.Time) (subject, body string)
  }
  func WithMessages(m Messages) Option         // plain default texts, no brand
  func WithContactResolver(r mfa.ContactResolver) Option // mfa.UsernameAsAddress
  func (m *Manager) activated(ctx context.Context, c *Credential, rc RegistrationContext) // queue Registered
  ```

- [ ] **Step 1: Write the failing tests.**
  - A binding notice to `ana@example.com` names `Phone`, the time and the repudiation contact, and contains no code, challenge or base64 of the credential ID.
  - A pending credential notifies at confirm, not at finish.
  - `NoSyncedPasskey` is true when every active credential has `BackupEligible=false`, and `BackupEligible` mirrors the new credential.
  - A refused queue is logged (assert through a captured `slog` handler) with neither the body nor the address, and the credential stays active.
  - A consumer `Messages` replaces the subject and body, while the recipient is still set by the library.
- [ ] **Step 2: Run** `go test -run 'TestNotices' -count=1 ./passkey/...`. **Expected:** the sender mock sees no call, so the rows fail.
- [ ] **Step 3: Implement** the default texts, `activated`, and the result flags.
- [ ] **Step 4: Run** `go test -race ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): binding notices and synced-passkey advice`

### Task 4.5: Passwordless begin and `Authenticate`

**Files:**
- Create: `passkey/login.go`
- Test: `passkey/login_test.go`

**Interfaces:**
- Produces:
  ```go
  type LoginFacts struct{ User identity.UserID; Credential id.ID; AAGUID []byte; BackupEligible, BackupState, UserVerified bool }
  type LoginResult struct{ User identity.UserID; Credential id.ID; Proof policy.SecondFactorProof }
  func WithLoginCheck(fn func(ctx context.Context, f LoginFacts) error) Option // none
  func WithoutSecondFactorAtLogin() Option                                      // the proof is minted by default
  func (m *Manager) BeginLogin(ctx context.Context, binding string) (json.RawMessage, error)
  func (m *Manager) Authenticate(ctx context.Context, body []byte, binding string) (*LoginResult, error)
  func (m *Manager) verifyAssertion(ctx context.Context, p ParsedAssertion, c *Credential, uv UserVerification) (*AssertionResult, error) // shared with 5.1
  ```

- [ ] **Step 1: Write the failing tests.** This is a table with a mock verifier. Rows:
  - **Begin:** a `RequestInput` with no `Allow`, UV required and `Timeout=5m`; a token issued with the binding.
  - **Purge:** 200 expired tokens are gone after one begin past the TTL; a second begin within the TTL does not purge again (count the store's reap calls via a spy).
  - **Happy path:** a UV assertion gives a `LoginResult` whose proof holds with kind `passkey`.
  - **`WithoutSecondFactorAtLogin`:** the proof does not hold.
  - **UV false under required:** `ErrAuthenticationFailed`. Under `UVPreferred`: OK with no proof.
  - **Uniform refusals:** an unknown credential, the user handle of `u-2` and a verify error each give `ErrAuthenticationFailed`, compared with `errors.Is` and the same text.
  - **Pending:** `ErrPending`. **Suspended:** `ErrSuspended`. Neither changes the counter.
  - **Binding:** a missing or wrong binding gives `ErrAuthenticationFailed`.
  - **One try per challenge:** a bad signature then a valid assertion on the same challenge: the second is refused.
  - **Consumer login check:** its error is returned unchanged, with the counter unchanged.
  - **Review Focus 1:** a challenge string issued by the registration manager presented here gives `ErrAuthenticationFailed`, with `FindByCredentialID` never called (the spy store).
- [ ] **Step 2: Run** `go test -run 'TestLogin' -count=1 ./passkey/...`. **Expected:** the stubs fail every row.
- [ ] **Step 3: Implement** the spec order steps 2–8:
  1. parse;
  2. decode the challenge, `Check(binding)`, `Consume`;
  3. `FindByCredentialID`;
  4. the state checks;
  5. `UserFor(UserHandle)` must equal `c.User`, compared with `subtle.ConstantTimeCompare` on the handle bytes against the stored handle;
  6. `VerifyAssertion`;
  7. the UV check;
  8. the BE check;
  9. the login check;
  10. the counter write (4.6 adds the clone branch; here treat a refused write as `ErrAuthenticationFailed`);
  11. mint the proof with `assurance.New(factor.Passkey, now)` when UV and not disabled.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): passwordless authentication and the second-factor proof`

### Task 4.6: Clone handling and logs

**Files:**
- Create: `passkey/clone.go`, `passkey/logs.go`
- Modify: `passkey/login.go` (the counter branch in `verifyAssertion`)
- Test: `passkey/clone_test.go`, `passkey/logs_test.go`

**Interfaces:**
- Produces:
  ```go
  type CloneResponse uint8
  const ( CloneSuspend CloneResponse = iota + 1; CloneSignalOnly ) // CloneSuspend is the default
  type CloneAction uint8
  const ( CloneAllow CloneAction = iota + 1; CloneRefuse; CloneRefuseSuspend )
  type CloneSignal struct{ User identity.UserID; Credential id.ID; Stored, Presented uint32; BackupEligible, BackupState bool }
  func WithCloneResponse(r CloneResponse) Option                                  // CloneSuspend
  func WithClonePolicy(fn func(ctx context.Context, s CloneSignal) CloneAction) Option
  func WithLogInterval(d time.Duration) Option                                    // 1 minute
  func (m *Manager) FlushRefusalLogs(ctx context.Context)
  ```

- [ ] **Step 1: Write the failing tests.**
  - `clone_test.go` rows:
    - 41 over 42 → `ErrCloneSuspected`, state suspended, a suspended notice queued, and `errors.Is(err, mfa.ErrAuthenticatorRefused)`;
    - 42 over 42 → the same;
    - 0 over 0 → OK;
    - two concurrent assertions with 43 over 42 → one OK and one `ErrCloneSuspected` (Review Focus 2);
    - signal-only → OK, still active, stored counter 42, one warning;
    - a policy returning `CloneAllow` for non-administrators → OK;
    - a BE flag changed → `ErrAuthenticationFailed`.
  - `logs_test.go` rows:
    - 200 refusals for an unknown credential in one minute give one record, and the reporter gets 199;
    - no record contains the challenge, the public key bytes (base64 and hex) or the handle.
- [ ] **Step 2: Run** `go test -run 'TestClone|TestPasskeyLogs' -count=1 ./passkey/...`. **Expected:** the refused counter write still maps to `ErrAuthenticationFailed`, so the clone rows fail.
- [ ] **Step 3: Implement.** On `RecordAssertion == false` with the credential still active, build a `CloneSignal` and decide by policy or response. Suspend with `Suspend(cid)`, notify `Suspended`, and return `fmt.Errorf("%w", ErrCloneSuspected)`. Under signal-only, write the sampled warning keyed `clone|<credential id>` and allow. Use `pkg/logsample` with a reporter for the samplers.
- [ ] **Step 4: Run** `go test -race -count=3 ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): suspected clones are refused and suspended by default`

### Task 5.1: The passkey MFA method

**Files:**
- Create: `passkey/mfamethod.go`
- Test: `passkey/mfamethod_test.go`

**Interfaces:**
- Produces:
  ```go
  type MFAMethod struct{ /* unexported */ }
  func (m *Manager) MFAMethod() *MFAMethod
  // implements mfa.ChallengeMethod, mfa.EnrolmentRemover, and
  func (*MFAMethod) SupportsEnrolmentPath() bool // true
  const MethodName = "passkey"
  const AssertionBodyLimit = 16 << 10
  const RegistrationBodyLimit = 64 << 10
  ```

- [ ] **Step 1: Write the failing tests.**
  - Compile-time assertions: `var _ mfa.ChallengeMethod = (*passkey.MFAMethod)(nil)` and `var _ mfa.EnrolmentRemover = …`.
  - Name, channel, `Response() == mfa.JSONBody(16<<10)`.
  - `Enrolled`: only pending → false; only suspended → false; one active → true; a store error → error.
  - `BeginChallenge` lists only active credentials, with transports, and includes non-discoverable ones.
  - `PresentedChallenge` round trips with the challenge.
  - `Verify`:
    - another user's credential → `mfa.ErrInvalidCode`;
    - a UP-only assertion under `UVPreferred` → OK;
    - under `UVRequired` → `mfa.ErrInvalidCode`;
    - suspended → `ErrSuspended`;
    - clone → `ErrCloneSuspected`.
  - `RemoveEnrolment` deletes every passkey of the user.
  - `mfa.LookupsFor(method)` succeeds.
- [ ] **Step 2: Run** `go test -run 'TestMFAMethod' -count=1 ./passkey/...`. **Expected:** the stubs fail.
- [ ] **Step 3: Implement** over `verifyAssertion` (4.5/4.6). Any non-clone, non-suspended refusal maps to `mfa.ErrInvalidCode`. The godoc says not to pass the method to `recovery.MFAEnrolments`; use `RecoveryKind()` instead.
- [ ] **Step 4: Run** `go test -race ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): passkey as a challenge-capable MFA method`

### Task 5.2: The recovery kind

**Files:**
- Create: `passkey/recoverykind.go`
- Test: `passkey/recoverykind_test.go`

**Interfaces:**
- Produces: `func (m *Manager) RecoveryKind() recovery.AuthenticatorKind`, which also implements `recovery.UsableLister`. Its refs are `{Kind: "passkey", ID: <id.ID text>}`.

- [ ] **Step 1: Write the failing tests** with a real `recovery` flow over in-memory stores:
  - **Default reset:** two passkeys plus TOTP are all removed by a saved plus issued recovery.
  - **Reported-loss mode:** reporting the security key's ID removes only it.
  - **`Held`:** a pending passkey is listed by `Held` but not by `Usable`.
  - **Way-back:** with issued codes on, a user with only a suspended passkey gets `HasWayBack` false.
  - **Errors:** a listing error is returned.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryKind' -count=1 ./passkey/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** `Remove` parses each ID with `id.Parse` and deletes it, ignoring unknown IDs.
- [ ] **Step 4: Run** `go test -race ./passkey/... ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): passkeys in the recovery reset and the way-back check`

### Task 5.3: Management

**Files:**
- Create: `passkey/manage.go`
- Test: `passkey/manage_test.go`

**Interfaces:**
- Produces:
  ```go
  type Summary struct {
      ID id.ID; Name string; State State; CreatedAt, LastUsedAt time.Time
      BackupEligible, BackupState bool; Transports []string; AAGUID []byte
  }
  func (m *Manager) List(ctx context.Context, user identity.UserID) ([]Summary, error)
  func (m *Manager) Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) error
  func (m *Manager) Remove(ctx context.Context, s *session.Session, cid id.ID) error
  ```

- [ ] **Step 1: Write the failing tests.**
  - `List` covers active and suspended credentials. `Summary` has no public-key field, so assert by reflection that no field holds the key bytes.
  - `Rename` to `"Old phone"` is listed.
  - `Remove` of `u-2`'s ID by `u-1` → `ErrNotFound`, and `u-2`'s passkey still exists.
  - A stale `Remove` → `ErrReauthenticationRequired`.
  - `Remove` of a suspended passkey succeeds and queues a `Removed` notice.
  - `Rename` with a 200-character name stores the default date name, through `NormaliseName`.
- [ ] **Step 2: Run** `go test -run 'TestManage' -count=1 ./passkey/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** `Remove` runs `admit` (from 4.1), then `Find` (not the user's → `ErrNotFound`), then `Delete`, then the notice.
- [ ] **Step 4: Run** `go test -race ./passkey/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(passkey): list, rename and remove`

### Task 6.1: The nested module and the layout guard

**Files:**
- Create: `passkey/webauthn/go.mod` (`module github.com/kartaladev/scrty/passkey/webauthn`, `go 1.26`, `require github.com/kartaladev/scrty`, `github.com/go-webauthn/webauthn v0.18.2`), `passkey/webauthn/doc.go`
- Modify: `go.work` (`use ./passkey/webauthn`), `layout_guard_test.go` (`integrationModules` gains `github.com/go-webauthn/webauthn`, `github.com/fxamacker/cbor`, `github.com/google/go-tpm`), `layout_test.go` (the exported-API check below)
- Test: `layout_test.go`

- [ ] **Step 1: Write the failing test.** `TestWebAuthnTypesStayInsideTheAdapter` runs `go list -json github.com/kartaladev/scrty/passkey/webauthn/...` and parses each package's exported API with `go/packages` (already a dependency of the layout tests; if not, `go doc -all` output). It fails when any exported identifier's type mentions `github.com/go-webauthn/`. Also add `github.com/go-webauthn/webauthn` to the forbidden list and confirm the existing core-dependency test now covers it.
- [ ] **Step 2: Run** `go test -run 'TestWebAuthnTypesStayInsideTheAdapter|TestCoreDependencies' -count=1 .`. **Expected:** FAIL, because the module does not exist ("package not found"). Make the red step meaningful by first creating the module with a deliberately leaking `func Leak() webauthn.Config`, seeing it fail for that reason, then deleting `Leak`.
- [ ] **Step 3: Implement** the module scaffold. Run `go mod tidy` in `passkey/webauthn` and `go work sync`.
- [ ] **Step 4: Run** `go test ./...` in the root (the layout tests) and `go build ./...` in `passkey/webauthn`. **Expected:** PASS. The core `go.mod` gained nothing (`git diff go.mod` is empty).
- [ ] **Step 5: Commit** `build: nested passkey/webauthn module and layout guard`

### Task 6.2: `webauthntest`, a software authenticator

**Files:**
- Create: `passkey/webauthn/webauthntest/authenticator.go`, `passkey/webauthn/webauthntest/cbor.go`
- Test: `passkey/webauthn/webauthntest/authenticator_test.go`

**Interfaces:**
- Produces:
  ```go
  type Authenticator struct {
      Counter uint32; UV, BE, BS bool; Transports []string; AAGUID [16]byte
      // unexported: key *ecdsa.PrivateKey, credID []byte, userHandle []byte
  }
  func New(t testing.TB) *Authenticator // ES256 key, 32-byte credential ID
  func (a *Authenticator) Create(rpID, origin, challenge string, userHandle []byte, attestation string /* "none"|"packed" */) []byte // RegistrationResponseJSON
  func (a *Authenticator) Assert(rpID, origin, challenge string) []byte                                                  // AuthenticationResponseJSON, userHandle from Create; increments Counter unless it is 0
  func (a *Authenticator) CredentialID() []byte
  ```
  The JSON follows the WebAuthn L3 `toJSON()` shapes: `id`, `rawId`, `type:"public-key"`, `response.{clientDataJSON, attestationObject|authenticatorData, signature, userHandle}`, `clientExtensionResults:{}`, `authenticatorAttachment`. The client data `challenge` is base64url of the challenge string's bytes.

- [ ] **Step 1: Write the failing test.** Round trip through go-webauthn directly (allowed in this module): `protocol.ParseCredentialCreationResponseBytes(a.Create(...))` succeeds and `Verify` passes for rp `example.com` and origin `https://example.com`. The same holds for `ParseCredentialRequestResponseBytes(a.Assert(...))` with `parsed.Verify` against the stored public key. Flags reflect `UV`, `BE` and `BS`.
- [ ] **Step 2: Run** `go test -count=1 ./webauthntest/...` in `passkey/webauthn`. **Expected:** FAIL (the stub returns empty bytes, and parsing fails).
- [ ] **Step 3: Implement.**
  - **CBOR.** Use `github.com/fxamacker/cbor/v2`, already in the module's graph through go-webauthn; require it directly. The COSE key is the map `{1:2, 3:-7, -1:1, -2:x, -3:y}`.
  - **authData.** `sha256(rpID) || flags || counter(be32)`, plus attested credential data (AAGUID, len(credID) be16, credID, COSE key) at create.
  - **Flags.** UP `0x01`, UV `0x04`, BE `0x08`, BS `0x10`, AT `0x40`.
  - **packed self-attestation.** `{alg:-7, sig: sign(authData||sha256(clientData))}`.
  - **Assertion signature.** ECDSA ASN.1 over `authData || sha256(clientDataJSON)`.
- [ ] **Step 4: Run** `go test -race ./...` in `passkey/webauthn`. **Expected:** PASS.
- [ ] **Step 5: Commit** `test(webauthn): software authenticator for ceremony tests`

### Task 6.3: `webauthn.New` implementing `passkey.Verifier`

**Files:**
- Create: `passkey/webauthn/verifier.go`, `passkey/webauthn/options.go`, `passkey/webauthn/parsed.go`
- Test: `passkey/webauthn/verifier_test.go`

**Interfaces:**
- Produces: `func New(rp passkey.RelyingParty, opts ...Option) (*Verifier, error)`, with `var _ passkey.Verifier = (*Verifier)(nil)`. Unexported `parsedRegistration` and `parsedAssertion` wrap `*protocol.ParsedCredentialCreationData` and `*protocol.ParsedCredentialAssertionData`.

- [ ] **Step 1: Write the failing table test,** driven by `webauthntest`:
  - creation options JSON carry `rp.id`, `rp.name`, `user.id` (base64url of the handle), `challenge` (base64url of the challenge string), `timeout` in ms, `authenticatorSelection.userVerification:"required"`, `residentKey:"required"`, `attestation:"none"`, and `excludeCredentials`;
  - request options have no `allowCredentials` when `Allow` is empty;
  - a valid create → `NewCredential` with the flags, transports and AAGUID;
  - origin `https://evil.example` → error;
  - the challenge mismatches the expectation → error;
  - a valid assert → `AssertionResult` with the counter and flags;
  - an assertion with UV false under `UVRequired` → error, and under `UVPreferred` → `UserVerified=false`, no error;
  - malformed JSON from `ParseAssertion` → an error that `errors.Is` the core's missing-credentials sentinel;
  - `New` with an invalid RP → `passkey.ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestVerifier' -count=1 .` in `passkey/webauthn`. **Expected:** FAIL against stubs.
- [ ] **Step 3: Implement.**
  - Build one `webauthn.Config{RPID, RPDisplayName, RPOrigins, AttestationPreference: none}` at `New`.
  - Options come from `BeginRegistration`/`BeginLogin` with `WithChallenge([]byte(in.Challenge))` (or the library's equivalent creation helpers) over a minimal internal `webauthn.User` adapter, and only `options.Response` is serialised.
  - Verification goes through the parsed data's `Verify(challenge, uvRequired, ...)` per the v0.18.2 API. Check the exact signature with `go doc github.com/go-webauthn/webauthn/protocol ParsedCredentialAssertionData.Verify`.
  - Map every library error to a core error: a parse failure is missing credentials, a verify failure is `authenticate.ErrAuthenticationFailed`, and the library text is never surfaced.
- [ ] **Step 4: Run** `go test -race ./...` in `passkey/webauthn`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(webauthn): verifier over go-webauthn`

### Task 6.4: Attestation modes and metadata

**Files:**
- Create: `passkey/webauthn/attestation.go`, `passkey/webauthn/metadata.go`
- Test: `passkey/webauthn/attestation_test.go`, `passkey/webauthn/metadata_test.go`

**Interfaces:**
- Produces:
  ```go
  func WithAttestationRecord() Option
  func WithTrustedAttestation(src MetadataSource, allowedAAGUIDs ...[16]byte) Option
  type MetadataSource interface{ /* unexported method: provider(ctx) (metadata.Provider, error) */ }
  func MetadataBlob(fetch func(ctx context.Context) ([]byte, error)) MetadataSource
  func MetadataFromMDS(client *outbound.Client, opts ...MDSOption) MetadataSource // URL default https://mds3.fidoalliance.org/
  ```

- [ ] **Step 1: Write the failing tests.**
  - The default mode accepts a `none` attestation and records no format.
  - Record mode with a `packed` self-attestation → `AttestationFormat "packed"` and a statement.
  - Trusted mode with a `none` response → `passkey.ErrAttestationRefused`.
  - Trusted mode with no source → `passkey.ErrConfig` at `New`.
  - `MetadataFromMDS` against an `httptest.NewTLSServer`, with the confined client configured to allow its origin:
    - one fetch, then a cached read before `nextUpdate`;
    - a refetch after it, with the fake clock;
    - a failed refetch keeps refusing trusted attestation, failing closed.

  Build the blob with a test-only FIDO-shaped JWT signed by a test root that the source is configured to trust via an `MDSOption` `WithMDSRoot(cert)`.
- [ ] **Step 2: Run** `go test -run 'TestAttestation|TestMetadata' -count=1 .` in `passkey/webauthn`. **Expected:** FAIL.
- [ ] **Step 3: Implement** with go-webauthn's `metadata` decoder over the fetched bytes. The library's own HTTP is never used, so construct the decoder only. The cache TTL is `min(nextUpdate-now, 24h)`.
- [ ] **Step 4: Run** `go test -race ./...` and `govulncheck ./...` in `passkey/webauthn`. **Expected:** PASS, with no reachable vulnerability.
- [ ] **Step 5: Commit** `feat(webauthn): attestation record and trusted modes with confined metadata`

### Task 7.1: Schema

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (up and down)
- Modify: `test/migrate_securitystate_test.go`

- [ ] **Step 1: Write the failing test.** Extend the expected table list to thirteen (`passkey_credentials`, `passkey_user_handles`). Add scenario checks through `information_schema` and `pg_indexes`:
  - a unique index on `passkey_credentials(credential_id)`;
  - an index on `passkey_credentials(user_id)`;
  - unique on `passkey_user_handles(handle)` and `(user_id)`;
  - `sessions.mfa_at_first_factor` is `boolean NOT NULL DEFAULT false`;
  - primary keys are `uuid`.
- [ ] **Step 2: Run** `go test -run 'TestSecurityStateMigration' -count=1 .` in `test/`. **Expected:** FAIL, missing tables.
- [ ] **Step 3: Implement** the DDL:

```sql
CREATE TABLE passkey_credentials (
    id uuid PRIMARY KEY,
    user_id text NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL,
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    transports text NOT NULL,
    aaguid bytea NULL,
    attestation_format text NULL,
    attestation_statement bytea NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz NULL,
    state smallint NOT NULL,
    pending smallint NOT NULL,
    email_code text NULL,
    email_code_expires_at timestamptz NULL,
    email_code_attempts smallint NOT NULL DEFAULT 0,
    CONSTRAINT passkey_credentials_credential_id_key UNIQUE (credential_id)
);
CREATE INDEX passkey_credentials_user_id_idx ON passkey_credentials (user_id);
CREATE TABLE passkey_user_handles (
    id uuid PRIMARY KEY,
    user_id text NOT NULL UNIQUE,
    handle bytea NOT NULL UNIQUE
);
ALTER TABLE sessions ADD COLUMN mfa_at_first_factor boolean NOT NULL DEFAULT false; -- or inline in CREATE TABLE sessions
```

  Prefer the inline column in `CREATE TABLE sessions`, matching how `recovered_at` was added. The down section drops both tables.
- [ ] **Step 4: Run** `go test -race ./...` in `test/` (needs Docker). **Expected:** PASS, including the leftover-table check.
- [ ] **Step 5: Commit** `feat(migrate): passkey tables and the session marker column`

### Task 7.2: `mfa_at_first_factor` through the session stores

**Files:**
- Modify: `internal/pgschema/sessions.go`, `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`, `gorm/models.go`
- Modify: `test/storetest/session_suite.go`, `test/crossbackend/crossbackend_test.go`

- [ ] **Step 1: Write the failing tests.** The session suite gains:
  - "marker round trip": create with `session.WithSecondFactorAtLogin()`, save, load, and the marker, state and satisfied time are equal;
  - "unmarked": a TOTP-satisfied session loads with the marker unset.

  The cross-backend test gains "saved through sqlstore, loaded through pgx and gorm".
- [ ] **Step 2: Run** `go test -run 'Session' -count=1 ./storetest/... ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/...` in `test/`. **Expected:** FAIL, because the marker loads false.
- [ ] **Step 3: Implement** the column in every insert, update and select list, following `recovered_at`.
- [ ] **Step 4: Run** `go test -race ./...` in the root, `pgx`, `gorm` and `test` modules. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(stores): persist the second factor met at login`

### Task 7.3: Passkey store suites and race fixtures

**Files:**
- Create: `test/storetest/passkeycredential_suite.go`, `test/storetest/passkeyhandle_suite.go`, `test/storetest/broken_passkey_test.go`, `test/internal/storefix/passkey.go`
- Modify: `test/storetest/memory_test.go` (append)

**Interfaces:**
- Produces:
  ```go
  func RunPasskeyCredentialStoreSuite(t *testing.T, newStore func(t *testing.T) passkey.CredentialStore)
  func RunPasskeyHandleStoreSuite(t *testing.T, newStore func(t *testing.T) passkey.HandleStore)
  // storefix, each run through the existing storetest race and ambient runners on a DurableHarness:
  func PasskeyCounterRace[S passkey.CredentialStore]() storetest.Race[S]   // 50 credentials × 8 RecordAssertion(n+1)
  func PasskeyInsertRace[S passkey.CredentialStore]() storetest.Race[S]    // 50 credential IDs × 8 inserts for different users
  func PasskeyHandleRace[S passkey.HandleStore]() storetest.Race[S]        // 50 users × 8 Assign
  func PasskeyCredentialAmbient[S passkey.CredentialStore]() storetest.Ambient[S]
  func PasskeyHandleAmbient[S passkey.HandleStore]() storetest.Ambient[S]
  func PasskeySealed[S passkey.CredentialStore]() storetest.Sealed[S]      // SENTINEL-PASSKEY emailed code
  ```

- [ ] **Step 1: Write the failing test.** `broken_passkey_test.go` defines read-then-write variants of `RecordAssertion`, `Insert` (check, then insert, without a unique index; use an in-memory map with a sleep-free yield via `runtime.Gosched` between the check and the write) and `Assign`. It asserts that each race fails against them, as `broken_race_test.go` does.
- [ ] **Step 2: Run** `go test -run 'Broken.*Passkey|Memory.*Passkey' -count=1 ./storetest/...` in `test/`. **Expected:** FAIL with "broken variant passed" (the suites are empty functions first).
- [ ] **Step 3: Implement** the suites with exact counts, porting every case from `passkey/memstore_test.go` and `passkey/handles_test.go`. Those keep their own copies, because the core cannot import `test`.
- [ ] **Step 4: Run** `go test -race ./storetest/...` in `test/`. **Expected:** PASS. The memory stores pass, and the broken variants are caught.
- [ ] **Step 5: Commit** `test(storetest): passkey store suites and race fixtures`

### Task 7.4: `sqlstore` passkey stores

**Files:**
- Create: `internal/pgschema/passkey.go`, `sqlstore/passkeycredential.go`, `sqlstore/passkeyhandle.go`, `test/sqlstore/passkey_test.go`
- Modify: `seal/aad.go` (add `PasskeyEmailCodeAAD(cid id.ID, user identity.UserID) []byte` with prefix `scrty/passkey:email-code:`)

**Interfaces:**
- Produces: `sqlstore.NewPasskeyCredentialStore(db *sql.DB, c seal.Cipher, opts ...Option) (*PasskeyCredentialStore, error)` and `sqlstore.NewPasskeyHandleStore(db *sql.DB, opts ...Option) (*PasskeyHandleStore, error)`.
  - Both take `WithTxResolver` and `WithIDGenerator`.
  - `WithClock` is `ErrConfig`.
  - A nil db, nil cipher or nil option is `ErrConfig`.

- [ ] **Step 1: Write the failing test.** Register under `t.Run("sqlstore", …)` both behavioural suites, all three races, both ambient fixtures, and the sealed-column suite. Add "Insert rolled back with the caller".
- [ ] **Step 2: Run** `go test -run 'Passkey' -count=1 ./sqlstore/...` in `test/`. **Expected:** FAIL (stub constructors return a not-implemented error).
- [ ] **Step 3: Implement** the design D19 SQL, shared in `internal/pgschema/passkey.go`:
  - `RecordAssertion`: `UPDATE passkey_credentials SET sign_count=$2, backup_state=$3, last_used_at=$4 WHERE id=$1 AND state=1 AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`, then check `RowsAffected`.
  - `Suspend`: `UPDATE … SET state=3 WHERE id=$1 AND state=1`.
  - `ClearReason`: `UPDATE … SET pending = pending & ~$3, state = CASE WHEN pending & ~$3 = 0 THEN 1 ELSE state END, email_code = CASE WHEN $3 = 2 THEN NULL ELSE email_code END WHERE id=$1 AND user_id=$2 AND state=2 AND pending & $3 <> 0 RETURNING state`. `$3` is exactly one reason (1 or 2); the driver refuses any other value before the query, as the contract does.
  - `ChargeEmailAttempt`: `UPDATE … SET email_code_attempts = email_code_attempts + 1 WHERE id=$1 AND user_id=$2 AND state=2 AND pending & 2 <> 0 AND email_code IS NOT NULL AND email_code_expires_at > $3 AND email_code_attempts < 5 RETURNING email_code, email_code_expires_at, email_code_attempts`, then open the sealed code.
  - `Insert`: a `23505` violation on `passkey_credentials_credential_id_key` → `passkey.ErrDuplicateCredential`.
  - `Assign`: savepoint or own transaction; `INSERT INTO passkey_user_handles (id,user_id,handle) VALUES ($1,$2,$3) ON CONFLICT (user_id) DO NOTHING`, then `SELECT handle FROM passkey_user_handles WHERE user_id=$1`.
  - `transports`: newline-joined.
- [ ] **Step 4: Run** `go test -race ./sqlstore/...` in `test/`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(sqlstore): passkey credential and handle stores`

### Task 7.5: `pgx` and `gorm` passkey stores

**Files:**
- Create: `pgx/passkeycredential.go`, `pgx/passkeyhandle.go`, `gorm/passkeycredential.go`, `gorm/passkeyhandle.go`; append the models to `gorm/models.go`
- Create: `test/pgxstore/passkey_test.go`, `test/gormstore/passkey_test.go`; add a row to `test/crossbackend`

- [ ] **Step 1: Write the failing tests.** They mirror 7.4's registration per backend. Add the cross-backend row: "a credential inserted through sqlstore is found by credential ID through pgx and gorm with every attribute equal".
- [ ] **Step 2: Run** `go test -run 'Passkey' -count=1 ./pgxstore/... ./gormstore/... ./crossbackend/...` in `test/`. **Expected:** FAIL.
- [ ] **Step 3: Implement** over `internal/pgschema/passkey.go`, with the same option rules. gorm uses `Raw`/`Exec` for the conditional writes, as its recovery stores do. Duplicate detection uses each driver's error code helper.
- [ ] **Step 4: Run** `go test -race ./...` in the `pgx`, `gorm` and `test` modules. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(pgx,gorm): passkey credential and handle stores`

### Task 8.1: `completeLogin` records the proof

**Files:**
- Modify: `httpsec/logincomplete.go` (`completeLogin`)
- Test: `httpsec/logincomplete_proof_test.go`

**Interfaces:**
- Consumes: `policy.Input.SecondFactorAtLogin`, `session.WithSecondFactorAtLogin()`.
- Produces: no signature change. Callers put the proof on `in.SecondFactorAtLogin`, and `postAuthenticationInput` leaves it zero.

- [ ] **Step 1: Write the failing test.** It is a table with a real engine and an in-memory session manager:
  - **"satisfied at creation":** the requirement policy for all, the user holds only passkey lookups, and the input carries a minted proof (from `policy.MintProofForTest`, exposed to `httpsec` tests through an `httpsec/export_test.go` re-export of `assurance.New`). The created session has `MFA==MFASatisfied` and `MFAAtFirstFactor`; one store `Create` and no `Save`; a token with no error.
  - **"password-change still challenges":** add the password-age policy and an old `PasswordChangedAt`. The result is a `ChallengeError{Kind: ChallengePasswordChange}`, and the saved session is satisfied with `PasswordChangePending`.
  - **"zero proof unchanged":** a TOTP-enrolled user gets an MFA challenge.
- [ ] **Step 2: Run** `go test -run 'TestCompleteLogin_Proof' -count=1 ./httpsec/...`. **Expected:** row 1 fails, because the session is `MFANone`.
- [ ] **Step 3: Implement.** After the phase, `if in.SecondFactorAtLogin.Holds() { create = append(create, session.WithSecondFactorAtLogin()) }`, before the first-factor option. The mark for other challenges is unchanged.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): login completion records a second factor met at login`

### Task 8.2: `EnablePasskeys`, registration and confirm endpoints

**Files:**
- Create: `httpsec/passkey.go` (enable, deps, options, interceptor), `httpsec/passkeyregister.go`, `httpsec/passkeyconfirm.go`, `httpsec/passkeyoptions.go`
- Modify: `httpsec/order.go` (`OrderPasskeys Order = 660`, `OrderPasskeyLogin Order = 380`), `httpsec/options.go` (assembly)
- Test: `httpsec/passkeyregister_test.go`, using a mockgen `passkey.Verifier` (`httpsec/passkeyverifier_mock_test.go`). The root module must not require the nested adapter module, so `webauthntest` end-to-end runs belong to 9.1 in the `test` module.

**Interfaces:**
- Produces:
  ```go
  const (
      DefaultPasskeyRegistrationPrefix = "/passkey/register"
      DefaultPasskeyCredentialsPrefix  = "/passkey/credentials"
      DefaultPasswordlessPrefix        = "/passkey/login"
      DefaultPasswordlessCookieName    = "passkey_ceremony"
  )
  type PasskeyDeps struct{ Passkeys *passkey.Manager; Sessions *session.Manager; Users identity.UserLoader }
  type PasskeyOption func(*passkeyInterceptor) error
  func EnablePasskeys(deps PasskeyDeps, opts ...PasskeyOption) Option
  func WithPasskeyRegistrationPrefix(p string) PasskeyOption
  func WithPasskeyCredentialsPrefix(p string) PasskeyOption
  type PasskeyBeginResponder func(ex *Exchange, options json.RawMessage) error
  type PasskeyRegistrationResponder func(ex *Exchange, res *passkey.RegistrationResult) error
  func WithPasskeyBeginResponder(fn PasskeyBeginResponder) PasskeyOption
  func WithPasskeyRegistrationResponder(fn PasskeyRegistrationResponder) PasskeyOption
  ```

- [ ] **Step 1: Write the failing tests.** These are tables through `http.Handler` with a bearer session:
  - **Begin:** 200 with `{"publicKey":…}`.
  - **Finish:**
    - JSON body → 200 with the documented fields and `Cache-Control: no-store`;
    - a form body → missing credentials (401 via `StatusForError`);
    - 70 KiB → 413 and the challenge not spent (the store spy);
    - the assertion in the query → missing credentials;
    - GET on `/passkey/register/finish` passes through.
  - **No bearer:** `ErrAuthenticationRequired`.
  - **Confirm** (form `code`) → 204.
  - **Confined session moved:** a recovery-pending session's finish with an active result gives a session in `MFAPending` with `EnrolmentOriginDeadline` and `RecoveredAt` kept, saved. A pending result leaves the session unchanged.
  - **Consumer prefix** `/account/passkeys` → `/account/passkeys/begin` works.
  - **Path collisions** with logout, login and `/mfa/verify/x` → `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestPasskeyRegistration' -count=1 ./httpsec/...`. **Expected:** FAIL against the stubs.
- [ ] **Step 3: Implement.**
  - The interceptor at `OrderPasskeys` matches POST paths, reads with `postedJSON(r, passkey.RegistrationBodyLimit)` and `postedFieldLimited(r, "code", 4<<10)`, and calls the manager.
  - On an activated credential for a confined session: `s.MFA = session.MFAPending`, then `deps.Sessions.Save`.
  - The default responders write JSON.
  - `RegistrationContext` for an enrolment-pending session comes from the enrolment interceptor's config (wired in 8.3). Until then it is the zero value.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey registration endpoints`

### Task 8.3: Gate exemptions and the enrolment path

**Files:**
- Modify: `httpsec/recoverygate.go`, `httpsec/recoveryoptions.go` (binding-route check), `httpsec/mfaenrol.go`, `httpsec/mfaenroloptions.go`, `httpsec/options.go`
- Test: `httpsec/passkeygates_test.go`, plus a scenario in `policy/enrolmentpath_test.go` ("Passkey registration serves the path", using a lookup stub whose `SupportsEnrolmentPath()` is true on channel `public-key`)

- [ ] **Step 1: Write the failing tests:**
  - **Recovery gate:** a recovery-pending session POSTing to the four registration paths is let through, and GET `/passkey/credentials` gets the account-recovery challenge.
  - **Enrolment gate:** with the passkey method enrolling, the four POSTs pass; GET `/passkey/credentials` gets the enrolment challenge; with `WithEnrolmentMethods("totp")`, `/passkey/register/begin` gets the enrolment challenge.
  - **Assembly:** the passkey method enrolling without `EnablePasskeys` → `ErrConfig`.
  - **Shared settings:** for an enrolment-pending session, `RegistrationContext.EmailConfirmation` follows `WithoutEmailConfirmation()`, and the confirm limiter is the path's.
  - **Recovery wiring:** `EnableAccountRecovery` with only passkey registration plus the passkey method on `EnableMFA` assembles; with none of the three binding routes it fails.
  - **End-to-end (with a verifier mock):** a required-for-all user logs in by password, gets the enrolment challenge, registers, posts the emailed code, begins and verifies at `/mfa/{begin,verify}/passkey`, and ends with a full rotated session.
- [ ] **Step 2: Run** `go test -run 'TestPasskeyGates|TestEnrolmentPath' -count=1 ./httpsec/... ./policy/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.**
  - Both gates read a set of exempt POST paths that the passkey interceptor registers at assembly.
  - The enrolment interceptor's enrolling-method list includes a method implementing `SupportsEnrolmentPath() bool` that is not an `mfa.Enroller`. It marks it "served by passkeys", and assembly requires `EnablePasskeys`.
  - The passkey interceptor gets a read-only view of the enrolment config: email confirmation, confirm limiter and contact resolver.
- [ ] **Step 4: Run** `go test -race ./httpsec/... ./policy/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey registration from enrolment-only and recovery-pending sessions`

### Task 8.4: Management endpoints

**Files:**
- Create: `httpsec/passkeymanage.go`
- Test: `httpsec/passkeymanage_test.go`

**Interfaces:**
- Produces: `type PasskeyListResponder func(ex *Exchange, list []passkey.Summary) error` and `func WithPasskeyListResponder(fn PasskeyListResponder) PasskeyOption`.

- [ ] **Step 1: Write the failing tests:**
  - GET list → 200 `{"passkeys":[…]}` without a public key;
  - POST rename (form `id`, `name`) → 204;
  - POST remove of another user's ID → 404 via `StatusForError`;
  - a stale remove → 403;
  - an invalid `id` text → 404, the same refusal.
- [ ] **Step 2: Run** `go test -run 'TestPasskeyManage' -count=1 ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement** with `id.Parse`. A parse failure is `passkey.ErrNotFound`.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey list, rename and remove`

### Task 8.5: Passwordless login

**Files:**
- Create: `httpsec/passkeylogin.go`
- Modify: `httpsec/passkey.go` (the `WithPasswordlessLogin` wiring check)
- Test: `httpsec/passkeylogin_test.go`

**Interfaces:**
- Produces:
  ```go
  type PasswordlessSetting func(*passwordlessConfig) error
  func WithPasswordlessLogin(settings ...PasswordlessSetting) PasskeyOption
  func PasswordlessPrefix(p string) PasswordlessSetting
  func PasswordlessCookieName(name string) PasswordlessSetting
  func PasswordlessLimiter(l ratelimit.Limiter) PasswordlessSetting       // 30 per 15m, flow "passkey-login"
  func PasswordlessTokens(g token.Generator) PasswordlessSetting           // default: form login's
  func PasswordlessResponder(fn LoginResponder) PasswordlessSetting        // default: form login's
  func PasswordlessBeginResponder(fn PasskeyBeginResponder) PasswordlessSetting
  ```

- [ ] **Step 1: Write the failing tests.** This is a table, with a verifier mock for parse and verify:
  - **Begin:** the cookie attributes exactly match the Global Constraints, `Max-Age=300`, and `Path=/passkey/login/finish`.
  - **31st begin from one source** → throttled, with no token written.
  - **`0.0.0.0`** → `ErrAuthenticationFailed`.
  - **Finish:**
    - no cookie → 401 and a cleared cookie in the response;
    - a bad signature → 401 and a cleared cookie;
    - success → token response, and the session is satisfied with `MFAAtFirstFactor`, recording `passkey`;
    - a disabled user → 401;
    - password age → a password-change challenge carrying a session;
    - a form body → missing credentials;
    - GET finish passes through.
  - **Review Focus 5:** two `passkey_ceremony` cookies where the first is wrong → 401.
  - **Passkeys without passwordless:** POST `/passkey/login/begin` passes through.
  - **Wiring:** passwordless with `passkey.New` lacking `Deps.Recovery` and not optional → `ErrConfig`.
  - **Slot order:** the interceptor runs after `OrderMagicLink` and before `OrderBasicAuth`.
- [ ] **Step 2: Run** `go test -run 'TestPasswordless' -count=1 -race ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.**
  - **Begin:** the source guard check, then 32 random bytes for the cookie value, then `BeginLogin(ctx, value)`, then `Set-Cookie`, then a guard record of every begin (recorded whatever the outcome).
  - **Finish:** a deferred clearing cookie; `postedJSON(r, passkey.AssertionBodyLimit)`; `Authenticate`; `Users.LoadByID` (disabled or unknown → `authenticate.ErrAuthenticationFailed`); `completeLogin(ex, tail, in)` with `in := postAuthenticationInput(principal, factor.Passkey, details.Username, details.PasswordChangedAt, now)` and `in.SecondFactorAtLogin = res.Proof`.
  - **Wiring:** `passkey.Manager` exposes `RequiresRecoveryCodes() bool` (false when `Deps.Recovery` is set or the optional mode is on) for the check. Add that method in this task with its own unit test in `passkey/manager_test.go`.
- [ ] **Step 4: Run** `go test -race -count=3 ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passwordless passkey login`

### Task 8.6: The MFA method over HTTP and the status rows

**Files:**
- Modify: `httpsec/status.go`, its sentinel-coverage test, `httpsec/refusallog.go` (flush the passkey samplers)
- Test: `httpsec/passkeymfa_test.go`, `httpsec/status_test.go`

- [ ] **Step 1: Write the failing tests:**
  - The passkey method on `EnableMFA`: a password login challenge lists `totp`, then `passkey` with a begin step. Begin at `/mfa/begin/passkey` gives options listing active credentials; verify succeeds and rotates.
  - After a non-UV passkey login under `UVPreferred`, `/mfa/verify/passkey` → the same-channel error.
  - Clone and suspended at verify: no failure recorded, 403.
  - Status table rows: every sentinel in Global Constraints and every scenario of the MODIFIED http-error-propagation requirements (403/404/401).
  - `FlushRefusalLogs` on the chain flushes the passkey samplers. Assert via the reporter.
- [ ] **Step 2: Run** `go test -run 'TestPasskeyMFA|TestStatusFor' -count=1 ./httpsec/...`. **Expected:** the status rows fail with 500.
- [ ] **Step 3: Implement** the rows and the flush hook.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`, then `go test ./...` in `fibersec` and `ginsec`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey refusal statuses and the MFA method over HTTP`

### Task 9.1: Conformance scenarios

**Files:**
- Create: `test/httpsecconformance/passkey_scenarios.go`
- Modify: `test/httpsecconformance/scenarios.go` (register them), `test/go.mod` (require `github.com/kartaladev/scrty/passkey/webauthn`)

- [ ] **Step 1: Write the scenarios,** each driven by `webauthntest` over the durable sqlstore backend on net/http, gin and fiber:
  - register, then passwordless login → a full session satisfied at login, reaching `/invoices`;
  - password plus the passkey second factor;
  - a counter regressed → 403 clone, then a TOTP-satisfied fresh session removes it;
  - a passwordless-only first passkey: codes returned, confirm, then login;
  - recovery → passkey registration → `/mfa/verify/passkey` → full session;
  - an enrolment-only user registers with the emailed code (the recording sender) and then verifies.
- [ ] **Step 2: Run** `go test -run 'Passkey' -count=1 ./...` in `test/`. **Expected:** the scenarios fail until registered and wired, then pass. A scenario that passes before it is wired is wrong, so check that it fails first.
- [ ] **Step 3: Run** `go vet ./...` and `go test -race ./...` in `test/` (needs Docker). **Expected:** PASS.
- [ ] **Step 4: Commit** `test(conformance): passkey scenarios across the chain and adapters`

### Task 9.2: README and examples

**Files:**
- Modify: `README.md` (a passkeys section)
- Create: `passkey/example_test.go`, `passkey/webauthn/example_test.go`

- [ ] **Step 1: Write** `Example` functions first: wiring the relying party, `webauthn.New`, `passkey.New` with stores, sender, `RecoveryDeps` and the way-back check including `RecoveryKind()`, `httpsec.EnablePasskeys(..., WithPasswordlessLogin())`, and `EnableMFA` with `MFAMethod()`. Each ends with a deterministic `// Output:` line, for example printing that construction succeeded.
- [ ] **Step 2: Run** `go test -run Example -count=1 ./passkey/...` and the same in `passkey/webauthn`. **Expected:** FAIL until the output matches, then PASS.
- [ ] **Step 3: Write the README section,** mirroring the examples verbatim. It states:
  - changing the relying-party ID orphans every passkey;
  - users are advised to hold two passkeys, one synced;
  - the optional recovery mode allows operator-only recovery;
  - attestation is off by default.
- [ ] **Step 4: Commit** `docs: passkeys in the README, with compiled examples`

### Task 9.3: Close out (main session)

- [ ] Run across every module in `go.work`: `go build ./...`, `go vet ./...`, `gofmt -l .` (empty), `go test -race ./...`, `govulncheck ./...` in `passkey/webauthn`, `make check`, and `openspec validate passkey-authentication --strict`.
- [ ] Dispatch one whole-branch reviewer against every requirement in this change's spec deltas. Findings go back to fresh dispatches of the owning lane.
