# mfa-multi-method Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the single-method MFA slot into one that holds several methods. Each method has its own path, a declared response format, and an optional server-issued challenge. One definition of "usable method" is shared by the policies, the verify, begin and listing endpoints, and the MFA challenge error.

**Architecture:**
- `policy` owns the lookup port and `UsableMFAMethods`, because `mfa` imports `policy`.
- `mfa` owns the method port, the response formats, the challenge-method port, `LookupsFor` and the reset.
- `httpsec` owns the two body readers, and the verify, begin, listing and enrolment endpoints, all driven from the path.
- Pending challenges are one-time tokens bound to the session handle.
- No store contract or schema changes (design D1).

**Tech Stack:** Go 1.27, `onetime` (pending challenges), clockwork fakes in tests, testify, gopls, and testcontainers (the `test` module).

**Spec:** `openspec/changes/mfa-multi-method/` — `proposal.md`, `design.md` (D1–D12), `specs/multi-factor-auth`, `specs/security-policy`, `specs/http-error-propagation`, `specs/http-security-chain`, and `tasks.md`. Task numbers below (`1.1`…`6.3`) are `tasks.md`'s.

## Global Constraints

- **Method names** are one path segment: `[a-z0-9][a-z0-9-]*`. TOTP is named `totp`.
- **Response formats:** `mfa.FormField(name, limit)` or `mfa.JSONBody(limit)`. The limit is in `(0, 1 MiB]`, and a form-field name is non-empty. TOTP uses `FormField("code", 4<<10)`.
- **Default paths:**
  - verify prefix `/mfa/verify`;
  - begin prefix `/mfa/begin`;
  - listing path `/mfa/methods` (off by default);
  - enrolment prefixes `/mfa/enrol/begin`, `/mfa/enrol/confirm` and `/mfa/enrol/confirm-email`.
- **Pending challenges** are one-time tokens:
  - purpose `mfa-challenge:<name>`;
  - subject the user;
  - bound to the session handle with `onetime.WithBinding`;
  - default TTL 5 minutes;
  - default in-memory store.
- **Challenge spending:** a challenge is spent by every attempt that presents it (Check, then Consume, then Verify).
- **The method choice is read from the path only**, never from a header, the query or the body.
- **Refusals before the body is read**, in this order: no session or no caller (401), unknown method (404), same channel (403), not usable (403). None of them is counted.
- **The throttle** has one key per user (`mfa-verify|<user>`) across all methods.
- **New sentinels:**
  - `httpsec.ErrUnknownMFAMethod` (404);
  - `httpsec.ErrMFAMethodNotUsable` (403);
  - `httpsec.ErrNoMFAChallengePending` (403).

  A refused pending challenge is `mfa.ErrInvalidCode` (401).
- **A lookup error is a refusal, never a shorter list.** `ChallengeError.Error()` text is unchanged and names no method.
- **Configuration errors:**
  - `mfa.LookupsFor` → `mfa.ErrConfig`;
  - policy constructors → `policy.ErrConfig`;
  - `httpsec` options → `httpsec.ErrConfig` (through `newConfigError`).

  An explicitly passed empty path, nil responder or empty list is refused, never read as the default.
- **Godoc:** every new option names its default (`library-design.md`).
- **Test-first** (`golang-tdd.md`): red for the intended reason, where a compile error is not red. Tables follow the `table-test` skill.
- **Test doubles:** generated with mockgen where an interface is mocked (`use-mockgen` skill). A hand-written challenge-method test double is fine where behaviour must be scripted.
- **No git command that discards work.** No edit under `openspec/`. The legacy snapshot is never read, copied or cited.

## Review Focus

1. **Two concurrent verifies presenting the same challenge.** Expected: exactly one reaches the method's `Verify`, and the other is refused as an invalid code. Pinned in 4.2.
2. **An empty or extra path segment** (`/mfa/verify/`, `/mfa/verify/totp/`, `/mfa/verify/totp/x`). Expected: refused as an unknown method (404), never a panic and never a match. Pinned in 3.2.
3. **`PresentedChallenge` fails on a malformed response.** Expected: invalid code, counted, and the method's `Verify` not called. Pinned in 4.2.
4. **A pending session whose user now has no usable method**, for example an enrolment removed mid-session. Expected: the gate still returns the MFA challenge, with an empty method list (the lookups succeeded), so the client can only log out. Only a lookup error replaces the challenge. Pinned in 4.3.
5. **POST or HEAD to the listing path.** Expected: not answered by the listing (passes through), exactly as a GET to a verify path passes through. Pinned in 5.1.

---

## Dispatch map

The six groups run **in sequence**, one dispatch each. The work does not parallelise, and here is why:
- `mfa` imports `policy`, and `httpsec` builds on both. Each group changes signatures the next group compiles against.
- Every group's callers include shared `httpsec` test files: `mfaverify_test.go`, `mfaenrole2e_test.go`, `example_enrolment_test.go` and others.

Each group leaves the whole workspace compiling and green, including the `test` module, so the group owns every caller of what it changes.

| Order | Tasks | Owns | Model | Why |
|---|---|---|---|---|
| 1 | 1.1–1.3 | `policy/**`, and every caller of `NewMFAPolicy`, `NewMFARequirementPolicy` and `MFAMethodLookup` test doubles in `mfa/`, `httpsec/` and `test/` | Opus | Security refusal logic, and an interface later groups compile against |
| 2 | 2.1–2.3 | `mfa/**`, `httpsec/mfaverify.go` (bytes hand-off only), and every caller of `LookupFor`/`Verify`/`ResetDeps` | Opus | Port change across packages |
| 3 | 3.1–3.3 | `httpsec/**` (verify path, readers, status) and the `test` module's `EnableMFA` callers | Opus | Refusal ordering before the body is read |
| 4 | 4.1–4.3 | `httpsec/**` (begin, challenges, challenge error), `fibersec`/`ginsec` tests if affected | Opus | A spend-on-every-attempt variant of check-then-consume; concurrency |
| 5 | 5.1–5.2 | `httpsec/**` (listing, enrolment prefixes), `test/httpsecconformance` enrolment callers | Opus | Settings-in-option wiring, and an enrolment refactor across several files |
| 6 | 6.1 | `test/**` | Sonnet | Mechanical move of the conformance scenarios |
| 7 | 6.2 | `README.md` | Sonnet | Documentation snippet, compiled in a scratch copy |
| — | 6.3 | main session | — | Final gate and whole-branch review |

---

### Task 1.1: `MFAMethodLookup.Name` and `UsableMFAMethods`

**Files:**
- Modify: `policy/mfa.go:56` (the port)
- Create: `policy/usable.go`, `policy/usable_test.go`
- Modify: every `MFAMethodLookup` test double in the workspace (find them with `gopls implementation` on `policy.MFAMethodLookup`)

**Interfaces:**
- Produces:
  ```go
  type MFAMethodLookup interface {
      Name() string
      Channel() factor.Channel
      Enrolled(ctx context.Context, user identity.UserID) (bool, error)
  }
  func UsableMFAMethods(ctx context.Context, methods []MFAMethodLookup, user identity.UserID, first factor.Kind) ([]MFAMethodLookup, error)
  ```

- [ ] **Step 1: Write the failing test** (`policy/usable_test.go`)

```go
func TestUsableMFAMethods(t *testing.T) {
	t.Parallel()

	storeDown := errors.New("store down")
	totp := lookupStub{name: "totp", channel: factor.AuthenticatorApp, enrolled: true}
	email := lookupStub{name: "email-code", channel: factor.Email, enrolled: true}

	type testCase struct {
		name    string
		methods []policy.MFAMethodLookup
		first   factor.Kind
		assert  func(t *testing.T, got []policy.MFAMethodLookup, err error)
	}

	names := func(ms []policy.MFAMethodLookup) []string {
		out := make([]string, 0, len(ms))
		for _, m := range ms {
			out = append(out, m.Name())
		}
		return out
	}

	cases := []testCase{
		{
			name: "usable methods in configuration order", methods: []policy.MFAMethodLookup{totp, email}, first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp", "email-code"}, names(got))
			},
		},
		{
			name: "a method on the first factor's channel is not usable", methods: []policy.MFAMethodLookup{totp, email}, first: factor.MagicLink,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp"}, names(got))
			},
		},
		{
			name: "a failed lookup is an error, not a shorter list",
			methods: []policy.MFAMethodLookup{totp, lookupStub{name: "email-code", channel: factor.Email, err: storeDown}}, first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, storeDown)
				assert.Nil(t, got)
			},
		},
		{
			name: "not enrolled anywhere is an empty list, not an error",
			methods: []policy.MFAMethodLookup{lookupStub{name: "totp", channel: factor.AuthenticatorApp}}, first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := policy.UsableMFAMethods(t.Context(), tc.methods, "u-1", tc.first)
			tc.assert(t, got, err)
		})
	}
}
```

`lookupStub` goes in `policy/usable_test.go`. It is a value type with `name`, `channel`, `enrolled` and `err` fields and the three methods. Reuse an existing policy test stub if one already has this shape, and add `Name` to it.

- [ ] **Step 2: Run it to see it fail.** First add `Name()` to the port and a `UsableMFAMethods` stub that returns `nil, nil`, so the package compiles. Run: `go test -run TestUsableMFAMethods -count=1 ./policy/`. Expected: FAIL on the first, second and third rows (an empty list, or no error).
- [ ] **Step 3: Implement**

```go
// UsableMFAMethods reports which of methods the user can use as a second factor
// after logging in with first: those the user is enrolled on whose channel
// differs from first's, in the order given. It is the one definition of
// "usable" the MFA policies and the chain share, exported so a consumer can
// list methods themselves. Any lookup error is returned as it is, and never
// yields a shorter list: a lost or unreadable enrolment must not look like
// "not enrolled".
func UsableMFAMethods(ctx context.Context, methods []MFAMethodLookup, user identity.UserID, first factor.Kind) ([]MFAMethodLookup, error) {
	var usable []MFAMethodLookup
	for _, m := range methods {
		enrolled, err := m.Enrolled(ctx, user)
		if err != nil {
			return nil, err
		}
		if enrolled && m.Channel() != first.Channel() {
			usable = append(usable, m)
		}
	}
	return usable, nil
}
```

- [ ] **Step 4: Add `Name` to every test double.** Use gopls implementations and diagnostics across the workspace (core module, `test` module). Run `go build ./...` and `go vet ./...` in the core and `test` modules. Expected: clean. Then run `go test -race -count=1 ./policy/...`. Expected: PASS.

### Task 1.2: `NewMFAPolicy` over a set

**Files:**
- Modify: `policy/mfa.go` (constructor from about line 261, `Evaluate` from about line 320)
- Test: `policy/mfa_test.go`, `policy/samechannel_test.go`
- Modify: every caller of `NewMFAPolicy`: `httpsec/*_test.go`, `policy/*_test.go`, `test/httpsecconformance/enrolment_scenarios.go`

**Interfaces:**
- Consumes: `UsableMFAMethods` (1.1).
- Produces: `func NewMFAPolicy(methods []MFAMethodLookup, opts ...MFAOption) (Policy, error)`.

- [ ] **Step 1: Write the failing tests.** In `TestNewMFAPolicy`, add construction rows asserting `require.ErrorIs(t, err, policy.ErrConfig)` for:
  - `nil` (empty set);
  - `[]MFAMethodLookup{nil}`;
  - `[]MFAMethodLookup{(*lookupPtr)(nil)}`;
  - two stubs named `totp`.

  In `TestMFAPolicyEvaluate`, add evaluation rows, each asserting its outcome kind:
  - "enrolled on the second of two methods" (TOTP not enrolled, `email-code` enrolled, password login): challenge;
  - "one method's lookup fails" (TOTP enrolled, second lookup errors): deny wrapping the error;
  - "a usable method alongside a same-channel one" (magic link; email enrolled, TOTP enrolled): challenge;
  - "enrolled only on same-channel methods" (magic link; only email enrolled): deny with `ErrSecondFactorSameChannel`, and with `WithSameChannelEnrolment(complete)` allow.

  Convert existing single-method callers to `[]policy.MFAMethodLookup{m}`.
- [ ] **Step 2: Run** `go test -run 'TestNewMFAPolicy|TestMFAPolicyEvaluate' -count=1 ./policy/`. Expected: build fails until the signature changes. Change only the signature to take the slice and use `methods[0]`, and construct without the new checks. Expected FAIL: the empty/duplicate/typed-nil construction rows, and "enrolled on the second of two methods" (method 0 is not enrolled).
- [ ] **Step 3: Implement.** Validate the set (non-empty, `nilcheck.IsNil` per entry, unique `Name()`), each failure wrapping `ErrConfig`. `Evaluate`:

```go
if in.MFA == MFASatisfied || p.exempt(in.FirstFactor) { return allow }
usable, err := UsableMFAMethods(ctx, p.methods, in.UserID, in.FirstFactor)
if err != nil { return denyWrapping(err) }          // existing fixed-text wrap
if len(usable) > 0 { return challenge(ChallengeMFA) }
enrolledSameChannel, err := p.enrolledOnAny(ctx, in.UserID) // any method enrolled at all
if err != nil { return denyWrapping(err) }
if enrolledSameChannel { return p.decideSameChannel(ctx, in) } // unchanged helper
return allow
```

`enrolledOnAny` loops `Enrolled` and returns true on the first enrolled method. A user with usable methods never reaches it; a user with none reaches it only when every enrolled method is on the first factor's channel. Keep the existing sampling, logger and clock behaviour unchanged.
- [ ] **Step 4: Update every caller.** Wrap single lookups as `[]policy.MFAMethodLookup{lookup}`; gopls references list them. Run `go test -race -count=1 ./policy/... ./mfa/... ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS and clean.

### Task 1.3: `NewMFARequirementPolicy` over a set

**Files:**
- Modify: `policy/mfarequirement.go` (constructor at about line 230, `hasUsableEnrolment` at about line 411), `policy/enrolmentpath.go` (`admits` at about line 160)
- Test: `policy/mfarequirement_test.go`, `policy/enrolmentpath_test.go`
- Callers: `httpsec/*_test.go`, `mfa/failclosed_test.go`, `test/httpsecconformance/enrolment_scenarios.go`

**Interfaces:**
- Produces: `func NewMFARequirementPolicy(required identity.MFARequirementLookup, methods []MFAMethodLookup, opts ...MFARequirementOption) (Policy, error)`.
- Unexported in `policy`: `type enrolmentPathCapable interface{ SupportsEnrolmentPath() bool }`.

- [ ] **Step 1: Write the failing tests.** Construction rows (`ErrConfig`):
  - required-for-all with an empty set;
  - an absent entry;
  - duplicate names.

  An empty set without required-for-all constructs, and evaluation denies with `ErrMFARequired`. Evaluation rows:
  - "Only a method that cannot enrol on another channel": email stub supporting the path, and an authenticator stub without `SupportsEnrolmentPath` (or returning false); a required, unenrolled user logs in by magic link with the path on. Deny with `ErrMFAEnrollmentRequired`.
  - "Only method on the first factor's channel", reworded to a set of one email stub: deny.
  - "any lookup failure denies" with two methods, the second erroring: deny.
  - "usable on the second method" (flagged mid-session): per request, an MFA challenge.

  Add test stubs with and without `SupportsEnrolmentPath() bool`.
- [ ] **Step 2: Run** `go test -run 'TestNewMFARequirementPolicy|TestMFARequirement|TestMFARequirementEnrolmentPath' -count=1 ./policy/`. After a signature-only change (use `methods[0]` when non-empty), expected FAIL: the construction rows, and "Only a method that cannot enrol on another channel" (method 0 is email on the same channel, and the check only looks at method 0 — whichever order produces the wrong outcome, record it).
- [ ] **Step 3: Implement.**
  - `hasUsableEnrolment` becomes `len(UsableMFAMethods(...)) > 0`, with the error denying.
  - `admits` ends with:

```go
for _, m := range methods {
	if c, ok := m.(enrolmentPathCapable); ok && c.SupportsEnrolmentPath() && m.Channel() != in.FirstFactor.Channel() {
		return true
	}
}
return false
```

  Update the godoc on both constructors to say they are built over the same methods given to `httpsec.EnableMFA` (`mfa.LookupsFor` builds this list).
- [ ] **Step 4: Update the callers.** Run `go test -race -count=1 ./policy/... ./mfa/... ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS.

---

### Task 2.1: Response formats and a byte-level `Verify`

**Files:**
- Create: `mfa/response.go`, `mfa/response_test.go`
- Modify: `mfa/mfa.go:87` (the `Method` port), `mfa/totp.go:134-200` (name, `Response`, `Verify`), `httpsec/mfaverify.go` (`Verify` call site only)
- Callers: every `Method` test double and every `Verify(…, "code")` call site (gopls)

**Interfaces:**
- Produces:
  ```go
  type ResponseKind int
  const (
      ResponseFormField ResponseKind = iota + 1
      ResponseJSONBody
  )
  type ResponseFormat struct{ kind ResponseKind; field string; limit int64 }
  func FormField(name string, limit int64) ResponseFormat
  func JSONBody(limit int64) ResponseFormat
  func (f ResponseFormat) Kind() ResponseKind
  func (f ResponseFormat) Field() string
  func (f ResponseFormat) Limit() int64
  // Method gains:
  Response() ResponseFormat
  Verify(ctx context.Context, user identity.UserID, response []byte) error
  ```

- [ ] **Step 1: Write the failing tests.**
  - `mfa/response_test.go`: a table checking that `FormField("code", 4096)` reports its kind, field and limit, and that `JSONBody(16<<10)` reports `ResponseJSONBody`, an empty field and `16384`.
  - `mfa/totp_test.go`: a row asserting `totp.Name() == "totp"` and `totp.Response() == mfa.FormField("code", 4<<10)`, and that `totp.Verify(ctx, user, []byte(validCode))` succeeds.
- [ ] **Step 2: Run** `go test -run 'TestResponseFormat|TestTOTP' -count=1 ./mfa/`. To get a real red: add the types with a `Kind()` that returns 0, and a `Response()` on TOTP that returns the zero `ResponseFormat`. Expected FAIL on kind, limit and equality.
- [ ] **Step 3: Implement** the constructors and getters. `TOTP.Verify(ctx, user, response []byte)` calls the existing code path with `string(response)`. In `httpsec/mfaverify.go` the call becomes `i.method.Verify(ctx, user, []byte(code))`. Its behaviour is unchanged until 3.1.
- [ ] **Step 4: Update the callers.** Run `go test -race -count=1 ./mfa/... ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS.

### Task 2.2: `ChallengeMethod` and `LookupsFor`

**Files:**
- Modify: `mfa/mfa.go` (replace `LookupFor` at about line 116), `mfa/lookup_test.go`
- Callers: `httpsec/options.go:1043` and every `LookupFor` caller (gopls: `httpsec` tests, `mfa` tests, `test/httpsecconformance`)

**Interfaces:**
- Produces:
  ```go
  type ChallengeMethod interface {
      Method
      BeginChallenge(ctx context.Context, user identity.UserID, challenge string) (json.RawMessage, error)
      PresentedChallenge(response []byte) (string, error)
  }
  func LookupsFor(methods ...Method) ([]policy.MFAMethodLookup, error)
  ```

- [ ] **Step 1: Write the failing test.** `TestLookupsFor` is a table; each refusal row asserts `require.ErrorIs(t, err, mfa.ErrConfig)`:
  - no methods;
  - `nil`;
  - a typed-nil `*TOTP`;
  - an empty channel;
  - names `""`, `"TOTP"`, `"a/b"`, `"-x"`;
  - two methods named `totp`;
  - `FormField("code", 0)`, `FormField("code", 1<<20+1)`, `FormField("", 10)`, `JSONBody(-1)`;
  - a zero `ResponseFormat{}`.

  One success row, TOTP plus a stub named `email-code`, returns two lookups in order.
- [ ] **Step 2: Run** `go test -run TestLookupsFor -count=1 ./mfa/`. To get a real red: a `LookupsFor` that only checks for an empty list and nil. Expected FAIL on the typed-nil, name, duplicate and format rows.
- [ ] **Step 3: Implement** it with `nilcheck.IsNil`, `regexp.MustCompile("^[a-z0-9][a-z0-9-]*$")`, a seen-names set, and a format check (`kind` is one of the two; `0 < limit <= 1<<20`; a form field has a name). Each failure is `fmt.Errorf("%w: …", ErrConfig)` naming the method's position and the mistake. Remove `LookupFor`. In `httpsec/options.go`, `EnableMFA` still takes one method until 3.2, and calls `mfa.LookupsFor(method)`.
- [ ] **Step 4: Update the callers.** Run `go test -race -count=1 ./mfa/... ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS.

### Task 2.3: Reset over every method

**Files:** Modify `mfa/reset.go` (`ResetDeps`, the dependency check, the removal loop at about lines 192–260). Test: `mfa/reset_test.go`.

**Interfaces:** `ResetDeps.Enrolments []EnrolmentRemover`.

- [ ] **Step 1: Write the failing tests.** Rows in the reset table:
  - "reset across methods": two removers, both called for `u-1`, sessions deleted, notification queued;
  - "a removal fails": the second remover errors; the reset returns it, the first remover was called, the session revoker was not called, and the sender was not called;
  - "no removers": `Enrolments: nil` gives `ErrConfig`, and neither the revoker nor the sender is called;
  - "an absent remover": `[]EnrolmentRemover{nil}` gives `ErrConfig`.

  Update the existing rows to pass a one-element slice.
- [ ] **Step 2: Run** `go test -run TestResetEnrolment -count=1 ./mfa/`. To get a real red: a loop that removes only through `Enrolments[0]`. Expected FAIL on "reset across methods" and "a removal fails".
- [ ] **Step 3: Implement.** Check the list is non-empty and every entry is non-nil in `check` (before any write). Remove in order, returning the first failure wrapped as today. Sessions and notification follow unchanged.
- [ ] **Step 4: Run** `go test -race -count=1 ./mfa/...` plus the gopls references on `ResetDeps` (update any other caller). Expected: PASS.

---

### Task 3.1: The JSON reader

**Files:**
- Create: `httpsec/postedjson.go`, `httpsec/postedjson_test.go`
- Modify: `httpsec/postedfield.go` (so it takes a limit)

**Interfaces:**
- Produces (unexported):
  ```go
  func postedFieldLimited(r Request, name string, limit int64) (string, error) // postedField keeps 4 KiB
  func postedJSON(r Request, limit int64) ([]byte, error)
  func readResponse(r Request, f mfa.ResponseFormat) ([]byte, error)             // dispatches on f.Kind()
  ```

- [ ] **Step 1: Write the failing test** `TestReadResponse`. It is a table over a fake `Request` (use the package's existing test request helper) with a method format per row:
  - a form of `code=123456` gives `[]byte("123456")`;
  - a JSON 6 KiB document with `application/json`, under a 16 KiB `JSONBody`, gives the same bytes;
  - `application/vnd.x+json` is accepted;
  - URL-encoded to a JSON method gives `ErrCredentialsMissing`;
  - an empty JSON body gives `ErrCredentialsMissing`;
  - invalid JSON (`{`) gives `ErrCredentialsMissing`;
  - a 5 KiB form to a 4 KiB field gives `ErrRequestTooLarge`;
  - a JSON body over its limit gives `ErrRequestTooLarge`;
  - a code only in the query gives `ErrCredentialsMissing`.
- [ ] **Step 2: Run** `go test -run TestReadResponse -count=1 ./httpsec/`. To get a real red: a `readResponse` that always calls `postedField(r, "code")`. Expected FAIL on the JSON rows.
- [ ] **Step 3: Implement.** `postedJSON`: `r.Body(limit)`; too large gives `ErrRequestTooLarge`; a transport error gives `refusedAs(ErrCredentialsMissing, …)`; `!declaresJSON(r.Header("Content-Type"))`, empty, or `!json.Valid(body)` gives `ErrCredentialsMissing`; otherwise it returns the body. `readResponse` switches on `f.Kind()`. Wire it into `verify`: `response, err := readResponse(ex.Request, i.method.Response())`, then `i.method.Verify(ctx, user, response)`.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected: PASS, with `TestVerifyReadsBodyOnly` still green.

### Task 3.2: `EnableMFA` over a set, with per-method verify paths

**Files:**
- Modify:
  - `httpsec/options.go:1001-1190` (`EnableMFA`, `WithMFAVerifyPath` becomes `WithMFAVerifyPrefix`);
  - `httpsec/mfaverify.go` (struct: `methods []mfa.Method`, `byName map[string]mfa.Method`, `lookups []policy.MFAMethodLookup`, `verifyPrefix string`; `isVerifyRequest`; `verify`);
  - `httpsec/errors.go` (sentinels).
- Create: `httpsec/mfapath.go` (segment parsing shared with begin and listing).
- Test: `httpsec/mfaverify_test.go`, `httpsec/mfagate_test.go`.
- Callers: every `EnableMFA` call in `httpsec/*_test.go` and `test/httpsecconformance/*`.

**Interfaces:**
- Produces:
  ```go
  func EnableMFA(methods []mfa.Method, opts ...MFAOption) Option
  func WithMFAVerifyPrefix(prefix string) MFAOption
  const DefaultMFAVerifyPrefix = "/mfa/verify"
  var ErrUnknownMFAMethod = errors.New("httpsec: unknown MFA method")
  var ErrMFAMethodNotUsable = errors.New("httpsec: MFA method not usable")
  // mfapath.go (unexported):
  func methodSegment(path, prefix string) (name string, ok bool) // ok only for prefix + "/" + one non-empty segment
  ```

- [ ] **Step 1: Write the failing tests** in `TestMFAVerify`, a table over a chain built with TOTP plus a stub method `email-code` (channel `email`, response `FormField("code", 4<<10)`). Each row states its request and asserts:
  - "successful verification" to `/mfa/verify/totp`: resolved, and the handle rotated;
  - "unknown method" to `/mfa/verify/sms`: `ErrUnknownMFAMethod`, no body read (use a request whose `Body` fails the test if called), no failure counted;
  - "method the user is not enrolled on" (`email-code` not enrolled) to `/mfa/verify/email-code`: `ErrMFAMethodNotUsable`, stub `Verify` not called, not counted;
  - "same channel": a magic-link session to `/mfa/verify/email-code` gives `mfa.ErrSameChannel`;
  - "lookup error propagates": the stub's `Enrolled` errors; that error is returned (maps to 500), not counted;
  - "method named in the query or body is ignored": `/mfa/verify/totp?method=email-code` with body `code=<valid>&method=email-code` is resolved by TOTP;
  - "empty and extra segments" (Review Focus 2): `/mfa/verify/`, `/mfa/verify/totp/`, `/mfa/verify/totp/x` each give `ErrUnknownMFAMethod`;
  - "GET passes through";
  - "consumer path": `WithMFAVerifyPrefix("/auth/second-factor")`, and `/auth/second-factor/totp` is resolved;
  - "guessing across methods": three wrong answers to TOTP and two to `email-code`, then a valid TOTP code, gives `mfa.ErrVerifyThrottled`.

  In `TestEnableMFA`, construction rows:
  - `EnableMFA(nil)`;
  - duplicate names;
  - `WithMFAVerifyPrefix("")`, `("/")` and `("mfa")` give `ErrConfig`.

  In `TestMFAGateVerifyExempt`, every `/mfa/verify/<name>` is exempt, and a pending session posting to `/mfa/verify/sms` gets `ErrUnknownMFAMethod`, not a challenge.
- [ ] **Step 2: Run** `go test -run 'TestMFAVerify|TestEnableMFA|TestMFAGate' -count=1 ./httpsec/`. To get a real red: change `EnableMFA` to take the slice but keep matching only `DefaultMFAVerifyPath` for `methods[0]`. Expected FAIL on the path, unknown-method and not-usable rows.
- [ ] **Step 3: Implement** `verify` in the order D5 fixes:

```go
name, ok := methodSegment(ex.Request.Path(), i.verifyPrefix)
// isVerifyRequest: POST and path under prefix (ok or not — a bad segment is still ours to refuse)
s := sessionFrom(ex) // existing lookups
if s == nil { return ErrAuthenticationRequired }
if ex.Authentication == nil || ex.Authentication.Principal == nil { return ErrAuthenticationRequired }
m, known := i.byName[name]
if !ok || !known { return ErrUnknownMFAMethod }
if m.Channel() == s.FirstFactor.Channel() { return mfa.ErrSameChannel }
usable, err := policy.UsableMFAMethods(ctx, i.lookups, s.UserID, s.FirstFactor)
if err != nil { return err }
if !contains(usable, name) { return ErrMFAMethodNotUsable }
if err := i.throttle.Check(ctx, s.UserID); err != nil { return err }
response, err := readResponse(ex.Request, m.Response())
if err != nil { return err }
if err := m.Verify(ctx, s.UserID, response); err != nil { i.throttle.RecordFailure(ctx, s.UserID); return err }
return i.resolve(ex, s)
```

`isVerifyRequest` is POST with a path equal to the prefix or starting with `prefix + "/"`. The gate exempts the same test. `WithMFAVerifyPrefix` normalises and validates like `oidcPrefix`. `EnableMFA` calls `mfa.LookupsFor(methods...)` and turns a failure into a config error. The godoc names the default prefix and says the policies must be built from the same methods.
- [ ] **Step 4: Update every `EnableMFA` caller** to `EnableMFA([]mfa.Method{totp}, …)`, and every `DefaultMFAVerifyPath` use to `DefaultMFAVerifyPrefix + "/totp"`. Run `go test -race -count=1 ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS.

### Task 3.3: Status rows and the gate exemption

**Files:** Modify `httpsec/status.go:24`. Test: `httpsec/status_test.go`.

- [ ] **Step 1: Write the failing test.** Rows in `TestStatusForError`: `ErrUnknownMFAMethod` gives 404; `fmt.Errorf("x: %w", ErrMFAMethodNotUsable)` gives 403. `TestStatusForErrorCoversEverySentinel` picks up both through its sentinel list; add them there if the list is explicit.
- [ ] **Step 2: Run** `go test -run TestStatusForError -count=1 ./httpsec/`. Expected: FAIL, 500 instead of 404 and 403.
- [ ] **Step 3: Implement.** Add the two table entries.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected: PASS.

---

### Task 4.1: The begin endpoint and pending challenges

**Files:**
- Create: `httpsec/mfabegin.go`, `httpsec/mfabegin_test.go`, `httpsec/mfachallenge_stub_test.go` (a scripted `mfa.ChallengeMethod` test double)
- Modify: `httpsec/options.go` (new options), `httpsec/mfaverify.go` (`Intercept` routes begin, the gate exempts the begin prefix, `wireMFA` builds one `onetime.Manager` per challenge method)

**Interfaces:**
- Consumes: `mfa.ChallengeMethod` (2.2), `methodSegment` (3.2).
- Produces:
  ```go
  const DefaultMFABeginPrefix = "/mfa/begin"
  const DefaultMFAChallengeTTL = 5 * time.Minute
  func WithMFABeginPrefix(prefix string) MFAOption
  func WithMFAChallengeTTL(d time.Duration) MFAOption       // <= 0 refused
  func WithMFAChallengeStore(s onetime.Store) MFAOption      // nil / typed nil refused
  type MFABeginResponder func(ex *Exchange, data json.RawMessage) error
  func WithMFABeginResponder(fn MFABeginResponder) MFAOption // nil refused
  // internal: i.challenges map[string]*onetime.Manager, keyed by method name
  ```

  The scripted double `challengeStub` has name `passkey`, channel `factor.Channel("authenticator-device")` (a test-only channel value), `JSONBody(16<<10)`, and scripted `Enrolled`. `BeginChallenge` returns `{"challenge":"<c>"}`. `PresentedChallenge` reads the `challenge` field of the JSON response. `Verify` records calls and returns a scripted error.

- [ ] **Step 1: Write the failing tests** in `TestMFABegin`:
  - "begin issues a challenge": a pending session POSTs `/mfa/begin/passkey`, and the response body is the stub's JSON, whose challenge is non-empty;
  - "begin for a method without a begin step": `/mfa/begin/totp` gives `ErrUnknownMFAMethod`;
  - "pending session begins a challenge method": the gate does not challenge `/mfa/begin/passkey`;
  - "begin while throttled": five recorded failures, then begin gives `mfa.ErrVerifyThrottled`;
  - "same channel" and "not usable" rows as in verify;
  - "consumer begin responder": the responder receives the stub's data;
  - construction: `WithMFABeginPrefix("")`, a prefix equal to the verify prefix, `WithMFAChallengeTTL(0)`, `WithMFAChallengeStore(nil)` and `WithMFABeginResponder(nil)` each give `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestMFABegin' -count=1 ./httpsec/`. To get a real red: add the options, and a begin route that returns `ErrUnknownMFAMethod` for every name. Expected FAIL on the issue, gate and responder rows.
- [ ] **Step 3: Implement.** In `wireMFA`, for each method that is an `mfa.ChallengeMethod`:

```go
m, err := onetime.NewManager("mfa-challenge:"+name, onetime.WithTTL(i.challengeTTL), onetime.WithStore(i.challengeStore))
```

The default store is `onetime.NewMemoryStore()`, shared by all methods; the purposes keep them apart. Begin runs the same prefix of checks as verify (session, caller, method known **and** a `ChallengeMethod`, channel, usable), then `throttle.Check`, then:

```go
tok, _, err := mgr.Issue(ctx, string(s.UserID), onetime.WithBinding(s.ID))
data, err := cm.BeginChallenge(ctx, s.UserID, tok)
return i.beginResponder(ex, data) // default: 200, Content-Type application/json, body data
```

It answers the request itself. Godoc on `WithMFAChallengeStore` states the in-memory default serves a single process.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected: PASS.

### Task 4.2: Verify spends the challenge on every attempt

**Files:** Modify `httpsec/mfaverify.go` (`verify`, between reading and `Verify`). Test: `httpsec/mfabegin_test.go` (the `TestMFAChallengeVerify` table).

- [ ] **Step 1: Write the failing tests.** Rows, each using begin then verify through the chain:
  - "begin then verify": resolved;
  - "one try per challenge": the stub refuses the first attempt; the second attempt with the same challenge gives `mfa.ErrInvalidCode` with the stub's `Verify` call count still 1;
  - "challenge from another session": session A begins, session B (same user) answers; `ErrInvalidCode`;
  - "expired challenge": answered 6 minutes after begin gives `ErrInvalidCode`, and a failure is counted;
  - "consumer challenge lifetime": `WithMFAChallengeTTL(2*time.Minute)`, answered at +3m, gives `ErrInvalidCode`.

  The chain's challenge managers read the system clock: `httpsec` has no clock option, the non-goal recorded in `clock-seam`. So these two rows run inside `testing/synctest.Test`, and time moves with `time.Sleep` inside the bubble. This is the D7 rule for code that uses package `time` directly; do not mix it with a clockwork fake in the same test;
  - "no challenge in the response": `{}`: `ErrInvalidCode`, counted, `Verify` not called;
  - "malformed response" (Review Focus 3): `PresentedChallenge` errors; `ErrInvalidCode`, counted, `Verify` not called;
  - "concurrent attempts" (Review Focus 1): 16 goroutines post the same valid answer at once after one begin. Exactly one reaches `Verify`, and the others get `ErrInvalidCode`. Run it under `-race`.
- [ ] **Step 2: Run** `go test -run TestMFAChallengeVerify -count=1 ./httpsec/`. Expected red, with begin from 4.1 and no spend step yet: "one try per challenge" (count 2), the other-session, expired, missing and malformed rows (all reach `Verify`), and concurrency (several reach `Verify`).
- [ ] **Step 3: Implement.** After `readResponse`:

```go
if cm, ok := m.(mfa.ChallengeMethod); ok {
	presented, err := cm.PresentedChallenge(response)
	if err != nil || presented == "" {
		i.throttle.RecordFailure(ctx, s.UserID)
		return mfa.ErrInvalidCode
	}
	mgr := i.challenges[name]
	checked, err := mgr.Check(ctx, presented, s.ID)
	if err != nil {
		i.throttle.RecordFailure(ctx, s.UserID)
		return mfa.ErrInvalidCode
	}
	if err := mgr.Consume(ctx, checked); err != nil { // lost race, gone, or store down: all ErrInvalidToken
		i.throttle.RecordFailure(ctx, s.UserID)
		return mfa.ErrInvalidCode
	}
}
```

  `onetime.Manager.Consume` reports every failure as `onetime.ErrInvalidToken`: a lost race, a token already gone, and a store that could not answer alike (see its godoc). The slot therefore refuses every `Check` or `Consume` failure as `mfa.ErrInvalidCode`, and counts it. This fails closed, because no attempt reaches `Verify` without a spent challenge. This follows the design's departure from check-then-consume (spent on every attempt): the comment in code says why.
- [ ] **Step 4: Run** `go test -race -count=3 ./httpsec/...`. Expected: PASS.

### Task 4.3: The challenge error carries the usable methods

**Files:**
- Modify: `httpsec/errors.go:45` (`ChallengeError`), `httpsec/mfaverify.go` (`gate` at about line 281), `httpsec/logincomplete.go:264` (and every other place `gopls references` shows building `ChallengeError{Kind: policy.ChallengeMFA…}`)
- Create: `httpsec/mfachallengeerr.go` (one builder)
- Test: `httpsec/errors_test.go`, `httpsec/mfagate_test.go`, `httpsec/logincomplete_test.go`

**Interfaces:**
- Produces:
  ```go
  type MFAMethod struct {
      Name    string
      Channel factor.Channel
      Begins  bool
  }
  // ChallengeError gains: Methods []MFAMethod
  // internal: func (c *chain) mfaChallenge(ctx context.Context, s *session.Session, token string) error
  // returns *ChallengeError with Methods filled, or the lookup error.
  ```

- [ ] **Step 1: Write the failing tests.**
  - "challenge carries the usable methods": TOTP plus `passkey`, both enrolled, a password login; the challenge lists `{totp, authenticator-app, false}` then `{passkey, …, true}`.
  - "challenge omits methods the user cannot use": the gate on `/invoices`, TOTP only enrolled, lists `totp` only.
  - "a failed lookup never yields an empty list": the gate returns the lookup error and not a `*ChallengeError` (`errors.As` false).
  - "no usable method left" (Review Focus 4): a pending session whose enrolment was removed; the gate returns `*ChallengeError` with empty `Methods` and a nil error from the lookups.
  - "challenge text carries no secret": `Error()` contains no method name.
  - Magic-link and OIDC handoff completions that raise `ChallengeMFA` carry the list (one row each where those tests exist).
- [ ] **Step 2: Run** `go test -run 'TestChallengeError|TestMFAGate|TestLoginComplete' -count=1 ./httpsec/`. Expected: FAIL, because `Methods` is nil everywhere.
- [ ] **Step 3: Implement** the builder, from the slot's lookups and methods:

```go
usable, err := policy.UsableMFAMethods(ctx, i.lookups, s.UserID, s.FirstFactor)
if err != nil { return err }
out := make([]MFAMethod, 0, len(usable))
for _, l := range usable {
	_, begins := i.byName[l.Name()].(mfa.ChallengeMethod)
	out = append(out, MFAMethod{Name: l.Name(), Channel: l.Channel(), Begins: begins})
}
return &ChallengeError{Kind: policy.ChallengeMFA, Session: s, Token: token, Methods: out}
```

  Route every `ChallengeMFA` construction through it. The chain reaches the MFA interceptor through the assembled chain, so a login completion asks the chain for the builder; when MFA is not enabled no MFA challenge can be raised (existing enforcer rule). `Error()` stays as it is.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...` and `go test -count=1 ./...` in `fibersec` and `ginsec`. Expected: PASS.

---

### Task 5.1: The method-listing endpoint

**Files:**
- Create: `httpsec/mfalisting.go`, `httpsec/mfalisting_test.go`
- Modify: `httpsec/options.go`, `httpsec/errors.go` (`ErrNoMFAChallengePending`), `httpsec/status.go` (403 row), `httpsec/mfaverify.go` (the gate exempts the listing path)

**Interfaces:**
- Produces:
  ```go
  const DefaultMFAMethodListingPath = "/mfa/methods"
  var ErrNoMFAChallengePending = errors.New("httpsec: no MFA challenge pending")
  type ListingSetting func(*listingConfig) error
  func ListingPath(path string) ListingSetting          // "" refused
  type MFAListingResponder func(ex *Exchange, methods []MFAMethod) error
  func ListingResponder(fn MFAListingResponder) ListingSetting // nil refused
  func WithMFAMethodListing(settings ...ListingSetting) MFAOption
  ```

  The default body is `{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}]}` (`Content-Type: application/json`, 200).

- [ ] **Step 1: Write the failing tests** in `TestMFAMethodListing`:
  - "off by default": a GET on `/mfa/methods` reaches the next handler;
  - "pending session lists its methods": the default JSON, TOTP only;
  - "a full session is refused": `ErrNoMFAChallengePending`;
  - "no session": `ErrAuthenticationRequired`;
  - "lookup failure": that error, with no body written;
  - "consumer path and responder";
  - "POST and HEAD are not answered" (Review Focus 5): they pass through to the next handler;
  - "query is not read": `?user=u-2` changes nothing;
  - construction: `ListingPath("")` and `ListingResponder(nil)` give `ErrConfig`; a path equal to `/mfa/verify/totp`, under the begin prefix, or the logout path fails assembly;
  - status: `ErrNoMFAChallengePending` gives 403.
- [ ] **Step 2: Run** `go test -run 'TestMFAMethodListing|TestStatusForError' -count=1 ./httpsec/`. To get a real red: `WithMFAMethodListing` recorded but nothing registered. Expected FAIL on every row except "off by default".
- [ ] **Step 3: Implement.** The option applies each setting to a `listingConfig{path: DefaultMFAMethodListingPath, responder: writeMethodListing}`, and the first error is returned. The listing is served by the MFA interceptor ahead of the gate: GET with an exact path match. It requires a session (else `ErrAuthenticationRequired`) with `MFA == MFAPending` (else `ErrNoMFAChallengePending`), computes the list with the builder from 4.3's helper, and responds. Collision checks go in `wireMFA` against the logout path and both prefixes.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected: PASS.

### Task 5.2: The enrolment path names its method

**Files:**
- Modify: `httpsec/mfaenroloptions.go` (constants and options), `httpsec/mfaenrol.go` (`enrolmentInterceptor.methods map[string]mfa.Enroller`, `enrolmentMethod` at about line 246 becomes `enrollableMethods`, begin at about line 442, confirm at about line 596, email at about line 883, and the gate exemptions)
- Test: `httpsec/mfaenroloptions_test.go`, `httpsec/mfaenrol*_test.go`, `httpsec/example_enrolment_test.go`
- Callers: `test/httpsecconformance/enrolment_scenarios.go`

**Interfaces:**
- Produces:
  ```go
  const (
      DefaultEnrolmentBeginPrefix        = "/mfa/enrol/begin"
      DefaultEnrolmentConfirmPrefix      = "/mfa/enrol/confirm"
      DefaultEnrolmentEmailConfirmPrefix = "/mfa/enrol/confirm-email"
  )
  func WithEnrolmentBeginPrefix(prefix string) EnrolmentOption        // replace WithEnrolmentBeginPath
  func WithEnrolmentConfirmPrefix(prefix string) EnrolmentOption      // replace WithEnrolmentConfirmPath
  func WithEnrolmentEmailConfirmPrefix(prefix string) EnrolmentOption // replace WithEnrolmentEmailConfirmPath
  func WithEnrolmentMethods(names ...string) EnrolmentOption          // empty list refused
  ```

- [ ] **Step 1: Write the failing tests.**
  - Construction (`TestEnableMFAEnrolmentConstruction`):
    - no enrollable method (a stub `mfa.Method` only);
    - `WithEnrolmentMethods("email-code")` naming a non-enrollable stub;
    - `WithEnrolmentMethods("sms")` naming an unknown method;
    - `WithEnrolmentMethods()` with an empty list;
    - prefix collisions with logout and verify.

    Each gives `ErrConfig` at assembly.
  - Behaviour:
    - "begin" at `/mfa/enrol/begin/totp` returns the secret and URI;
    - "unknown method at begin": `/mfa/enrol/begin/sms` gives `ErrUnknownMFAMethod`, and nothing is stored;
    - "GET on an enrolment path": `/mfa/enrol/begin/totp` gives the enrolment challenge;
    - "consumer path": `WithEnrolmentBeginPrefix("/account/2fa/start")`, then a post to `/account/2fa/start/totp`;
    - "device code confirms the device" at `/mfa/enrol/confirm/totp`;
    - "a generation belongs to its method": with two TOTP instances named `totp` and `totp-backup`, each with its own memory store, begin on `totp`, then confirm on `totp-backup`, is refused by `totp-backup`'s store and proves nothing.

  Rename the existing path-based rows to prefix plus `/totp`.
- [ ] **Step 2: Run** `go test -run 'TestEnableMFAEnrolmentConstruction|TestEnrolment' -count=1 ./httpsec/`. To get a real red: rename the constants and options, keep matching the bare prefix, and keep using the single method. Expected FAIL on the per-method paths, the unknown method and `WithEnrolmentMethods`.
- [ ] **Step 3: Implement.** Rewrite `EnableMFAEnrolment`'s godoc (`httpsec/mfaenroloptions.go` about lines 146–150), which still speaks of one method and only the same-channel test: admission needs an enrollable method on another channel. `wireMFAEnrolment` collects the `EnableMFA` methods that are `mfa.Enroller` with `SupportsEnrolmentPath()`, narrowed by `WithEnrolmentMethods` (each name must be known and enrollable). Each endpoint parses its segment with `methodSegment`; an unknown name is `ErrUnknownMFAMethod`. The same-channel check uses the named method. Each endpoint calls the named method's `BeginEnrolmentGeneration`, `ProveDevice`, `CompleteEnrolment` or `RedeemEmailCode`, with the session's generation. The enrolment gate exempts POSTs under the three prefixes (email only when email confirmation is on).
- [ ] **Step 4: Update the callers.** Run `go test -race -count=1 ./httpsec/...` and `go vet ./...` in `test/`. Expected: PASS.

---

### Task 6.1: The `test` module

**Files:** `test/httpsecconformance/enrolment_scenarios.go`, `request_scenarios.go`, `scenarios.go`, `test/httpsec_construction_test.go`, and any other caller that `go vet ./...` in `test/` reports.

- [ ] **Step 1: Update the scenarios.**
  - `enrolmentOptions` builds `methods := []mfa.Method{totp}`, `lookups, err := mfa.LookupsFor(methods...)`, both policies over `lookups`, `EnableMFA(methods, …)` and `EnableMFAEnrolment(…)`.
  - The scenario "verification ends the enrolment and grants a full session" posts to `httpsec.DefaultMFAVerifyPrefix + "/totp"`.
  - The enrolment scenarios use the prefixes plus `/totp`.
  - `verifyBuild`, `verifyCodeInTheQueryIsNotRead` and `verifyBodyCodeWinsOverTheQuery` target `/mfa/verify/totp`.
- [ ] **Step 2: Run** `go vet ./...` and `go test -race -count=1 ./...` in `test/`. This needs Docker; if it is unavailable, say so and run the non-container packages. Expected: PASS. Because this task moves existing scenarios to the new paths and adds no behaviour, its red step is `go vet` failing before the update. Report that output, and say plainly that no new behaviour test was needed.

### Task 6.2: README examples

**Files:** Modify `README.md` (the MFA sample near line 143, and any other MFA snippet).

- [ ] **Step 1:** Rewrite every MFA snippet to the final API: `methods := []mfa.Method{totp}`, `lookups, err := mfa.LookupsFor(methods...)`, `policy.NewMFAPolicy(lookups, …)`, `policy.NewMFARequirementPolicy(required, lookups, …)`, `httpsec.EnableMFA(methods, …)`, and the paths `/mfa/verify/totp` and `/mfa/enrol/begin/totp`.
- [ ] **Step 2:** Prove it compiles. Copy the snippet into a disposable `example_test.go` in a scratch copy of the module, fill in the declarations the README elides, and run `go vet` there. Before the rewrite the copy fails to compile against the new API; after it, the copy vets clean. Report both outputs.

### Task 6.3: Close out (main session)

- [ ] For every module in `go.work`, run `go build ./...`, `go vet ./...`, `gofmt -l .` (expected empty) and `go test -race ./...`. Then run `openspec validate mfa-multi-method --strict`. Then dispatch one fresh reviewer against every requirement and scenario of the four spec deltas and the Review Focus list. Its findings go back to a fresh dispatch of the owning group.
