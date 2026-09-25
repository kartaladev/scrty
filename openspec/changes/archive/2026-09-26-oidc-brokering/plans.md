# OIDC Brokering Implementation Plan

> **For agentic workers:** This plan is executed under `.claude/rules/subagent-delegation.md`, not task by task in one session. The main session never writes code. It dispatches one fresh subagent per row of the dispatch table below, running dispatches of different lanes in parallel and dispatches of one lane in order. After each dispatch the main session runs its verification commands itself and reads the output; then a fresh reviewer agent checks the dispatch's diff against the items in its "Reviewer checks" column. The next dispatch in that lane starts only when both are clean. The main session chooses each implementer's model (Sonnet or Opus) from the dispatch's complexity, per the rule's "Choosing the implementer's model", and names it with a one-line reason when it announces the dispatch. Steps use checkbox (`- [ ]`) syntax; only the main session ticks `tasks.md`, and only for tasks whose verification output it has seen.

**Goal:** Let an application embedding scrty log users in through external OpenID Connect providers, link those identities to its own users without email-based takeover, convey the login to an ordinary scrty session through a single-use handoff code, and end federated sessions through back-channel and RP-initiated logout.

**Architecture:** A new framework-free `oidc` package holds the provider registry, a TTL key-set and discovery cache over the confined `outbound.Client`, the PKCE flow store, ID and logout token verification (jwx v4), the identity broker with its link store, and the handoff manager with its store. Four new `httpsec` interceptors at `OrderOIDC` drive it, reusing the chain's login tail, source throttle and magic-link redemption guards. Four archived capabilities gain small, additive seams: `outbound.PostForm` headers, login-tail create options, an end-session step on logout, two status rows, and a load-by-reference conformance case.

**Tech Stack:** Go 1.27, `github.com/lestrrat-go/jwx/v4` (`jwt`, `jws`, `jwk`), `golang.org/x/sync/singleflight`, `golang.org/x/crypto/bcrypt` (already present via `password`), testify, `go.uber.org/mock` (typed), `testing/synctest`, testcontainers-go (Keycloak, `test` module only).

**Spec:** `openspec/changes/oidc-brokering/` — `proposal.md`, `design.md` (decisions 1–17), `specs/oidc-login`, `specs/identity-linking`, `specs/oidc-logout`, and the deltas `specs/http-security-chain`, `specs/http-error-propagation`, `specs/outbound-http-confinement`, `specs/identity-model`. Every task number below (`1.1` … `11.4`) is the task of the same number in `tasks.md`; no step exists without one.

## Global Constraints

- Go 1.27 floor; the core module imports no framework, driver, scheduler or DI container (`layout_guard_test.go`). The only new core dependency is `golang.org/x/sync`.
- `jwkfetch` is **not** used. Every outbound byte goes through `outbound.Client` (`Get`, `PostForm`).
- The core module never imports `github.com/kartaladev/scrty/test`, not even from `_test.go`.
- Test-first on every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, see it pass, then refactor. When a test is hard to make fail, invert the implementation temporarily.
- Table tests: `assert` closures, a `ctx` modifier where context matters, `t.Context()`, never `want`/`wantErr` (skill `table-test`).
- Mocks: `mockgen --typed` from a `//go:generate` directive, into a `_test.go` file of the consuming package (skill `use-mockgen`). No hand-rolled doubles for interfaces scrty owns.
- Identifiers from `id.Generator` (default `id.NewV7Generator()`); secrets from the configured `io.Reader` (default `crypto/rand.Reader`); time from `func() time.Time` (default `time.Now`).
- Every option's godoc names the default it replaces; every port says what is used when none is supplied.
- Wiring mistakes fail at construction with the package's `ErrConfig` (`oidc.ErrConfig`, httpsec's `newConfigError`).
- Never log a handoff code, an ID token, a logout token, a client secret, a PKCE verifier, a state, a nonce or a claim value. Usernames and emails in logs are redacted to their domain.
- Refusal logs go through `pkg/logsample` with a reporter configured; `httpsec` interceptors use the chain's sampler with keys prefixed `oidc.callback`, `oidc.handoff`, `oidc.backchannel`.
- Agents never run `git checkout --`, `git restore`, `git reset --hard`, `git stash` or `git clean`, never edit `openspec/`, and never tick `tasks.md`. Commits are the main session's.
- Defect claims (`defect-claims.md`): anything an agent calls a bug in existing code needs a failing test, or is reported `UNREPRODUCED`.

## Review Focus

- **A provider that answers a key-set or discovery request with an HTML error page, a truncated body or a 200 with `{"keys": []}`.** Expect a provider failure (`ErrDiscoveryFailed`), never a panic and never an "invalid token" that sends operators hunting for a signing bug. Pinned in task 3.2 (`TestKeyCacheTTL` rows "non-JSON key set" and "empty key set").
- **A callback whose `code` or `state` query parameter is repeated, empty or absent, and a callback with no flow cookie at all.** Expect `ErrInvalidState` with no store write and no cookie-clearing header. Pinned in task 9.4 (`TestOIDCCallback` rows "no flow cookie", "empty state", "repeated state").
- **Clock skew between replicas and the provider around the 60-second handoff window**, e.g. a code redeemed at `ExpiresAt` exactly, or with the clock stepping backwards. Expect refusal at and after `ExpiresAt`, acceptance strictly before, and no panic on a negative remaining duration when computing `Max-Age`. Pinned in tasks 7.3 (`TestHandoffIssue` row "redeemed exactly at expiry") and 9.3 (`TestOIDCAuthorize` row "flow expiry already passed clamps Max-Age to 1").
- **A provider name or `{provider}` path segment containing percent-encoding, a dot segment or a trailing slash** (`/oauth2/authorization/corp%2F..`, `/oauth2/authorization/corp/`). Expect `ErrUnknownProvider` or pass-through, never a match against another provider. Pinned in task 9.3 (`TestOIDCAuthorize` rows "encoded slash", "trailing slash").
- **A back-channel request whose body exceeds the login body bound or is not form-encoded.** Expect `ErrInvalidLogoutToken` (400) without reading past the bound. Pinned in task 9.8 (`TestOIDCBackchannel` rows "oversized body", "JSON body").

---

## Lanes, dispatches, file ownership and review

A **lane** is a set of files one line of work owns; two lanes never own the same file, so lanes run in parallel. A lane longer than a handful of tasks is split into **dispatches**: each is a fresh subagent, the dispatches of one lane run in order (they share the lane's files, never concurrently), and each is verified and reviewed before the next starts. A dispatch prompt names the files it owns, every file another lane holds, the tasks it implements, the test-first order, the verification commands, and what to report.

**After every dispatch:**
1. The main session runs the dispatch's verification commands (each task's "Verify" line in `tasks.md`, plus `go vet` and `gofmt -l` on the touched packages) and reads the output, including the red-step failures the agent reports.
2. A fresh reviewer agent, which did not write the code, reads the diff and checks the items in the dispatch's "Reviewer checks" column against `design.md` and the named spec requirements. It reports findings; it edits nothing. A defect it claims needs a failing test or is marked `UNREPRODUCED` (`defect-claims.md`).
3. Findings go back to a fresh dispatch of the same lane (or, for a few lines, the main session corrects them and says so). The lane's next dispatch starts only when verification is green and the review is clean.

Before task 11.4, one reviewer reads the whole branch against every spec requirement in the self-review table at the end of this plan.

| Wave | Lane | Dispatch | Tasks | Owns | Must not touch | Reviewer checks before the next dispatch |
|---|---|---|---|---|---|---|
| A | A-out | **A-out** | 1.1 | `outbound/client.go`, `outbound/client_test.go` | everything else | spec `outbound-http-confinement` "A form POST carries the caller's headers"; the redirect row pins the header too; no other caller of `PostForm` left unconverted |
| A | A-tail | **A-tail** | 1.2, 1.3 | `httpsec/logincomplete.go`, `httpsec/logout.go`, the `LogoutDeps`/`EnableLogout` block of `httpsec/options.go`, new cases in `httpsec/logincomplete_test.go` and `httpsec/logout_test.go` (or `httpsec/logout_endsession_test.go`) | `outbound/`, `oidc/`, `test/` | spec `http-security-chain` "Logout ends the session" and "Redemption flows plug into named seams"; every existing `completeLogin` caller unchanged in behaviour; the session is deleted before the end-session step; a step error never fails the logout |
| A | A-id | **A-id** | 1.4 | `test/identity/conformance.go`, `test/identity/conformance_guard_test.go` | everything else | spec `identity-model` "User loader contract"; the new defect is in `everyDefect` and caught |
| B0 | B-found | **B-found** | 2.1–2.3 | `oidc/doc.go`, `oidc/errors.go`, `oidc/registry.go`, `oidc/ports.go`, `oidc/manager.go`, `oidc/options_manager.go`, `oidc/idp_helper_test.go`, `oidc/export_test.go`, their tests | `httpsec/`, `outbound/`, `test/` | spec `oidc-login` "Provider configuration is validated at construction" and "OIDC wiring mistakes fail at construction"; decisions 1, 2; the port and record types match task 2.3 exactly, since three lanes compile against them |
| B0 | B-found | **B-found-2** | 1.6, and the revisions to 2.1–2.3 | `outbound/client.go`, `outbound/client_test.go`, B-found's files | `httpsec/`, `test/`, the B-brk and B-hof files | spec `outbound-http-confinement` "A client reports the schemes it allows"; the revised "Provider configuration is validated at construction" (scheme follows the client; host name; issuer query/fragment; redirect fragment; scopes without `openid`; symmetric algorithm with an empty secret); typed nils refused through `internal/nilcheck`; design decision 2's scheme bullet |
| B | B-mgr | **B-mgr-1** | 1.5, 3.1–3.7 | `go.mod`, `go.sum`, `oidc/discovery.go`, `oidc/keycache.go`, `oidc/manager.go`, `oidc/options_manager.go`, `oidc/idp_helper_test.go`, `oidc/export_test.go`, their tests | the B-brk and B-hof files | the four cache requirements of `oidc-login` and "An unknown key id refetches at most once per cooldown per provider"; decision 3; no goroutine outlives a request; the three mutations of tasks 3.4–3.6 were run and each was killed |
| B | B-mgr | **B-mgr-2** | 4.1–4.4 | `oidc/flow.go`, `oidc/flowstore_memory.go`, `oidc/authorize.go`, B-mgr-1's files as needed, their tests; `test/oidc/doc.go`, `test/oidc/flowstore_suite.go`, `test/oidc/flowstore_guard_test.go`, `test/oidc/flowstore_suite_test.go` | the B-brk and B-hof files | "A flow is completed only by a caller who knows its provider and state" and "Authorization always uses PKCE, state and nonce"; decisions 4, 5; every refusal row is paired with a success; the suite is load-bearing |
| B | B-mgr | **B-mgr-3** | 5.1–5.3 | `oidc/exchange.go`, `oidc/verify.go`, `oidc/callback.go`, B-mgr's earlier files as needed, their tests | the B-brk and B-hof files | "The code exchange authenticates the client and hides provider detail", "ID tokens are verified strictly", "A provider error redirect cannot cancel someone else's login"; decision 6; `ErrFlowUnspent` only on returns at or before `Complete`; no provider body in a returned error |
| B | B-mgr | **B-mgr-4** | 8.1–8.2 | `oidc/logouttoken.go`, `oidc/endsession.go`, B-mgr's earlier files as needed, their tests | the B-brk and B-hof files | "Logout tokens are verified strictly", "Logout-token replay is bounded by issued-at", "RP-initiated logout offers the provider's end-session URL"; decisions 12, 13; the `iat` mutation was killed |
| B | B-brk | **B-brk-1** | 6.1–6.4 | `oidc/link.go`, `oidc/linkstore_memory.go`, `oidc/broker.go`, `oidc/provision.go`, `oidc/claims.go`, `oidc/options_broker.go`, `oidc/broker_mocks_test.go`, their tests; `test/oidc/linkstore_suite.go`, `test/oidc/linkstore_guard_test.go`, `test/oidc/linkstore_suite_test.go` | the B-mgr and B-hof files | `identity-linking` requirements on the link key, the link store contract, resolution by reference, and provisioning; decision 7 and departure 2; `LoadByUsername` is never called; the suite is load-bearing; both mutations of task 6.3 were killed |
| B | B-brk | **B-brk-2** | 6.5–6.8 | `oidc/passwordclaim.go`, `oidc/mirror.go`, `oidc/roles.go`, `oidc/callback_consumerbroker_test.go`, B-brk-1's files as needed, their tests | the B-mgr and B-hof files | the password-hash, mirroring, roles, role-sync and consumer-broker requirements of `identity-linking`; decisions 8, 8a; no hash or claim value reaches a log. Task 6.8 compiles against B-mgr-3's `Callback`, so this dispatch starts only after B-mgr-3 is clean |
| B | B-hof | **B-hof** | 7.1–7.4 | `oidc/handoff.go`, `oidc/handoffstore_memory.go`, `oidc/options_handoff.go`, `oidc/handoff_mocks_test.go`, their tests; `test/oidc/handoffstore_suite.go`, `test/oidc/handoffstore_guard_test.go`, `test/oidc/handoffstore_suite_test.go` | the B-mgr and B-brk files | "The callback conveys the login by a short-lived single-use code", "Handoff redemption is check-then-consume", "Handoff redemption failures reveal nothing about the cause"; decisions 9, 10; outages are `ErrInvalidHandoff`; the code never reaches a log; both mutations of task 7.4 were killed |
| C | C-http | **C-http-1** | 9.1–9.2 | `httpsec/status.go`, `httpsec/status_test.go`, `httpsec/order.go`, `httpsec/oidc.go`, `httpsec/oidc_options.go`, the `wireMagicLink` call site in `httpsec/options.go`, their tests | `oidc/`, `test/`, the A-tail files | spec `http-error-propagation` "One public table maps refusals to a status"; "OIDC wiring mistakes fail at construction", "Logout wiring mistakes fail at construction"; decision 14; every option's godoc names its default |
| C | C-http | **C-http-2** | 9.3–9.4 | `httpsec/oidc_authorize.go`, `httpsec/oidc_callback.go`, `httpsec/oidc_provider_helper_test.go`, C-http-1's files as needed, their tests | `oidc/`, `test/` | "Authorization always uses PKCE, state and nonce" (cookie and redirect), "A provider error redirect cannot cancel someone else's login", "The callback conveys the login…", "The post-login destination is allowlisted", "A consumer can replace the callback's conveyance"; the Review Focus rows of both tasks |
| C | C-http | **C-http-3** | 9.5–9.7 | `httpsec/redemption.go`, `httpsec/magiclink.go`, `httpsec/oidc_redeem.go`, `httpsec/oidc_mfa_test.go`, C-http's earlier files as needed, their tests | `oidc/`, `test/` | "Policy decisions at redemption cannot be lost", "Refused redemptions count against the per-source limit by default", "A successful redemption establishes a federated session", "OIDC logins are exempt from local MFA by default"; magic-link behaviour unchanged by the extraction; the four mutations of task 9.5 were killed |
| C | C-http | **C-http-4** | 9.8–9.9 | `httpsec/oidc_backchannel.go`, C-http's earlier files as needed, their tests | `oidc/`, `test/` | the back-channel and RP-initiated logout requirements of `oidc-logout`; the Review Focus rows of task 9.8; both mutations were killed |
| D | D-test | **D-test-1** | 10.1–10.2 | `test/oidc/idp.go`, `test/oidc/idp_test.go`, `test/httpsecconformance/oidc_scenarios.go`, the `Scenarios()` list | core module | every adapter produces the same outcome; no scenario weakened to hide an adapter difference |
| D | D-test | **D-test-2** | 10.3 | `test/testutils.go` (`RunTestKeycloak`), `test/oidc_keycloak_test.go`, `test/testdata/keycloak/` | core module | the `use-testcontainers` skill; the test is reported not run, never passing, without Docker |
| D | D-doc | **D-doc** | 11.1 | godoc comments in `oidc/*.go`, `httpsec/oauth2*.go`, `httpsec/logout.go`, `outbound/client.go`; `README.md` | any non-comment code | every limit design.md commits to documenting is stated; every option names its default |

The main session keeps 11.2–11.4 (`design.md`, the flag to `durable-persistence`, `make check`).

"Their tests" means the `_test.go` files beside the named sources. "Files as needed" lets a later dispatch of the same lane extend a file an earlier dispatch of that lane created. That is safe because the dispatches of one lane never run at the same time.

**Compile order.** Wave A dispatches are independent and run together. B-found-2 follows B-found in the same lane and owns `outbound/client.go` for task 1.6 because `NewManager` is that accessor's only caller, so the definition and its caller land in one dispatch. B0 (both dispatches) must land before the three B lanes, because they share `oidc`'s sentinels, `Provider`, `Registry`, the port interfaces (`FlowStore`, `LinkStore`, `HandoffStore`, `IdentityBroker`) and the record types they carry (`Flow`, `Link`, `HandoffRecord`, `ExternalIdentity`, `CallbackResult`). B-mgr, B-brk and B-hof then run in parallel, each lane's dispatches in order: `Manager.Callback` calls the broker only through `IdentityBroker`, and the handoff manager only through `HandoffStore` and `identity.UserLoader`. The one cross-lane wait inside wave B is B-brk-2, whose task 6.8 compiles against B-mgr-3's `Callback`. C-http needs A-tail (the tail options and the end-session step) and all of wave B. D-test needs C-http. D-doc runs last, touching comments only.

**Why three options files:** each B lane adds options for its own constructor (`ManagerOption`, `BrokerOption`, `HandoffOption`), so each owns its own file and no two lanes write one file. The shared option *types* and the defaults they resolve against live in the file of the constructor they configure. A lane that finds it needs another lane's file stops and reports.

---
## Wave A — seams in archived capabilities

### Task 1.1: `outbound.PostForm` carries caller headers (lane A-out)

**Files:**
- Modify: `outbound/client.go` (`PostForm`, around line 152)
- Test: `outbound/client_test.go` (fold `TestOutboundPostForm` into a table; update the `PostForm` call in `TestOutboundNoBodyReplay`)

**Interfaces:**
- Consumes: `(*Client).do(ctx, method, rawURL string, header http.Header, body string)` — already takes a header.
- Produces: `func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values, header http.Header) (*Response, error)`. B-mgr's exchange (task 5.1) calls it.

- [ ] **Step 1: Write the failing test.** Replace the standalone `TestOutboundPostForm` with a table (the `table-test` skill makes two cases on one SUT a table). Keep its existing assertions as the first row.

```go
func TestOutboundPostForm(t *testing.T) {
	t.Parallel()

	type received struct {
		contentType, authorization string
		form                       url.Values
	}

	type testCase struct {
		name   string
		header http.Header
		assert func(t *testing.T, got received, err error)
	}

	cases := []testCase{
		{
			name:   "no header sends only the form and its content type",
			header: nil,
			assert: func(t *testing.T, got received, err error) {
				require.NoError(t, err)
				assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
				assert.Empty(t, got.authorization)
				assert.Equal(t, "authorization_code", got.form.Get("grant_type"))
				assert.Equal(t, "the code", got.form.Get("code"))
			},
		},
		{
			name:   "a caller header is sent exactly as given",
			header: http.Header{"Authorization": {"Basic Y2xpZW50OnNlY3JldA=="}},
			assert: func(t *testing.T, got received, err error) {
				require.NoError(t, err)
				assert.Equal(t, "Basic Y2xpZW50OnNlY3JldA==", got.authorization)
				assert.Equal(t, "the code", got.form.Get("code"),
					"the header travels beside the form, not instead of it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got received
			idp, _ := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				got.contentType = r.Header.Get("Content-Type")
				got.authorization = r.Header.Get("Authorization")
				got.form, _ = url.ParseQuery(string(body))
				w.WriteHeader(http.StatusOK)
			})

			c, err := outbound.New(outbound.WithHTTPClient(trusting(t, idp)))
			require.NoError(t, err)

			_, err = c.PostForm(t.Context(), idp.URL+"/token", url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"the code"},
			}, tc.header)
			tc.assert(t, got, err)
		})
	}
}
```

In `TestOutboundNoBodyReplay`, pass `http.Header{"Authorization": {"Basic c2VjcmV0"}}` as the new fourth argument, and make the evil server also count `r.Header.Get("Authorization") != ""` into `secretsReceived`, so the redirect case pins that the header is not replayed either (spec scenario "Credential header is not replayed across origins").

- [ ] **Step 2: Run it and see it fail.** Temporarily add the parameter to `PostForm` but pass `nil` to `do` instead of `header` (so the test compiles), then run:

Run: `go test -run 'TestOutboundPostForm|TestOutboundNoBodyReplay' -count=1 ./outbound/`
Expected: FAIL in row "a caller header is sent exactly as given": `expected "Basic Y2xpZW50OnNlY3JldA==", actual ""`. A compile error here is not the red step.

- [ ] **Step 3: Implement.**

```go
// PostForm sends form to rawURL as application/x-www-form-urlencoded, which is
// what a token exchange is.
//
// The header may be nil. Whatever it carries is sent as given, beside the form
// content type this method sets: a client authenticating with HTTP Basic puts
// its credentials here. Because the body and the header may both carry a client
// secret, the redirect policy this package installs matters most here: a 307 or
// 308 answer that would resend them somewhere else is refused before the
// redirected request goes out.
func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values, header http.Header) (*Response, error) {
	h := header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Content-Type", "application/x-www-form-urlencoded")

	return c.do(ctx, http.MethodPost, rawURL, h, form.Encode())
}
```

Keep whatever the current body does to set the content type if it differs; the only change is that the caller's header is merged in and a nil header means none.

- [ ] **Step 4: Run it and see it pass.** Same command; expected PASS. Then `go test -race -count=1 ./outbound/` and `gofmt -l outbound/` (empty).

---

### Task 1.2: the login tail accepts session create options (lane A-tail)

**Files:**
- Modify: `httpsec/logincomplete.go` (`completeLogin`, line 128)
- Modify: every existing `completeLogin(` call site the compiler reports (`httpsec/login.go`, `httpsec/magiclink.go`, and any others) — each passes nothing new
- Modify: `httpsec/export_seams_test.go` only if the exported alias's type changes
- Test: `httpsec/logincomplete_test.go` (`TestCompleteLogin`)

**Interfaces:**
- Produces: `func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input, opts ...session.CreateOption) (string, error)`. C-http's redemption interceptor (task 9.6) passes `session.WithExternalSession(provider, issuer, sid, idToken)`.

Find the callers first: `gopls references httpsec/logincomplete.go:128:6` (not grep). A variadic parameter keeps every existing caller compiling unchanged, which is why it is variadic.

- [ ] **Step 1: Write the failing test.** Add a row to `TestCompleteLogin`. The table's harness calls `CompleteLoginForTest(ex, deps, in)`; add an `opts []session.CreateOption` field to `testCase` and pass `tc.opts...`. The spy store must capture the created session: extend `loginSpies` with `expectCreateCapturing(log *callLog, got **session.Session)`.

```go
{
	name:   "caller create options land in the creating write",
	engine: allowingEngine,
	opts: []session.CreateOption{
		session.WithExternalSession("corp", "https://idp.example", "sid-9", "raw.id.token"),
	},
	wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
		s.expectCreateCapturing(log, &s.created)
		s.expectGenerate(log, jti)
	},
	assert: func(t *testing.T, ex *httpsec.Exchange, _ string, err error, calls []string, _ string) {
		require.NoError(t, err)
		assert.Equal(t, []string{"Create", "Generate"}, calls,
			"the federated fields are in the first write; no Save follows to add them")
		require.NotNil(t, ex.Session)
		assert.Equal(t, "corp", ex.Session.ExternalProvider)
		assert.Equal(t, "https://idp.example", ex.Session.ExternalIssuer)
		assert.Equal(t, "sid-9", ex.Session.ExternalSessionID)
		assert.Equal(t, factor.Password, ex.Session.FirstFactor,
			"the tail's own first factor still applies beside the caller's options")
	},
},
```

The `created` field on `loginSpies` is what `expectCreateCapturing` stores the `*session.Session` passed to `store.Create` into; assert on it too (`s.created.ExternalIssuer`) if the harness exposes the spies to `assert`. If it does not, `ex.Session` is the same pointer the store received and is sufficient.

- [ ] **Step 2: Run it and see it fail.** Add the variadic parameter to `completeLogin` but do not forward it to `Create` yet.

Run: `go test -run 'TestCompleteLogin' -count=1 ./httpsec/`
Expected: FAIL in "caller create options land in the creating write": `expected: "corp", actual: ""`.

- [ ] **Step 3: Implement.**

```go
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input, opts ...session.CreateOption) (string, error) {
	// ...unchanged up to the Create call...

	// The first factor first, then the caller's own attributes: a federated
	// login records its provider session here, in the write that creates the
	// session, so no request ever sees the session without it.
	create := append([]session.CreateOption{session.WithFirstFactor(in.FirstFactor)}, opts...)

	s, err := deps.sessions.Create(ctx, in.User, create...)
	// ...unchanged...
}
```

Update the function's godoc to say what `opts` is for and that it is applied after the first factor.

- [ ] **Step 4: Run it and see it pass.** Run: `go test -run 'TestCompleteLogin|TestFormLogin|TestMagicLink' -count=1 ./httpsec/` — PASS, proving form login and magic-link are unchanged.

---

### Task 1.3: logout's optional end-session step (lane A-tail)

**Files:**
- Modify: `httpsec/options.go` (`LogoutDeps`, `EnableLogout` block around line 1533)
- Modify: `httpsec/logout.go`
- Test: new `httpsec/logout_endsession_test.go`, or new rows in `TestLogout` if its harness supports them (prefer rows; the `table-test` skill makes a second table on the same SUT a refactor smell)

**Interfaces:**
- Produces:

```go
// EndSessionBuilder produces the identity provider's end-session URL for a
// session that a local logout has just deleted.
type EndSessionBuilder interface {
	// EndSessionURL returns the URL to send the browser to, or "" when the
	// provider offers none. It is called only for a session that records an
	// identity provider, and only after that session was deleted.
	EndSessionURL(ctx context.Context, s *session.Session, state string) (string, error)
}

type LogoutDeps struct {
	Sessions   *session.Manager
	EndSession EndSessionBuilder // optional; nil means no end-session step
}

// logoutDocument is the body logout answers with when an end-session URL was
// produced.
type logoutDocument struct {
	EndSessionURL string `json:"end_session_url"`
}
```

- C-http (task 9.9) sets `logout.endSession` when the consumer left it nil. For that, `logout` gains `endSession EndSessionBuilder` and `log *slog.Logger` (wired from the chain like other interceptors), and `config` records the registered `*logout` so `EnableOIDCLogin` can find it: add `c.logout = l` in `EnableLogout`.

- [ ] **Step 1: Write the failing tests.** Rows (in the `TestLogout` table, reusing its harness, `served`, and `authHarness`; add a `deps func(h *authHarness) httpsec.LogoutDeps` field defaulting to `{Sessions: h.sessions}`):

```go
{
	name: "a federated session with an end-session step answers its URL",
	// The session the harness authenticates carries ExternalProvider "corp".
	wire: federatedSessionWire("corp", "https://idp.example"),
	deps: func(h *authHarness) httpsec.LogoutDeps {
		return httpsec.LogoutDeps{Sessions: h.sessions, EndSession: endSessionFunc(
			func(_ context.Context, s *session.Session, state string) (string, error) {
				// The delete has already happened: the session is gone.
				_, err := h.sessions.Load(context.Background(), s.ID)
				require.ErrorIs(h.t, err, session.ErrSessionNotFound)
				return "https://idp.example/logout?state=" + state, nil
			})}
	},
	request: func(ctx context.Context) *http.Request {
		return logoutRequestWithForm(ctx, url.Values{"state": {"s-1"}})
	},
	assert: func(t *testing.T, _ *httpsec.Chain, s served) {
		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))
		assert.JSONEq(t, `{"end_session_url":"https://idp.example/logout?state=s-1"}`, s.rec.Body.String())
	},
},
{
	name: "a password session never calls the end-session step",
	wire: passwordSessionWire(),
	deps: withEndSession(failIfCalled),
	request: authorizedLogout,
	assert: endedCleanly,
},
{
	name: "an end-session failure is logged and the logout still succeeds",
	wire: federatedSessionWire("corp", "https://idp.example"),
	deps: withEndSession(func(context.Context, *session.Session, string) (string, error) {
		return "", errors.New("discovery unavailable")
	}),
	request: authorizedLogout,
	assert: endedCleanly,
},
{
	name: "no end-session step behaves exactly as before",
	wire: federatedSessionWire("corp", "https://idp.example"),
	request: authorizedLogout,
	assert: endedCleanly,
},
```

`endSessionFunc` is a test-only adapter type in the test file (`type endSessionFunc func(...) (string, error)` with the method). It is an adapter over a function, not a double for a scrty interface with behaviour to verify, so it is not a mockgen case; if a reviewer disagrees, generate `MockEndSessionBuilder` with `//go:generate mockgen -destination=endsession_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec EndSessionBuilder` and use it instead. `federatedSessionWire` creates the harness session with `session.WithExternalSession(...)`.

- [ ] **Step 2: Run and see them fail.** Add `EndSession` to `LogoutDeps` so the tests compile, and change nothing else.

Run: `go test -run 'TestLogout' -count=1 ./httpsec/`
Expected: FAIL in "a federated session with an end-session step answers its URL" with an empty body where JSON was expected. The other three new rows pass already: that is correct, they pin that nothing else changes.

- [ ] **Step 3: Implement** in `logout.Intercept`, after the delete:

```go
	if ex.Session != nil {
		if err := l.sessions.Delete(ex.Context(), ex.Session.ID); err != nil &&
			!errors.Is(err, session.ErrSessionNotFound) {
			return err
		}

		if l.endSession != nil && ex.Session.ExternalProvider != "" {
			if target := l.endSessionURL(ex); target != "" {
				ex.Writer.SetHeader("Cache-Control", "no-store")

				return writeSuccessDocument(ex, logoutDocument{EndSessionURL: target})
			}
		}
	}

	ex.Writer.WriteHeader(http.StatusOK)

	return nil
}

// endSessionURL asks the end-session step for the provider's URL. A failure is
// logged and swallowed: the session is already deleted, and answering an error
// would tell the client its logout did not happen.
func (l *logout) endSessionURL(ex *Exchange) string {
	state := formValue(ex.Request, l.bodyLimit, "state")

	target, err := l.endSession.EndSessionURL(ex.Context(), ex.Session, state)
	if err != nil {
		l.log.WarnContext(ex.Context(), "httpsec: the session was ended but the provider's end-session URL could not be built",
			slog.String("provider", ex.Session.ExternalProvider), slog.Any("error", err))

		return ""
	}

	return target
}
```

`formValue` reads one field from a form-encoded body under `DefaultLoginBodyLimit`, returning "" for anything else; reuse the body-reading helper form login already has if one fits. Wire `l.log` from the chain in a `wire` func registered with `c.wire(...)`, as magic-link does. In `EnableLogout`, set `l.endSession = d.EndSession` and `c.logout = l`.

- [ ] **Step 4: Run and see them pass.** `go test -run 'TestLogout|TestLogoutConstruction' -count=1 ./httpsec/` — PASS. Then `go test -race -count=1 ./httpsec/`.

---

### Task 1.4: identity conformance covers loading by reference (lane A-id)

**Files:**
- Modify: `test/identity/conformance.go` (`runUserLoaderCases`, or a new `runLoadByUserIDCases` called from `RunUserLoaderSuite`)
- Modify: `test/identity/conformance_guard_test.go` (a new `defect` and its `brokenStore` branch, added to `everyDefect`)

**Interfaces:**
- Consumes: `identity.UserLoader.LoadByUserID(ctx, identity.UserID) (*identity.Details, error)`; the suite's `Fixture` (`Provision` returns `*Details` with the store-assigned `ID`).
- Produces: nothing another lane consumes.

- [ ] **Step 1: Write the failing cases.** In `conformance.go`:

```go
func runLoadByUserIDCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		lookup func(created identity.UserID) identity.UserID
		assert func(t *testing.T, created identity.UserID, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name:   "an existing reference loads details carrying exactly that reference",
			lookup: func(created identity.UserID) identity.UserID { return created },
			assert: func(t *testing.T, created identity.UserID, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, created, d.ID, "the reference is returned byte for byte")
			},
		},
		{
			name:   "an unknown reference is user not found",
			lookup: func(identity.UserID) identity.UserID { return "no-such-user" },
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "a case-folded reference is user not found",
			lookup: func(created identity.UserID) identity.UserID {
				return identity.UserID(swapCase(string(created)))
			},
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"a reference is opaque: one that differs only in case names another user")
			},
		},
		{
			name: "a reference with a trailing space is not trimmed",
			lookup: func(created identity.UserID) identity.UserID { return created + " " },
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			created, err := f.Provision(t.Context(), "ada@example.com")
			require.NoError(t, err)

			d, err := f.LoadByUserID(t.Context(), tc.lookup(created.ID))
			tc.assert(t, created.ID, d, err)
		})
	}
}
```

`swapCase` inverts the case of every letter; if the store's generated references contain no letters (a numeric id), the row still holds because the swapped value equals the original only when there are no letters — in that case the row asserts nothing useful, so have `swapCase` append a letter-bearing suffix when nothing changed and assert not-found. The Fixture's in-memory store cannot choose its own reference text, which is why the "trailing space" spec scenario is expressed as a lookup of `created + " "` rather than a seed of `"U-1 "`.

In `conformance_guard_test.go`, add `defectCaseFoldsUserID defect = "case-folds user references"` to `everyDefect`, and in `brokenStore.LoadByUserID` return the user whose `strings.EqualFold(id, requested)` when that defect is active.

- [ ] **Step 2: Run and see it fail.** Run the load-bearing guard, which re-executes the suite against the broken store:

Run: `cd test && go test -run 'TestConformanceSuiteIsLoadBearing' -count=1 ./identity/`
Expected before wiring `runLoadByUserIDCases` into `RunUserLoaderSuite`: FAIL on row "case-folds user references is caught" — "the suite passed a store whose case-folds user references defect breaks a contract". That is the red step: the defect exists and the suite does not yet catch it.

- [ ] **Step 3: Implement.** Call `runLoadByUserIDCases(t, newFixture)` from `RunUserLoaderSuite` inside `t.Run("LoadByUserID", ...)`.

- [ ] **Step 4: Run and see it pass.** `cd test && go test -run 'TestInMemoryStoreConformance|TestBrokenStoreConformance|TestConformanceSuiteIsLoadBearing' -count=1 ./identity/` — PASS.

---

### Task 1.6: the client reports the schemes it allows (lane B-found, dispatch B-found-2)

**Files:**
- Modify: `outbound/client.go`
- Test: `outbound/client_test.go` (`TestOutboundAllowsScheme`)

**Interfaces:**
- Consumes: the client's existing scheme allow-set (default `https`, extended by `WithAllowedSchemes`).
- Produces: `func (c *Client) AllowsScheme(scheme string) bool`. Task 2.3's `NewManager` and task 3.1's discovery check call it.

- [ ] **Step 1: Write the failing table** `TestOutboundAllowsScheme`:

```go
func TestOutboundAllowsScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		opts   []outbound.Option
		assert func(t *testing.T, c *outbound.Client)
	}{
		{name: "the default client allows https only",
			assert: func(t *testing.T, c *outbound.Client) {
				assert.True(t, c.AllowsScheme("https"))
				assert.False(t, c.AllowsScheme("http"))
				assert.False(t, c.AllowsScheme(""))
			}},
		{name: "a client allowing http reports it, case-insensitively",
			opts: []outbound.Option{outbound.WithAllowedSchemes("http")},
			assert: func(t *testing.T, c *outbound.Client) {
				assert.True(t, c.AllowsScheme("HTTP"))
				assert.True(t, c.AllowsScheme("https"))
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := outbound.New(tc.opts...)
			require.NoError(t, err)
			tc.assert(t, c)
		})
	}
}
```

- [ ] **Step 2: See it fail.** Add `AllowsScheme` returning `false`. Run: `go test -run TestOutboundAllowsScheme -count=1 ./outbound/`. Expected: FAIL on the `https` and `HTTP` assertions ("Should be true").
- [ ] **Step 3: Implement.** Answer from the same allow-set and the same normalisation the request-time scheme check uses, so the two cannot disagree. If the request-time check does not lower-case the scheme, share one helper between both rather than normalising in only one place.
- [ ] **Step 4: See it pass.** Then `go test -race -count=1 ./outbound/`.

---

## Wave B0 — the `oidc` foundation (lane B-found)

B0 lands the vocabulary every other `oidc` lane compiles against. Nothing here talks to the network.

### Task 2.1: sentinels

**Files:**
- Create: `oidc/doc.go` (package godoc; D-doc completes it later), `oidc/errors.go`
- Test: `oidc/errors_test.go`

**Interfaces:**
- Produces (all in package `oidc`):

```go
var (
	ErrConfig = errors.New("oidc: invalid configuration")

	// Authentication failures. Each is identifiable as itself and as
	// authenticate.ErrAuthenticationFailed, so the chain's status table maps
	// it to 401 with no row of its own.
	ErrInvalidState        = authFailure("oidc: invalid or expired login flow")
	ErrInvalidIDToken      = authFailure("oidc: invalid ID token")
	ErrNoLinkedAccount     = authFailure("oidc: no linked account")
	ErrProvisioningRefused = authFailure("oidc: account provisioning refused")
	ErrInvalidHandoff      = authFailure("oidc: invalid handoff code")

	// Refusals with a status of their own (http-error-propagation rows).
	ErrInvalidLogoutToken = errors.New("oidc: invalid logout token") // 400
	ErrUnknownProvider    = errors.New("oidc: unknown identity provider") // 404

	// Not refusals: a provider or store failing. They map to 500.
	ErrExchangeFailed  = errors.New("oidc: code exchange failed")
	ErrDiscoveryFailed = errors.New("oidc: provider metadata unavailable")

	// Store contract outcomes.
	ErrLinkNotFound    = errors.New("oidc: link not found")
	ErrLinkExists      = errors.New("oidc: link exists")
	ErrHandoffNotFound = errors.New("oidc: handoff code not found")
	ErrRetainSinceRequired = errors.New("oidc: a retain-since cutoff is required")

	// ErrFlowUnspent marks a callback failure that happened at or before the
	// flow was completed, so the flow and its cookie are still live.
	ErrFlowUnspent = errors.New("oidc: login flow not spent")
)

// authFailure builds a sentinel that is also authenticate.ErrAuthenticationFailed.
func authFailure(msg string) error { return &refusal{msg: msg} }

type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return authenticate.ErrAuthenticationFailed }
```

`ErrRetainSinceRequired` is `oidc`'s own because the flow and handoff stores are `oidc`'s; its text mirrors `onetime`'s.

- [ ] **Step 1: Write the failing test.**

```go
func TestOIDCSentinels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error)
	}

	authFailures := []error{
		oidc.ErrInvalidState, oidc.ErrInvalidIDToken, oidc.ErrNoLinkedAccount,
		oidc.ErrProvisioningRefused, oidc.ErrInvalidHandoff,
	}
	others := []error{
		oidc.ErrInvalidLogoutToken, oidc.ErrUnknownProvider, oidc.ErrExchangeFailed,
		oidc.ErrDiscoveryFailed, oidc.ErrConfig, oidc.ErrLinkNotFound, oidc.ErrLinkExists,
		oidc.ErrHandoffNotFound, oidc.ErrRetainSinceRequired, oidc.ErrFlowUnspent,
	}

	var cases []testCase
	for _, e := range authFailures {
		cases = append(cases, testCase{name: e.Error(), err: e, assert: func(t *testing.T, err error) {
			assert.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			assert.ErrorIs(t, fmt.Errorf("wrapped: %w", err), err, "identifiable as itself when wrapped")
		}})
	}
	for _, e := range others {
		cases = append(cases, testCase{name: e.Error(), err: e, assert: func(t *testing.T, err error) {
			assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		}})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err)
		})
	}

	t.Run("every sentinel is distinct", func(t *testing.T) {
		all := append(append([]error{}, authFailures...), others...)
		for i, a := range all {
			for j, b := range all {
				if i != j {
					assert.NotErrorIs(t, a, b)
				}
			}
		}
	})
}
```

- [ ] **Step 2: See it fail.** Declare the sentinels with plain `errors.New` first. Run: `go test -run TestOIDCSentinels -count=1 ./oidc/`. Expected: FAIL on each authentication failure row, "Target error should be in err chain".
- [ ] **Step 3: Implement** `authFailure` as above.
- [ ] **Step 4: See it pass.** Same command, PASS.

---

### Task 2.2: provider registry

**Files:**
- Create: `oidc/registry.go`
- Test: `oidc/registry_test.go`

**Interfaces:**
- Produces:

```go
type ClientAuthMethod uint8

const (
	ClientSecretPost ClientAuthMethod = iota // default
	ClientSecretBasic
)

type Provider struct {
	Name, Issuer, ClientID, ClientSecret, RedirectURL string
	Scopes     []string         // nil: openid, profile, email
	ClientAuth ClientAuthMethod // zero: ClientSecretPost

	// All three or none. Pinned endpoints are never discovered.
	AuthorizationEndpoint, TokenEndpoint, JWKSURI string

	// Optional and outside the pin rule. Empty: RP-initiated logout comes
	// from discovery, or the provider offers none.
	EndSessionEndpoint string

	// Accepted signature algorithms. nil: RS256. A symmetric (HS*) entry is
	// accepted only when listed here, and uses ClientSecret as the key.
	SigningAlgs []string
}

type Registry struct{ /* unexported: ordered names, map by name */ }

func NewRegistry(providers ...Provider) (*Registry, error)
func (r *Registry) Lookup(name string) (Provider, bool)
func (r *Registry) Names() []string

var DefaultScopes = []string{"openid", "profile", "email"}
```

`WithSigningAlgs(provider, algs...)` from design decision 2 becomes the `Provider.SigningAlgs` field: it is plain data on the provider it governs, which is what "provider configuration is trusted, validated input" means, and a per-provider manager option would be a second place to say the same thing. Report this to the main session as a design refinement for task 11.3.

- [ ] **Step 1: Write the failing table.** One row per refusal in spec "Provider configuration is validated at construction", each asserting `require.ErrorIs(t, err, oidc.ErrConfig)` and `assert.Contains(t, err.Error(), "<provider name>")` where a provider is named; plus accepted rows:

```go
func TestNewRegistry(t *testing.T) {
	t.Parallel()

	valid := func() oidc.Provider {
		return oidc.Provider{
			Name: "corp", Issuer: "https://idp.example", ClientID: "client",
			ClientSecret: "secret", RedirectURL: "https://app.example/login/oauth2/callback/corp",
		}
	}

	type testCase struct {
		name      string
		providers func() []oidc.Provider
		assert    func(t *testing.T, r *oidc.Registry, err error)
	}

	refused := func(fragment string) func(t *testing.T, r *oidc.Registry, err error) {
		return func(t *testing.T, r *oidc.Registry, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), fragment)
		}
	}

	cases := []testCase{
		{name: "a valid provider is accepted", providers: func() []oidc.Provider { return []oidc.Provider{valid()} },
			assert: func(t *testing.T, r *oidc.Registry, err error) {
				require.NoError(t, err)
				p, ok := r.Lookup("corp")
				require.True(t, ok)
				assert.Equal(t, oidc.DefaultScopes, p.Scopes, "nil scopes resolve to the default")
				assert.Equal(t, []string{"RS256"}, p.SigningAlgs, "nil algorithms resolve to RS256")
			}},
		{name: "no provider", providers: func() []oidc.Provider { return nil }, assert: refused("no provider")},
		{name: "duplicate name", providers: func() []oidc.Provider { return []oidc.Provider{valid(), valid()} }, assert: refused("corp")},
		{name: "empty name", providers: mutate(valid, func(p *oidc.Provider) { p.Name = "" }), assert: refused("name")},
		{name: "name with a slash", providers: mutate(valid, func(p *oidc.Provider) { p.Name = "a/b" }), assert: refused("a/b")},
		{name: "missing issuer", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "" }), assert: refused("corp")},
		{name: "missing client id", providers: mutate(valid, func(p *oidc.Provider) { p.ClientID = "" }), assert: refused("corp")},
		{name: "missing redirect URL", providers: mutate(valid, func(p *oidc.Provider) { p.RedirectURL = "" }), assert: refused("corp")},
		{name: "issuer with a port and no host name", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://:8443/realms/dev" }), assert: refused("corp")},
		{name: "issuer with a query", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://idp.example?x=1" }), assert: refused("corp")},
		{name: "issuer with a fragment", providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://idp.example#f" }), assert: refused("corp")},
		{name: "redirect URL with a fragment", providers: mutate(valid, func(p *oidc.Provider) { p.RedirectURL = "https://app.example/cb#f" }), assert: refused("corp")},
		{name: "configured scopes without openid", providers: mutate(valid, func(p *oidc.Provider) { p.Scopes = []string{"profile", "email"} }), assert: refused("openid")},
		{name: "configured empty scopes", providers: mutate(valid, func(p *oidc.Provider) { p.Scopes = []string{} }), assert: refused("openid")},
		{name: "HS256 with an empty client secret", providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"HS256"}; p.ClientSecret = "" }), assert: refused("corp")},
		{name: "plain-text issuer is left to the manager's scheme check",
			providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "http://localhost:8080/realms/dev" }),
			assert:    func(t *testing.T, _ *oidc.Registry, err error) { require.NoError(t, err) }},
		{name: "partial endpoint pin", providers: mutate(valid, func(p *oidc.Provider) { p.TokenEndpoint = "https://idp.example/token" }), assert: refused("corp")},
		{name: "algorithm none", providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"RS256", "none"} }), assert: refused("none")},
		{name: "internal development provider is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.Issuer = "https://localhost:8443/realms/dev" }),
			assert:    func(t *testing.T, _ *oidc.Registry, err error) { require.NoError(t, err) }},
		{name: "end-session endpoint alone is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.EndSessionEndpoint = "https://idp.example/logout" }),
			assert:    func(t *testing.T, _ *oidc.Registry, err error) { require.NoError(t, err) }},
		{name: "HS256 listed explicitly is accepted",
			providers: mutate(valid, func(p *oidc.Provider) { p.SigningAlgs = []string{"HS256"} }),
			assert:    func(t *testing.T, _ *oidc.Registry, err error) { require.NoError(t, err) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := oidc.NewRegistry(tc.providers()...)
			tc.assert(t, r, err)
		})
	}
}
```

`mutate(base func() Provider, fn func(*Provider)) func() []Provider` is a test helper in the same file. There is no separate "symmetric algorithm not listed" refusal to test at the registry: the list is the explicit configuration, so an `HS*` entry *is* explicitly listed. The spec's refusal is realised by `RS256` being the default: a provider that never listed `HS256` never accepts it, which task 5.2's `HS256 signed with the client secret` row pins.

- [ ] **Step 2: See it fail.** Stub `NewRegistry` to return `&Registry{}, nil`. Run: `go test -run TestNewRegistry -count=1 ./oidc/`. Expected: every refusal row FAILs "An error is expected but got nil".
- [ ] **Step 3: Implement.** Validate each provider in order; the URL rule is: parse with `url.Parse`, require a non-empty `Scheme`, a non-empty `Hostname()` (not merely `Host`, which a bare port satisfies), no `User`; the issuer additionally has no `RawQuery` and no `Fragment`, and the redirect URL no `Fragment`. The scheme itself is not checked here: the registry cannot see the outbound client, and design decision 2 makes the scheme follow it (task 2.3). A non-nil `Scopes` must contain `openid`. An `HS*` entry in `SigningAlgs` requires a non-empty `ClientSecret`. The name rule: non-empty, no `/`, and `url.PathEscape(name) == name`. Resolve nil `Scopes` and `SigningAlgs` to copies of the defaults. Error text names the provider and the field, never a secret.
- [ ] **Step 4: See it pass.**

---

### Task 2.3: the Manager constructor and its base options

**Files:**
- Create: `oidc/ports.go` (port interfaces and record types every lane shares), `oidc/manager.go`, `oidc/options_manager.go`, `oidc/idp_helper_test.go`
- Test: `oidc/manager_test.go`

**Interfaces:**
- Produces, in `oidc/ports.go`:

```go
// Flow is one authorization attempt, from Authorize to Callback.
type Flow struct {
	Provider, State, Nonce, Verifier, Next string
	ExpiresAt time.Time
}

type FlowStore interface {
	Begin(ctx context.Context, f Flow) (handle string, err error)
	// Complete decides existence, the provider and state bindings, single
	// completion and expiry in one indivisible operation. Every refusal is
	// ErrInvalidState and leaves the flow as it was.
	Complete(ctx context.Context, handle, provider, state string) (Flow, error)
	// DeleteExpired removes flows that expired before the cutoff. A zero
	// cutoff is refused with ErrRetainSinceRequired.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// ExternalIdentity is a verified identity as the provider asserted it.
type ExternalIdentity struct {
	Provider, Issuer, Subject, Email string
	EmailVerified bool
	Claims        map[string]any // every claim, unchanged
}

type IdentityBroker interface {
	Broker(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error)
}

type Link struct {
	ID                        id.ID
	Provider, Issuer, Subject string
	UserID                    identity.UserID
	Username, Email           string
	CreatedAt                 time.Time
}

type LinkStore interface {
	FindByExternal(ctx context.Context, provider, issuer, subject string) (*Link, error) // ErrLinkNotFound
	Insert(ctx context.Context, l Link) error                                           // ErrLinkExists
	DeleteByUser(ctx context.Context, user identity.UserID) (int, error)
}

type HandoffRecord struct {
	ID         id.ID
	TokenID    string
	SecretHash []byte
	UserID     identity.UserID
	Provider, Issuer, SessionID, IDToken, Next string
	ExpiresAt, CreatedAt time.Time
	ConsumedAt *time.Time
}

type HandoffStore interface {
	Insert(ctx context.Context, rec HandoffRecord) error
	FindByTokenID(ctx context.Context, tokenID string) (*HandoffRecord, error) // ErrHandoffNotFound
	// Consume marks an unconsumed record consumed; a consumed or missing one
	// is ErrHandoffNotFound. Exactly one of racing calls succeeds.
	Consume(ctx context.Context, tokenID string, at time.Time) error
	DeleteExpired(ctx context.Context, before time.Time) (int, error) // zero cutoff: ErrRetainSinceRequired
}

// CallbackResult is a completed, verified and brokered login.
type CallbackResult struct {
	Principal                               *identity.Principal
	Provider, Issuer, SessionID, IDToken    string
	Next                                    string // the requested destination, untrusted
}

//go:generate mockgen -source=ports.go -package=oidc_test -destination=ports_mock_test.go -typed
```

`FindByExternal` returns a pointer so a non-conforming store's nil can be refused rather than dereferenced (design decision 7); `FindByTokenID` likewise. `HandoffRecord.Next` is added here because the redemption response re-resolves the destination the callback carried, and the record is the only thing that crosses from callback to redemption; report it for task 11.3.

- Produces, in `oidc/manager.go` and `oidc/options_manager.go`:

```go
type Manager struct {
	registry *Registry
	out      *outbound.Client
	random   io.Reader
	now      func() time.Time
	flows    FlowStore
	broker   IdentityBroker
	log      *slog.Logger
	sampler  *logsample.Sampler
	// B-mgr adds: cache, flowTTL, cookie/flow limits, skew, logout max age, post-logout redirect.
}

type ManagerOption func(*Manager) error

func NewManager(registry *Registry, broker IdentityBroker, opts ...ManagerOption) (*Manager, error)

func WithOutboundClient(c *outbound.Client) ManagerOption // default outbound.New()
func WithRandom(r io.Reader) ManagerOption                // default crypto/rand.Reader
func WithClock(now func() time.Time) ManagerOption        // default time.Now
func WithFlowStore(s FlowStore) ManagerOption             // default: the in-memory store (B-mgr, task 4.1)
func WithLogger(l *slog.Logger) ManagerOption             // default slog.Default()
```

Also in `oidc/manager.go`, the accessors the chain needs, built on two optional interfaces a broker may implement (the library `Broker` implements both in task 6.3; a consumer broker may implement neither):

```go
// providerScoped is implemented by a broker whose options name providers.
type providerScoped interface{ ConfiguredProviders() []string }

// linkBacked is implemented by a broker that resolves identities through a
// link store, which back-channel logout reuses for subject-only tokens.
type linkBacked interface{ Links() LinkStore }

// roleSyncing is implemented by a broker that can sync roles per provider.
type roleSyncing interface{ RoleSyncProviders() []string }

func (m *Manager) Providers() []string         // the registry's names, in order
func (m *Manager) Links() LinkStore            // nil for a broker that is not link-backed
func (m *Manager) RoleSyncProviders() []string // nil for a broker that does not sync roles
```

`NewManager` refuses, with `ErrConfig` naming the provider, a broker whose `ConfiguredProviders()` names a provider the registry lacks (spec "OIDC wiring mistakes fail at construction": "just-in-time provisioning or role derivation is configured for a provider name that is not registered"). That check lives here because the manager is the one place that holds both the registry and the broker.

`NewManager` takes the broker as a required argument: a manager with no way to resolve an identity cannot complete a login, so its absence is a wiring mistake refused at construction (`identity.MissingPort("identity broker")`), not a default.

- Produces, in `oidc/idp_helper_test.go`: an in-package test provider for every later `oidc` test.

```go
// testProvider is an httptest TLS server acting as an OpenID provider: a
// discovery document, a key set and a token endpoint, with call counters and a
// signer for ID and logout tokens. It lives in a _test.go file because the core
// module never imports the test module.
type testProvider struct {
	srv                          *httptest.Server
	key                          jwk.Key // current RS256 signing key, kid "k1"
	discoveryCalls, jwksCalls    atomic.Int64
	tokenCalls                   atomic.Int64
	tokenResponse                func(r *http.Request) (status int, body string)
	failJWKS, failDiscovery      atomic.Bool
}

func newTestProvider(t *testing.T) *testProvider
func (p *testProvider) Issuer() string
func (p *testProvider) Provider(name string) oidc.Provider // unpinned, pointing at the server
func (p *testProvider) Outbound(t *testing.T) *outbound.Client // trusts the server's certificate
func (p *testProvider) Rotate(t *testing.T, kid string)
func (p *testProvider) Sign(t *testing.T, claims map[string]any, opts ...signOption) string
```

`signOption` covers `withAlg`, `withKid`, `withKey` (to sign with a key the set does not contain), `withHS256Secret` and `withNoneAlg`, so task 5.2's malformed rows need no second helper.

- [ ] **Step 1: Write the failing test.**

```go
func TestNewManagerOptions(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)

	type testCase struct {
		name   string
		broker oidc.IdentityBroker
		opts   []oidc.ManagerOption
		assert func(t *testing.T, m *oidc.Manager, err error)
	}

	fixed := bytes.NewReader(bytes.Repeat([]byte{7}, 4096))

	cases := []testCase{
		{name: "defaults construct with no options", broker: stubBroker{},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a missing broker is refused as a missing port", broker: nil,
			assert: func(t *testing.T, _ *oidc.Manager, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				require.ErrorIs(t, err, identity.ErrMissingPort)
			}},
		{name: "a nil outbound client is refused", broker: stubBroker{},
			opts:   []oidc.ManagerOption{oidc.WithOutboundClient(nil)},
			assert: func(t *testing.T, _ *oidc.Manager, err error) { require.ErrorIs(t, err, oidc.ErrConfig) }},
		{name: "a nil random source is refused", broker: stubBroker{},
			opts:   []oidc.ManagerOption{oidc.WithRandom(nil)},
			assert: func(t *testing.T, _ *oidc.Manager, err error) { require.ErrorIs(t, err, oidc.ErrConfig) }},
		{name: "a broker option naming an unregistered provider is refused",
			broker: scopedStubBroker{providers: []string{"corpp"}},
			assert: func(t *testing.T, _ *oidc.Manager, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				assert.Contains(t, err.Error(), "corpp")
			}},
		{name: "a nil clock is refused", broker: stubBroker{},
			opts:   []oidc.ManagerOption{oidc.WithClock(nil)},
			assert: func(t *testing.T, _ *oidc.Manager, err error) { require.ErrorIs(t, err, oidc.ErrConfig) }},
		{name: "a consumer random source and outbound client are used", broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithRandom(fixed), oidc.WithOutboundClient(p.Outbound(t))},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				// Proven observably in task 4.4, where Authorize's state is the
				// base64url of the fixed bytes; here construction must accept it.
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := oidc.NewManager(reg, tc.broker, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
```

`stubBroker` is a test adapter returning a fixed principal; where a test must verify calls, use the generated `MockIdentityBroker` instead.

- [ ] **Step 2: See it fail.** Stub `NewManager` to return `&Manager{}, nil` ignoring options. Expected: FAIL on every refusal row.
- [ ] **Step 3: Implement.** Apply options in order, then fill defaults for fields still nil (`outbound.New()` — propagate its error wrapped in `ErrConfig`; `crypto/rand.Reader`; `time.Now`; `slog.Default()`; the memory flow store once B-mgr adds it — until then leave `flows` nil and let task 4.1 add the default). Each option refuses nil with `fmt.Errorf("%w: WithX was given nil", ErrConfig)`. A nil registry is refused the same way.
- [ ] **Step 4: See it pass.** Then `go vet ./oidc/ && gofmt -l oidc/`.

**Revision (dispatch B-found-2, after task 1.6).** Two rules added once B-found landed:

- **Typed nils.** The broker, `WithFlowStore` and `WithRandom` are checked with `internal/nilcheck.IsNil`, as `magiclink`, `onetime` and `authenticate` do, so a nil pointer inside a non-nil interface is refused, not dereferenced. Rows: "a typed-nil broker is refused" (`var b *oidc.Broker` passed as the broker; `require.ErrorIs(err, oidc.ErrConfig)`, no panic) and "a typed-nil flow store is refused" (`var fs *MockFlowStore` passed to `WithFlowStore`). Red step: run them against the `== nil` checks; the broker row panics or passes construction, the flow-store row reports "got nil".
- **The scheme follows the client.** After options are applied and the outbound default filled, `NewManager` checks every provider's issuer, redirect URL, end-session endpoint and pinned endpoints with `m.outbound.AllowsScheme(u.Scheme)`, refusing with `fmt.Errorf("%w: provider %q: %s scheme %q is not allowed by the outbound client", ErrConfig, name, field, scheme)`. Rows: "an http issuer is refused with the default client" (error names `corp`); "an http issuer is accepted with a client allowing http" (`outbound.New(outbound.WithAllowedSchemes("http"))`). Red step: before the check exists, the first row reports "An error is expected but got nil".

Run: `go test -run 'TestNewRegistry|TestNewManagerOptions' -race -count=1 ./oidc/`.

---

## Wave B — lane B-mgr: discovery, key cache, flows, callback, logout tokens

B-mgr owns the `Manager` after B0. It runs as four dispatches in order: B-mgr-1 (1.5, 3.x), B-mgr-2 (4.x), B-mgr-3 (5.x), B-mgr-4 (8.x). Each builds on the Manager fields the previous one added, and each is verified and reviewed before the next starts.

### Task 3.1: discovery, confined to the issuer

**Files:**
- Create: `oidc/discovery.go`
- Test: `oidc/discovery_test.go`

**Interfaces:**
- Consumes: `outbound.Client.Get(ctx, url, nil) (*outbound.Response, error)` (`Response.Status`, `Response.Body`); `origin.Same(a, b string) bool` from `internal/origin` (importable: `oidc` is inside the module).
- Produces:

```go
// metadata is what the manager needs from a provider, discovered or pinned.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func (m *Manager) fetchMetadata(ctx context.Context, p Provider) (metadata, error)
func pinnedMetadata(p Provider) (metadata, bool) // true when all three endpoints are pinned
```

- [ ] **Step 1: Write the failing table** `TestDiscovery`, driving `Manager.metadataFor(ctx, "corp")` through an exported test seam in `oidc/export_test.go` (`var MetadataForTest = (*Manager).metadataFor`, `type MetadataForTest = metadata` field accessors). Rows, each serving a crafted document from `testProvider`:
  - "a matching document is accepted": issuer equal, all endpoints on the issuer's origin → no error, `AuthorizationEndpoint` as served.
  - "issuer mismatch is refused": document issuer `https://evil.example` → `require.ErrorIs(err, oidc.ErrDiscoveryFailed)`.
  - "an endpoint on another origin is refused": `jwks_uri` on another host → `ErrDiscoveryFailed`, and the other host's counter is zero.
  - "an endpoint whose scheme the outbound client does not allow is refused": an `http://` endpoint with the default client → `ErrDiscoveryFailed`.
  - "a fully pinned provider sends no discovery request": `discoveryCalls == 0` after `metadataFor`.
  - "a non-JSON document is a provider failure" (Review Focus): an HTML body → `ErrDiscoveryFailed`, no panic.
  - "a non-200 status is a provider failure".
- [ ] **Step 2: See it fail.** Stub `fetchMetadata` to return the pinned metadata or an empty `metadata{}` with nil error. Run `go test -run TestDiscovery -count=1 ./oidc/`. Expected: FAIL on the mismatch, other-origin and non-JSON rows ("An error is expected but got nil").
- [ ] **Step 3: Implement.**

```go
func (m *Manager) fetchMetadata(ctx context.Context, p Provider) (metadata, error) {
	if md, ok := pinnedMetadata(p); ok {
		return md, nil
	}

	res, err := m.out.Get(ctx, strings.TrimSuffix(p.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return metadata{}, fmt.Errorf("%w: %s: %w", ErrDiscoveryFailed, p.Name, err)
	}
	if res.Status != http.StatusOK {
		return metadata{}, fmt.Errorf("%w: %s: status %d", ErrDiscoveryFailed, p.Name, res.Status)
	}

	var md metadata
	if err := json.Unmarshal(res.Body, &md); err != nil {
		return metadata{}, fmt.Errorf("%w: %s: malformed document", ErrDiscoveryFailed, p.Name)
	}
	if md.Issuer != p.Issuer {
		return metadata{}, fmt.Errorf("%w: %s: the document names another issuer", ErrDiscoveryFailed, p.Name)
	}
	for _, u := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JWKSURI} {
		if u == "" {
			return metadata{}, fmt.Errorf("%w: %s: a required endpoint is missing", ErrDiscoveryFailed, p.Name)
		}
	}
	for _, u := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JWKSURI, md.EndSessionEndpoint} {
		if u == "" {
			continue // only end_session_endpoint may be absent, checked above
		}
		pu, err := url.Parse(u)
		if err != nil || !m.outbound.AllowsScheme(pu.Scheme) || !origin.Same(p.Issuer, u) {
			return metadata{}, fmt.Errorf("%w: %s: an endpoint is not on the issuer's origin", ErrDiscoveryFailed, p.Name)
		}
	}
	if p.EndSessionEndpoint != "" {
		md.EndSessionEndpoint = p.EndSessionEndpoint // a pin wins over discovery
	}

	return md, nil
}
```

Check the name of `outbound.Response`'s status field with `go doc ./outbound Response` before writing.
- [ ] **Step 4: See it pass.**

---

### Task 3.2: the TTL cache

**Files:**
- Create: `oidc/keycache.go`
- Modify: `oidc/manager.go` (the `cache` field), `oidc/options_manager.go` (`WithDiscoveryTTL`)
- Test: `oidc/keycache_test.go`

**Interfaces:**
- Produces:

```go
const DefaultDiscoveryTTL = 15 * time.Minute

func WithDiscoveryTTL(d time.Duration) ManagerOption // non-positive: ErrConfig

type entry struct {
	md      metadata // for meta:<provider>
	keys    jwk.Set  // for keys:<provider>
	fetched time.Time
	err     error     // last failure, for the backoff window (task 3.4)
	until   time.Time // end of the backoff window (task 3.4)
	misses  int       // consecutive failures (task 3.4)
	cooled  time.Time // unknown-kid cooldown end (task 3.5)
}

type keyCache struct {
	mu      sync.Mutex
	entries map[string]*entry // "meta:<provider>", "keys:<provider>"
	flight  singleflight.Group
	ttl     time.Duration
	// backoff, cooldown, stale window: tasks 3.4-3.6
}

func (m *Manager) metadataFor(ctx context.Context, provider string) (metadata, error)
func (m *Manager) keysFor(ctx context.Context, provider, kid string) (jwk.Set, error)
```

`keysFor` takes the `kid` from the start so tasks 3.5 and 3.6 change behaviour, not signatures.

- [ ] **Step 1: Write the failing table** `TestKeyCacheTTL`, run inside `synctest.Test` so the clock and `time.Sleep` are the bubble's: construct with `WithClock(time.Now)` inside the bubble.

```go
func TestKeyCacheTTL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.ManagerOption
		setup  func(p *testProvider)
		after  time.Duration // time between the first and second keysFor
		assert func(t *testing.T, p *testProvider, err error)
	}

	cases := []testCase{
		{name: "a fresh entry makes no request", after: 10 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 1, p.jwksCalls.Load())
			}},
		{name: "an expired entry is refetched once", after: 20 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 2, p.jwksCalls.Load())
			}},
		{name: "a consumer TTL of one hour serves a 30-minute-old entry",
			opts: []oidc.ManagerOption{oidc.WithDiscoveryTTL(time.Hour)}, after: 30 * time.Minute,
			assert: func(t *testing.T, p *testProvider, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 1, p.jwksCalls.Load())
			}},
		{name: "a non-JSON key set is a provider failure", after: 0,
			setup: func(p *testProvider) { p.jwksBody.Store("<html>oops</html>") },
			assert: func(t *testing.T, _ *testProvider, err error) { require.ErrorIs(t, err, oidc.ErrDiscoveryFailed) }},
		{name: "an empty key set is a provider failure", after: 0,
			setup: func(p *testProvider) { p.jwksBody.Store(`{"keys":[]}`) },
			assert: func(t *testing.T, _ *testProvider, err error) { require.ErrorIs(t, err, oidc.ErrDiscoveryFailed) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				p := newTestProvider(t)
				if tc.setup != nil {
					tc.setup(p)
				}
				m := newTestManager(t, p, tc.opts...)

				_, _ = oidc.KeysForTest(m, t.Context(), "corp", "k1")
				time.Sleep(tc.after)
				_, err := oidc.KeysForTest(m, t.Context(), "corp", "k1")
				tc.assert(t, p, err)
			})
		})
	}
}
```

`synctest` fakes time for goroutines in the bubble; the `httptest` server's handler goroutines are started from inside the bubble by `newTestProvider`, so they belong to it. If `httptest` TLS handshakes block the bubble's "durably blocked" detection in practice, move the server outside the bubble and inject a controllable clock (`WithClock(fake.Now)`) instead of `time.Sleep` — the design allows either, and the report must say which was used. Add `jwksBody atomic.Value` to `testProvider` (B0's helper; B-mgr owns it from here on) for crafted bodies. The spec row "Consumer TTL" and the non-positive TTL refusal also go here: add `{name: "a zero TTL is refused"}` as a construction row in `TestNewManagerOptions`' style, or as a separate small table `TestKeyCacheOptions` for all the cache's option refusals (TTL, backoff, cooldown, stale window) — one table, filled by 3.2, 3.4, 3.5 and 3.6.
- [ ] **Step 2: See it fail.** Stub `keysFor` to fetch every time. Expected: FAIL on "a fresh entry makes no request" (2 calls, expected 1) and the consumer-TTL row.
- [ ] **Step 3: Implement.** `keysFor` reads the entry under `mu`; when fresh (`now().Sub(fetched) < ttl`), returns it. Otherwise it calls `refresh(ctx, "keys:"+provider)` (task 3.3 wraps that in singleflight). The fetch: `metadataFor` for `JWKSURI`, `m.out.Get`, `jwk.Parse(res.Body)`, refuse `set.Len() == 0` with `ErrDiscoveryFailed`, then filter to keys whose `alg` (or, if absent, key type) fits the provider's `SigningAlgs`.
- [ ] **Step 4: See it pass.**

---

### Task 3.3: coalescing

**Files:** Modify `oidc/keycache.go`, `go.mod`/`go.sum` (task 1.5 lands here: this is the first import of `golang.org/x/sync/singleflight`). Test: `oidc/keycache_test.go`.

- [ ] **Step 1: Write the failing table** `TestKeyCacheCoalesces` with rows:
  - "eight concurrent misses share one fetch": a `testProvider` whose JWKS handler blocks on a channel until 8 callers are waiting (count them with an `atomic.Int64` incremented before `keysFor`), then releases; assert `jwksCalls == 1` and all 8 got the same set.
  - "a cancelling leader does not fail a waiter": the first caller's context is cancelled (the `ctx` modifier field) after the fetch starts; the second caller, on `t.Context()`, still receives the set.
  - "no goroutine outlives the callers": after all callers return and the handler is released, `goleak.VerifyNone(t)` or, if `go.uber.org/goleak` is not already a test dependency, a `runtime.NumGoroutine()` comparison after `synctest.Wait()` inside a bubble. Prefer the bubble: `synctest.Test` itself fails when goroutines started in it are still running at the end, which is the leak check this row needs with no new dependency.
- [ ] **Step 2: See it fail.** Without singleflight, the first row counts 8 fetches.
- [ ] **Step 3: Implement.**

```go
func (c *keyCache) shared(ctx context.Context, key string, fetch func(context.Context) (*entry, error)) (*entry, error) {
	ch := c.flight.DoChan(key, func() (any, error) {
		// The shared call must outlive any single caller's cancellation, but
		// not the outbound bound: WithoutCancel keeps values, drops the cancel.
		return fetch(context.WithoutCancel(ctx))
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*entry), nil
	}
}
```

The outbound client's own timeout bounds the shared call, so a shared fetch cannot hang forever even though no caller can cancel it.
- [ ] **Step 4: See it pass** with `-race`. Then run `go mod tidy` and confirm `go.mod` lists `golang.org/x/sync` as a direct requirement, and `go test -run 'TestModuleLayout|TestConsumerModuleGraph' -count=1 .` still passes (task 1.5).

---

### Task 3.4: failure backoff

**Files:** Modify `oidc/keycache.go`, `oidc/options_manager.go` (`WithDiscoveryFailureBackoff`). Test: `oidc/keycache_test.go` (`TestKeyCacheBackoff`, and refusal rows in `TestKeyCacheOptions`).

**Interfaces:**
- Produces: `func WithDiscoveryFailureBackoff(base, max time.Duration) ManagerOption` (default 1 s, 30 s; non-positive base or `max < base` → `ErrConfig`); `errNotAttempted` (unexported marker joined onto refusals that never reached the network).

- [ ] **Step 1: Write the failing table** `TestKeyCacheBackoff` (synctest bubble):
  - "twenty requests inside the window send nothing": fail the JWKS once; 20 calls within 1 s → `jwksCalls` stays 1, each error `ErrDiscoveryFailed`.
  - "the window doubles and caps": consecutive failures at t=1s, 3s, 7s, … → windows 1, 2, 4, 8, 16, 30, 30 s (assert by probing just before and just after each window's end).
  - "a success resets the window".
  - "a not-attempted refusal leaves the window untouched": trigger a cooldown refusal (task 3.5 must exist — so this row is added in 3.5, and the mutation below is run then).
  - "each window transition is logged once": capture the manager's logger with a `slog` handler that records messages; 20 refusals in one window produce one "backoff" record.
- [ ] **Step 2: See it fail.** Without backoff, row 1 counts 21 fetches.
- [ ] **Step 3: Implement.** On a failed fetch that reached the network, `misses++`, `until = now + min(base << (misses-1), max)`, `err = cause`. A caller finding `now < until` returns the recorded error wrapped in `ErrDiscoveryFailed` without fetching. A refusal wrapped with `errNotAttempted` changes neither `misses` nor `until`. A success sets `misses = 0`, `until = zero`. Log each transition once, directly on the manager's logger and outside the cache lock (not through `m.sampler`, whose one-minute interval would swallow the 1–16 s transitions; the backoff itself bounds the volume). A provider whose algorithms are all symmetric has no key set: `Prefetch` skips it, and `keysFor` is never called for an HS* token.
- [ ] **Step 4: See it pass.**

---

### Task 3.5: unknown `kid` and its cooldown

**Files:** Modify `oidc/keycache.go`, `oidc/options_manager.go` (`WithJWKSRefetchCooldown`). Test: `oidc/keycache_test.go` (`TestKeyCacheUnknownKid`).

**Interfaces:**
- Produces: `func WithJWKSRefetchCooldown(d time.Duration) ManagerOption` (default 30 s, non-positive → `ErrConfig`); `errUnknownSigningKey` (unexported) which verification (task 5.2) maps to `ErrInvalidIDToken`.

- [ ] **Step 1: Write the failing table** `TestKeyCacheUnknownKid`:
  - "key rotation is picked up": cache holds `k1`; `p.Rotate(t, "k2")`; `keysFor(..., "k2")` refetches once and the set contains `k2`.
  - "a hundred random kids cost one fetch": within 10 s, 100 calls each with a random `kid` → `jwksCalls` increases by at most 1; each error `errors.Is(err, oidc.ErrUnknownSigningKeyForTest)` and not `ErrDiscoveryFailed`.
  - "the cooldown is per provider": two providers; `a` inside its cooldown; an unknown `kid` for `b` refetches `b`.
  - "concurrent unknown kids share the refetch": 8 concurrent calls with the same unknown `kid` → one fetch.
  - "a cooldown refusal does not open a backoff window" (the row deferred from 3.4).
- [ ] **Step 2: See it fail.**
- [ ] **Step 3: Implement.** In `keysFor`, when the fresh set lacks `kid`: inside the singleflight body for `keys:<provider>` — **not before it** — check `cooled`; if `now < cooled`, return `errUnknownSigningKey` joined with `errNotAttempted`; otherwise set `cooled = now + cooldown` and fetch. Claiming inside the flight is what makes the goroutine that claims the window the one that fetches.
- [ ] **Step 4: See it pass**, then run the mutations by hand and see each killed: (a) move the cooldown claim before `DoChan` → "concurrent unknown kids share the refetch" or the 100-kid row fails; (b) stop joining `errNotAttempted` → "a cooldown refusal does not open a backoff window" fails. Restore, re-run green, and record in the report which test killed each mutation.

---

### Task 3.6: the stale window

**Files:** Modify `oidc/keycache.go`, `oidc/options_manager.go` (`WithDiscoveryStaleWhileError`). Test: `TestKeyCacheStaleWindow`.

- [ ] **Step 1: Write the failing table:**
  - "the default refuses an expired set during an outage": set fetched at 0; at 20 min the JWKS fails → `ErrDiscoveryFailed`.
  - "a consumer window serves an expired set with a warning": window 10 min, 15 min TTL, at 20 min fetch fails, token `kid` present → the set is returned, one warning naming the provider and the age.
  - "a stale set lacking the kid is a provider failure": same, `kid` absent → `ErrDiscoveryFailed`, not unknown-signing-key.
  - "beyond TTL plus window is refused": at 26 min → `ErrDiscoveryFailed`.
  - "a failed unknown-kid refetch never falls back to the fresh set": fresh set, unknown `kid`, refetch fails → error, not the fresh set.
  - construction: negative window refused (row in `TestKeyCacheOptions`).
- [ ] **Step 2: See it fail.** **Step 3: Implement** the fallback only in the expired-and-refetch-failed branch. **Step 4: See it pass**, then run the mutation "serve the fresh entry after a failed unknown-kid refetch" and see the last row fail.

---

### Task 3.7: `Prefetch`

**Files:** Modify `oidc/keycache.go` or `oidc/manager.go`. Test: `TestManagerPrefetch`.

**Interfaces:** Produces `func (m *Manager) Prefetch(ctx context.Context) error`.

- [ ] **Step 1: Write the failing table:** "construction makes no request" (a registry of two unreachable providers — issuers pointing at a closed port — constructs, zero requests); "prefetch names the unreachable provider" (`Prefetch` error contains `"b"` and wraps `ErrDiscoveryFailed`); "prefetch of reachable providers fills the cache" (a following `keysFor` makes no request); "a cancelled context stops prefetch" (`ctx` modifier cancels first → `context.Canceled`).
- [ ] **Step 2–4:** fail with a no-op `Prefetch`, implement by iterating `registry.Names()` in order calling `metadataFor` and `keysFor(ctx, name, "")` (an empty `kid` means "no key required"), pass.

---

### Task 4.1: the in-memory flow store

**Files:** Create `oidc/flowstore_memory.go`, `oidc/options_manager.go` (`WithFlowTTL`, `WithMaxFlows`; `WithFlowStore` exists from B0). Modify `oidc/manager.go` (default `flows`). Test: `oidc/flowstore_memory_test.go`.

**Interfaces:**
- Produces: `func NewMemoryFlowStore(opts ...MemoryFlowStoreOption) *MemoryFlowStore`, `func WithMaxFlows(n int) MemoryFlowStoreOption` (default `DefaultMaxFlows = 100_000`), `func WithMemoryFlowStoreClock(now func() time.Time) MemoryFlowStoreOption`, `func WithMemoryFlowStoreRandom(r io.Reader) MemoryFlowStoreOption`, `var ErrFlowStoreFull = errors.New("oidc: flow store full")`. `NewManager` uses `NewMemoryFlowStore` with the manager's clock and random source when no `WithFlowStore` is given.

- [ ] **Step 1: Write the failing table** `TestMemoryFlowStore`. The spec's pairing rule applies: every refusal row calls `Complete` wrongly, asserts `ErrInvalidState`, then calls it correctly and asserts success — which is what catches a store that burns the flow before comparing.

```go
func TestMemoryFlowStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	begin := func(t *testing.T, s *oidc.MemoryFlowStore) string {
		h, err := s.Begin(t.Context(), oidc.Flow{Provider: "a", State: "st", ExpiresAt: now.Add(10 * time.Minute)})
		require.NoError(t, err)
		return h
	}

	type testCase struct {
		name   string
		wrong  func(t *testing.T, s *oidc.MemoryFlowStore, h string) error // the refused call
		after  time.Duration                                                // clock advance before the correct call
		assert func(t *testing.T, refused error, retry error)
	}

	noop := func(*testing.T, *oidc.MemoryFlowStore, string) error { return nil }

	stillCompletable := func(t *testing.T, refused, retry error) {
		require.ErrorIs(t, refused, oidc.ErrInvalidState)
		require.NoError(t, retry, "a refused completion must leave the flow exactly as it was")
	}

	cases := []testCase{
		{name: "unknown handle", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, _ string) error {
			_, err := s.Complete(t.Context(), "nope", "a", "st"); return err }, assert: stillCompletable},
		{name: "wrong provider", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, h string) error {
			_, err := s.Complete(t.Context(), h, "b", "st"); return err }, assert: stillCompletable},
		{name: "wrong state", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, h string) error {
			_, err := s.Complete(t.Context(), h, "a", "attacker"); return err }, assert: stillCompletable},
		{name: "empty state", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, h string) error {
			_, err := s.Complete(t.Context(), h, "a", ""); return err }, assert: stillCompletable},
		{name: "zero purge cutoff", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, _ string) error {
			_, err := s.DeleteExpired(t.Context(), time.Time{}); return err },
			assert: func(t *testing.T, refused, retry error) {
				require.ErrorIs(t, refused, oidc.ErrRetainSinceRequired)
				require.NoError(t, retry)
			}},
		{name: "expired flow is refused", after: 11 * time.Minute, wrong: noop,
			assert: func(t *testing.T, _, retry error) { require.ErrorIs(t, retry, oidc.ErrInvalidState) }},
		{name: "a completed flow is refused the second time", wrong: func(t *testing.T, s *oidc.MemoryFlowStore, h string) error {
			_, err := s.Complete(t.Context(), h, "a", "st"); return err },
			assert: func(t *testing.T, first, second error) {
				require.NoError(t, first)
				require.ErrorIs(t, second, oidc.ErrInvalidState)
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clock := now
			s := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreClock(func() time.Time { return clock }))
			h := begin(t, s)
			refused := tc.wrong(t, s, h)
			clock = clock.Add(tc.after)
			_, retry := s.Complete(t.Context(), h, "a", "st")
			tc.assert(t, refused, retry)
		})
	}
}
```

Add rows for the capacity limit ("the store refuses above its maximum and evicts nothing": `WithMaxFlows(2)`, begin three, the third is `ErrFlowStoreFull`, the first two still complete) and inline pruning ("expired flows do not count toward the maximum").

- [ ] **Step 2: See it fail** with a map that deletes on lookup before comparing. The "wrong state" row's retry fails: that is the burn-before-compare defect the pairing exists to catch.
- [ ] **Step 3: Implement** under one `sync.Mutex`: prune expired entries whenever `Begin` finds the map at capacity; `Complete` checks existence, `provider ==`, `subtle.ConstantTimeCompare([]byte(state), []byte(f.State)) == 1 && state != ""`, and `now < ExpiresAt`, and deletes only when every check passed. Handles are 32 random bytes, base64url.
- [ ] **Step 4: See it pass.**

### Task 4.2: racing completions

- [ ] **Step 1:** `TestMemoryFlowStoreRacingComplete`: begin one flow; 8 goroutines wait on a `sync.WaitGroup` barrier, then `Complete` with correct arguments; collect results. Assert exactly one nil error and seven `ErrInvalidState`.
- [ ] **Step 2:** See it fail by temporarily splitting `Complete` into a locked read and a separately locked delete (read-then-write). Run `go test -run TestMemoryFlowStoreRacingComplete -race -count=20 ./oidc/` — more than one success appears.
- [ ] **Step 3:** Restore the single critical section. **Step 4:** PASS under `-race -count=20`.

### Task 4.3: `RunFlowStoreSuite` (test module)

**Files:** Create `test/oidc/doc.go` (package `oidctest`, "conformance suites and a test identity provider for the oidc package"), `test/oidc/flowstore_suite.go`, `test/oidc/flowstore_guard_test.go`, `test/oidc/flowstore_suite_test.go`.

**Interfaces:** Produces `func RunFlowStoreSuite(t *testing.T, newStore func(t *testing.T, now func() time.Time) oidc.FlowStore)`. The factory takes a clock so the suite can expire flows without sleeping; a durable adapter passes it to its own clock option.

- [ ] **Step 1:** Write the suite: every row of task 4.1 (paired), the racing row behind a barrier, and "deleting expired flows removes only those before the cutoff and reports the count". Write the guard in the identity suite's pattern: a `brokenFlowStore` with named defects (`burns-before-compare`, `read-then-write`, `ignores-provider`, `accepts-zero-cutoff`, `non-constant-time-irrelevant` is **not** a defect the suite can observe, so leave it out), `TestBrokenFlowStoreConformance` reading `SCRTY_OIDC_FLOW_DEFECT`, and `TestFlowStoreSuiteIsLoadBearing` re-executing the binary once per defect.
- [ ] **Step 2:** Run `cd test && go test -run TestFlowStoreSuiteIsLoadBearing -race -count=1 ./oidc/` before the suite has its rows: every "defect is caught" row FAILs (the suite passed a broken store). That is the red step.
- [ ] **Step 3:** Fill the rows. **Step 4:** `cd test && go test -run 'TestFlowStoreSuite|TestMemoryFlowStoreConformance' -race -count=1 ./oidc/` PASS, where `TestMemoryFlowStoreConformance` runs the suite against `oidc.NewMemoryFlowStore`.

### Task 4.4: `Authorize`

**Files:** Create `oidc/authorize.go`. Modify `oidc/options_manager.go` (`WithFlowTTL`, default `DefaultFlowTTL = 10 * time.Minute`). Test: `oidc/authorize_test.go`.

**Interfaces:**
- Produces:

```go
type Authorization struct {
	RedirectURL string    // the provider's authorization endpoint with every parameter
	Handle      string    // opaque flow handle for the cookie
	ExpiresAt   time.Time // when the flow expires, for the cookie's Max-Age
}

func (m *Manager) Authorize(ctx context.Context, provider, next string) (Authorization, error)
```

- [ ] **Step 1: Write the failing table** `TestManagerAuthorize`: "the redirect carries PKCE, state and nonce" (parse `RedirectURL`: `response_type=code`, `client_id`, `redirect_uri`, `scope=openid profile email`, `code_challenge_method=S256`, `code_challenge` equal to `base64url(sha256(verifier))` where the verifier is recovered through `FlowForTest(store, handle)`; no `code_verifier` parameter); "two attempts carry different values"; "consumer scopes are requested exactly" (`Scopes: {"openid","groups"}` → `scope=openid groups`); "an unknown provider stores no flow" (`ErrUnknownProvider`, store empty); "the configured random source is used" (fixed reader → deterministic state, which proves `WithRandom` from task 2.3); "a discovery failure is a provider failure".
- [ ] **Step 2–4:** fail with a stub, implement (`randomToken(m.random, 32)` for state, nonce and verifier; `FlowStore.Begin`; build the URL with `url.Values`), pass.

---

### Task 5.1: the code exchange

**Files:** Create `oidc/exchange.go`. Test: `oidc/exchange_test.go`.

**Interfaces:**
- Consumes: `outbound.Client.PostForm(ctx, url, form, header)` from task 1.1.
- Produces: `func (m *Manager) exchange(ctx context.Context, p Provider, md metadata, code, verifier string) (rawIDToken string, err error)`.

- [ ] **Step 1: Write the failing table** `TestExchange` (through `ExchangeForTest`), with `testProvider.tokenResponse` recording the request:
  - "client_secret_post sends credentials in the form": form has `client_id`, `client_secret`, `code`, `code_verifier`, `redirect_uri`, `grant_type=authorization_code`; no `Authorization` header.
  - "client_secret_basic sends a Basic header and no secret field": header equals `"Basic " + base64(url.QueryEscape(id) + ":" + url.QueryEscape(secret))` (RFC 6749 §2.3.1 form-encodes both before joining); form has `client_id`? — **no**: with Basic the form carries neither `client_id` nor `client_secret`.
  - "invalid_grant is a provider failure that hides the description": 400 `{"error":"invalid_grant","error_description":"code reused by 203.0.113.9"}` → `ErrExchangeFailed`, and `err.Error()` does not contain `203.0.113.9`.
  - "a response without an ID token is a provider failure".
  - "a malformed JSON response is a provider failure".
  - "the provider's access and refresh tokens are discarded": the function's only output is the raw ID token (a compile-time fact; assert the returned string equals the `id_token` member).
- [ ] **Step 2:** Fail with the post form always, **Step 3** implement, **Step 4** pass. Log the provider's error body truncated to 256 bytes at WARN through the manager's sampler, never in the returned error.

### Task 5.2: ID token verification

**Files:** Create `oidc/verify.go`. Modify `oidc/options_manager.go` (`WithClockSkew`, default 60 s). Test: `oidc/verify_test.go`.

**Interfaces:**
- Produces:

```go
// parseProviderJWT verifies signature, algorithm, kid, issuer, audience and
// times, and returns the token for the caller's own claim checks.
func (m *Manager) parseProviderJWT(ctx context.Context, p Provider, raw string, requireExp bool) (jwt.Token, error)

func (m *Manager) verifyIDToken(ctx context.Context, p Provider, raw, nonce string) (idClaims, error)

type idClaims struct {
	Subject, SessionID, Email string
	EmailVerified            bool
	Claims                   map[string]any
}
```

- [ ] **Step 1: Write the failing table** `TestVerifyIDToken` — one row per malformed token, each built with `testProvider.Sign` and its `signOption`s, each asserting `require.ErrorIs(t, err, oidc.ErrInvalidIDToken)`:
  wrong `iss`; wrong `aud`; expired; missing `exp`; `iat` 5 minutes in the future; `nbf` in the future; bad signature (`withKey` of an unknown key but the set's `kid`); unknown `kid` inside the cooldown; `alg: none` (`withNoneAlg`); `HS256` signed with the client secret for a provider that never listed it; wrong `nonce`; missing `sub`; empty `sub`; audiences `client` and `other` with no `azp`; audiences with `azp` naming another client; provider configured for `ES256` only and a token signed `RS256`.
  Plus accepted rows: "a valid token", "several audiences with azp equal to the client id", "a consumer skew of 5 minutes accepts an iat 3 minutes ahead", "HS256 listed for the provider verifies with the client secret".
  Plus: "a key set that cannot be fetched is a provider failure" → `ErrDiscoveryFailed`, not `ErrInvalidIDToken`.
- [ ] **Step 2: See it fail.** First implementation: parse without `WithValidate` — the time and audience rows fail.
- [ ] **Step 3: Implement.**

```go
func (m *Manager) parseProviderJWT(ctx context.Context, p Provider, raw string, requireExp bool) (jwt.Token, error) {
	hdr, err := peekHeader(raw) // jws.Parse(..) without verification, for alg and kid only
	if err != nil || !slices.Contains(p.SigningAlgs, hdr.alg) || hdr.kid == "" {
		return nil, fmt.Errorf("%w: header", ErrInvalidIDToken)
	}

	set, err := m.keysFor(ctx, p.Name, hdr.kid)
	switch {
	case errors.Is(err, errUnknownSigningKey):
		return nil, fmt.Errorf("%w: unknown signing key", ErrInvalidIDToken)
	case err != nil:
		return nil, err // ErrDiscoveryFailed from the cache
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set, jws.WithRequireKid(true)),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(p.ClientID),
		jwt.WithAcceptableSkew(m.skew),
		jwt.WithClock(jwt.ClockFunc(m.now)),
		jwt.WithValidate(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}
	if _, ok := tok.Expiration(); requireExp && !ok {
		return nil, fmt.Errorf("%w: no expiry", ErrInvalidIDToken)
	}

	return tok, nil
}
```

The exact jwx v4 accessor and option names (`Expiration()` returning `(time.Time, bool)`, `jwt.WithClock`, `jwt.ClockFunc`, whether an `HS256` entry needs the secret as a `jwk.Key` added to a derived set) must be confirmed with `go doc github.com/lestrrat-go/jwx/v4/jwt` before writing; adjust names, not behaviour. For an `HS*` algorithm, verify against `jwk.Import([]byte(p.ClientSecret))` with that `alg` instead of the provider's key set. `verifyIDToken` then checks `sub` non-empty, `azp == ClientID` when `len(aud) > 1`, and `subtle.ConstantTimeCompare(nonce claim, flow nonce) == 1`.
- [ ] **Step 4: See it pass.**

### Task 5.3: `Callback` and `AbortFlow`

**Files:** Create `oidc/callback.go`. Test: `oidc/callback_test.go`.

**Interfaces:**
- Consumes: `FlowStore.Complete`, `exchange`, `verifyIDToken`, `IdentityBroker.Broker` (a generated `MockIdentityBroker` in tests).
- Produces:

```go
func (m *Manager) Callback(ctx context.Context, provider, code, state, handle string) (CallbackResult, error)

// AbortFlow ends the flow when the echoed state completes it, and reports
// whether it did. Only then may the caller clear the cookie or log the
// provider's error text.
func (m *Manager) AbortFlow(ctx context.Context, provider, state, handle string) (bool, error)
```

- [ ] **Step 1: Write the failing table** `TestManagerCallback`:
  - "a forged callback leaves the victim's flow completable": `Callback(corp, attackerCode, "attacker", victimHandle)` → `ErrInvalidState` joined with `ErrFlowUnspent`; then the genuine callback succeeds.
  - "a forged error link changes nothing": `AbortFlow(corp, "", victimHandle)` → `false, nil`; genuine callback still succeeds.
  - "a genuine denial ends the flow": `AbortFlow(corp, realState, handle)` → `true`; a later genuine callback is `ErrInvalidState`.
  - "an unknown provider": `ErrUnknownProvider`, with `ErrFlowUnspent`.
  - "an exchange failure spends the flow": after `Complete`, `ErrExchangeFailed` **without** `ErrFlowUnspent`.
  - "a store fault propagates as itself": a `MockFlowStore` returning `errors.New("db down")` from `Complete` → that error, with `ErrFlowUnspent`, not `ErrInvalidState`.
  - "a successful callback returns the brokered principal and the provider session": `CallbackResult` carries the broker's principal, `Provider`, `Issuer`, `SessionID` from `sid`, the raw ID token, and `Next` from the flow.
  - "a broker refusal is returned as itself": the broker returns `ErrNoLinkedAccount` → that error, flow spent.
- [ ] **Step 2–4:** fail, implement (join `ErrFlowUnspent` with `errors.Join` only on returns at or before `Complete`), pass.

---

### Task 8.1: logout-token verification

**Files:** Create `oidc/logouttoken.go`. Modify `oidc/options_manager.go` (`WithLogoutTokenMaxAge`, default 2 min). Test: `oidc/logouttoken_test.go`.

**Interfaces:** Produces `type LogoutClaims struct { Issuer, Subject, SessionID, JTI string }` and `func (m *Manager) VerifyLogoutToken(ctx context.Context, provider, raw string) (LogoutClaims, error)`.

- [ ] **Step 1: Write the failing table** `TestVerifyLogoutToken`, every row a signed token from `testProvider.Sign`, refusals asserting `ErrInvalidLogoutToken`: an ID token (has `nonce`, no `events`); issued 5 minutes ago with the default max age; missing `iat` and `exp`; `iat` 5 minutes in the future; an expired `exp`; missing `jti`; `events` without the back-channel member; the back-channel member not an object (`true`); neither `sub` nor `sid`; wrong audience; unknown provider (`ErrUnknownProvider`). Accepted rows: `sid` only; `sub` only; both; an extra member inside the event object; "a consumer max age of 10 minutes accepts a 5-minute-old token". Provider failure row: key set unreachable → `ErrDiscoveryFailed`.
- [ ] **Step 2: See it fail**, **Step 3** implement on `parseProviderJWT(ctx, p, raw, false)` then the logout-specific checks (the `iat` presence and both directions checked explicitly, not left to jwx defaults), mapping every `ErrInvalidIDToken` from the shared parser to `ErrInvalidLogoutToken`, **Step 4** pass. Then run the mutation "drop the `iat` presence check" and see "missing iat and exp" fail.

### Task 8.2: end-session URL

**Files:** Create `oidc/endsession.go`. Modify `oidc/options_manager.go` (`WithPostLogoutRedirect`). Test: `oidc/endsession_test.go`.

**Interfaces:**
- Produces: `func (m *Manager) EndSessionURL(ctx context.Context, provider, idTokenHint, state string) (string, error)` and the adapter the chain uses: `func (m *Manager) EndSessionBuilder() interface{ EndSessionURL(context.Context, *session.Session, string) (string, error) }` returning a value whose method reads `s.ExternalProvider` and `s.ExternalIDToken`. `oidc` must not import `httpsec`, so the adapter satisfies `httpsec.EndSessionBuilder` structurally; C-http asserts it with `var _ httpsec.EndSessionBuilder = (*oidc.Manager)(nil).EndSessionBuilder()` in a test.
- `WithPostLogoutRedirect(u string) ManagerOption`: absolute `https`, host, no user information, else `ErrConfig`. Design decision 13 passes the redirect as an argument of `EndSessionURL`; the option form keeps it validated once at construction and out of every call site. Report it for task 11.3.

- [ ] **Step 1: Write the failing table** `TestEndSessionURL`: "with an endpoint and a redirect" (URL targets the endpoint with `client_id`, `id_token_hint`, `post_logout_redirect_uri`, `state`); "no redirect configured omits the parameter"; "an empty state is omitted"; "no end-session endpoint yields no URL and no error"; "an unknown provider yields no URL and no error" (a session from a provider since removed from the registry must not fail logout); "the session adapter reads the session's provider and token"; construction rows for an invalid redirect (`http://`, `https://user@app.example/`, relative).
- [ ] **Step 2–4.**

---

## Wave B — lane B-brk: links, broker, provisioning, mirroring, roles

### Task 6.1: the in-memory link store

**Files:** Create `oidc/link.go` (helpers shared by link code), `oidc/linkstore_memory.go`. Test: `oidc/linkstore_memory_test.go`.

**Interfaces:** Produces `func NewMemoryLinkStore() *MemoryLinkStore` implementing `LinkStore` from B0.

- [ ] **Step 1: Write the failing table** `TestMemoryLinkStore`, closure form, rows:
  - "a conflicting insert is refused and the stored link is unchanged": insert `(corp, iss, s-1) → u-1`, insert same key → `u-2`: `ErrLinkExists`; `FindByExternal` returns `u-1`.
  - "an identical re-insert is refused": `ErrLinkExists`.
  - "the same subject at another issuer is another key": both inserts succeed.
  - "find of a missing key is link not found".
  - "deleting a user's links returns the count": two providers for `u-1` → `2`; both keys then `ErrLinkNotFound`; a third link for `u-2` untouched.
  - "references and usernames round-trip byte for byte": user `U-1 ` and username ` Ada@Example.COM` come back unchanged.
  - "refusal errors carry no identifying value": `ErrLinkExists`'s text contains neither the subject, the email, the username nor the reference.
- [ ] **Step 2: See it fail** with a map that overwrites on insert: the first and second rows fail.
- [ ] **Step 3: Implement** a mutex-guarded map keyed by the three-part key (joined with a separator that cannot appear unescaped, or a struct key). `FindByExternal` returns a copy.
- [ ] **Step 4: See it pass.**

### Task 6.2: `RunLinkStoreSuite` (test module)

**Files:** Create `test/oidc/linkstore_suite.go`, `test/oidc/linkstore_guard_test.go`, `test/oidc/linkstore_suite_test.go`. (`test/oidc/doc.go` is B-mgr's; this lane only adds files in the package.)

**Interfaces:** `func RunLinkStoreSuite(t *testing.T, newStore func(t *testing.T) oidc.LinkStore)`.

- [ ] **Steps 1–4** as task 4.3: every task 6.1 row plus "eight concurrent inserts of one key: exactly one succeeds, seven are ErrLinkExists" behind a barrier; the guard with defects `overwrites-on-insert`, `read-then-write`, `ignores-issuer`, `case-folds-reference`, `no-delete-count`, re-executed by `TestLinkStoreSuiteIsLoadBearing` reading `SCRTY_OIDC_LINK_DEFECT`. Red step: the load-bearing test before the suite has rows. Verify: `cd test && go test -run 'TestLinkStoreSuite|TestMemoryLinkStoreConformance' -race -count=1 ./oidc/`.

### Task 6.3: `NewBroker` and linked resolution by user reference

**Files:** Create `oidc/broker.go`, `oidc/options_broker.go`, `oidc/claims.go` (dotted-path claim lookup, shared by name, password and role claims), `oidc/broker_mocks_test.go` (generated). Test: `oidc/broker_test.go`.

**Interfaces:**
- Produces:

```go
type Broker struct{ /* links, users, provisioner, per-provider config, log, sampler, ids, now */ }

type BrokerOption func(*Broker) error

func NewBroker(links LinkStore, users identity.UserLoader, opts ...BrokerOption) (*Broker, error)
func (b *Broker) Broker(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error)
func (b *Broker) RoleSyncProviders() []string

func WithBrokerLogger(l *slog.Logger) BrokerOption      // default slog.Default()
func WithBrokerClock(now func() time.Time) BrokerOption // default time.Now
func WithBrokerIDGenerator(g id.Generator) BrokerOption // default id.NewV7Generator()

func (b *Broker) ConfiguredProviders() []string // every provider any option names, deduplicated
func (b *Broker) Links() LinkStore             // the link store it was built with
```

These satisfy the optional interfaces B0 declared in `oidc/manager.go`; add `var _ interface{ ConfiguredProviders() []string } = (*oidc.Broker)(nil)`-style assertions in a test.

The `Broker`-prefixed names exist because `oidc` has one namespace and the manager already has `WithClock`/`WithLogger`; "options are named after what they govern". Report the naming for task 11.3.

- Mock directive in `oidc/broker_test.go`: `//go:generate mockgen -destination=broker_mocks_test.go -package=oidc_test -typed github.com/kartaladev/scrty/identity UserLoader,UserProvisioner`. Confirm reflect-mode multi-interface syntax with `mockgen --help`; if it takes one interface per invocation, add two directives with distinct destinations.

- [ ] **Step 1: Write the failing table** `TestBrokerLinkedResolution` with a `MockUserLoader` and the memory link store seeded with `(corp, https://corp.example, s-1) → u-1 / alice`:
  - "a linked identity resolves by reference": `LoadByUserID(u-1)` returns active details for `u-1` → principal `u-1`. `LoadByUsername` has **no** expectation, so gomock fails the test if it is called.
  - "a dangling link is an authentication failure": `LoadByUserID` → `identity.ErrUserNotFound` → `ErrNoLinkedAccount`.
  - "a recycled username never reaches the loader": details for `u-1` missing; the mock expects only `LoadByUserID(u-1)`; the result is `ErrNoLinkedAccount` and nothing ever asked for `alice`.
  - "a non-conforming loader returning another user is refused": `LoadByUserID(u-1)` returns details with `ID: u-2` → `ErrNoLinkedAccount`.
  - "nil details are refused" → `ErrNoLinkedAccount`.
  - "a disabled user is refused" → `ErrNoLinkedAccount`.
  - "a loader outage is not an authentication failure": `errors.New("db down")` → error wraps it, `NotErrorIs(authenticate.ErrAuthenticationFailed)`.
  - "the same email at another issuer does not resolve": ext `(social, https://social.example, s-2, alice@corp.example)` with no link → `ErrNoLinkedAccount`, loader never called.
  - "the same subject at another issuer does not resolve".
  - construction: "a nil link store is a missing port", "a nil user loader is a missing port" (both `ErrConfig` and `identity.ErrMissingPort`).
- [ ] **Step 2: See it fail** with an implementation that calls `LoadByUsername(link.Username)`: the first row fails on the unexpected call. That is also the mutation "LoadByUsername substituted for LoadByUserID".
- [ ] **Step 3: Implement.**

```go
func (b *Broker) resolveLinked(ctx context.Context, l *Link) (*identity.Details, error) {
	det, err := b.users.LoadByUserID(ctx, l.UserID)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		b.warn(ctx, "a link names a user that no longer exists", l)
		return nil, ErrNoLinkedAccount
	case err != nil:
		return nil, fmt.Errorf("oidc: loading a linked user: %w", redact(err))
	case det == nil || det.ID != l.UserID:
		b.warn(ctx, "a link resolved to another user", l)
		return nil, ErrNoLinkedAccount
	case !det.Active:
		b.debug(ctx, "a linked user is inactive", l)
		return nil, ErrNoLinkedAccount
	}

	return det, nil
}
```

`b.warn`/`b.debug` log the provider and the domain of the link's email, never the subject, username or reference. `redact` wraps the error in a type whose `Error()` replaces bcrypt-shaped substrings (`\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}`) with `[redacted]` and whose `Unwrap` returns the original (task 6.5 pins redaction; define it here because this is its first use).
- [ ] **Step 4: See it pass**, then run the mutation "drop the `det.ID != l.UserID` check" and see "a non-conforming loader returning another user is refused" fail.

### Task 6.4: just-in-time provisioning

**Files:** Create `oidc/provision.go`. Modify `oidc/options_broker.go`. Test: `oidc/provision_test.go`.

**Interfaces:** Produces `WithJIT(provider string) BrokerOption`, `WithJITAllowUnverifiedEmail(provider string) BrokerOption`, `WithJITEmailDomains(provider string, domains ...string) BrokerOption`, `WithNameClaim(provider, path string) BrokerOption`, `WithProvisioner(p identity.UserProvisioner) BrokerOption`, `WithDefaultRole(role string) BrokerOption` (used here for the provisioned user's roles; task 6.7 adds the claim-derived roles).

- [ ] **Step 1: Write the failing table** `TestBrokerProvisioning`, one row per scenario of the three provisioning requirements in `specs/identity-linking`, with `MockUserProvisioner` expectations stating exactly the `Provision` call (use a gomock matcher that applies the options with `identity.ApplyUserOptions` and compares the resulting `*NewUser` fields and `IsSet` flags):
  - off by default: unlinked identity → `ErrNoLinkedAccount`; provisioner has no expectation.
  - enabled for `corp` only: `corp` identity → `Provision("bob@corp.example", name, email, roles)`, link inserted for the returned `ID`/`Username`; `social` identity → `ErrNoLinkedAccount`.
  - pre-created link resolves with provisioning off.
  - unverified email refused; consumer allows unverified; subdomain refused; case-insensitive domain accepted; configured-empty allowlist refuses everyone; no email refused.
  - username taken: `Provision` → `identity.ErrUserExists` → `ErrProvisioningRefused`; no link inserted.
  - provisioner normalizes: returns `Username: "bob@corp.example"` for `Bob@Corp.example` → link records the returned username; the next login resolves.
  - consumer display-name claim: `WithNameClaim("corp","name")`, claim `Bob B.` → `WithUserName("Bob B.")`.
  - link insert fails after the user was created → the login fails, an ERROR log names the provider and says later logins will be refused until an operator inserts the link.
  - construction: `WithJIT` without `WithProvisioner` → `ErrConfig` and `identity.ErrMissingPort`, text names "user provisioner"; `WithJIT("corpp")` naming an unknown provider is **not** checked here — the broker has no registry — and is instead refused by `NewManager` (task 2.3), which sees both through `ConfiguredProviders()`. Add a row asserting `ConfiguredProviders()` lists `corpp`.
- [ ] **Step 2–4.** Implement "configured" versus "configured empty" with a `map[string][]string` and a comma-ok read.

### Task 6.5: password-hash claim

**Files:** Create `oidc/passwordclaim.go`. Modify `oidc/options_broker.go`. Test: `oidc/passwordclaim_test.go`.

**Interfaces:** Produces `WithPasswordClaim(provider, path string) BrokerOption`, `WithPasswordEncoder(enc password.Encoder) BrokerOption`, `WithPasswordClaimCostRange(min, max int) BrokerOption` (default 10, 15), and `func (b *Broker) mappedUserOptions(provider string, claims map[string]any) []identity.UserOption` — the single resolution used by provisioning (6.4) and mirroring (6.6). Check `password.Encoder`'s method name with `go doc ./password Encoder` before writing the probe.

- [ ] **Step 1: Write the failing table** `TestBrokerPasswordClaim`, one row per scenario of spec "A password hash can be mapped from a claim only in a verifiable, bounded form": cost-12 hash accepted into provisioning; `hunter2` ignored and absent from every log record (capture with a recording `slog.Handler`); cost 31 ignored with a WARN naming `31` and `10`–`15`; a second cost-31 claim for the same provider logs at DEBUG; a widened band `4`–`15` accepts cost 4; construction refusals (no encoder; an Argon2id encoder — use the real `password` package's Argon2id encoder; band `3`–`15`; band `12`–`10`; empty provider key; name claim path equal to the password path; role claim path equal to the password path); a provisioner error containing a bcrypt hash has it redacted in `err.Error()` while `errors.Is` still reaches the original.
- [ ] **Step 2–4.** Anchored regexp `^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$`, then `bcrypt.Cost([]byte(v))` for the band.

### Task 6.6: claim mirroring

**Files:** Create `oidc/mirror.go`. Modify `oidc/options_broker.go` (`WithClaimMirror(provider string, on bool)`). Test: `oidc/mirror_test.go`.

- [ ] **Step 1: Write the failing table** `TestBrokerClaimMirroring`, one row per scenario of spec "Claim mirroring refreshes mapped fields on later logins through an update", with `MockUserProvisioner.Update` expectations whose matcher asserts `ApplyUserOptions(opts...).IsSet(identity.FieldPassword)` true and `IsSet(identity.FieldName)` false for the changed-hash row; the partial-result row returns details with no roles from `Update` and asserts the principal still carries `editor`; the failure row returns an error from `Update` and asserts the login succeeds with the old name and one ERROR record; construction refusals (mirroring without a provisioner; without any claim path).
- [ ] **Step 2–4.**

```go
// mirroredFields is the one table seeding, comparison and copy-back read, so
// the three cannot disagree about which fields mirroring owns.
var mirroredFields = []struct {
	field identity.Field
	get   func(*identity.Details) any
	set   func(dst *identity.Details, src *identity.NewUser)
}{
	{identity.FieldName, func(d *identity.Details) any { return d.Name },
		func(dst *identity.Details, src *identity.NewUser) { dst.Name = src.Name }},
	{identity.FieldPassword, func(d *identity.Details) any { return string(d.Password) },
		func(dst *identity.Details, src *identity.NewUser) { dst.Password = src.Password }},
}
```

Compare each field only when `proposal.IsSet(f.field)`; call `Update` with only the options whose field differs; on success copy back only those fields onto the per-request details.

### Task 6.7: roles from claims

**Files:** Create `oidc/roles.go`. Modify `oidc/options_broker.go` (`WithRoleClaim`, `WithRoleMapping`, `WithAllowedRoles`, `WithRoleSync`). Test: `oidc/roles_test.go`.

- [ ] **Step 1: Write the failing table** `TestBrokerRoles`, one row per scenario of specs "Roles can be derived from a claim path at provisioning" and "Role sync applies claim-derived roles to each login without persisting them" that the broker decides alone (the conveyance refusal is task 9.2's): default role; nested path `realm_access.roles`; explicitly empty path yields none with no default; allowlist drops `admin`; mapping drops unmapped values; a path resolving to a number yields none and one sampled log; configured-empty mapping or allowlist drops everything; matching is case-sensitive; role sync replaces the principal's roles with name-and-primary-only roles and never calls `Update`; a stored super role does not survive sync; `RoleSyncProviders()` lists exactly the providers with sync on; `WithRoleSync` without a claim path is refused.
- [ ] **Step 2–4.**

### Task 6.8: a consumer broker

**Files:** Test only: `oidc/callback_consumerbroker_test.go`. (It exercises `Manager.Callback` with a consumer `IdentityBroker`; it lives in this lane because it asserts the *library* broker's collaborators are never called, which this lane owns. It compiles against B-mgr's `Callback`, so it is the lane's last task and runs after B-mgr's task 5.3 lands.)

- [ ] **Step 1:** `TestConsumerBroker`: a `MockIdentityBroker` receives an `ExternalIdentity` whose `Claims["department"] == "R&D"` exactly; the memory link store is wrapped to count calls (zero) and a `MockUserProvisioner` has no expectations. **Step 2:** fail by passing the library `Broker` instead. **Step 3–4:** use the consumer broker; pass.

---

## Wave B — lane B-hof: the handoff code

### Task 7.1: the in-memory handoff store

**Files:** Create `oidc/handoffstore_memory.go`. Test: `oidc/handoffstore_memory_test.go`.

**Interfaces:** `func NewMemoryHandoffStore(opts ...MemoryHandoffStoreOption) *MemoryHandoffStore`, `WithMemoryHandoffStoreClock`.

- [ ] **Step 1: Write the failing table** `TestMemoryHandoffStore`: insert then find returns a copy (mutating it does not change the store); find of a missing id is `ErrHandoffNotFound`; consume of an unconsumed record succeeds and a second consume is `ErrHandoffNotFound`; consume of a missing id is `ErrHandoffNotFound` and a following find of another record still works; `DeleteExpired` removes only records expired before the cutoff and returns the count; a zero cutoff is `ErrRetainSinceRequired` and every record survives.
- [ ] **Step 2–4.**

### Task 7.2: `RunHandoffStoreSuite` (test module)

**Files:** Create `test/oidc/handoffstore_suite.go`, `test/oidc/handoffstore_guard_test.go`, `test/oidc/handoffstore_suite_test.go`.

- [ ] **Steps 1–4** as task 4.3: every 7.1 row, plus "eight concurrent consumes: exactly one succeeds" behind a barrier; defects `consume-twice`, `read-then-write`, `accepts-zero-cutoff`, `find-returns-shared-pointer`; `SCRTY_OIDC_HANDOFF_DEFECT`. Verify: `cd test && go test -run 'TestHandoffStoreSuite|TestMemoryHandoffStoreConformance' -race -count=1 ./oidc/`.

### Task 7.3: issuing a code

**Files:** Create `oidc/handoff.go`, `oidc/options_handoff.go`. Test: `oidc/handoff_issue_test.go`.

**Interfaces:**

```go
const HandoffTTL = 60 * time.Second // fixed; see the godoc for why it is not an option

type HandoffManager struct{ /* store, users, random, now, ids, log */ }
type HandoffOption func(*HandoffManager) error

func NewHandoffManager(store HandoffStore, users identity.UserLoader, opts ...HandoffOption) (*HandoffManager, error)
func WithHandoffRandom(r io.Reader) HandoffOption
func WithHandoffClock(now func() time.Time) HandoffOption
func WithHandoffIDGenerator(g id.Generator) HandoffOption
func WithHandoffLogger(l *slog.Logger) HandoffOption

// Issue stores a handoff for a completed callback and returns the code.
func (h *HandoffManager) Issue(ctx context.Context, res CallbackResult) (code string, err error)
```

`NewHandoffManager` refuses a nil store or loader with `identity.MissingPort`. A nil store is not defaulted inside `NewHandoffManager`: `httpsec.EnableOIDCLogin` takes a `*HandoffManager` the consumer built, and the consumer passes `oidc.NewMemoryHandoffStore()` for the default — which the godoc example shows. Report whether this should instead default like the flow store for task 11.3.

- [ ] **Step 1: Write the failing table** `TestHandoffIssue`: "the stored record holds a digest, not the secret" (split the code on `.`, find by token id, assert `SecretHash == sha256(secret)` and that no field contains the secret); "the record carries the reference, provider, issuer, sid, ID token and next"; "the code is 16 and 32 random bytes, base64url" (fixed random reader → deterministic code); "the record id comes from the generator" (mockgen `id.Generator`); "expiry is exactly 60 seconds after issue"; construction refusals.
- [ ] **Step 2–4.**

### Task 7.4: redeeming a code

**Files:** Modify `oidc/handoff.go`. Test: `oidc/handoff_redeem_test.go`.

**Interfaces:**

```go
// RedeemCheck has magiclink.Check's exact shape, so the chain's policy check
// builder serves both.
type RedeemCheck func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

type HandoffResult struct {
	Principal                            identity.Principal
	PasswordChangedAt                    time.Time
	Provider, Issuer, SessionID, IDToken string
	Next                                 string
}

func (h *HandoffManager) Redeem(ctx context.Context, code string, checks ...RedeemCheck) (HandoffResult, error)
```

- [ ] **Step 1: Write the failing table** `TestHandoffRedeem` (clock injected; `MockUserLoader`; the memory store, or a `MockHandoffStore` for fault rows):
  - "a valid code redeems once": result carries the principal from `identity.PrincipalFromDetails`, the provider fields and `Next`; the record is consumed.
  - "malformed", "unknown", "wrong secret", "expired" (exactly at `ExpiresAt` — Review Focus), "already consumed": each `ErrInvalidHandoff`.
  - "a disabled user and a wrong secret look alike": same error value.
  - "a reference mismatch leaves the code": loader returns `u-2` for `u-1` → `ErrInvalidHandoff`; the record is still unconsumed.
  - "a loader outage then success": first call with the loader failing → `ErrInvalidHandoff`, an ERROR log, record unconsumed; second call with the loader recovered → success.
  - "a check refusal is returned unwrapped and leaves the code": a check returning `errX` → exactly `errX` (`assert.Same`), record unconsumed; a following redemption with a passing check succeeds.
  - "checks run in order and stop at the first refusal".
  - "a consume failure is invalid-handoff and yields no principal": `MockHandoffStore.Consume` → `errors.New("db down")` → `ErrInvalidHandoff`, zero `HandoffResult`.
  - "a store find outage is invalid-handoff".
  - "the fast path skips the loader for a consumed code": consumed record → `ErrInvalidHandoff` and `LoadByUserID` has no expectation.
  - "no error or log contains the code": capture logs, assert the code string appears nowhere.
- [ ] Add `TestHandoffRedeemRacing`: 8 goroutines behind a barrier redeem one code with the memory store → exactly one success.
- [ ] **Step 2: See them fail**, **Step 3: implement** in the design's order (parse → find → constant-time compare → expiry → consumed fast path → `LoadByUserID` with nil, reference and active checks → checks → consume), **Step 4: pass** with `-race`. Then run the mutations "consume moved before the checks" (the check-refusal row fails: the code is spent) and "fast path dropped" (the fast-path row fails on the unexpected loader call), and record which test killed each.

---

## Wave C — lane C-http: the OIDC interceptors

C-http-1 starts only when wave A and every wave B dispatch is clean and `go build ./...` is green. C-http-3 owns `httpsec/magiclink.go` for one refactor (task 9.5, step 0) so the redemption guards are shared rather than copied.

### Task 9.1: status rows and the sentinel registry

**Files:** Modify `httpsec/status.go` (`statusTable`), `httpsec/status_test.go` (`TestStatusForErrorCoversEverySentinel`'s package list, and the table test of `StatusForError`).

- [ ] **Step 1: Write the failing tests.** In `TestStatusForErrorCoversEverySentinel`, add `oidc` to the packages whose exported `Err*` sentinels are walked, with an `unmapped` entry and reason for each sentinel that deliberately maps to 500 or is never returned to a client: `oidc.ErrConfig` ("a wiring fault, refused at construction"), `oidc.ErrExchangeFailed` and `oidc.ErrDiscoveryFailed` ("a provider failure, deliberately 500"), `oidc.ErrLinkNotFound`, `oidc.ErrLinkExists`, `oidc.ErrHandoffNotFound` ("a store outcome the library converts before it leaves oidc"), `oidc.ErrRetainSinceRequired` ("a purge misuse, never a request outcome"), `oidc.ErrFlowUnspent` ("a marker joined onto another refusal, never returned alone"), `oidc.ErrFlowStoreFull` ("capacity exhaustion, deliberately 500"). In the `StatusForError` table add rows: `oidc.ErrUnknownProvider` → 404; `oidc.ErrInvalidLogoutToken` → 400; `oidc.ErrInvalidHandoff` → 401 (no row of its own: it wraps authentication failed); `fmt.Errorf("x: %w", oidc.ErrInvalidIDToken)` → 401.
- [ ] **Step 2: See it fail.** Run `go test -run 'TestStatusFor' -count=1 ./httpsec/`. Expected: the registry test fails naming `oidc.ErrUnknownProvider` and `oidc.ErrInvalidLogoutToken` as unmapped; the 404 and 400 rows fail with 500.
- [ ] **Step 3: Implement.** Add `{oidc.ErrInvalidLogoutToken, http.StatusBadRequest}` beside `ErrCredentialsMissing`, and `{oidc.ErrUnknownProvider, http.StatusNotFound}` in its own group with a one-line comment. `httpsec` importing `oidc` is allowed (decision 1); `oidc` never imports `httpsec`.
- [ ] **Step 4: See it pass.**

### Task 9.2: `EnableOIDCLogin` and its construction refusals

**Files:** Create `httpsec/oidc.go` (the interceptor type and `Intercept` dispatch), `httpsec/oidc_options.go` (`EnableOIDCLogin`, `OIDCOption`, every `WithOIDC*`/`WithHandoff*`/`WithCallbackSuccess`/`WithBackchannel*` option, `wireOIDCLogin`, `resolve`, `check`). Modify `httpsec/options.go` (call `c.wireOIDCLogin()` after `c.wireMagicLink()`), `httpsec/order.go` (the `OrderOIDC` comment gains "and back-channel logout"). Test: `httpsec/oidc_construction_test.go`.

**Interfaces:**
- Consumes: `*oidc.Manager` with `Providers()`, `Links()` and `RoleSyncProviders()` (task 2.3), `*oidc.HandoffManager`. A broker option naming an unregistered provider is already refused by `oidc.NewManager`, so the chain does not re-check it.
- Produces:

```go
const (
	DefaultOIDCAuthorizePath   = "/oauth2/authorization/"          // + {provider}
	DefaultOIDCCallbackPath    = "/login/oauth2/callback/"         // + {provider}
	DefaultOIDCHandoffPath     = "/login/oauth2/handoff"
	DefaultOIDCBackchannelPath = "/logout/oauth2/backchannel/"     // + {provider}
	DefaultOIDCFlowCookieName  = "oidc_flow"
	DefaultOIDCHandoffParam    = "handoff"
	DefaultOIDCNextParam       = "next"
	defaultHandoffFailureLimit   = 10
	defaultHandoffFailureWindow  = 5 * time.Minute
	oidcCallbackFlow           = "oidc.callback"
	oidcHandoffFlow            = "oidc.handoff"
	oidcBackchannelFlow        = "oidc.backchannel"
)

type OIDCOption func(*oidcInterceptor) error

// CallbackSuccess replaces the handoff conveyance. It receives the verified,
// brokered login and the destination the allowlist resolved.
type CallbackSuccess func(ex *Exchange, res oidc.CallbackResult, next string) error

// HandoffRedeemer is what the redemption endpoint calls. The default is the
// *oidc.HandoffManager given to EnableOIDCLogin.
type HandoffRedeemer interface {
	Redeem(ctx context.Context, code string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error)
}

type BackchannelLogoutScope uint8

const (
	IssuerSessions BackchannelLogoutScope = iota // default
	AllSessions
)

func EnableOIDCLogin(m *oidc.Manager, h *oidc.HandoffManager, opts ...OIDCOption) Option

func WithOIDCTokens(g token.Generator) OIDCOption              // required
func WithOIDCSessions(m *session.Manager) OIDCOption           // required unless another built-in supplies one
func WithOIDCAuthorizePath(prefix string) OIDCOption
func WithOIDCCallbackPath(prefix string) OIDCOption
func WithOIDCHandoffPath(path string) OIDCOption
func WithBackchannelLogoutPath(prefix string) OIDCOption
func WithOIDCFlowCookieName(name string) OIDCOption
func WithOIDCAllowedRedirects(entries ...string) OIDCOption   // default none: destination "/"
func WithOIDCAllowedOrigins(origins ...string) OIDCOption     // default none
func WithCallbackSuccess(fn CallbackSuccess) OIDCOption         // default: issue a handoff
func WithHandoffRedeemer(r HandoffRedeemer) OIDCOption           // default: the HandoffManager
func WithHandoffLimiter(l ratelimit.Limiter) OIDCOption          // default: in-memory, dedicated
func WithHandoffRateLimit(limit int, window time.Duration) OIDCOption // default 10 per 5 min
func WithHandoffCountRefusals(count bool) OIDCOption             // default true
func WithBackchannelLogoutScope(s BackchannelLogoutScope) OIDCOption // default IssuerSessions
func WithOIDCRPInitiatedLogout(on bool) OIDCOption             // default true
```

Design decision 14 writes the path option as `WithBackchannelLogoutPath(p string)` with `{provider}` in the template; the prefix form above (`{provider}` is the one segment after it) is simpler to validate and to collision-check. Report it for task 11.3.

- [ ] **Step 1: Write the failing table** `TestEnableOIDCLoginConstruction`, each row building a chain with `httpsec.New(...)` and asserting `require.ErrorIs(t, err, httpsec.ErrConfig)` plus a fragment of the message:
  nil manager; nil handoff manager with no `WithCallbackSuccess`; no token generator; no session manager; the handoff path equal to the callback prefix; the back-channel prefix equal to the callback prefix (spec "Back-channel path shadows the callback"); an empty path; an invalid allowlist entry (`//evil.example/app`); an absolute entry on an undeclared origin; a nil limiter; a non-positive rate limit or window; an out-of-range scope value; role sync enabled for `corp` with no `WithCallbackSuccess` (message names `corp`, found through `Manager.RoleSyncProviders()`).
  Accepted row: a minimal wiring with tokens and sessions constructs.
- [ ] **Step 2: See it fail** with an `EnableOIDCLogin` that registers without checks.
- [ ] **Step 3: Implement** in magic-link's shape: `EnableOIDCLogin` builds the interceptor with defaults, applies options, calls `c.enable(option, func() error { return i.check(c, option) })`, `c.useSessions(i.sessions)`, `c.register(i, OrderOIDC)`, `c.wire(i.wire)`; `wireOIDCLogin` runs `i.resolve(c)` for each registered interceptor, building `origin.NewAllowlist(entries, origins, "WithOIDCAllowedRedirects", "WithOIDCAllowedOrigins")` and the guard with `c.resolveSourceGuard("EnableOIDCLogin", oidcHandoffFlow, i.limiter, i.limit, i.window)`.
- [ ] **Step 4: See it pass.**

### Task 9.3: the authorize endpoint

**Files:** Create `httpsec/oidc_authorize.go`. Test: `httpsec/oidc_authorize_test.go`.

- [ ] **Step 1: Write the failing table** `TestOIDCAuthorize`, serving through a `net/http` chain against an `oidc.Manager` backed by an in-package test provider (C-http writes its own small `httptest` TLS provider helper in `httpsec/oidc_provider_helper_test.go`; it cannot import the `oidc` package's `_test.go` helper). Rows:
  - "a GET redirects to the provider with a flow cookie": 302 to the authorization endpoint; `Set-Cookie: oidc_flow=…; Path=/login/oauth2/callback/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`; `Referrer-Policy: no-referrer`; the handler did not run.
  - "an unknown provider is not found": 404 via `StatusForError(oidc.ErrUnknownProvider)`; no flow stored.
  - "an encoded slash in the provider segment is not a provider" and "a trailing slash is not a provider" (Review Focus): 404 or pass-through, never a redirect to `corp`.
  - "a POST passes through"; "an off-route GET passes through".
  - "the requested destination is recorded untrusted": `?next=https://evil.example/` is stored as given (the callback resolves it, task 9.4).
  - "a flow expiry already passed clamps Max-Age to 1" (Review Focus): with a clock that makes `ExpiresAt` equal to now, `Max-Age=1`.
  - "a consumer cookie name is used".
- [ ] **Step 2–4.** `Max-Age` is the flow's remaining lifetime rounded up to whole seconds, at least 1 and at most MaxInt32, so the cookie never expires before a flow that can still complete; `Path` is the callback prefix.

### Task 9.4: the callback endpoint

**Files:** Create `httpsec/oidc_callback.go`. Test: `httpsec/oidc_callback_test.go`.

- [ ] **Step 1: Write the failing table** `TestOIDCCallback`:
  - "a successful callback redirects with a handoff and creates no session": 302 to `/` (no allowlist) with `handoff=<code>`; `Referrer-Policy: no-referrer`; `Cache-Control: no-store`; a cookie-clearing `Set-Cookie: oidc_flow=; Max-Age=0`; the session store is empty.
  - "an allowlisted destination is used": allowlist `/welcome`, flow `next=/welcome` → `Location: /welcome?handoff=…`.
  - "an unlisted destination falls back to /": `next=https://evil.example/`.
  - "a forged callback does not clear the cookie": wrong state → 401, no `Set-Cookie` header at all.
  - "a forged error link does not clear the cookie": `?error=access_denied` with no valid state → 401, no `Set-Cookie`, and the genuine callback afterwards succeeds.
  - "a genuine denial ends the flow and clears the cookie": `?error=access_denied&state=<real>` → 401 and the clearing cookie; the provider's error text is logged, not returned.
  - "no flow cookie is an invalid state" (Review Focus): 401, no store write.
  - "an empty state" and "a repeated state parameter" (Review Focus): 401.
  - "a provider outage is a server error": token endpoint down → 500, not 401.
  - "the consumer conveyance receives the login and no handoff is stored": `WithCallbackSuccess` records its arguments; the handoff store is empty; the function's `next` is the allowlist-resolved one.
- [ ] **Step 2–4.** Read `code`, `state`, `error` with `url.Values.Get` from the query (first value; a repeated `state` whose values differ is refused as invalid state — implement by comparing `len(values["state"]) > 1`). Clear the cookie only when `!errors.Is(err, oidc.ErrFlowUnspent)`. Log refusals with `logSampled` under `oidcCallbackFlow`.

### Task 9.5: the redemption endpoint

**Files:** Create `httpsec/redemption.go` (shared helpers), `httpsec/oidc_redeem.go`. Modify `httpsec/magiclink.go` (use the shared helpers). Test: `httpsec/oidc_redeem_test.go`; the existing magic-link tests are the regression net for step 0.

**Interfaces:**
- Produces, in `httpsec/redemption.go` (moved from `magiclink.go`, behaviour unchanged):

```go
type policyOutcome struct {
	evaluated bool
	decision  policy.Decision
	denyErr   error
	checkErr  error
}

// redemptionPolicyCheck builds the refusal check a redemption runs for a first
// factor, and the record of what it decided.
func redemptionPolicyCheck(engine *policy.Engine, first factor.Kind, now func() time.Time) (
	func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error, *policyOutcome)

// wrapChecks records which consumer check refused.
func wrapChecks[C ~func(context.Context, identity.Principal, time.Time) error](checks []C, out *policyOutcome) []C

func guardRedemption(out *policyOutcome) error // unchanged

// countsAgainstSource decides whether a redemption failure is recorded.
func countsAgainstSource(countRefusals bool, err error, out *policyOutcome) bool
```

- [ ] **Step 0 (refactor, green to green).** Move `policyOutcome`, the body of `magicLinkInterceptor.policyCheck`, `wrappedChecks`, `guardRedemption` and `recordRefusal` into `redemption.go` as the functions above, and make `magiclink.go` call them (`magiclink.Check(fn)` conversions where needed). Run `go test -run 'TestMagicLink' -count=1 ./httpsec/` before and after: both green. No behaviour change, so no red step; this is the refactor step of the magic-link tests' own loop.
- [ ] **Step 1: Write the failing table** `TestOIDCRedeem`, POSTing a form body `handoff=<code>` to `/login/oauth2/handoff`, with a `MockHandoffRedeemer` where the row needs to misbehave and the real `*oidc.HandoffManager` otherwise:
  - "a code in the query string only is refused": 401 (`ErrInvalidHandoff`), the redeemer is not called.
  - "a throttled source is refused without redeeming": pre-fill the limiter to the limit → 401 and no `Redeem` call.
  - "an unattributable source is refused without redeeming".
  - "deny with no reason": a policy denying with a nil reason → 403 `policy.ErrPolicyDenied`; the code is still redeemable afterwards once the policy allows.
  - "an implementation that skips the checks is refused": the mock returns success without calling any check → 403, no session.
  - "an implementation that discards a deny is refused": the mock calls the checks, gets the deny, returns success → 403, no session.
  - "replaying a denied code is throttled by default": 10 policy denials from `203.0.113.7` → the 11th is 401 without a `Redeem` call.
  - "a consumer opts out of counting refusals": `WithHandoffCountRefusals(false)`, 10 denials → the 11th is evaluated (403 again, `Redeem` called).
  - "guessing still counts with the opt-out": 10 wrong codes → the 11th is 401 without `Redeem`.
  - "an outage counts against the source": the redeemer returns `oidc.ErrInvalidHandoff` for an outage 10 times → throttled.
- [ ] **Step 2: See it fail.** **Step 3: Implement** `oidcInterceptor.redeem` in the order of `magicLinkInterceptor.consume`: `sourceThrottled` → on error return `oidc.ErrInvalidHandoff`; read the code from the body only; `check, out := redemptionPolicyCheck(i.engine, factor.OIDC, i.now)`; `i.redeemer.Redeem(ctx, code, oidc.RedeemCheck(check))`; on error, `if countsAgainstSource(i.countRefusals, err, out) { recordSourceFailure(ctx, i.guard, src) }` and return the error; `guardRedemption(out)`; then task 9.6's tail. **Step 4: Pass.** Then run the mutations by hand, each killing its row: drop `!out.evaluated` from `guardRedemption` ("skips the checks"); drop the `Outcome == Deny` test ("discards a deny"); return `d.Reason` without the `policy.ErrPolicyDenied` fallback (this one cannot be killed through `*policy.Engine`, which already substitutes `ErrPolicyDenied` for a reasonless deny; the fallback stays as defence in depth and the "deny with no reason" row pins the observable outcome); skip `recordSourceFailure` ("replaying a denied code").

### Task 9.6: redemption ends through the login tail

**Files:** Modify `httpsec/oidc_redeem.go`. Test: `httpsec/oidc_redeem_session_test.go`.

- [ ] **Step 1: Write the failing table** `TestOIDCRedeemSession`:
  - "the session carries the OIDC first factor and the federated fields from its first write": a session store spy records `Create` calls and no `Save`; the created session has `FirstFactor == factor.OIDC`, `ExternalProvider`, `ExternalIssuer`, `ExternalSessionID`, `ExternalIDToken`.
  - "the response is the login document plus next": 200, `Content-Type: application/json`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, body has `access_token`, `refresh_token`, `valid_until`, `next == "/welcome"` (allowlisted), and an unlisted recorded `next` becomes `/`.
  - "a challenge consumes the code and returns the challenge": a policy challenging MFA (with `EnableMFA` wired) → 401 challenge error with a pending session; a second redemption of the code is 401 invalid handoff.
  - "the default exemption creates a session without a challenge": an MFA-required user, default classification → 200.
- [ ] **Step 2–4.**

```go
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	tok, err := completeLogin(ex, loginTailDeps{engine: i.engine, sessions: i.sessions, tokens: i.tokens},
		postAuthenticationInput(&res.Principal, factor.OIDC, "", res.PasswordChangedAt, i.now()),
		session.WithExternalSession(res.Provider, res.Issuer, res.SessionID, res.IDToken))
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Cache-Control", "no-store")

	return writeSuccessDocument(ex, oidcHandoffDocument{
		loginDocument: loginDocument{AccessToken: tok, ValidUntil: ex.Session.IdleExpiresAt},
		Next:          i.redirects.Resolve(res.Next),
	})
```

### Task 9.7: removing the exemption

**Files:** Test only: `httpsec/oidc_mfa_test.go`.

- [ ] **Step 1:** `TestOIDCRedeemMFAExemptionRemoved`, a table with rows: "with EnableMFA wired, a required-but-unenrolled user is refused with enrolment required and keeps the code" (403 `policy.ErrMFAEnrollmentRequired`; a later redemption after enrolment succeeds); "without EnableMFA, the classification fails chain assembly" (`httpsec.New` returns `ErrConfig` naming the unenforced challenge). Both use `policy.WithMFAExemption(func(k factor.Kind) bool { return k != factor.OIDC && k.MFAExempt() })` on `NewMFAPolicy` and `NewMFARequirementPolicy`. Check `policy.WithMFAExemption`'s exact signature with `go doc ./policy WithMFAExemption` first.
- [ ] **Step 2:** the second row fails if the chain's existing `policy.Challenger` check does not cover this configuration; if both rows pass on first run, invert the classification in the test (keep OIDC exempt) and see the first row fail with 200, which proves the test is load-bearing, then restore.
- [ ] **Steps 3–4:** no production change is expected; if one is, report it before making it.

### Task 9.8: the back-channel endpoint

**Files:** Create `httpsec/oidc_backchannel.go`. Test: `httpsec/oidc_backchannel_test.go`.

- [ ] **Step 1: Write the failing table** `TestOIDCBackchannel`, one row per scenario of the four back-channel requirements in `specs/oidc-logout`, each posting `logout_token=<signed>` (from the test provider helper's signer) with no credential:
  - sid preferred (two sessions `abc`, `def`, token with `sub` and `sid=abc` → only `abc` ends); subject-only ends both sessions from the issuer; an unlinked subject → 200, nothing ended; a sid from another issuer does not end the other issuer's session; a password session survives; another provider's session survives; `AllSessions` ends both; same answer for zero and three sessions (200, empty body, `Cache-Control: no-store`); a session store outage → not 200 and not 400; a forged token → 400 with an empty body and `no-store`; no `logout_token` → 400; a GET passes through; an unknown provider → 404; replay inside the window ends a session created after the first delivery; replay after the window → 400.
  - Review Focus: "an oversized body" (over `DefaultLoginBodyLimit`) → 400 without reading past the bound; "a JSON body" → 400.
- [ ] **Step 2–4.** Dispatch:

```go
	claims, err := i.manager.VerifyLogoutToken(ctx, provider, token)
	if err != nil {
		ex.Writer.SetHeader("Cache-Control", "no-store")
		return err // ErrInvalidLogoutToken -> 400, ErrDiscoveryFailed -> 500
	}

	switch {
	case claims.SessionID != "":
		n, err := i.sessions.DeleteByExternalSession(ctx, claims.Issuer, claims.SessionID)
		// log n through the chain sampler under oidcBackchannelFlow
	default:
		link, err := i.manager.Links().FindByExternal(ctx, provider, claims.Issuer, claims.Subject)
		if errors.Is(err, oidc.ErrLinkNotFound) { break }
		if i.scope == AllSessions {
			err = i.sessions.DeleteByUser(ctx, link.UserID) // no count to log
		} else {
			n, err := i.sessions.DeleteByUserAndExternalIssuer(ctx, link.UserID, claims.Issuer)
		}
	}
```

The link store is `i.manager.Links()` (task 2.3). For a consumer broker it is nil: a subject-only token then ends nothing, is answered 200, and logs once through the sampler that the subject could not be resolved; add that row. Then run the mutations "`AllSessions` as the default" and "`sub` checked before `sid`", each killing its row.

### Task 9.9: RP-initiated logout wiring

**Files:** Modify `httpsec/oidc_options.go` (`wireOIDCLogin`). Test: `httpsec/oidc_rplogout_test.go`.

- [ ] **Step 1: Write the failing table** `TestOIDCRPInitiatedLogout`: "on by default when OIDC login is wired" (a federated session logging out gets `end_session_url`); "the consumer turns it off" (`WithOIDCRPInitiatedLogout(false)` → empty 200); "a consumer end-session step takes precedence" (`LogoutDeps.EndSession` set → its URL); "a chain without EnableLogout is unaffected" (no panic, OIDC still wires). Add the compile-time assertion `var _ httpsec.EndSessionBuilder = (&oidc.Manager{}).EndSessionBuilder()` in the test file.
- [ ] **Step 2–4.** In `wireOIDCLogin`: `if c.logout != nil && c.logout.endSession == nil && i.rpLogout { c.logout.endSession = i.manager.EndSessionBuilder() }`.

---

## Wave D — lane D-test: the test identity provider, adapter parity, a real provider

### Task 10.1: the in-process test identity provider

**Files:** Create `test/oidc/idp.go`, `test/oidc/idp_test.go`.

**Interfaces:**

```go
// IdentityProvider is an in-process OpenID provider for tests: discovery, a
// key set and a token endpoint over TLS, rotatable keys, call counters, both
// client authentication methods, and a signer that emits valid and malformed
// ID and logout tokens.
type IdentityProvider struct{ /* ... */ }

func NewIdentityProvider(t *testing.T, opts ...IdentityProviderOption) *IdentityProvider
func (p *IdentityProvider) Issuer() string
func (p *IdentityProvider) Provider(name string, auth oidc.ClientAuthMethod) oidc.Provider
func (p *IdentityProvider) Outbound(t *testing.T) *outbound.Client
func (p *IdentityProvider) Rotate(t *testing.T, kid string)
func (p *IdentityProvider) Calls() (discovery, jwks, token int64)

// Login simulates the user at the provider: given the authorization redirect,
// it records the code the next token request will exchange for an ID token
// with these claims, and returns the callback URL the browser would follow.
func (p *IdentityProvider) Login(t *testing.T, authorizeURL string, claims map[string]any) (callbackURL string)

// LogoutToken signs a back-channel logout token.
func (p *IdentityProvider) LogoutToken(t *testing.T, claims map[string]any, opts ...TokenOption) string

// Malformed token options, one per row of design decision 15.
func WrongIssuer() TokenOption
func WrongAudience() TokenOption
func Expired() TokenOption
func FutureIssuedAt() TokenOption
func BadSignature() TokenOption
func UnknownKid() TokenOption
func AlgNone() TokenOption
func HS256WithClientSecret() TokenOption
func WrongNonce() TokenOption
func NoSubject() TokenOption
func MultipleAudiencesWithoutAZP() TokenOption
```

- [ ] **Step 1: Write the failing test** `TestTestIdentityProvider`: a `net/http` chain with `EnableFormLogin` absent, `EnableOIDCLogin` present, memory stores; drive `GET /oauth2/authorization/corp` → `p.Login` → `GET` the callback URL with the flow cookie → `POST /login/oauth2/handoff` with the code from `Location` → 200 with an access token, and a session exists with `ExternalIssuer == p.Issuer()`. A second table `TestTestIdentityProviderMalformedTokens` runs each malformed option through the same flow and asserts 401 — this is the end-to-end mirror of task 5.2's unit rows, proving the chain surfaces each as an authentication failure.
- [ ] **Step 2:** fails until `IdentityProvider` is written. **Step 3:** implement, reusing `test/testutils.go`'s `serverCertificate` for TLS. **Step 4:** `cd test && go test -run 'TestTestIdentityProvider' -count=1 ./oidc/` PASS.

### Task 10.2: adapter parity

**Files:** Create `test/httpsecconformance/oidc_scenarios.go`. Modify the `Scenarios()` list (in `test/httpsecconformance/runner.go` or wherever it is declared) to append `oidcScenarios()...`. The gin and fiber adapter test files need no change if they already run `httpsecconformance.Run` over `Scenarios()`; confirm with `go doc`/reading `test/httpsec_gin_test.go` before editing.

- [ ] **Step 1: Write the scenarios**, each a `Scenario{Name, Build, Request, Assert}`: "OIDC authorize redirects with a flow cookie"; "OIDC callback with a forged state is 401 without clearing the cookie"; "OIDC handoff redemption establishes a federated session"; "OIDC handoff code in the query string is refused"; "OIDC back-channel logout ends the session named by sid"; "OIDC back-channel with a forged token is 400"; "logout of a federated session answers end_session_url"; "an unknown provider is 404". `Build` starts a `NewIdentityProvider` (the scenarios package imports `test/oidc` — same module) and returns a `ChainSpec` whose `Options` include `EnableOIDCLogin`. Where a scenario needs a code, `Build` performs the authorize and provider-login steps directly against the manager and stores the code on the spec's `Effects`.
- [ ] **Step 2:** Run `cd test && go test -run 'TestConformance(NetHTTP|Gin|Fiber)' -count=1 .` with the scenarios registered but `Build` returning a chain **without** `EnableOIDCLogin`: every OIDC row fails on all three adapters (404/pass-through where a redirect was expected). That is the red step.
- [ ] **Step 3:** Wire `EnableOIDCLogin` in `Build`. **Step 4:** PASS on all three adapters. A row that passes on `net/http` and fails on gin or fiber is an adapter difference: report it with the failing output, and do not change the scenario to hide it.

### Task 10.3: Keycloak

**Files:** Modify `test/testutils.go` (`RunTestKeycloak`, `WithTestKeycloakImage`). Create `test/oidc_keycloak_test.go`, and a realm export fixture under `test/testdata/keycloak/realm.json`.

**Interfaces:**

```go
type KeycloakConn struct {
	Issuer       string // https issuer URL of the test realm
	ClientID     string
	ClientSecret string
	Outbound     *outbound.Client // trusts the container's certificate
	Login        func(t *testing.T, authorizeURL, username, password string) (callbackURL string)
}

func RunTestKeycloak(t *testing.T, opts ...TestOption) KeycloakConn
```

Follow the `use-testcontainers` skill and the shape of `RunTestSMTP` in the same file: one helper, options for the image, cleanup through `t.Cleanup`, TLS with `serverCertificate`. `Login` drives Keycloak's login form over HTTP (a `net/http` client with a cookie jar posting the form Keycloak renders), because a browser is not available.

- [ ] **Step 1: Write the test** `TestKeycloak`, a table over the two client authentication methods (the realm defines two clients, one per method): discovery succeeds with no pinned endpoints; the authorize redirect targets Keycloak; the code exchange succeeds; the ID token verifies; redemption establishes a session; a back-channel logout triggered through Keycloak's admin API ends it.
- [ ] **Step 2:** Run with the container started but the realm's back-channel URL pointing at a wrong path: the logout row fails. **Step 3:** correct it. **Step 4:** `cd test && go test -run TestKeycloak -count=1 .` PASS. **Without Docker, report the test as not run** — never as passing.

---

### Task 10.4: gin commits an unrouted 404 refusal (lane D-test)

**Files:** Modify `ginsec/middleware.go` (the refusal path around the `gc.Status(httpsec.StatusForError(err))` call) and `ginsec/guards.go` (the same rule for guards). Test: the existing ginsec refusal test table (or a new `TestRefusalUnroutedNotFound`).

- [ ] **Step 1: Write the failing rows.** An engine with the chain and no route for `/oauth2/authorization/nope`, refused with 404: the body is empty and the status 404 (fails today with `404 page not found`). A 404 refusal on a matched route, and a 401 refusal on an unrouted path, with consumer error middleware that writes a JSON body: the consumer's body and status win (pins that the late-binding rule is untouched).
- [ ] **Step 2: See the first row fail** with gin's default body.
- [ ] **Step 3: Implement.** After setting the status, when it is 404 and `gc.FullPath() == ""` and nothing has been written, commit it with `gc.Writer.WriteHeaderNow()`. Document the case in the refusal godoc and `ginsec/doc.go`.
- [ ] **Step 4: See it pass,** then the gin conformance row "OIDC authorize for an unknown provider is 404" passes unchanged.

## Wave D — lane D-doc: documentation

### Task 11.1: godoc and README

**Files:** Comments only in `oidc/*.go`, `httpsec/oauth2*.go`, `httpsec/logout.go`, `outbound/client.go`; `README.md`.

- [ ] **Step 1:** List every exported identifier added by this change (`go doc -all ./oidc`, `go doc ./httpsec | grep -i oauth2`) and check each option's godoc names its default and each port says what is used when none is supplied.
- [ ] **Step 2:** Write the package godoc of `oidc` with a runnable-looking wiring example (`NewRegistry` → `NewBroker` → `NewManager` → `NewHandoffManager(NewMemoryHandoffStore(), users)` → `httpsec.EnableOIDCLogin`), and a "Limits" section stating, one paragraph each: trusted provider configuration and the client secret; per-process caches, flow store and rate limiter; the first request after expiry waiting a fetch; the handoff code in a URL and its fixed 60-second window; a refused code staying live; logout-token replay within the maximum age; the total MFA exemption; role sync removing roles on a provider misconfiguration; the mapped hash as a standby credential and mirroring's limits; the crash between provisioning and linking; and not rendering `err.Error()`.
- [ ] **Step 3:** Add the OIDC section to `README.md`, including removing the `handoff` parameter with `history.replaceState` before loading any third-party resource.
- [ ] **Step 4:** Verify: `go doc ./oidc` shows the Limits section; `go doc ./httpsec EnableOIDCLogin` names every default; `go vet ./...` and `gofmt -l .` are clean. No behaviour changed, so there is no red step; `go test ./oidc/ ./httpsec/` must still pass.

---

## Main session — records and the gate

### Task 11.2: report to `durable-persistence`

- [ ] Add to `openspec/changes/durable-persistence/design.md` (or its proposal's dependencies, whichever that change uses for inbound needs) what this change needs: link, flow and handoff tables matching `oidc.Link`, `oidc.Flow` and `oidc.HandoffRecord` (the handoff subject column holds the user reference; `Next` is stored); running `RunLinkStoreSuite`, `RunFlowStoreSuite` and `RunHandoffStoreSuite` against the durable adapters, zero-cutoff refusal included; and a `session.Cipher` for the existing sealing store. Record the flag in this change's `design.md` Risks. If `durable-persistence`'s `tasks.md` changes as a result, regenerate its `plans.md` (`tasks-plans.md`).

### Task 11.3: record implementation departures in `design.md`

- [ ] Record, as decisions naming the default and the override, every refinement the lanes reported. Expected from this plan already: `Provider.SigningAlgs` instead of a per-provider manager option (task 2.2); `HandoffRecord.Next` (task 2.3); `NewManager` taking the broker as a required argument and refusing unregistered provider names (task 2.3); `WithPostLogoutRedirect` as a manager option (task 8.2); the `Broker`/`Handoff`-prefixed option names (tasks 6.3, 7.3); whether `NewHandoffManager` should default its store (task 7.3); the back-channel path as a prefix (task 9.2); the shared `redemption.go` helpers (task 9.5). If any changes a spec-visible behaviour, update the spec delta too and re-run `openspec validate oidc-brokering --strict`.

### Task 11.4: the full gate

- [ ] Run `make check` across every module and confirm it is green. Paste the tail of its output into the completion report. Tick `tasks.md` only for tasks whose verification output the main session has seen.

---

## Self-review against the spec

**Spec coverage.** Every requirement in the three new capability specs and the four deltas maps to a task:

| Spec requirement | Task(s) |
|---|---|
| oidc-login: Provider configuration is validated at construction | 1.6, 2.2, 2.3 (scheme against the outbound client) |
| oidc-login: Discovery is lazy by default and confined to the issuer | 3.1, 3.7 |
| oidc-login: Provider metadata is cached, coalesced and backed off | 3.2, 3.3, 3.4 |
| oidc-login: Expired provider metadata is never served by default | 3.6 |
| oidc-login: Provider metadata is fetched on demand, with no background work | 3.2, 3.3 |
| oidc-login: An unknown key id refetches at most once per cooldown per provider | 3.5 |
| oidc-login: Authorization always uses PKCE, state and nonce | 4.4, 9.3 |
| oidc-login: A flow is completed only by a caller who knows its provider and state | 4.1, 4.2, 4.3, 5.3 |
| oidc-login: A provider error redirect cannot cancel someone else's login | 5.3, 9.4 |
| oidc-login: The code exchange authenticates the client and hides provider detail | 1.1, 5.1 |
| oidc-login: ID tokens are verified strictly | 5.2, 10.1 |
| oidc-login: The callback conveys the login by a short-lived single-use code | 7.1–7.3, 9.4 |
| oidc-login: The post-login destination is allowlisted | 9.2, 9.4, 9.6 |
| oidc-login: A consumer can replace the callback's conveyance | 9.4 |
| oidc-login: Handoff redemption is check-then-consume | 7.4, 9.5 |
| oidc-login: Handoff redemption failures reveal nothing about the cause | 7.4 |
| oidc-login: Policy decisions at redemption cannot be lost | 9.5 |
| oidc-login: Refused redemptions count against the per-source limit by default | 9.5 |
| oidc-login: A successful redemption establishes a federated session | 1.2, 9.6 |
| oidc-login: OIDC logins are exempt from local MFA by default | 9.6, 9.7 |
| oidc-login: Endpoints fail in a way that separates bad input from outages | 2.1, 9.1, 9.4, 10.2 |
| oidc-login: OIDC wiring mistakes fail at construction | 2.3, 9.2 |
| identity-linking: every requirement | 6.1–6.8 |
| oidc-logout: An OIDC login records its provider session | 1.2, 9.6 |
| oidc-logout: Logout tokens are verified strictly; replay bounded by issued-at | 8.1, 9.8 |
| oidc-logout: The back-channel endpoint…; scoped to its issuer…; responses reveal nothing | 9.8 |
| oidc-logout: RP-initiated logout offers the provider's end-session URL | 1.3, 8.2, 9.9 |
| oidc-logout: Logout wiring mistakes fail at construction | 8.2, 9.2 |
| http-security-chain (modified): Logout ends the session; Redemption flows plug into named seams | 1.3, 1.2 |
| http-error-propagation (modified): One public table maps refusals to a status | 9.1 |
| outbound-http-confinement (added): A form POST carries the caller's headers | 1.1 |
| outbound-http-confinement: A client reports the schemes it allows | 1.6 |
| framework-adapters (modified): gin refusals reach the error channel and fail closed | 10.2, 10.4 |
| identity-model (modified): User loader contract | 1.4 |

**Placeholder scan.** The plan names three things an implementer must confirm against the installed library rather than invent: jwx v4's exact option and accessor names (task 5.2), `mockgen`'s multi-interface reflect syntax (task 6.3), and `policy.WithMFAExemption`'s signature (task 9.7). Each is a lookup with a stated command, not a gap in behaviour.

**Type consistency.** `FindByExternal` and `FindByTokenID` return pointers throughout (tasks 2.3, 6.1, 7.1, 9.8). `RedeemCheck` takes `identity.Principal` by value, matching `magiclink.Check`, so `redemptionPolicyCheck` serves both (tasks 7.4, 9.5). `CallbackResult.Principal` is `*identity.Principal`; `HandoffResult.Principal` is a value, as `magiclink.Redemption.Principal` is, and task 9.6 takes its address for `postAuthenticationInput`. `PostForm`'s fourth argument is `http.Header` in tasks 1.1 and 5.1.

**Review Focus.** Each of the five lines at the top has its test in the task that owns the code: 3.2, 9.4, 7.3/7.4 and 9.3, 9.3, 9.8.
