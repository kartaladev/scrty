# Brokered Sign-In Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A consumer can see upstream access and UserInfo on every brokered sign-in, and decide the user through a per-provider hook that may write only after scrty accepts the decision. When the application is its own OpenID Provider, a federated sign-in completes on the server with every check the script path applies.

**Architecture:**
- `authenticate/oidc` keeps the upstream access token in a callback-local `Upstream` value, and passes it to brokers implementing `UpstreamBroker`.
- The library `*Broker` runs a decide-then-apply `SignInHook`. Link checks, the one-link rule and the link insert all come before the consumer's `Apply`. The rule relies on a new optional `LinkLister`, which every shipped link store implements.
- `httpsec` gains an opt-in callback conveyance. It replays the redemption, then the resume, step for step, and falls back to the handoff when a step is owed.

**Tech Stack:** Go 1.27; `authenticate/oidc`, `httpsec`, `oidcprovider`, `outbound`, `session`, `policy`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `internal/pgschema`; testify; `net/http/httptest`; mockgen (`use-mockgen`); testcontainers (`use-testcontainers`).

**Spec:** `openspec/changes/brokered-sign-in-hook/`:
- `design.md`: decisions D1–D12 and failure modes F1–F31;
- `specs/oidc-login/spec.md` and `specs/identity-linking/spec.md`;
- `tasks.md`, groups 1–6;
- `proposal.md`.

## Global Constraints

- **Opt-in only.** With no new option set, every existing test passes unchanged. There is no migration: `oidc_links_user` already exists. `LinkStore` itself is unchanged.
- **The access token** lives only in `Upstream`'s pointed-to state, for one `RelyingParty.Callback`. It never enters `CallbackResult`, `Flow`, `HandoffRecord`, a session, a log, an event, an error or a response. The refresh token is discarded.
- **UserInfo:**
  - `outbound.Client.Get` with `Authorization: Bearer <token>`;
  - a 200 with a JSON object only; `application/jwt` is refused;
  - `sub` must equal the ID token's subject;
  - every failure wraps `ErrUserInfoFailed` with fixed text, and the body is never logged.
- **Assurance** comes from the verified ID token only.
- **Hook order (D5):**
  1. `FindByExternal`;
  2. the hook decides;
  3. checks: user named; no conflicting link; the user loads, is active and matches; the one-link rule;
  4. insert, with a re-read on `ErrLinkExists` and a one-link re-check, deleting the duplicate;
  5. `Apply`;
  6. reload, active check, resolve.

  Nothing a refused decision names is ever written.
- **Provisioning decision (D13):** `SignInDecision.Provision` names a user that does not exist yet. Step 3 requires `Apply`, and requires that the user does not load unless the identity's own link already names it. Step 4 inserts the link with an empty username before `Apply` creates the user. In step 6, a user still missing is a broker failure, and the link stays.
- **Completion order (D7):**
  1. recognise `Next`;
  2. `PendingRequest` pre-check, charging the source on a miss;
  3. load the user via `OIDCDeps.Users`;
  4. post-authentication policy and federated-assurance guard (deny → refuse; challenge → handoff fallback);
  5. login tail, external session, `cancelHeldRecoveries`, commit;
  6. per-request policy, full-session and raised-challenge checks;
  7. `Resume` with `oidcSignInOf(session, <chain assurance mapping>)`;
  8. `confirmSignIn` after `Resume`;
  9. cookies and the 303.

  Any failure after step 5 ends the session.
- **Git.** Never undo an edit with `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`; edit the file back. Agents do not commit, and edit nothing under `openspec/`, nor `README.md` unless their dispatch owns it.
- **Binding rules:**
  - `golang-tdd.md`: a compile error or a missing fixture is not a red step;
  - `defensive-coding.md`: the F-rows are binding;
  - `defect-claims.md`, `library-design.md`;
  - `legacy-reference.md`: never read or cite `.claude/.legacy`.
- **Skills to load:** `/golang-how-to`, then `golang-security`, `golang-concurrency`, `golang-error-handling` and `golang-testing`, plus the project skills `table-test`, `use-mockgen` and `use-testcontainers`.

### Scoped verification commands (`test-scope.md`)

**Lane A** (`authenticate/oidc`):
1. Core module: `go test -race -count=1 -timeout 45m ./authenticate/oidc/... ./httpsec/... ./policy/... ./store/sqlstore/... ./oidcprovider/... ./authenticate/passkey/...`
2. `go test -race -count=1 ./...` in each of `httpsec/ginsec`, `httpsec/fibersec`, `httpsec/prblmsec`, `store/pgxstore`, `store/gormstore` and `test`.
3. `go vet` on the changed packages, and `gofmt -l .`.

**Lane S** (link stores):
1. Core module: `go test -race -count=1 ./internal/pgschema/... ./store/sqlstore/...`
2. `go test -race -count=1 ./...` in `store/pgxstore`, `store/gormstore` and `test`.
3. `go vet` and `gofmt -l`.

**Lane B** (`oidcprovider`, `httpsec`):
1. Core module: `go test -race -count=1 -timeout 45m ./oidcprovider/... ./httpsec/... ./policy/... ./store/sqlstore/... ./authenticate/passkey/...` (`httpsec` takes about 21 minutes under `-race`, past the 10-minute default).
2. `go test -race -count=1 ./...` in `httpsec/ginsec`, `httpsec/fibersec`, `httpsec/prblmsec`, `store/pgxstore` and `test`.
3. `go vet` and `gofmt -l`.

The red step always runs focused first: `go test -run '<Name>' -count=1 ./<pkg>/`.

## Review Focus

1. **A hook whose `Apply` closes over data from another user's lookup.** For example, it found `u-9` by e-mail but decided `u-7` because a link exists. `Apply` must run only for the decided user. Pinned in Dispatch A3, Step 2: an `Apply` that records which user it wrote, asserted equal to the resolved user.
2. **A UserInfo answer with the same e-mail but a different `sub`.** It must fail. Pinned in Dispatch A1, Step 5.
3. **A completion `Next` with an encoded, case-varied or trailing-slash path.** It must not qualify. Pinned in Dispatch B1, Step 3.
4. **Two parked requests in two tabs, signed in one after the other.** Each callback resumes its own handle. Starting the second SSO login before the first returns makes the first callback an invalid state (D12). Pinned in Dispatch B2, Step 5.
5. **A consumer's `LinkStore` wrapper that hides `ListByUser`.** For example, a logging decorator that embeds only the `LinkStore` interface. With a hook and no allow-many, construction must fail; it must not fall back to allowing many links. Pinned in Dispatch A2, Step 1.

---

### Lanes and order

```
Lane A:  A1 ──► A1-fix ──► A2 ──► A2-fix ──► A3 ──► A4
                 │
Lane S:          └─(worktree from A2's merge)──► S1
Lane B:  B1 ──► B1-fix ──► B2   (own worktree from the start; uses no Lane A symbol)
Then:    merge S and B ──► C (README) ──► D (integration) ──► 6.2 / 6.3 (main session)
```

- Lane S needs A2's `LinkLister` and memory implementation. It runs in a worktree cut after A2 is reviewed clean, beside A3 and A4, because the stores import `authenticate/oidc`, which A3 is editing.
- Lane B runs in its own worktree from the start.
- After each dispatch, the main session runs that lane's scoped commands. A fresh reviewer, on the model named, then checks the diff against the cited requirements and decisions. It enumerates failures first, and edits nothing.

---

### Dispatch A1: upstream access and UserInfo (tasks 1.1–1.6)

**Model: Opus.** Credential handling and redaction, written for the first time. **Reviewer: Opus.**

**Files** (owned):
- `authenticate/oidc/login.go`: `tokenResponse`, `exchange`, `Callback`.
- `authenticate/oidc/remote.go`, `registry.go`, `errors.go`, `ports.go` (`UpstreamBroker`).
- Create: `authenticate/oidc/upstream.go`, `upstream_test.go`, `userinfo_test.go`.
- `example_test.go`: the Upstream example only.

**Must not touch:** `broker*.go`, `link.go`, anything outside `authenticate/oidc`.

**Interfaces** (produces):
```go
type Upstream struct{ s *upstreamState }
func (u Upstream) AccessToken() string
func (u Upstream) HasAccessToken() bool
func (u Upstream) UserInfo(ctx context.Context) (map[string]any, error)
// plus Format, String and LogValue, each writing the package's `redacted` text
type UpstreamBroker interface {
    BrokerUpstream(ctx context.Context, ext ExternalIdentity, up Upstream) (*identity.Principal, error)
}
var ErrUserInfoFailed error // matches the provider-failure classification, as ErrExchangeFailed does
// Provider.UserInfoEndpoint string
// test seam, unexported:
func newUpstream(token, subject string, endpoint func(context.Context) (string, error), out *outbound.Client) Upstream
```

- [ ] **Step 1 (1.1, red).** Write `TestCallback_DropsUpstreamTokensFromResults`.
  - Setup: a fake token endpoint answers `access_token: "at-secret"` and `refresh_token: "rt-secret"`, and the broker is a recording plain broker.
  - Assert: `fmt.Sprintf("%#v", res)`, the stored `Flow`, and the `HandoffRecord` from `Handoff.Issue(ctx, res)` contain neither string.
  - Run it. It passes today, because the tokens are dropped: it is a regression guard. To give it a red step, temporarily add `AccessToken` to `CallbackResult`, set it in `exchange`, watch the test fail, then remove it.
- [ ] **Step 2 (1.3, red).** Write `TestCallback_UpstreamBrokerReceivesToken`. Declare `UpstreamBroker` first (an empty `Upstream` struct compiles). The upstream broker double asserts `up.AccessToken() == "at-secret"`. It fails because `Callback` never calls `BrokerUpstream`.
- [ ] **Step 3 (1.1, 1.3, green).**
  - `tokenResponse` gains `AccessToken string \`json:"access_token"\``.
  - `exchange` returns `(idToken, accessToken string, err error)`.
  - `Callback` dispatches to `BrokerUpstream` when the broker implements it.

  Add `TestCallback_PlainBrokerUnchanged`, and `TestCallback_NoAccessTokenStillLogsIn` (`HasAccessToken() == false`, F1). All pass.
- [ ] **Step 4 (1.2).** Write `TestUpstream_NeverPrintsToken`, a table (`table-test`) with these rows: `%v`, `%+v`, `%#v`, `%s`, a slog JSON attribute, `struct{ Up oidc.Upstream }` with `%+v`, and `struct{ up oidc.Upstream }` with `%+v`. Each asserts `NotContains(out, "at-secret")`.
  - Red: run it first against an `Upstream` that holds the token in a plain (non-pointer) field. The unexported-field row fails.
  - Green: switch to the pointer-to-state layout plus the methods.
- [ ] **Step 5 (1.5, red).** Write `TestUpstream_UserInfo` as a table against `httptest`:

  | Row | Server | Expected |
  |---|---|---|
  | ok | 200 `{"sub":"s-1","email":"a@corp.example","password":"enc"}` | that map; the request carried `Authorization: Bearer at-secret` |
  | sub-mismatch | 200 `{"sub":"s-2"}` | `ErrUserInfoFailed`, nil map |
  | same-email-other-sub | 200 `{"sub":"s-2","email":"<ID token email>"}` | `ErrUserInfoFailed` |
  | sub-missing | 200 `{}` | `ErrUserInfoFailed` |
  | unauthorized / server-error | 401 / 500 | `ErrUserInfoFailed` |
  | jwt | 200 with `application/jwt` | `ErrUserInfoFailed` |
  | not-object | 200 `[1]` | `ErrUserInfoFailed` |
  | oversized | body over `outbound.WithMaxResponseBytes(1024)` | `ErrUserInfoFailed` |
  | no-endpoint / no-token | none | `ErrUserInfoFailed`, zero requests made |
  | cancelled | cancelled context | the error matches `context.Canceled` |

  Each row also captures slog and asserts that neither `at-secret` nor `enc` appears in a record or in `err.Error()`. Implement `UserInfo` (D3) as a stub returning nil; every row except `ok` and `cancelled` then fails on its assertion.
- [ ] **Step 6 (1.5, green).** Implement `UserInfo` on `outbound.Client.Get`. The endpoint resolver uses `Provider.UserInfoEndpoint`, falling back to the cached metadata through `metadataFor`. All rows pass.
- [ ] **Step 7 (1.4).** Write `TestProvider_UserInfoEndpoint` as a table:
  - discovered;
  - pinned wins;
  - pinned `http://` with only `https` allowed is `ErrConfig`;
  - discovery without the endpoint succeeds;
  - three classic endpoints plus UserInfo pinned make zero discovery calls.

  Red, implement `metadata.UserInfoEndpoint` and the `Provider` field and validation, green.
- [ ] **Step 8 (1.6).** Write godoc for every new symbol, each naming its default and override. `AccessToken` places the logging duty on the caller and says a broker may keep the value. Add `ExampleUpstream_UserInfo` with an `// Output:` line. Run `go doc ./authenticate/oidc Upstream` and `go test -run Example -count=1 ./authenticate/oidc/`.
- [ ] **Step 9.** Run Lane A's scoped commands. Report: files changed, tests added, each red output seen, and the final results.

### Dispatch A1-fix: review findings on A1 (tasks 1.3–1.5)

**Model: Sonnet.** Each finding states its fix. **Reviewer: Sonnet.**

**Files** (owned): `authenticate/oidc/login.go` (`tokenResponse` decoding), `upstream.go`, `registry.go` (godoc of `Provider.UserInfoEndpoint`), `callback_upstream_test.go`, `userinfo_test.go`.

- [ ] **Step 1 (1.3, F1).** Add a `TestCallback_Upstream` row: a plain broker, and a token response with `"access_token":{"v":1}`. The login succeeds, and an upstream broker in a second row sees `HasAccessToken() == false`. Red: `the token response is not a JSON object`. Then decode the field so that any non-string value means absent. Green.
- [ ] **Step 2 (1.5).** Add these `TestUpstream_UserInfo` rows:
  - `{"sub":"s-1","emp":12345678901234567890}`: `emp` is `json.Number("12345678901234567890")`. The `ok` row's numbers become `json.Number`;
  - `{"sub":"s-2","sub":"s-1"}`, and `{"sub":"s-1","a":1,"a":2}`: both `ErrUserInfoFailed`;
  - a 302 to a second TLS server on another origin: `ErrUserInfoFailed`, zero requests at the second server, no token in `err.Error()`.

  Red, then decode with `UseNumber`, refuse repeated names (for example with `encoding/json/v2`'s default, or `jsontext`), and keep the trailing-data check. Green.
- [ ] **Step 3 (1.6).** The godoc of `Provider.UserInfoEndpoint` states that a discovered endpoint off the issuer's origin, or on a refused scheme, is dropped with a WARN, and that such a provider needs a pin. `UserInfo`'s godoc states that members are returned unchanged, numbers as `json.Number`, and that repeated names are refused.
- [ ] **Step 4.** Run `go test -race -count=1 ./authenticate/oidc/...`, plus `go vet` and `gofmt -l` on the package, and report.

### Dispatch A2: link lister, hook option, dispatch, error classification (tasks 2.1, 3.1–3.3)

**Model: Opus.** Refusal classification and redaction for a security path, written for the first time. **Reviewer: Opus.**

**Files** (owned):
- `authenticate/oidc/ports.go`: `LinkLister` only.
- `authenticate/oidc/link.go`: memory `ListByUser`.
- `authenticate/oidc/broker.go`: fields, construction checks, `ConfiguredProviders`, `redact` gains the token.
- Create: `authenticate/oidc/broker_hook.go`, `broker_hook_test.go`, `link_list_test.go`.

**Must not touch:** `login.go`, `upstream.go`, anything outside `authenticate/oidc`.

**Interfaces:**
- Consumes: A1's `Upstream`, `newUpstream` and `UpstreamBroker`.
- Produces:
  ```go
  type LinkLister interface { ListByUser(ctx context.Context, user identity.UserID) ([]Link, error) }
  type SignInDecision struct { User identity.UserID; Provision bool; Apply func(ctx context.Context) error }
  type SignInHook func(ctx context.Context, ext ExternalIdentity, up Upstream, linked identity.UserID) (SignInDecision, error)
  func WithBrokerSignInHook(provider string, hook SignInHook) BrokerOption
  func WithBrokerSignInHookAllowManyLinks(provider string) BrokerOption
  func (b *Broker) BrokerUpstream(ctx context.Context, ext ExternalIdentity, up Upstream) (*identity.Principal, error)
  var ErrUpstreamRequired error // a broker failure
  // unexported, filled by A3:
  func (b *Broker) acceptDecision(ctx context.Context, ext ExternalIdentity, up Upstream, l *Link, d SignInDecision) (*identity.Principal, error)
  ```

- [ ] **Step 1 (2.1, 3.1).** Write `TestMemoryLinkStore_ListByUser`: three links naming `u-7` (`corp/s-1`, `corp/s-2`, `partner/p-1`) and one naming `u-8`; `u-9` returns an empty list with a nil error. Red, then green.

  Then write `TestNewBroker_SignInHookWiring` as a table:
  - nil hook → `ErrConfig`;
  - `""` provider → `ErrConfig`;
  - hook plus `WithBrokerJIT("corp")` → `ErrConfig` naming `corp`;
  - hook plus `WithBrokerClaimMirror("corp", true)` → `ErrConfig`;
  - hook plus role sync on `corp` → `ErrConfig`;
  - hook on `corp` with JIT on `partner` → built;
  - a store with no `ListByUser` → `ErrConfig`, then built once `WithBrokerSignInHookAllowManyLinks("corp")` is added (**Review Focus 5:** the store is a struct embedding only `LinkStore` around a memory store);
  - `ConfiguredProviders()` contains `corp`;
  - `NewRelyingParty` with a hook on `ghost` and only `corp` registered → `ErrConfig` naming `ghost`.

  Red, then green.
- [ ] **Step 2 (3.2).** Write `TestBroker_HookDispatch`. An unhooked provider through `BrokerUpstream` behaves exactly like `Broker`. A hooked `corp` through `Broker()` returns `ErrorIs(err, ErrUpstreamRequired)` with the hook never called (F15). Red, then green, with `acceptDecision` as a stub returning an error.
- [ ] **Step 3 (3.3).** Write `TestBroker_HookDecisionErrors` as a table, using mockgen `LinkStore` and `UserLoader` mocks with `Insert` expected zero times:

  | Hook returns | Expected |
  |---|---|
  | `ErrNoLinkedAccount` | `ErrorIs` it |
  | `ErrProvisioningRefused` | `ErrorIs` it |
  | `fmt.Errorf("wrap: %w", ErrExchangeFailed)` | neither `ErrExchangeFailed` nor `ErrFlowUnspent`; a broker failure |
  | `errors.New("db down a@corp.example s-1 at-secret")` | the error text and captured logs contain none of the three |
  | `SignInDecision{}`, nil | a broker failure |

  Red, then implement the classification (D10) and extend `redact` with the token. Green.
- [ ] **Step 4.** Run Lane A's scoped commands, and report as in A1, Step 9.

### Dispatch A2-fix: review findings on A2 (task 3.3)

**Model: Sonnet.** Each finding states its fix. **Reviewer: Sonnet.**

**Files** (owned):
- `authenticate/oidc/broker_hook.go` and `broker_hook_test.go`;
- `authenticate/oidc/broker.go` (`redactedError` printing only);
- `httpsec/errors_test.go` and `httpsec/lookup_status_internal_test.go`, plus `httpsec/errors.go` if the classification needs it (registering `ErrUpstreamRequired`).

- [ ] **Step 1.** Add these `TestBroker_HookDecisionErrors` rows:
  - the hook returns `fmt.Errorf("wrap: %w", &httpsec.ChallengeError{})`. `errors.As` into `*httpsec.ChallengeError` is false, and `httpsec.StatusForError` gives 500;
  - `errors.As` into `interface{ error; Unwrap() error }` is false. This replaces the row whose target does not implement `error`.

  Prove each bites by disabling its branch (`definedInLibrary`; the interface-kind check), then edit it back.
- [ ] **Step 2.** Add a row: the hook's error text carries `at-secret`, and `fmt.Sprintf("%#v", err)`, `%+v` and `%v` contain neither it nor the e-mail. Red, then give `hookFailure` and `redactedError` a `Format` method that writes only their fixed text. Green.
- [ ] **Step 3 (F43).** Add a row: `FindByExternal` returns `&Link{UserID: ""}`. Expect a broker failure, with the hook not called. Red, then green.
- [ ] **Step 4.** Correct the `SignInHook` godoc: other errors fail with fixed text, and the consumer logs its own text (D10).
- [ ] **Step 5.** Register `oidc.ErrUpstreamRequired` in `httpsec`'s sentinel registry as a broker failure, following how the other broker-failure sentinels are classified. The red step is the current failure of `TestStatusForErrorCoversEverySentinel`.
- [ ] **Step 6.** Run `go test -race -count=1 ./authenticate/oidc/...` and the focused `go test -race -count=1 -run 'Sentinel|LookupStatus|OIDC|Callback' ./httpsec/`, plus `go vet` and `gofmt -l`, and report.

### Dispatch A3: decision checks, linking, apply (tasks 3.4–3.7, except 3.7's provisioning bullet)

**Model: Opus.** Ordering under races; a wrong order passes tests and still allows takeover. **Reviewer: Opus.**

**Files** (owned): `authenticate/oidc/broker_hook.go`, `broker_hook_test.go`, `example_test.go` (the hook example only), and for task 2.6 `ports.go` (`LinkRemover`), `link.go` (memory `DeleteLink`), `link_list_test.go`, `ports_mock_test.go` (regenerated).

**Must not touch:** any other file.

- [ ] **Step 0 (2.6).** Write `TestMemoryLinkStore_DeleteLink`: of two links naming `u-7` (`corp/s-1`, `partner/p-1`), removing the `corp` one by its ID and identity returns true and leaves `partner`; the `corp` ID with subject `s-2` returns false and removes nothing. Add a `TestNewBroker_SignInHookWiring` row: a store with `ListByUser` but no `DeleteLink` is `ErrConfig`, and is built with allow-many. Red, then green. The post-insert undo in Step 3/4 uses `DeleteLink`, never `DeleteByUser`.

**Interfaces:**
- Consumes: A2's `acceptDecision` stub, plus the existing `resolveLinked`, `principalFor`, `refusal`, `redact` and `idgen.New(b.ids)`.
- Produces: `LinkRemover { DeleteLink(ctx context.Context, link Link) (bool, error) }` and the memory store's `DeleteLink` (task 2.6).

- [ ] **Step 1 (3.4).** Write `TestBroker_HookChecksBeforeWrite` as a table. `Apply` records each call, and a memory store and fake loader back it:

  | Case | Expected |
  |---|---|
  | link `s-1→u-7`, hook decides `u-9` | `ErrNoLinkedAccount`; `Apply` never called; the link still names `u-7`; one WARN with `provider=corp`, no `u-7` or `u-9` |
  | decides `u-404` (missing) | `ErrNoLinkedAccount`; `Apply` never called; no link |
  | decides disabled `u-7` | the same |
  | the loader returns ID `u-8` for `u-7` | the same |

  Red against the stub, then implement D5 step 3. Green.
- [ ] **Step 2 (3.5, 3.6).** Write `TestBroker_HookLinksThenApplies` as a table:
  - first sign-in: link `corp/iss/s-1→u-7` is stored with the loaded username; `Apply` runs once, after the link exists (checked inside `Apply` with `FindByExternal`); the principal is `u-7`;
  - later sign-in: no insert, `Apply` runs again;
  - `Apply` returns an error: a broker failure, and the link stays (F13);
  - `Apply` disables the user: `ErrNoLinkedAccount`, and the link stays (F19);
  - **Review Focus 1:** the hook is handed `linked=u-7`, finds `u-9` by e-mail, and decides `u-7`. `Apply` writes only `u-7`; the test records the user `Apply` targeted;
  - store faults: `FindByExternal`, `Insert`, `ListByUser` and `DeleteLink` each return an error, and each gives a redacted broker failure, never `ErrNoLinkedAccount` (F12). `DeleteByUser` is never called by the hook path.

  Red, implement D5 steps 4–6, green.
- [ ] **Step 3 (3.5, D11).** Write `TestBroker_HookOneLinkPerUser`:
  - `s-1→u-7` exists and `s-2` decides `u-7`: `ErrNoLinkedAccount`, `Apply` never called, no link for `s-2` (F16);
  - with `WithBrokerSignInHookAllowManyLinks("corp")`: the `s-2` link is stored and the principal is `u-7`.

  Red, then green.
- [ ] **Step 4 (3.5, races).** Write `TestBroker_HookRaces`, run under `-race` with `-count=3`. A barrier wrapper over the memory store holds both goroutines after their first lookup.
  - **Same identity:** both decide `u-7`. Exactly one link; both principals are `u-7`; `Apply` runs twice, after the link (F11).
  - **Same identity, different users:** `u-7` vs `u-9`. One succeeds; the other gets `ErrNoLinkedAccount` with `Apply` never called.
  - **Two subjects, one user:** `s-1` and `s-2` both decide `u-7`. At most one link to `u-7` from the issuer remains, and each refused login's `Apply` was never called (F17).

  Prove the test bites: temporarily delete the post-insert one-link re-check, watch the third row fail, then restore it.
- [ ] **Step 5 (3.7).** Write godoc for `SignInDecision`, `SignInHook`, `WithBrokerSignInHook` and `WithBrokerSignInHookAllowManyLinks`. It covers:
  - the decide-then-apply order;
  - the meaning of `linked`;
  - the library never matching by e-mail, with the `email_verified` advice;
  - the one-link default and its override;
  - that it runs in the request (F31).

  Add `ExampleWithBrokerSignInHook`: an adoption hook that calls `up.UserInfo`, prefers `linked`, and puts its writes in `Apply`. It compiles, with no output line. Run `go doc` and `go test -run Example`.
- [ ] **Step 6.** Run Lane A's scoped commands, including `go test -race -count=3 -run 'TestBroker_Hook' ./authenticate/oidc/`. Report.

### Dispatch A4: provisioning decision (task 3.8, and 3.7's provisioning bullet)

**Model: Opus.** Ordering under races on a security path, written for the first time. **Reviewer: Opus.** Runs after A3 is reviewed clean.

**Files** (owned): `authenticate/oidc/broker_hook.go` (the `Provision` field and its branch), `broker_hook_test.go` (or a new `broker_hook_provision_test.go`), `example_test.go` (the hook example, only if it gains a provisioning variant).

**Must not touch:** any other file.

**Interfaces:**
- Consumes: A3's `acceptDecision` and its check, insert and re-read helpers.
- Produces: `SignInDecision.Provision bool`. No other exported symbol.

- [ ] **Step 1 (3.8, red).** Write `TestBroker_HookProvisions` as a table over a memory link store and a fake loader whose `Apply` can create users:

  | Case | Expected |
  |---|---|
  | first sign-in provisions `u-new` (absent); `Apply` creates it | inside `Apply`, `FindByExternal` already returns a link to `u-new` with `Username == ""`; `Apply` called once; principal `u-new` |
  | provisions `u-7`, which exists, with no link for the identity | `ErrNoLinkedAccount`; `Apply` never called; no link (F32) |
  | provisions `u-new` with `Apply == nil` | a broker failure (not `ErrNoLinkedAccount`); no link (F33) |
  | `Apply` returns an error | a broker failure; the link to `u-new` stays (F34) |
  | `Apply` returns nil without creating `u-new` | a broker failure; the link stays (F34) |
  | the identity is linked to absent `u-new`, and the hook provisions `u-new` again, with `Apply` creating it | no insert; `Apply` once; principal `u-new` (F34 resume) |
  | provisions `u-new`; the loader faults on the pre-check load | a redacted broker failure; no link |
  | provisions `u-new`; `Apply` creates it disabled | `ErrNoLinkedAccount`; the link stays |

  Run it focused: every row except the refusal rows fails, because A3's path refuses a user that does not load.
- [ ] **Step 2 (3.8, green).** Implement the `Provision` branch of D13 in `acceptDecision`, reusing A3's conflict check, one-link rule, insert, re-read and post-insert re-check. Green.
- [ ] **Step 3 (3.8, race; F35).** Add a row to `TestBroker_HookRaces`: two first sign-ins of one identity, held by the barrier after `FindByExternal`, provision `u-a` and `u-b`. Expect exactly one link, only the winner's `Apply` recorded, the loser `ErrNoLinkedAccount`, and the loser's `Apply` never called. Prove it bites: temporarily move the insert after `Apply`, watch the row fail on the loser's `Apply` call, then edit it back. Run `go test -race -count=3 -run 'TestBroker_Hook' ./authenticate/oidc/`.
- [ ] **Step 4 (3.7, provisioning bullet).** Godoc on `SignInDecision.Provision` and in `SignInHook`'s doc: what provisioning means, that the reference must not exist, that `Apply` is required, why the link comes first, the empty username, and resuming on a later sign-in. Run `go doc ./authenticate/oidc SignInDecision`.
- [ ] **Step 5.** Run Lane A's scoped commands, and report as in A1, Step 9.

### Dispatch S1: `ListByUser` in the shipped stores (tasks 2.2–2.5)

**Model: Sonnet.** A conformance case and three adapters against a stated contract. **Reviewer: Sonnet.** Runs in a worktree cut after A2's merge.

**Files** (owned):
- `test/oidc/linkstore_suite.go` (the new case only), `test/oidc/linkstore_suite_test.go`;
- `internal/pgschema/oidc.go`: `LinkListByUser`;
- `store/sqlstore/oidc_link.go`, `store/pgxstore/oidc_link.go`, `store/gormstore/oidc_link.go`, and their `_test.go` files.

**Must not touch:** `authenticate/oidc/*`, and any other file.

**Interfaces:**
- Consumes: `oidc.LinkLister` and `oidc.Link`.
- Produces: `LinkListByUser` and `LinkDeleteOne` (`DELETE … WHERE id = $1 AND provider = $2 AND issuer = $3 AND subject = $4`) in `internal/pgschema`, and `ListByUser` and `DeleteLink` on each store type, with the compile-time assertions `var _ oidc.LinkLister = (*LinkStore)(nil)` and `var _ oidc.LinkRemover = (*LinkStore)(nil)` in each package. Until A3 lands `LinkRemover`, assert the method with a local interface of the same shape.

- [ ] **Step 1 (2.2).** Add a `ListByUser` case to the conformance suite, skipped when the store does not implement `oidc.LinkLister`. It covers three links for `u-7` across two providers, one for `u-8`, and none for `u-9`. Fields come back byte for byte, including a user reference with mixed case and non-ASCII bytes. Run it against the memory store: green, since A2 implemented it. Then prove it bites by temporarily making the memory store return links for every user, and watch it fail.
- [ ] **Step 2 (2.3).** Add the suite run with `ListByUser` for `sqlstore`, plus the compile assertion. It is red because the method is missing: write the method as a stub returning nil, and watch the content assertion fail. Then implement it with `LinkListByUser`, and get it green in the PostgreSQL container.
- [ ] **Step 3 (2.4).** Do the same for `pgxstore`.
- [ ] **Step 4 (2.5).** Do the same for `gormstore`.
- [ ] **Step 5.** Run Lane S's scoped commands, and report.

### Dispatch B1: login URL, wiring, recognition, pre-check, policy and fallback (tasks 4.1–4.5)

**Model: Opus.** Security refusal logic across several packages. **Reviewer: Opus.** Runs in its own worktree.

**Files** (owned):
- `oidcprovider/provider.go`: `LoginURL()` only; `oidcprovider/provider_test.go`.
- `httpsec/oidc_options.go`: `OIDCDeps.Users`, the option, and `check`.
- `httpsec/oidc.go` and `httpsec/oidc_login.go`: dispatch in `callback`.
- Create: `httpsec/oidc_completion.go`, `oidc_completion_test.go`.
- `httpsec/oidc_redeem.go` and `oidc_resume.go`: **behaviour-preserving extraction only**, of the shared policy, login-tail and per-request helpers. Their existing tests stay green, unchanged.

**Must not touch:** `authenticate/oidc/*`, `README.md`.

**Interfaces:**
- Consumes:
  - `oidc.CallbackResult`;
  - `Provider.PendingRequest(ctx, handle, flowSecret)`, `Provider.Resume`, `ResumeInput`;
  - `oidcRedemptionCheck`, `guardFederatedAssurance`, `newRedemptionLogin`, `postAuthenticationInput`;
  - `session.WithExternalSession`, `cancelHeldRecoveries`;
  - `oidcSignInOf`, `confirmSignIn`, `setOIDCCookie`, `OIDCFlowCookie`, `OIDCBrowserSessionCookie`, `conveyHandoff`.
- Produces:
  ```go
  func (p *Provider) LoginURL() string
  // OIDCDeps.Users identity.UserLoader
  func WithOIDCProviderCompletion() OIDCOption
  func parkedHandle(next string, loginURL *url.URL) (string, bool)
  func (i *oidcInterceptor) completeProviderSignIn(ex *Exchange, provider string, res oidc.CallbackResult, handle string) error
  ```

- [ ] **Step 1 (4.1).** Write `TestProvider_LoginURL`, asserting it returns `Deps.LoginURL` unchanged. Red against a stub returning `""`, then green.
- [ ] **Step 2 (4.2).** Write `TestEnableOIDCLogin_ProviderCompletionWiring` as a table on `httpsec.New`. Each of these is `ErrConfig`:
  - no `EnableOIDCProvider`;
  - `WithOIDCCallbackSuccess`;
  - `WithOIDCHandoffRedeemer`;
  - a nil handoff manager;
  - `OIDCDeps.Users` nil;
  - `WithOIDCSessions` with a manager other than the provider's;
  - a provider redirect URL on `https://other.example`;
  - `LoginURL` `https://id.example/login?tenant=a`.

  A valid wiring builds. Red, then green.
- [ ] **Step 3 (4.3).** Write `TestParkedHandle` as a table, with `LoginURL` = `https://id.example/login`:
  - `…/login?req=h1` → `("h1", true)`;
  - false for each of: port `:8443`; host `evil.example`; `/login/`; `/LOGIN`; `/%6Cogin`; `?req=h1&x=1`; `?req=h1&req=h2`; `?req=`; and relative `/login?req=h1`.

  Red, then green. Add a chain test where a non-qualifying `Next` takes the allowlisted handoff or `/`, and one where a qualifying `Next` with an empty allowlist is never replaced by `/` (F27).
- [ ] **Step 4 (4.4).** Write `TestOIDCCompletion_PreChecksHandle` as a table with three rows: unknown handle; expired handle (fake clock past 10 minutes); a flow cookie that does not bind the handle. Each asserts:
  - `ErrOIDCUnknownHandle`;
  - the source charged once;
  - no stored session;
  - no login event;
  - a held recovery for the user still held (F20).

  Red, then green.
- [ ] **Step 5 (4.5).** Write `TestOIDCCompletion_PolicyAndFallback` as a table:
  - user missing, or disabled → refused as redemption refuses (F21);
  - policy deny → the policy's reason, and no session;
  - second factor required with upstream `amr` `["pwd"]` → 302 (the existing handoff conveyance) to `https://id.example/login?req=h1&handoff=…`, and no session (F22);
  - stored password-change time requiring a change → the same fallback;
  - required second factor, with `["mfa"]` accepted by the provider config → proceeds to the stub of step 5 onward.

  Red, then green.
- [ ] **Step 6.** Run Lane B's scoped commands in the worktree, and report.

### Dispatch B1-fix: review findings on B1 (tasks 4.2–4.4)

**Model: Sonnet.** Test additions and two small fixes that the findings state. **Reviewer: Sonnet.** Same worktree.

**Files** (owned): `httpsec/oidc_completion.go`, `oidc_completion_test.go`, `oidc_completion_internal_test.go`.

- [ ] **Step 1 (4.2).** In `TestEnableOIDCLogin_ProviderCompletionWiring`, drop `noHandoff: true` from the callback-success row. Prove it bites: temporarily disable the callback-success check, watch the row fail, then edit it back.
- [ ] **Step 2 (4.3).** `TestParkedHandle` rows:
  - `https://user@id.example/login?req=h1` → false. Prove it bites by removing the userinfo check;
  - login URL `https://id.example` (empty path) with `https://id.example/?req=h1` → `("h1", true)`. Red, then compare an empty login URL path as `/` (D7 step 1). Green.
- [ ] **Step 3 (4.3).** A chain row with completion **off**: destination `<LoginURL>?req=h1` with an empty allowlist takes the handoff to `/`.
- [ ] **Step 4 (4.4, F38).** Rows in `TestOIDCCompletion_PreChecksHandle`:
  - a handle parked at the consent stage → `ErrOIDCUnknownHandle`, not charged, loader not called;
  - a resume limiter over the limit → `ErrOIDCThrottled`, with neither `PendingRequest` nor the loader reached;
  - a failing pending-request store → a dependency error, not charged, nothing written.

  For each row, show that it bites by disabling its branch.
- [ ] **Step 5.** Run Lane B's scoped commands, and report.

### Dispatch B2: success path, failure paths, events, godoc (tasks 4.6–4.9)

**Model: Opus.** Session lifecycle and cleanup on refusal; a mistake leaves a live sign-in. **Reviewer: Opus.** Same worktree.

**Files** (owned): `httpsec/oidc_completion.go`, `oidc_completion_test.go`, `oidc_completion_internal_test.go`, `oidc_options.go` (godoc and the loader check), `oidc_redeem.go` (the redemption's destination carve-out only).

**Must not touch:** any other file.

**Interfaces:** consumes B1's `completeProviderSignIn` and helpers. Produces nothing new.

- [ ] **Step 1 (4.6).** Write `TestOIDCCompletion_SignsInWithoutScript`.
  - Setup: a chain with `EnableOIDCLogin(…, WithOIDCProviderCompletion())` and `EnableOIDCProvider`; a fake upstream IdP; client `app` with no consent needed; parked handle `h1`; the broker principal with role `admin`, while the stored roles are `viewer`; the user holds a recovery; `WithOIDCSignInAssurance` mapping to `amr` `["fed"]`.
  - Assert:
    - 303 to `app`'s redirect URI with `code`, `state` and `iss`;
    - `Set-Cookie` for `OIDCBrowserSessionCookie` (`HttpOnly`, `Secure`, `SameSite=Lax`), and the login flow cookie cleared;
    - `Cache-Control: no-store` and `Referrer-Policy: no-referrer`;
    - no `handoff` and no body credential;
    - the stored session has role `viewer` only, plus `factor.OIDC`, the provider, issuer, provider session id and asserted assurance;
    - the recovery is cancelled;
    - the provider grant's sign-in carries `amr` `["fed"]`;
    - the code exchanges at `/oauth2/token`.

  Add a consent row: 303 to `ConsentURL?req=h1`. Red, implement D7 steps 5–9, green.
- [ ] **Step 2 (4.7).** Write `TestOIDCCompletion_FailurePaths` as a table:

  | Case | Expected |
  |---|---|
  | consumer PerRequest policy refuses | that refusal; the session ended; no code (F23) |
  | `Resume` returns an error | the refusal; the session ended |
  | `Resume` answers `login_required` (id_token_hint naming another subject) with a nil error | the session ended; 303 to the client error response; no code (F24) |
  | the sign-in ends between `Resume` and `confirmSignIn` | `ErrOIDCReauthenticate`; no redirect to the client |
  | ending the session fails | one ERROR record; the original refusal unchanged (F25) |
  | the session store fails | a dependency failure; `Resume` never called (F26) |

  Red, then green.
- [ ] **Step 3 (4.8).** Write `TestOIDCCompletion_Events`.
  - A completed sign-in emits the same event kinds, in the same order, as a handoff redemption of the same login, compared with an event recorder.
  - A broker returning `ErrNoLinkedAccount` on a completion-enabled callback emits `AuthnLoginFail`.

  Red if anything is missing, then green.
- [ ] **Step 4 (4.9).** Write godoc for `Provider.LoginURL`, `OIDCDeps.Users` and `WithOIDCProviderCompletion`. It covers:
  - default off, with the handoff;
  - the exact trusted login URL rule;
  - the fallback;
  - the exclusions;
  - the required loader;
  - one SSO login at a time per browser (D12).

  Run `go doc ./httpsec WithOIDCProviderCompletion`.
- [ ] **Step 4a (4.2, F28).** Add a row to `TestEnableOIDCLogin_ProviderCompletionWiring`: `OIDCDeps.Users` set without `WithOIDCProviderCompletion()` → `ErrConfig`. Red, then refuse it in `check`. Green.
- [ ] **Step 4b (4.3, F37).** Write `TestOIDCCompletion_FallbackRedemptionKeepsDestination`: with completion on and an empty allowlist, an owed second factor falls back with `handoff=…`; redeeming that code at the handoff endpoint answers `next` = `https://id.example/login?req=h1`, not `/`. A row with completion off and the same stored destination still answers `/`. Red (it answers `/` today), then apply `parkedHandle` with the same `loginURL` in the redemption's destination resolution. Green.
- [ ] **Step 5 (Review Focus 4).** Write `TestOIDCCompletion_TwoTabsSequential`:
  - two parked requests `h1` and `h2` under one provider flow cookie; the SSO login for `h1` runs to its callback, then the one for `h2`. Each callback redirects to its own client response, and both codes exchange;
  - the second row starts the SSO login for `h2` before the callback for `h1`. The `h1` callback answers `ErrInvalidState` and creates no session (D12, F29).
- [ ] **Step 6.** Run Lane B's scoped commands, and report.

### Merge (main session)

- [ ] Merge Lane S's worktree after S1 and A4 are reviewed clean, then Lane B's after B2. Run all three lanes' scoped commands together, and read the output.

### Dispatch C: README (tasks 5.1–5.2)

**Model: Sonnet.** Documentation of decided behaviour. **Reviewer: Sonnet.**

**Files** (owned): `README.md`, the "OIDC" and "OpenID Provider" sections only.

- [ ] **Step 1 (5.1).** In "OIDC", add "Sign-in hook and upstream access". It covers:
  - decide, then apply;
  - `linked`;
  - the example matching `ExampleWithBrokerSignInHook`;
  - the one-link default and `WithBrokerSignInHookAllowManyLinks`;
  - that e-mail matching is the consumer's rule;
  - assurance from the ID token only;
  - the conflicting options.
- [ ] **Step 2 (5.2).** In "OpenID Provider", add "Federated sign-in without a page script". It covers:
  - the flow, with the frontend as a client of the provider and brokering inside;
  - the SSO link `/sso/login/{provider}?next=<LoginURL>?req=<handle>`;
  - `WithOIDCProviderCompletion` and `OIDCDeps.Users`;
  - the fallback to the handoff landing page;
  - the one-SSO-login-per-browser limit.

  Do not state that a frontend never talks to the upstream provider.
- [ ] **Step 3.** Check every identifier in the new text with `go doc`, and every path with `rg`. Report.

### Dispatch D: integration test (task 6.1)

**Model: Sonnet.** An end-to-end test of built behaviour in an existing suite. **Reviewer: Sonnet.**

**Files** (owned):
- `test/oidc/idp.go`: `access_token` in the token response; a `/userinfo` endpoint with a per-subject body option, advertised in discovery.
- Create: `test/oidc/brokered_signin_test.go`.

**Interfaces:** consumes everything above, plus `admin.Importer` and `admin.Users`.

- [ ] **Step 1.** Extend the IdP fixture: tokens and UserInfo. This is fixture work, so it has no red step of its own. Check that the existing `test/oidc` suites stay green.
- [ ] **Step 2 (6.1).** Write `TestBrokeredSignIn_AdoptsImportedUser`, with subtests in order on one store:
  - **imported:** an `admin.Importer` user `a@corp.example` with no link signs in. The hash is stored as given, attributes and primary role are updated, the user count is unchanged, and there is one link.
  - **second:** the second sign-in goes through the link, `Apply` runs again, and the hash and role are refreshed.
  - **conflict:** another linked identity whose UserInfo e-mail now names `a@corp.example` is refused, and `a@corp.example` is unchanged.
  - **inactive:** a deactivated account is refused.
  - **hook-off:** an unlinked identity is refused, as before.
  - **no-secret-in-logs:** a slog buffer over all subtests holds no access token, UserInfo body value or hash.

  Run it: green. Prove it bites without touching library code: temporarily make the test's own hook write in its decide phase instead of in `Apply`. The conflict subtest must then fail. Edit the hook back afterwards.
- [ ] **Step 3.** Run `go test -race -count=1 ./...` in `test/`, and report.

### Main session: 6.2 and 6.3

- [ ] **6.2.** After every dispatch, run that lane's scoped commands, `go vet` and `gofmt -l`, and read the output.
- [ ] **6.3.** Run `make check` and `make spec-check` once, after the last code edit, and read the output. Then dispatch the whole-branch review (Opus) against every requirement of both deltas.
