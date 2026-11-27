# OpenAPI Document Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An opt-in OpenAPI 3.1.2 document of exactly the enabled built-in endpoints. It is built once while the chain is built, served publicly under the base path, and accurate for responses the consumer replaced.

**Architecture:**
- **The core describes, and records Go types.** `httpsec` stays dependency-free. Each endpoint's request, responses, refusals and security are described on its inventory entry, and typed JSON responders record `reflect.Type`s. A `BuildHook` lets a registered interceptor finish building once the chain is assembled.
- **The nested module renders.** `httpsec/openapisec` turns the inventory into a document with its own write-only model, reflecting types with `invopop/jsonschema`. `Enable` registers a serving interceptor at `OrderOpenAPI`, and `Build` produces the same bytes without serving.

**Tech Stack:** Go 1.27; `net/http`, gin, fiber v3; `github.com/invopop/jsonschema` (in `openapisec` only); `github.com/pb33f/libopenapi` (in `test` only); testify, gomock.

**Spec:** `openspec/changes/openapi-document/`: `proposal.md`, `design.md` (D1–D10), `specs/{openapi-document,http-security-chain,multi-factor-auth,passkey-authentication,module-layout}/spec.md` and `tasks.md`. Task numbers (1.1 … 9.1) are `tasks.md`'s.

**Builds on** `endpoint-inventory-base-path`: `Endpoint`, `(*Chain).Endpoints()`, `WithBasePath`, the operation identifier table and `checkEndpointCollisions` exist when this plan starts.

## Global Constraints

- **Test-first** for every task: the red step fails for the intended reason, not a compile error. A task that keeps behaviour shows its red step by temporary inversion (`golang-tdd.md`). Table tests use `table-test`, and mocks use `use-mockgen`.
- **Library design.** Every new option's godoc names the default it replaces, and every default and one override is tested (`library-design.md`).
- **Document defaults:**
  - `openapi: "3.1.2"`;
  - `info.title` `"Security endpoints"` and `info.version` `"1"`;
  - no `servers`;
  - path `/openapi.json`, joined to the base path;
  - `Content-Type: application/json`;
  - `ETag` `"` + lowercase hex SHA-256 of the bytes + `"`;
  - slot `OrderOpenAPI Order = 150`.
- **Precedence of a response's schema:** the `WithCustomizer` hook, then `WithResponse[T]`, then the typed form, then the default. A plain responder with nothing declared gives the description `"Defined by the application."` and no `content`.
- **Begin data.** When every challenge method behind `{method}` describes its begin data, the 200 schema is the single type, or a `oneOf` of them. When any method does not, the 200 has no schema.
- **No third-party type in exported APIs.** None of invopop's types appears in `openapisec`'s exported API, and none of the WebAuthn library's types in `webauthn`'s.
- **The core module** never requires `github.com/invopop/jsonschema`.
- **Agents** never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`. The reference-material rule binds every dispatch.

## Review Focus

- **A declaration that names nothing:** `WithResponse[T]("scrty.lgoin", 200)` fails construction with an error naming `scrty.lgoin`, never silently ignored. Added to Task 8 (6.3).
- **The document path collides:** `WithPath("/login")` beside form login fails `New`, naming both, even though the document endpoint is not in the inventory. Added to Task 9 (7.1).
- **Conditional and wrong-method requests:** `If-None-Match` with the weak form `W/"<tag>"` or `*` gets 304, as RFC 9110's weak comparison requires. A POST to the document path passes through to the handler. Added to Task 9 (7.1).
- **Two methods on one path:** recovery codes produce one path item with both `get` (`scrty.recovery.codes.count`) and `post` (`scrty.recovery.codes.regenerate`). Added to Task 7 (6.2).
- **Two chains in one process:** each serves its own document, with no shared state. Added to Task 9 (7.1).

## Execution lanes and dispatches

All core dispatches compile `httpsec`, so the ones that run at the same time get **their own worktrees** (`isolation: "worktree"`). The main session merges each wave, verifies, then dispatches a reviewer. No two agents own one file.

| Wave | Dispatch | Plan tasks (tasks.md) | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 1 | A1 | 1, 2 (1.1, 2.1) | `httpsec/buildhook.go` (new), `buildhook_test.go` (new), `options.go` (`build()` call), `chain.go` (`OrderOpenAPI`), `endpoints.go` (descriptor types), `endpoint_descriptions_test.go` (new); `login*.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go`, `magiclink*.go` (descriptor methods only) | Opus: exported types and a hook other lanes compile against | Opus |
| 1 | M1 | 7 step 1 (5.1) | `httpsec/openapisec/` (new module: `go.mod`, `doc.go`), `go.work`, `layout_guard_test.go`, `layout_test.go` | Sonnet: scaffolding with stated guard rows | Sonnet |
| 2 | A2 | 3 (2.2) | `mfa_verify.go`, `mfa_begin.go`, `mfa_enrol*.go`, `reauth*.go` (descriptor methods), their descriptor tests in `endpoint_descriptions_mfa_test.go` (new) | Sonnet: applies Task 2's pattern | Sonnet |
| 2 | A3 | 4 (2.3) | `passkey*.go`, `recovery*.go`, `oidc*.go` (descriptor methods), `endpoint_descriptions_more_test.go` (new) | Sonnet: applies Task 2's pattern | Sonnet |
| 2 | O1 | 7 step 2 (6.1) | `openapisec/document.go`, `openapisec/schema.go`, their tests | Opus: reflection whose mistakes can pass tests and still misdescribe | Opus |
| 3 | A4 | 5 (2.4) | `httpsec/refusaldrift_test.go` (new) and the refusal table tests it wraps | Sonnet: a test helper over existing tables | Sonnet |
| 3 | T1 | 6, first group (3.1) | `login_options.go`, `session_renewal.go`, `mfa_options.go`, `mfa_verify.go`, `reauth_options.go`, `magiclink_options.go`, `json_response_test.go` (new) | Sonnet: one generic pattern, fully pinned | Sonnet |
| 3 | T2 | 6, second group (3.2) | `recovery_options.go`, `recovery_codes.go`, `passkey_manage.go`, `passkey.go`, `json_response_more_test.go` (new) | Sonnet: the same pattern | Sonnet |
| 4 | P1 | 10 (4.1) | `authenticate/mfa/describe.go` (new), `authenticate/passkey/describe.go` (new), their tests; the begin descriptors in `mfa_begin.go`, `passkey.go`, `passkey_login.go` | Sonnet: optional interfaces with stated contracts | Sonnet |
| 4 | O2 | 7 step 3 (6.2) | `openapisec/build.go`, `openapisec/options.go`, their tests | Sonnet: maps a described inventory to the model | Sonnet |
| 5 | W1 | 11 (4.2) | `authenticate/passkey/webauthn/describe.go` (new), its test | Sonnet: two methods returning reflected types | Sonnet |
| 5 | O3 | 8 (6.3) | `openapisec/responses.go`, its tests | Sonnet: the precedence is stated | Sonnet |
| 6 | O4 | 9 (7.1) | `openapisec/enable.go`, `openapisec/example_test.go`, its tests, the `README.md` section | Sonnet: serving with stated headers | Sonnet |
| 7 | V1 | 12 (8.1) | `test/openapi/validate_test.go` (new), `test/go.mod` (libopenapi) | Sonnet: validation tests | Sonnet |
| 7 | C1 | 13 (8.2) | `test/httpsecconformance/openapi_scenarios.go` (new), its registration in `scenarios.go` | Sonnet: conformance cases | Sonnet |
| — | main | 14 (9.1) | — | the main session runs the gate | — |

- **Why some waves are sequential.** Waves 2 and 3 both touch interceptor files, and wave 4's begin descriptors edit files that waves 2 and 3 touched. Wave 7 needs everything.
- **Before archive,** one whole-branch review on Opus checks every requirement in the five deltas.

---

### Task 1: The build hook and the slot (tasks.md 1.1)

**Files:** create `httpsec/buildhook.go`, `httpsec/buildhook_test.go`; modify `options.go` and `chain.go`.

**Interfaces:**
- Produces:
  - `type BuildHook interface{ ChainBuilt(c *Chain) error }`;
  - `const OrderOpenAPI Order = 150`;
  - `config.build()` calls every registered `BuildHook` in slot order, after the endpoint list and collision check, as its last step before returning.

- [ ] **Step 1: Write the failing tests.**
  - `TestBuildHook` registers a recording hook beside form login and asserts one call, whose `c.Endpoints()` contains `scrty.login`.
  - A second row has the hook return `errors.New("boom")`, and asserts `New` returns `nil` and an error matching `boom`.
  - `TestOrderOpenAPI` asserts `OrderJWKS < OrderOpenAPI && OrderOpenAPI < OrderOIDC`.
- [ ] **Step 2: Run** `go test -run 'TestBuildHook|TestOrderOpenAPI' -count=1 ./httpsec/`. Expected: FAIL on the call count.
- [ ] **Step 3: Implement** it. The godoc on `OrderOpenAPI` follows the other slots' style.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): a hook for interceptors that need the built chain`.

### Task 2: Descriptor types, and the first endpoints (tasks.md 2.1)

**Files:** `httpsec/endpoints.go`, `httpsec/endpoint_descriptions_test.go`, and the descriptor methods in the files A1 owns.

**Interfaces:**
- Produces, as fields added to `Endpoint`:

```go
Request   *Request   // nil when the endpoint reads no body
Responses []Response
Refusals  []Refusal
Security  []Security // empty when the endpoint needs no credential

type Request struct {
    MediaTypes []string // e.g. "application/x-www-form-urlencoded", "application/json"
    Fields     []Field
}
type Field struct {
    Name     string
    Type     reflect.Type
    Required bool
}
type Response struct {
    Status  int
    Body    []reflect.Type // possible body types; empty when there is no body or it is unknown
    Unknown bool           // the application defines the body
}
type Refusal struct {
    Err    error // a sentinel
    Status int   // StatusForError(Err)
}
type Security struct {
    Scheme SecurityScheme // type SecurityScheme int: SchemeBasic, SchemeBearerJWT, SchemeBearerReference, SchemeAPIKey
    Header string         // the API key header; empty otherwise
}
```

- [ ] **Step 1: Write the failing test.** `TestEndpointDescriptions` covers:
  - **default login:** `Request.MediaTypes` holds both form and JSON; the fields are `username` and `password`, both required; `Responses` is `[{Status: 200, Body: [login document type]}]`; `Refusals` includes `{authenticate.ErrAuthenticationFailed, 401}` and `{ErrCredentialsMissing, 400}`; `Security` is empty;
  - **renamed fields** (`email` and `secret` through `WithLoginParams`) appear in `Fields`;
  - **a plain `WithLoginResponder`** gives `{Status: 200, Unknown: true}`;
  - **logout** has bearer security.
- [ ] **Step 2: Run** `go test -run 'TestEndpointDescriptions' -count=1 ./httpsec/`. Expected: FAIL.
- [ ] **Step 3: Implement** the types, and the descriptor data in each owned interceptor's `endpoints()`. Refusals list the sentinels each interceptor's code returns.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): endpoints describe requests, responses and refusals`.

### Task 3: MFA, enrolment and re-authentication descriptions (tasks.md 2.2)

- [ ] **Step 1: Write the failing test.** In `endpoint_descriptions_mfa_test.go`:
  - `scrty.mfa.verify` requires a pending session, and its refusals include `ErrUnknownMFAMethod` (404) and `ErrMFAMethodNotUsable` (403);
  - `scrty.mfa.begin`'s 200 is `Unknown: true` until Task 10;
  - `scrty.reauth.methods` has its methods-document type.
- [ ] **Step 2: Run** with `-run 'TestEndpointDescriptions'`. Expected: FAIL.
- [ ] **Step 3: Implement** the descriptor data.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): MFA and re-authentication describe themselves`.

### Task 4: Passkey, recovery and OIDC descriptions (tasks.md 2.3)

- [ ] **Step 1: Write the failing test.** In `endpoint_descriptions_more_test.go`:
  - the recovery codes path has two entries, GET with the count type and POST with the codes type;
  - `scrty.oidc.callback` responds 302 with no body (`Body` empty, `Unknown` false);
  - `scrty.passkey.register.begin`'s 200 is `Unknown: true` until Task 10.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the descriptor data.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey, recovery and OIDC describe themselves`.

### Task 5: The refusal drift guard (tasks.md 2.4)

**Interfaces:**
- Produces: `func assertDeclaredStatus(t *testing.T, ch *Chain, operationID string, status int)` in `refusaldrift_test.go`, called from each built-in's refusal table test after its status assertion.

- [ ] **Step 1: Wire the helper** into the refusal tables (login, MFA, re-authentication, passkeys, recovery, OIDC redemption, renewal, magic link).
- [ ] **Step 2: Red step.** Remove `ErrMFAMethodNotUsable` from MFA verify's declared refusals, and confirm its refusal test fails, naming the status and the operation. Then restore it.
- [ ] **Step 3: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 4: Commit** `test(httpsec): observed refusal statuses are declared`.

### Task 6: Typed JSON responders (tasks.md 3.1, 3.2)

**Interfaces:**
- Produces one generic option per plain responder, of this shape:

```go
func WithLoginJSONResponse[T any](status int, fn func(*Exchange, LoginResult) (T, error)) LoginOption
```

The others take the same shape: `WithRenewalJSONResponse` (`RenewalResult`), `WithMFAJSONResponse` (`MFAResult`), `ListingJSONResponse` (`[]MFAMethod`, returning `ListingSetting`), `WithReauthenticationJSONResponse`, `WithReauthenticationMethodsJSONResponse`, `WithMagicLinkJSONResponse` (first group, 3.1); `WithRecoveryJSONResponse`, `WithRecoveryHoldJSONResponse` (`recovery.Hold`), `WithRecoveryCodesJSONResponse` (`[]string`), `WithRecoveryCountJSONResponse` (`recovery.RemainingCodes`), `WithPasskeyListJSONResponse` (`[]passkey.Summary`), `WithPasskeyRenameJSONResponse`, `WithPasskeyRemoveJSONResponse` (`id.ID`), `WithPasskeyRegistrationJSONResponse` (`*passkey.RegistrationResult`) (second group, 3.2). The first group (3.1) is everything before the semicolon.

- Each one sets the plain responder to a function that encodes `T` with `encoding/json`, and records `Response{Status: status, Body: []reflect.Type{reflect.TypeFor[T]()}}`.
- A status outside 200–299 is a configuration error naming the option.

- [ ] **Step 1: Write the failing tests.** `TestJSONResponse`, a table with one row per option:
  - the endpoint answers the given status with `Content-Type: application/json` and the encoded value;
  - the description records `T`;
  - a function returning an error propagates it unchanged, with nothing written;
  - status 400 is refused at construction.
- [ ] **Step 2: Run** with `-run 'TestJSONResponse'`. Expected: FAIL.
- [ ] **Step 3: Implement** the options. Each godoc names the plain option it stands beside, and its default.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): typed JSON responders`.

### Task 7: The module, its model and the builder (tasks.md 5.1, 6.1, 6.2)

**Files:** `httpsec/openapisec/{go.mod,doc.go,document.go,schema.go,build.go,options.go}` and tests; `go.work`; `layout_guard_test.go`.

**Interfaces:**

```go
package openapisec

type Option func(*config) error
func Build(c *httpsec.Chain, opts ...Option) ([]byte, error)
func WithInfo(title, version string) Option
func WithServer(url string) Option // repeatable, in order

type Document struct { /* OpenAPI, Info, Servers, Paths, Components, Tags */ } // write-only model, JSON-encoded
```

- [ ] **Step 1 (5.1).** In `layout_guard_test.go`:
  - add `httpsec/openapisec` to the listed integrations and its package name to the package table;
  - add `github.com/invopop/jsonschema` to the modules the core must not require;
  - add an exported-API row with `forbidden: "github.com/invopop/"`.

  Run `go test -count=1 .` at the root: FAIL on the missing module. Create the module (requiring the root and invopop), add it to `go.work`, and re-run: PASS.
- [ ] **Step 2 (6.1).** `TestSchema` checks that:
  - a recursive type yields a component whose field `$ref`s it;
  - a `jsonschema:"enum=active,enum=locked"` field enumerates both values;
  - a type with a `chan int` field returns an error naming the type.

  Run it: FAIL. Implement `schema.go` with invopop: named types under `components/schemas`, references to them, and a check after each reflection. Run it: PASS.
- [ ] **Step 3 (6.2).** `TestBuild` checks that:
  - only enabled endpoints appear, at their `/auth` paths with `operationId`s and tags;
  - `method` enumerates `totp` and `passkey`;
  - renamed login fields appear in both media types;
  - login has no security and logout requires bearer;
  - the API key scheme uses the configured header;
  - the document declares `openapi: 3.1.2`, the default title and version, and no servers;
  - `WithServer` adds a server;
  - recovery codes give one path item with `get` and `post` (Review Focus).

  Run it: FAIL. Implement `build.go`. Run `go test -race -count=1 ./...` in `httpsec/openapisec`: PASS.
- [ ] **Step 4: Commit** each step separately: `build(openapisec): the module`, `feat(openapisec): schema reflection`, `feat(openapisec): build the document`.

### Task 8: Responses, refusals and the hook (tasks.md 6.3)

**Interfaces:**

```go
func WithResponse[T any](operationID string, status int) Option
func WithErrorBody[T any](mediaType string) Option
func WithCustomizer(fn func(*Document) error) Option
```

- [ ] **Step 1: Write the failing test.** `TestResponses` covers the spec's scenarios:
  - **default login:** a 200 schema requiring `access_token`, `refresh_token` and `valid_until`;
  - **typed login:** 201 only;
  - **a declaration:** overrides the inferred schema;
  - **a plain responder:** `"Defined by the application."` and no content;
  - **refusals:** they include 400, 401 and 429 with no content;
  - **`WithErrorBody[Problem]("application/problem+json")`:** applies to every refusal;
  - **the hook:** sets a description that is served, and an error from it is returned;
  - **begin data:** an undescribed method gives no schema;
  - **an unknown operation:** `WithResponse` naming `scrty.lgoin` is an error naming it (Review Focus).
- [ ] **Step 2: Run** it. Expected: FAIL.
- [ ] **Step 3: Implement** `responses.go` with the Global Constraints' precedence.
- [ ] **Step 4: Run** `go test -race -count=1 ./...` in the module. Expected: PASS.
- [ ] **Step 5: Commit** `feat(openapisec): responses, refusals and the document hook`.

### Task 9: Serving (tasks.md 7.1)

**Interfaces:**

```go
func Enable(opts ...Option) httpsec.Option // RegisterInterceptor at httpsec.OrderOpenAPI
func WithPath(p string) Option              // relative to the base path; refused by Build
```

- The endpoint implements `httpsec.BuildHook`. It builds the bytes, computes the `ETag`, and resolves its path against the base. It then checks that path against `c.Endpoints()` from their exported `Path` and `Match`: it collides with an exact path equal to it, or with a segment or subtree endpoint whose prefix it lies under or equals, with or without the trailing slash. The core's unexported check is not reachable from the module.

- [ ] **Step 1: Write the failing test.** `TestEnable` checks that:
  - `GET` and `HEAD` at `/auth/openapi.json` answer 200;
  - `/openapi.json` passes through;
  - an expired bearer and a deny-all rule set still get 200;
  - repeated responses carry identical bytes and the same `ETag`;
  - `If-None-Match` with the tag, with `W/"<tag>"` or with `*` gets 304 and no body;
  - a POST passes through;
  - `WithPath("/spec.json")` serves `/auth/spec.json`;
  - `WithPath("/login")` beside form login fails `New`, naming both;
  - a hook error fails `New`;
  - `Build` returns identical bytes;
  - nothing is served without `Enable`;
  - two chains serve their own documents (Review Focus).
- [ ] **Step 2: Run** it. Expected: FAIL.
- [ ] **Step 3: Implement** `enable.go`. Add `ExampleEnable`, and write the README section covering the tiers, `WithErrorBody`, and the optional `jsonschema` tag convention.
- [ ] **Step 4: Run** `go test -race -count=1 ./...` in the module, including the example. Expected: PASS.
- [ ] **Step 5: Commit** `feat(openapisec): serve the document`.

### Task 10: Optional describing interfaces (tasks.md 4.1)

**Interfaces:**

```go
// authenticate/mfa
type BeginDataDescriber interface{ BeginDataType() reflect.Type }

// authenticate/passkey
type OptionsDescriber interface {
    CreationOptionsType() reflect.Type
    RequestOptionsType() reflect.Type
}
```

- [ ] **Step 1: Write the failing test.** A challenge method implementing `BeginDataDescriber` makes `scrty.mfa.begin`'s 200 `Body` its type. One that does not leaves `Unknown: true`. The same applies to the passkey register begin and the passwordless begin through `OptionsDescriber`.
- [ ] **Step 2: Run** `go test -race -count=1 ./authenticate/mfa/... ./authenticate/passkey/... ./httpsec/`. Expected: FAIL.
- [ ] **Step 3: Implement** the interfaces, and the type assertions in the begin descriptors. The godoc says both are optional.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(mfa,passkey): methods may describe their begin data`.

### Task 11: The WebAuthn descriptions (tasks.md 4.2)

- [ ] **Step 1: Write the failing test.** `TestVerifier_DescribesOptions`, with no new dependency:
  - the verifier asserts as `passkey.OptionsDescriber`;
  - the creation options it renders for a user decode into a new value of `CreationOptionsType()` through a `json.Decoder` with `DisallowUnknownFields`, without error, and likewise the request options into `RequestOptionsType()`;
  - the request-options type has a field whose JSON name is `challenge` and which is not `omitempty`.
- [ ] **Step 2: Run** `go test -race -count=1 ./...` in `authenticate/passkey/webauthn`. Expected: FAIL.
- [ ] **Step 3: Implement** both methods, returning the reflected types of the inner option structs the verifier marshals. The exported API names only `reflect.Type`.
- [ ] **Step 4: Run** the module's tests and `go test -run 'TestLayout' .` at the root. Expected: PASS.
- [ ] **Step 5: Commit** `feat(webauthn): describe creation and request options`.

### Task 12: Validation (tasks.md 8.1)

- [ ] **Step 1: Write the tests** in `test/openapi`:
  - `TestDocumentsValidate` builds a minimal chain, a chain with every built-in, and the same under `/auth`, and validates each with `libopenapi` as OpenAPI 3.1;
  - `TestDefaultOutputsMatchSchemas` drives each default responder and validates its body against the reflected schema.
- [ ] **Step 2: Red step.** Temporarily drop `required` from the login document's schema mapping. `TestDefaultOutputsMatchSchemas` must fail. Then restore it.
- [ ] **Step 3: Run** `go test -race -count=1 ./...` in `test`. Expected: PASS.
- [ ] **Step 4: Commit** `test(openapi): generated documents validate`.

### Task 13: Conformance (tasks.md 8.2)

- [ ] **Step 1: Write the scenario.** `OpenAPIServedUnderBasePath`, on net/http, gin and fiber: 200 with an `ETag` at `/auth/openapi.json`, then 304 on `If-None-Match`, and `/openapi.json` passing through.
- [ ] **Step 2: Run** `go vet ./...` and `go test -race ./...` in `test`. Expected: PASS. Show the red step by registering the scenario before `Enable` is wired, and watching it fail.
- [ ] **Step 3: Commit** `test(conformance): the OpenAPI document on every adapter`.

### Task 14: The gate (tasks.md 9.1)

- [ ] **Step 1: Run the gate.**
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module from `go list -m`;
  - `gofmt -l`;
  - `openspec validate openapi-document --strict`.
- [ ] **Step 2: Check the results.** Every command exits 0. The main session records the output and ticks 9.1.
