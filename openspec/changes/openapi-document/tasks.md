# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor with the suite green. Table tests follow the project's `table-test` skill; test doubles come from `use-mockgen`.

## 1. Core seams (`http-security-chain`)

- [ ] 1.1 A hook for an interceptor that needs the assembled chain, and the document's named slot:
  - `BuildHook`: an interceptor registered with `RegisterInterceptor` that implements it is called once in `New`, after paths are resolved and the endpoint list is built, in slot order;
  - an error from it fails `New` and returns no chain;
  - `OrderOpenAPI` lies between `OrderJWKS` and `OrderOIDC`;
  - tests: the hook sees the login endpoint in `Endpoints()`, is called exactly once, and an error from it returns a nil chain; a table checks the slot order.

  (D1, D2; "A registered interceptor can finish building once the chain is assembled", "The document endpoint has a named slot", every scenario.) Verify with `go test -race -count=1 -run 'TestBuildHook|TestOrderOpenAPI' ./httpsec/`

## 2. Endpoint descriptions (`http-security-chain`)

- [ ] 2.1 Extend each inventory entry with its request, success responses, refusals and security schemes, for form login, logout, the key set, session renewal, the password-change endpoint and magic link:
  - **requests:** the media types each accepts and the field names it reads, as configured;
  - **responses:** the status, and the Go type of the default responder's document struct;
  - **refusals:** the sentinels each can return, each with `StatusForError`'s status;
  - tests: login's default description (form and JSON, `username` and `password`, 200 with the login document, refusals including 401), and login with renamed fields.

  (D5, D7, D8; "The endpoint list describes requests, responses and refusals", scenario "Default login description".) Verify with `go test -race -count=1 -run 'TestEndpointDescriptions' ./httpsec/`
- [ ] 2.2 The same for MFA (verify, begin, listing), enrolment and re-authentication. A begin step's response type is "owned by the method" (Task 4.1). (D5, D7, D8, D9.) Verify with `go test -race -count=1 -run 'TestEndpointDescriptions' ./httpsec/`
- [ ] 2.3 The same for passkeys, recovery (including the codes count and regeneration) and OIDC. The OIDC callback's response is a redirect with no body. (D5, D7, D8.) Verify with `go test -race -count=1 -run 'TestEndpointDescriptions' ./httpsec/`
- [ ] 2.4 Guard the refusal lists against drift. A test helper wraps each built-in's existing refusal table tests and asserts that every status a test observes is one the endpoint declares. Show the red step by removing one declared refusal and watching its endpoint's refusal test fail, then restore it. (D10.) Verify with `go test -race -count=1 ./httpsec/`

## 3. Typed JSON responders (`http-security-chain`)

- [ ] 3.1 Add the typed form for login, renewal, MFA verification, the MFA listing (a `ListingSetting`), re-authentication and its methods listing, and magic link. Each is `With<Responder>JSONResponse[T](status int, fn func(*Exchange, R) (T, error))`, named after the plain option it stands beside (`WithLoginJSONResponse`, `WithRenewalJSONResponse`, `WithMFAJSONResponse`, `ListingJSONResponse`, `WithReauthenticationJSONResponse`, `WithReauthenticationMethodsJSONResponse`, `WithMagicLinkJSONResponse`). Each:
  - writes `T` as JSON with the given status and `Content-Type: application/json`;
  - propagates the function's error unchanged and writes nothing;
  - records `T` as the endpoint's response type for that status;
  - refuses a status outside 200–299 at construction.

  Tests cover each spec scenario ("Typed login response", "The typed function refuses") for one of these, and a table checks every option's recorded type. (D6; "Each JSON responder has a typed form".) Verify with `go test -race -count=1 -run 'TestJSONResponse' ./httpsec/`
- [ ] 3.2 The same for recovery and its hold, the recovery codes and the count, and the passkey list, rename, remove and registration (`WithRecoveryJSONResponse`, `WithRecoveryHoldJSONResponse`, `WithRecoveryCodesJSONResponse`, `WithRecoveryCountJSONResponse`, `WithPasskeyListJSONResponse`, `WithPasskeyRenameJSONResponse`, `WithPasskeyRemoveJSONResponse`, `WithPasskeyRegistrationJSONResponse`). Each option's godoc names the default it replaces. (D6.) Verify with `go test -race -count=1 -run 'TestJSONResponse' ./httpsec/`

## 4. Methods that describe their data (`multi-factor-auth`, `passkey-authentication`)

- [ ] 4.1 Add optional describing interfaces:
  - an `mfa.ChallengeMethod` may describe its begin data;
  - a `passkey.Verifier` may describe its creation and request options;
  - the core reads them only through optional interface assertions, so a method or verifier without one behaves exactly as before;
  - tests: a method with and without a description, and the begin endpoint's response type in each case.

  (D9; `multi-factor-auth` "A challenge method may describe its begin data", `passkey-authentication` "A passkey verifier may describe its options".) Verify with `go test -race -count=1 ./authenticate/mfa/... ./authenticate/passkey/... ./httpsec/`
- [ ] 4.2 Implement the descriptions in `authenticate/passkey/webauthn` for creation and request options:
  - the rendered options validate against the description;
  - the request options require `challenge`;
  - the module's exported API still names no type of the WebAuthn library, and the existing layout check stays green.

  (D9; `passkey-authentication` "The WebAuthn verifier describes its options", every scenario.) Verify with `go test -race -count=1 ./...` in `authenticate/passkey/webauthn`, and `go test -run 'TestLayout' .` at the root

## 5. The nested module (`module-layout`)

- [ ] 5.1 Create the module `github.com/kartaladev/scrty/httpsec/openapisec` (package `openapisec`):
  - it requires the root module and `github.com/invopop/jsonschema`, and `go.work` lists it;
  - the layout guard (`layout_guard_test.go`) adds it to the listed integrations and adds `github.com/invopop/jsonschema` to the modules the core must not require;
  - the exported-API check covers `openapisec` against `github.com/invopop/`.

  Red step: the guard's new rows fail before the module and the lists exist. (`module-layout` "The core module does not require the OpenAPI reflector", every scenario; "Integration modules are published under the concept they extend".) Verify with `go test -count=1 -run 'TestLayout' .` at the root and `go build ./...` in `httpsec/openapisec`

## 6. Building the document (`openapi-document`)

- [ ] 6.1 The document model and schema reflection:
  - the write-only model covers what D4 lists;
  - reflection with invopop places named types under `components/schemas` and refers to them by `$ref`;
  - every reflected schema is checked, and an undescribable type fails with an error naming the operation and the type;
  - tests: a recursive type refers back to its component, a tagged enumeration appears, a channel field is refused.

  (D4, D5; "Response types are reflected faithfully or refused", every scenario.) Verify with `go test -race -count=1 ./...` in `httpsec/openapisec`
- [ ] 6.2 `Build(chain, ...)` from the endpoint list:
  - one operation per endpoint and method, at its resolved path, with its `operationId` and feature tag;
  - path parameters enumerating the configured methods and providers;
  - request bodies from the descriptions;
  - security schemes and per-operation security from the enabled authenticators;
  - `openapi: 3.1.2`;
  - default `info` (`Security endpoints`, `1`) and no servers;
  - `WithInfo` and `WithServer`.

  Tests cover each spec scenario of "The document describes exactly the enabled built-in endpoints", "Requests are described as configured", "Security requirements follow the enabled authenticators", "The document is OpenAPI 3.1.2" (version only; validity is 8.1) and "Document metadata has neutral defaults". (D3, D4, D8.) Verify with `go test -race -count=1 ./...` in `httpsec/openapisec`
- [ ] 6.3 Responses and refusals:
  - default schemas from the recorded document types, and typed responses from their recorded types;
  - `WithResponse[T](operationID, status)` replacing both;
  - a plain responder with nothing declared gives the status with no schema and the "defined by the application" description;
  - every refusal status with no content, or with the `WithErrorBody[T](mediaType)` schema;
  - begin data from a method's description;
  - `WithCustomizer` applied last, its error returned;
  - precedence: hook, then declaration, then typed form, then default.

  Tests cover each spec scenario of the response, refusal, hook and begin-data requirements. (D6, D7, D9.) Verify with `go test -race -count=1 ./...` in `httpsec/openapisec`

## 7. Serving it (`openapi-document`)

- [ ] 7.1 `Enable(...)` registers the endpoint at `OrderOpenAPI`:
  - it builds the document in its `BuildHook`, so a failure fails `New`;
  - it answers GET and HEAD at `/openapi.json` joined to the base path, relocatable with `WithPath` within the base;
  - responses carry a strong `ETag`, and a matching `If-None-Match` gets 304 with no body;
  - it is never refused by a stale credential or a deny-all rule set;
  - `Build` on the same configuration returns identical bytes;
  - nothing is served without `Enable`.

  Tests cover each spec scenario of "The document is opt-in", "The document is served publicly under the base path", "The document is built once, at construction" and "The document can be built without serving it". An `ExampleEnable` shows a chain serving its document. A README section covers the document, its tiers, `WithErrorBody`, and the optional `jsonschema` struct-tag convention for consumer types. (D1, D2.) Verify with `go test -race -count=1 ./...` in `httpsec/openapisec`, including the example

## 8. Validation and conformance (`test` module)

- [ ] 8.1 In `test`, validate the generated documents with `github.com/pb33f/libopenapi`: a minimal chain, a chain with every built-in enabled, and the same under the base `/auth`. Each default responder's real output is validated against its reflected schema. Show the red step by temporarily breaking one default schema (dropping a required property) and watching the output check fail. (D10; "The document is OpenAPI 3.1.2" scenario "Version and validity", "Default responses are described from what the library writes".) Verify with `go test -race -count=1 ./...` in `test`
- [ ] 8.2 `test/httpsecconformance` scenarios on net/http, gin and fiber: the document is served at `/auth/openapi.json` with 200 and an `ETag`, a repeat with `If-None-Match` gets 304, and `/openapi.json` passes through. Verify with `go vet ./...` and `go test -race ./...` in `test`

## 9. Close-out

- [ ] 9.1 Run the whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`, `httpsec/openapisec` included;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate openapi-document --strict`.

  Verify that every command exits 0 and record its output.

## Workflow follow-up

- Implementation starts after `endpoint-inventory-base-path` is merged. It can run beside `observability`.
- Run one whole-branch review against every spec requirement this change covers before the final gate and before archive.
- If `release-readiness` has fixed the list of lockstep-tagged modules by then, add `httpsec/openapisec` to it.
- At archive, update `openspec/config.yaml`:
  - `httpsec/openapisec` joins the Layout integrations;
  - `openapi-document` joins the capability map.
- `observability` also modifies `module-layout`'s requirement "Integration modules are published under the concept they extend". Whichever change archives second rebases its copy of that requirement onto the archived one first, so neither overwrites the other's module.
