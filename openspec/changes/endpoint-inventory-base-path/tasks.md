# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor with the suite green. Table tests follow the project's `table-test` skill; test doubles come from `use-mockgen`.

## 1. Reproduce the OIDC redirect gap (`oidc-login`)

- [ ] 1.1 Write the reproducing test for D5 in `httpsec`:
  - a chain enables OIDC login, moves the callback path with `WithOIDCCallbackPath("/sso/callback/")`, and registers provider `corp` whose redirect URL still ends in `/login/oauth2/callback/corp`;
  - the test expects `New` to fail with a configuration error;
  - name it after the behaviour, for example `TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback`.

  Run it and record the failing output, which shows `New` accepting the chain. If it passes on the current code, the gap was wrong: remove D5 and the `oidc-login` delta, and record that in `design.md`. The test stays red until 5.2. (D5; `oidc-login` "A provider's redirect URL must reach the callback path", scenario "Callback path moved without the redirect URL".) Verify with `go test -run 'TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback' -count=1 ./httpsec/`

## 2. Base path and path resolution at assembly (`http-security-chain`)

- [ ] 2.1 `WithBasePath` and its validation. A table test over:
  - an empty value, `/`, `auth`, `/auth/../admin` and `/auth//x`, each refused with a configuration error naming `WithBasePath`;
  - `/auth/`, accepted as `/auth`;
  - no base path, which leaves every path unchanged.

  (D1; "An unusable base path fails at construction", every scenario.) Verify with `go test -race -count=1 -run 'TestWithBasePath' ./httpsec/`

- [ ] 2.2 Resolve the paths of login, logout, the key set, session renewal and the password-change endpoint at assembly, joined to the base path:
  - each interceptor keeps the path its option declared and resolves it in `New`, after every option has run;
  - a table test per endpoint checks that with the base `/auth` it answers under `/auth` and the unprefixed path passes through to the handler;
  - with a consumer path (`WithLoginRequestPath("/signin")`) it answers `/auth/signin`;
  - the base option given after the `Enable*` options gives the same result;
  - the existing tests of these endpoints stay green unchanged, since with no base path every path is today's.

  (D1, D2; "Built-in endpoints answer under an optional base path", scenarios "No base path", "Base path moves the defaults", "Consumer path within the base", "Option order does not matter".) Verify with `go test -race -count=1 ./httpsec/`

- [ ] 2.3 Resolve at assembly the MFA verify and begin prefixes, the MFA method listing path and the three enrolment prefixes. Same tests as 2.2, including the `{method}` segment under `/auth/mfa/verify/`. (D1.) Verify with `go test -race -count=1 ./httpsec/`
- [ ] 2.4 Resolve at assembly the passkey registration, credentials and passwordless prefixes, the two magic-link paths and the five recovery paths:
  - same tests as 2.2;
  - one test checks that the emailed magic link still points at the confirm page given to `magiclink.New` while the consume endpoint answers at `/auth/login/magic/consume`.

  (D1, D2; "The base path covers only the endpoints the chain answers", scenario "Emailed sign-in link unchanged".) Verify with `go test -race -count=1 ./httpsec/`
- [ ] 2.5 Resolve at assembly the re-authentication prefix and the four OIDC paths:
  - same tests as 2.2;
  - one test checks that the OIDC flow cookie's `Path` is the resolved callback path;
  - one test checks that an authorization rule for `GET /projects/{id}` still judges `/projects/42` under the base `/auth`.

  (D1, D2; "The base path covers only the endpoints the chain answers", scenario "Authorization rules keep the consumer's paths".) Verify with `go test -race -count=1 ./httpsec/`
- [ ] 2.6 Document the base path:
  - godoc on `WithBasePath` names the default (none), what it covers, and what it does not: consumer pages, authorization rules, consumer interceptors, a prefix a proxy already strips;
  - the godoc of every per-feature path option says the path is relative to the base path;
  - the magic-link godoc tells the confirm page (not moved) from the consume endpoint (moved);
  - an `ExampleWithBasePath` shows login answering under `/auth`;
  - a README section covers the base path, the list of what does not move, and the migration steps (OIDC redirect URLs, the key set's URL).

  Verify that `go test -run 'ExampleWithBasePath' ./httpsec/` passes and that `go doc ./httpsec WithBasePath` shows the default and the exclusions.

## 3. The endpoint inventory (`http-security-chain`)

- [ ] 3.1 Add `Endpoint`, `PathMatch`, `SessionState` and `(*Chain).Endpoints()`:
  - every path-answering built-in declares its endpoints through an unexported method, and `New` collects them after resolution, in slot order and then registration order;
  - operation identifiers follow D3 (`scrty.login`, `scrty.mfa.verify`, ...) and are listed in the godoc;
  - tests cover each spec scenario:
    - enabled endpoints listed with resolved paths under `/auth`;
    - disabled ones absent;
    - a consumer interceptor answering `/status` absent;
    - a caller modifying the returned slice does not change a fresh list or a later request;
    - identical operation identifiers with and without a base path.

  (D3; "The chain lists the endpoints it answers", every scenario.) Verify with `go test -race -count=1 -run 'TestChainEndpoints' ./httpsec/`
- [ ] 3.2 Add the drift guard. A test builds a chain with every built-in enabled, under the base `/auth`, and sends each inventoried method and path (with a sample segment where the path reads one). It asserts that the request is answered by its endpoint and never reaches the handler. Show the red step by temporarily dropping one endpoint's declaration and watching this test fail, then restore it. (D3; Risks: "an endpoint matches a path it does not declare".) Verify with `go test -race -count=1 -run 'TestChainEndpoints_EveryEntryIsAnswered' ./httpsec/`

## 4. One collision check over the resolved paths (`http-security-chain`)

- [ ] 4.1 Check every pair of inventoried endpoints in `New`, after resolution:
  - two endpoints that would both answer some request path, given how each matches (exact, one segment, or everything beneath), fail with a configuration error naming both options and both paths;
  - endpoints of the same option on one path with different methods do not collide;
  - an exact path equal to another endpoint's prefix, with or without its trailing slash, collides;
  - tests cover each spec scenario: two features on `/signin`, a re-authentication password path under the MFA verify prefix, recovery codes' GET and POST on one path accepted, and `/login` set as the logout path under the base `/auth`.

  (D4; "Colliding endpoint paths fail at construction", every scenario.) Verify with `go test -race -count=1 -run 'TestChainPathCollisions' ./httpsec/`
- [ ] 4.2 Replace `reauthInterceptor.checkPaths` and `oidcInterceptor.checkPaths` with the shared check, keeping behaviour:
  - their collision tests (in `reauth_test.go`, `oidc_options_test.go` and `magiclink_options_test.go`) move to the shared check's table with their assertions unchanged, except for the error wording, which now names both options;
  - OIDC's own rule that the handoff path must not name one of its prefixes, with or without the trailing slash, is kept as a declaration the shared check enforces.

  Red step: temporarily make the shared check skip one pair and watch a moved case fail, then restore it. (D4.) Verify with `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`

## 5. The OIDC redirect path check (`oidc-login`)

- [ ] 5.1 In `authenticate/oidc`, give `RelyingParty` read access to each registered provider's redirect URL, alongside `Providers()`. A test registers two providers and reads both URLs back, and checks that an unknown name reports none. (D5.) Verify with `go test -race -count=1 ./authenticate/oidc/`
- [ ] 5.2 Check at chain assembly that each provider's redirect URL path ends with the resolved callback path followed by its name, and add `WithoutOIDCRedirectPathCheck()`:
  - 1.1's test turns green;
  - tests cover each spec scenario: a matching URL, the base `/auth` not reflected in the URL (the error names `corp`, the URL path and the expected path), a prefix-stripping proxy URL accepted, and the waiver accepting `https://example.com/cb?p=corp`;
  - existing OIDC test fixtures and examples whose redirect URLs do not match their callback path are corrected, and each correction is listed in the report;
  - godoc on the option states what the waiver gives up.

  (D5; `oidc-login` "A provider's redirect URL must reach the callback path", every scenario.) Verify with `go test -race -count=1 ./httpsec/ ./authenticate/oidc/` and `go test ./...` in the `test` module

## 6. Adapters and conformance

- [ ] 6.1 Add base-path scenarios to `test/httpsecconformance`, run on net/http, gin and fiber:
  - login and the key set answer under `/auth` and their unprefixed paths pass through;
  - an authorization rule keeps judging the consumer's own path;
  - a chain with no base path answers a request whose prefix a proxy removed.

  Each scenario mirrors a spec scenario. ("Built-in endpoints answer under an optional base path", scenario "Every adapter answers the same paths"; "The base path covers only the endpoints the chain answers", scenario "Prefix stripped before the chain".) Verify with `go vet ./...` and `go test -race ./...` in the `test` module

## 7. Close-out

- [ ] 7.1 Run the whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate endpoint-inventory-base-path --strict`.

  Verify that every command exits 0 and record its output.

## Workflow follow-up

- Implementation starts after `reauthentication` is archived, on a new branch from `main`, so the `/reauth` endpoints are in the inventory from the start.
- Run one whole-branch review against every spec requirement this change covers before the final gate and before archive.
- At archive, update `openspec/config.yaml`:
  - in the capability map, this change appears under follow-ups with `http-security-chain` and `oidc-login`;
  - in the context, the base-path rule joins "HTTP and errors".
- `openapi-document` and `observability` start after this change is merged.
