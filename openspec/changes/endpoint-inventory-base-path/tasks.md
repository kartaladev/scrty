# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor with the suite green. Table tests follow the project's `table-test` skill; test doubles come from `use-mockgen`. Every task also follows `defensive-coding.md`: the failure modes `design.md` lists for its decisions are each tested or handled as that table says.

## 1. Reproduce the OIDC redirect gap (`oidc-login`)

- [x] 1.1 Write the reproducing test for D10 in `httpsec`:
  - a chain enables OIDC login, moves the callback path with `WithOIDCCallbackPath("/federation/callback/")`, and registers provider `corp` whose redirect URL still ends in the old default callback path followed by `corp`;
  - the test expects `New` to fail with a configuration error;
  - name it after the behaviour, for example `TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback`.

  Run it and record the failing output, which shows `New` accepting the chain. If it passes on the current code, the gap was wrong: remove D10 and the `oidc-login` ADDED requirement, and record that in `design.md`. The red test is recorded but not merged, so the suite stays green for every later task; it lands with 7.2, which turns it green. (D10; `oidc-login` "A provider's redirect URL must reach the callback path", scenario "Callback path moved without the redirect URL".) Verify with `go test -run 'TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback' -count=1 ./httpsec/`

## 2. One path shape and the new defaults (`http-security-chain`, `passkey-authentication`, `multi-factor-auth`, `reauthentication`)

- [x] 2.1 Apply one shape rule to every path setting, in all four forms (`With*Path`/`With*Prefix`, `WithOIDCProviderPath`, the `SessionSignals.Path` field and the `ListingPath` setting, `WithPasswordChangeEndpoint`):
  - a table test per form over `signin`, `/`, `/a/../b`, `/a//b`, `/session/sig nals`, `/a%20b` and `/a?b`, each refused with a configuration error naming the setting;
  - a trailing slash on a prefix is accepted (`/federation/callback/`), and on the signal stream path (`/session/signals/`);
  - a provider path holding `:` or `@` is refused (D13 lists both changes);
  - the per-option checks it replaces are removed, and their tests move to the table.

  (D4; "Every endpoint path has one shape", every scenario.) Verify with `go test -race -count=1 -run 'TestEndpointPathShape' ./httpsec/`
- [x] 2.2 Change the default constants and suffixes to D3's table in `httpsec` (`reauth.go`'s begin suffix included) and the magic-link confirm page default in `authenticate/magiclink` (`links.go`, and its godoc in `links_options.go`):
  - red step: a table test that enables each built-in with defaults and asserts it answers at D3's path and that the old default passes through; run it and see every renamed row fail;
  - update every test, example and doc comment that names a default path: `httpsec`, `httpsec/ginsec`, `httpsec/fibersec`, `authenticate/magiclink`, `authenticate/oidc` (`doc.go`, `example_test.go`), `authenticate/passkey/example_test.go` and `policy/example_test.go`, using the constants where the literal is not the point;
  - update every old default path in `README.md`.

  (D3; "Built-in endpoints have documented default paths", every scenario; the MODIFIED default-path requirements of `http-security-chain`, `passkey-authentication`, `multi-factor-auth` and `reauthentication`.) Verify with `go test -race -count=1 ./httpsec/... ./authenticate/magiclink/...`
- [x] 2.3 Update `test/httpsecconformance` scenarios, `csrf-protection`, `framework-adapters` and `sender-constrained-tokens` tests that name a default path, so each mirrors its MODIFIED scenario, and the Keycloak test realm (`test/testdata/keycloak/realm.json`), whose registered redirect URIs end in the old callback path. Verify with `go vet ./...` and `go test -race ./...` in the `test` module.

## 3. Base path and resolution before validation (`http-security-chain`)

- [x] 3.1 `WithBasePath` and its refusals. A table test over:
  - `/`, `auth`, `/auth/../admin`, `/auth%20x`, each refused naming `WithBasePath`;
  - `/auth/`, accepted as `/auth`;
  - a base path on a chain that answers no built-in endpoint, refused;
  - `/auth` with `WithLoginRequestPath("/auth/sign-in/password")`, refused naming the option and `/auth/auth/sign-in/password`; `/api` with key set path `/api-keys`, accepted at `/api/api-keys`;
  - given twice, the last wins.

  (D1, D5; "An unusable base path fails at construction", "A path that repeats the base path fails at construction", "Built-in endpoints answer under an optional base path" scenario "Given twice".) Verify with `go test -race -count=1 -run 'TestWithBasePath' ./httpsec/`
- [x] 3.2 Add the resolution step to `New`, between the option loop and `validate`, and resolve password sign-in, logout, the key set, session renewal, the password-change endpoint, the signal stream and session management:
  - each interceptor keeps its declared path and resolves it in the new step;
  - per endpoint: with `/auth` it answers under `/auth` and the unprefixed path passes through; a consumer path (`/signin`) answers `/auth/signin`; the base option given after the `Enable*` options gives the same result;
  - existing tests stay green, since with no base path every path is unchanged.

  (D1, D2; "Built-in endpoints answer under an optional base path", scenarios "No base path", "Base path moves the defaults", "Consumer path within the base", "Option order does not matter".) Verify with `go test -race -count=1 ./httpsec/`
- [x] 3.3 Resolve the MFA challenge, verify and listing paths, the three enrolment prefixes, the passkey registration, list and passwordless paths, the two magic-link paths and the five recovery paths. Same tests as 3.2, including `{method}` under `/auth/mfa/verify/`, and one test that the emailed link still points at the confirm page while redemption answers at `/auth/sign-in/magic-link/redeem`. (D1, D2; "The base path covers only the endpoints the chain answers", scenario "Emailed sign-in link unchanged".) Verify with `go test -race -count=1 ./httpsec/`
- [x] 3.4 Resolve the re-authentication prefix and the four OIDC login paths. Same tests as 3.2, and one test that an authorization rule for `GET /projects/{id}` still judges `/projects/42` under `/auth`. (D1, D2; scenario "Authorization rules keep the consumer's paths".) Verify with `go test -race -count=1 ./httpsec/`
- [x] 3.5 Resolve the provider's prefix and per-endpoint overrides, relative to the base, and move `settlePaths` and `routers` after resolution:
  - the token endpoint answers at `/auth/oauth2/token`, and with `WithOIDCProviderPath(OIDCToken, "/tokens")` at `/auth/tokens`;
  - with issuer `https://id.example.com/auth`, `token_endpoint` and `jwks_uri` name the moved paths, the OpenID configuration answers at `/auth/.well-known/openid-configuration` and the authorization server metadata at `/.well-known/oauth-authorization-server/auth`;
  - the provider options given before `WithBasePath` give the same result;
  - an authorization request needing a sign-in is sent to the consumer's login page unchanged.

  (D1, D2; "The base path covers only the endpoints the chain answers", scenario "Provider pages unchanged"; "The provider's paths are replaceable and published as used" MODIFIED, every scenario; "The public key set is served" scenario "Under a base path"; `oidc-provider-metadata` "A base path does not move the metadata documents".) Verify with `go test -race -count=1 ./httpsec/`
- [x] 3.6 Derive every path-derived value from resolved paths, one test each under `/auth`:
  - a session owing a second factor, an enrolment-only session, a session owing a password change and a recovery-pending session can each post to `/auth/sign-out`;
  - the recovery gate's enrolment and passkey exemptions follow the moved paths;
  - the cross-site layer exempts `/auth/sso/backchannel-logout/{p}` and the provider's POST endpoints; the provider's CORS scope covers `/auth/oauth2/...`;
  - the provider's POST bounce URLs, DPoP URL check and assertion audience check use the moved paths;
  - the OIDC flow cookie, passkey ceremony cookie and magic-link binding cookie are scoped to the moved paths;
  - a GET to `/auth/session/signals` records no session activity.

  (D11; "Values derived from an endpoint path follow it", every scenario.) Verify with `go test -race -count=1 ./httpsec/`

## 4. The endpoint inventory (`http-security-chain`)

- [x] 4.1 Add `Endpoint`, `PathMatch`, `MethodPolicy`, `Requirement` and `(*Chain).Endpoints()`:
  - every path-answering built-in declares one entry per operation, with D6's operation identifier, `PlacedBy` and `Requires`; `New` collects them after resolution, in slot order and then registration order;
  - the discovery documents are listed at the paths they are served on;
  - tests cover each spec scenario: enabled endpoints under `/auth`, disabled ones absent, discovery entries, two entries on the recovery codes path, a consumer interceptor on `/status` absent, a modified returned slice or entry `Methods` not affecting a fresh list or a later request, identical identifiers with and without a base path;
  - a table pins every operation's identifier, methods, match, other-method policy and `Requires`.

  (D6; "The chain lists the endpoints it answers", every scenario but "Every entry is answered".) Verify with `go test -race -count=1 -run 'TestChainEndpoints' ./httpsec/`
- [x] 4.2 Add the drift guard. A test builds a chain with every built-in enabled under `/auth` (the provider's prerequisites included), and for each entry:
  - sends each listed method and path, with a sample segment where the path reads one, and asserts its endpoint answers and the handler is not reached;
  - sends a near-miss (a sibling path), the parent path and an unlisted method, and asserts each passes through or is refused as the entry's other-method policy says;
  - cancels the signal stream's request so the test does not hang.

  Red step: temporarily drop one declaration and watch the guard fail, then restore it. (D6, D11; scenario "Every entry is answered".) Verify with `go test -race -count=1 -run 'TestChainEndpoints_EveryEntryIsAnswered' ./httpsec/`

## 5. One collision check over the inventory (`http-security-chain` and the MODIFIED collision requirements)

- [x] 5.1 Check every pair of inventoried operations in `New`, after resolution:
  - collisions by match kind, with `Match` applied to the path before its first `{…}` segment; a path claimed for every method by an endpoint that answers 405; the exact-versus-prefix rule across features; sharing only within one feature, by matching `SharesPath` with different methods or exact beside one-segment;
  - the error names both settings, both paths and what the collision would break; the first colliding pair in inventory order is reported;
  - tests cover each spec scenario: two features on `/signin`, re-authentication under the MFA verify prefix, MFA challenge and verify on `/mfa/step`, password sign-in on `/oauth2/token` beside the provider, recovery codes shared, default session management and default consents built, two provider overrides on `/oauth2/me` refused, logout under the MFA verify prefix with its explanation, and the key set on the OpenID configuration's path under `/auth`.

  (D7; "Colliding endpoint paths fail at construction", every scenario.) Verify with `go test -race -count=1 -run 'TestChainPathCollisions' ./httpsec/`
- [x] 5.2 Retire the collision checks in `mfa_options.go`, `mfa_verify.go`, `mfa_enrol.go`, `passkey.go`, `recovery.go`, `session_renewal.go` and `magiclink.go`:
  - their tests in `mfa_options_test.go`, `mfa_enrol_options_test.go`, `mfa_verify_test.go`, `passkey_login_test.go`, `passkey_register_test.go`, `recovery_options_test.go`, `session_renewal_test.go`, `magiclink_options_test.go`, `logout_test.go` and `password_change_test.go` move to 5.1's table, assertions kept except the error wording;
  - red step: temporarily make the shared check skip one moved pair and watch its case fail, then restore it.

  (D7; `passkey-authentication` "Passkey wiring mistakes fail at construction", `account-recovery` "Recovery is off by default, and its wiring mistakes fail at construction", `http-security-chain` "An opt-in endpoint lists the methods a pending session can use", each MODIFIED.) Verify with `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`
- [x] 5.3 Retire the collision checks in `signals.go`, `reauth_options.go` (`checkPaths`, `claimedPaths`, `collides`), `oidc_options.go` and `oidc_provider.go` (`settlePaths` and `routers` duplicate refusals, `checkCollisions`, `checkConsentSubtree`, `oidcForeignPaths`, `oidcForeignPrefixes`):
  - their tests in `signals_construction_test.go`, `reauth_test.go`, `oidc_options_test.go` and `oidc_provider_test.go` move to 5.1's table;
  - every changed verdict in D13 gets its own row, among them a re-authentication prefix of `/passkeys/register` now built, listed in the report;
  - same red step as 5.2.

  (D7; `reauthentication`, `oidc-login`, `oidc-logout` and `http-security-chain` "Provider wiring mistakes fail at construction", each MODIFIED.) Verify with `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`

## 6. Checks for a base path's reach (`http-security-chain`)

- [x] 6.1 Refuse an issuer that does not cover the base path, and add `WithoutOIDCIssuerBasePathCheck()`:
  - tests cover each spec scenario: root issuer refused, issuer at the base, with a trailing slash, deeper than the endpoints refused, an endpoint override outside the issuer's path refused, and the waiver with the OpenID configuration at the root and `token_endpoint` under `/auth`;
  - one test pins that the waiver with a root issuer and a provider built with `AudienceIssuerOrTokenEndpoint` is refused by the existing assertion endpoint check.

  (D8; "Under a base path the provider's issuer must cover it", every scenario; "Provider wiring mistakes fail at construction" scenario "Issuer outside the base path".) Verify with `go test -race -count=1 -run 'TestOIDCProvider_IssuerBasePath' ./httpsec/`
- [x] 6.2 Refuse consumer routes left at a pre-base endpoint path, and add `WithoutBasePathRouteCheck()`:
  - covers recovery cool-down routes and `WithCSRFExemption` routes, each compared in its own matcher's normal form (cool-down lower-cased and trailing-slash-trimmed; exemption patterns with `*` segments); "lies under" only for subtree and segment endpoints;
  - tests cover each spec scenario: a cool-down route at `/reauth/password` under `/auth` refused, `/Reauth/Password/` refused, the same route at `/auth/reauth/password` applied, the waiver accepting a cross-site exemption at `/sign-in/password`; plus a cross-site exemption pattern `/sso/*/x` refused under `/auth`;
  - `WithHeaderProfile`'s godoc states that its matcher is not checked.

  (D9; "A consumer route naming a moved endpoint fails at construction", every scenario.) Verify with `go test -race -count=1 -run 'TestBasePathRouteCheck' ./httpsec/`

## 7. The OIDC redirect path check (`oidc-login`)

- [x] 7.1 In `authenticate/oidc`, give `RelyingParty` read access to each registered provider's redirect URL, alongside `Providers()`. A test registers two providers and reads both URLs back, and checks that an unknown name reports none. (D10.) Verify with `go test -race -count=1 ./authenticate/oidc/`
- [x] 7.2 Check at chain assembly that each provider's decoded redirect URL path ends with the resolved callback path followed by its name, and add `WithoutOIDCRedirectPathCheck()`:
  - 1.1's test turns green;
  - tests cover each spec scenario: a matching URL, the base `/auth` not reflected, the callback moved, a prefix-stripping proxy accepted, a percent-encoded path accepted, and the waiver;
  - existing OIDC fixtures and examples whose redirect URLs do not match their callback path are corrected, and each correction is listed in the report.

  (D10; `oidc-login` "A provider's redirect URL must reach the callback path", every scenario.) Verify with `go test -race -count=1 ./httpsec/ ./authenticate/oidc/` and `go test ./...` in the `test` module

## 8. Documentation

- [x] 8.1 Godoc and README:
  - `WithBasePath` names the default (none), what it covers, what it does not (consumer pages, authorization rules, consumer routes, consumer interceptors, a prefix a proxy already strips), and its refusals;
  - every path setting, the struct fields included, says the path is relative to the base path and names its default;
  - the three waivers state what each gives up; `Endpoints()` states that consumer interceptors are not listed and documents every operation identifier;
  - the magic-link godoc tells the confirm page (not moved) from the redeem endpoint (moved);
  - an `ExampleWithBasePath` shows password sign-in answering under `/auth`;
  - README sections: the default path table, the base path and what does not move, and the migration steps of `design.md`; no old default path remains in the README.

  Verify that `go test -run 'ExampleWithBasePath' ./httpsec/` passes and that `go doc ./httpsec WithBasePath` shows the default and the exclusions.

## 9. Adapters and conformance

- [x] 9.1 Add base-path scenarios to `test/httpsecconformance`, run on net/http, gin and fiber:
  - password sign-in, the key set and the token endpoint answer under `/auth` and their unprefixed paths pass through;
  - an authorization rule keeps judging the consumer's own path;
  - a chain with no base path answers a request whose prefix a proxy removed.

  Each scenario mirrors a spec scenario. ("Built-in endpoints answer under an optional base path", scenario "Every adapter answers the same paths"; "The base path covers only the endpoints the chain answers", scenario "Prefix stripped before the chain".) Verify with `go vet ./...` and `go test -race ./...` in the `test` module

## 10. Close-out

- [ ] 10.1 Run the whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate endpoint-inventory-base-path --strict`.

  Verify that every command exits 0 and record its output.

## Workflow follow-up

- Implementation starts on a new branch from `main`.
- Run one whole-branch review against every spec requirement this change covers before the final gate and before archive.
- At archive, update `openspec/config.yaml`:
  - in the capability map, this change appears under follow-ups with the capabilities it modifies;
  - in the context, the base-path rule and the default path vocabulary join "HTTP and errors".
- Tell the `bff-resource-server` change that its cross-site exemption overlap check should read the inventory, and `release-readiness` that this change lands before `v0.1.0`.
- `openapi-document` and `observability` start after this change is merged.
