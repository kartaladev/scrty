# Tasks

**How tasks are worked:**
- **Test-first.** Every Go task writes the failing test, runs it, and confirms it fails for the
  intended reason; a compile error is not a red step. Then it implements, re-runs, and refactors with
  the tests green. Tables follow the `table-test` skill; doubles come from `use-mockgen`; PostgreSQL
  from `use-testcontainers`.
- **Failure modes.** `design.md` § Failure modes is binding. A task names the rows it covers, and each
  handled row it covers ends in a test.
- **Maintainer tasks.** Tasks marked **(maintainer)** merge, tag or publish. Only the maintainer does
  them, never an agent.
- **Lanes and files.**
  - Lane T (group 2): `token/`, `internal/grantclaims/` (new), `authenticate/factor/` and the godoc
    of `identity/principal.go`.
  - Lane P (group 3): `authenticate/password/`.
  - Lane I (group 4): `authenticate/password.go`, `authenticate/authenticate.go` and their tests.
  - Lane O (group 5): `oidcprovider/` (the verifier). It starts after group 2.
  - Lane H (groups 6–10): `httpsec/` and the adapter tests. Its groups run in order. Group 6 starts
    after groups 2 and 5, and group 10 after group 4.
  - Groups 2, 3 and 4 run in parallel with each other. Groups 3 and 4 also run in parallel with
    group 5.
- **Model per dispatch:**
  - Opus for task 2.4 (the unforgeable mark), group 5 and groups 6–9: security-critical
    verification and refusal logic written for the first time, a change to the bearer's hot path
    that must keep first-party behaviour, and an interface other lanes compile against.
  - Sonnet for tasks 2.1–2.3 and for groups 3, 4, 10 and 11.
  - Each dispatch gets a fresh reviewer of the same tier.

## 1. Branch and baseline

- [ ] 1.1 Confirm `harden-chain-boundary` is merged to `main`, since it reshapes `httpsec/chain.go` and
  `httpsec/exchange.go`: `git log origin/main --oneline | grep -i harden-chain-boundary` finds its
  merge. If it is not merged, stop and ask.
- [ ] 1.2 Cut `feat/provider-resource-server` from `origin/main` and carry this change's directory onto
  it. Verify that `git branch --show-current` names it, and that `go test ./... -count=1` passes in
  every workspace module as the baseline.

## 2. Token type port, access-token factor kind and the grant-backed mark (design decisions 3, 9, 10)

- [ ] 2.1 Red: `TestGenerator_TokenType`, a table test checking that `token.NewGenerator` reports
  `token.TypeFirstParty` by default and the retyped value under `token.WithTokenType("at+jwt")`. Then
  add `token.TypedGenerator` and implement `TokenType()` on the generator. Verify with
  `go test ./token/... -count=1`.
- [ ] 2.2 Red: extend the factor kind table test with `factor.AccessToken`, expecting no channel and
  exemption, while `api-key` stays exempt and `oidc` does not. Then add the kind and its exemption.
  Verify with `go test ./authenticate/factor/... ./policy/... -count=1`.
- [ ] 2.3 Update `identity.Principal.Scopes` godoc to say it holds a service's scopes, or an access
  token's granted scopes for a user. Verify with `go doc ./identity Principal`.
- [ ] 2.4 Red: `TestGrantClaims_Mark`. Claims from `token.NewClaims` and
  `token.NewClaimsWithConfirmation` carry no mark. `WithGrant(grantclaims.New(p))` returns a marked copy
  whose `Grant().Payload()` is `p`, and leaves the original unmarked. `WithGrant(nil)` marks nothing.
  Add `TestGrantClaims_InternalOnly` to `layout_test.go`, which asserts that the package path is under
  `internal/` and that the package imports nothing from scrty. Implement `internal/grantclaims` and
  `Claims.WithGrant` and `Claims.Grant`. Verify with
  `go test ./token/... ./internal/grantclaims/... . -count=1`.

## 3. Password policy: consumer rules (decision 11; spec "The consumer can add rules of its own")

- [ ] 3.1 Red: `TestPolicy_ConsumerRule`, a table test with these cases:
  - letters-and-digits refuses `abcdefghijkl` with `RejectedError{Rule: "letters-and-digits"}`, which is
    not `ErrReused`;
  - `abcdefghij12` is accepted;
  - two rules run in the order given;
  - a refused rule skips the breach lookup (mock `BreachSource`, no call);
  - a rule error fails closed, is reachable, is not `ErrPasswordRejected`, and the text holds no
    candidate.

  Confirm it fails for the intended reason. Implement `WithRule` and `RuleFunc`. Verify with
  `go test ./authenticate/password/... -count=1`.
- [ ] 3.2 Red: extend the construction table with these cases, each a configuration error naming the
  rule: a nil or typed-nil check, an empty name, a built-in name (`reused`), and a duplicate name.
  Implement it. Verify with the same command.
- [ ] 3.3 Red: `TestPolicy_Change_ConsumerRuleAndReuse`. With `MinLength(10)`, letters-and-digits and
  `NoReuse(history, 1)`, the current password is refused as `ErrReused` and a weak one by the
  consumer rule, and in neither case is the write called. Implement any gap, then add an `Example`
  for `WithRule` and godoc naming the default (no rule). Verify with the same command and
  `go vet ./authenticate/password/...`.

## 4. Inactive account beneath the uniform failure (decision 12; spec authentication delta)

- [ ] 4.1 Red: extend the password provider's refusal table:
  - an inactive account with its correct password returns an error matching both
    `ErrAuthenticationFailed` and the new `ErrAccountInactive`;
  - an unknown user and a wrong password match only `ErrAuthenticationFailed`, and an inactive
    account with a wrong password is in that set (F28).

  Confirm the inactive case fails today for the intended reason. Implement it. Verify with
  `go test ./authenticate/... -count=1`.
- [ ] 4.2 Red: a timing-parity assertion. The inactive path spends the same encoder calls as a wrong
  password (encoder mock call count). Implement any gap, then add godoc on `ErrAccountInactive`
  stating that it is reachable only after a verified password. Verify with the same command.

## 5. The provider's access-token verifier (decisions 2, 3; F4–F8, F10, F13; spec "The provider offers a verifier…", "The verifier routes…", "A provider access token is verified…", "Verified provider tokens are marked…")

- [ ] 5.1 Red: `TestProvider_AccessTokenVerifier_Construction`, a table test:
  - `https://hris.example/api` and `urn:kartala:hris:api` are built;
  - `""`, `hris-api`, `https://x/api#f`, the issuer, and a nil or typed-nil first-party verifier each
    give `ErrConfig`.

  Implement `AccessTokenVerifier`, the `AccessTokenVerifierOption` type and `WithFirstPartyVerifier`,
  reusing `validResource`. Verify with `go test ./oidcprovider/ -run AccessTokenVerifier -count=1`.
- [ ] 5.2 Red: `TestAccessTokenVerifier_Routes`, a table test (F4):
  - with a first-party route: `scrty+jwt` goes to the first-party mock, unmarked; an ID token goes to
    the first-party mock;
  - without one: `scrty+jwt` gives `token.ErrInvalid`;
  - `at.x.y`, `at+jwt` and `application/AT+JWT` go to the provider (the first-party mock is never
    called);
  - an oversized, non-base64 or non-JSON header, and `typ xat+jwt`, take the first-party route.

  Then add `FuzzAccessTokenVerifierRoute` with no panic and a bounded read. Implement it. Verify with
  the table and `go test ./oidcprovider/ -run '^$' -fuzz FuzzAccessTokenVerifierRoute -fuzztime 30s`.
- [ ] 5.3 Red: `TestAccessTokenVerifier_Verify`, with the provider and an in-memory store, a fixed
  clock (08:00) and a 5 m lifetime (F5–F8, F10):
  - marked claims with the subject as the user ID, and a payload equal to `VerifyAccessToken`'s;
  - refused as provider-routed `token.ErrInvalid`: an altered signature, a foreign key, a clock at
    08:05:00 and 08:06, `RevokeUserGrants`, logout of an online grant, a revoked opaque token, another
    audience, and the issuer-only audience;
  - an audience holding both the issuer and the configured value passes;
  - a grant-store outage matches `ErrDependency` and not `token.ErrInvalid`;
  - caller cancellation matches `context.Canceled`.

  Implement it. Verify with `go test ./oidcprovider/... -race -count=1`.
- [ ] 5.4 Add godoc for `AccessTokenVerifier` and `WithFirstPartyVerifier`: the audience rule, the
  routing, the mark, no defaults, and lines F21 and F22. Add `ExampleProvider_AccessTokenVerifier`.
  Verify with `go test ./oidcprovider/ -run Example -count=1`.

## 6. The bearer's grant-backed path: construction, verification, user (decisions 4, 5, 8; F2, F3, F9, F17–F20, F23, F26, F30)

- [ ] 6.1 Safety net: run `go test ./httpsec/ -run 'Bearer|DPoP|Cert|Renewal' -count=1 -v` and record
  the passing list in the scratchpad. Every later group in lane H reruns it, and it must stay
  identical.
- [ ] 6.2 Red: `TestEnableBearerToken_GrantBackedConstruction`, a table test (F23):
  - nil `Sessions` with the provider's verifier and no first-party route builds;
  - nil `Sessions` with the provider's verifier plus a first-party route, or with a plain verifier,
    gives `ErrConfig`;
  - `WithBearerUsernameSubject` with the provider's verifier gives `ErrConfig`;
  - a form-login generator typed `at+jwt` beside the provider's verifier gives `ErrConfig` (uses 2.1);
  - the binding default with neither DPoP nor certificate binding gives `ErrConfig`.

  Implement the `validate` checks. Verify with a focused `go test -run`.
- [ ] 6.3 Red: `TestBearer_GrantBackedSkipsSession`. A session-manager mock with `.Times(0)` for a valid
  bound provider token, which gives 200 and no `ex.Session`. Also an unmarked-claims guard: a consumer
  verifier returning `NewClaimsWithConfirmation` still loads a session (F13). With nil `Sessions` and
  unmarked claims, the request fails closed with `ErrConfig` and 500 (F30). Implement the branch on
  the mark. Verify with a focused `go test -run` and the 6.1 list.
- [ ] 6.4 Red: a request-shape table (F2, F3), with the provider's verifier:
  - two `Authorization` headers give 400 `ErrMalformedRequest`, with no key-source read (mock,
    `.Times(0)`);
  - query and header together give 400;
  - a query token alone gives no caller;
  - `"DPoP\t<tok>"` and `"dpop  <tok> "` are read as tokens.

  Implement it. Verify with a focused `go test -run`.
- [ ] 6.5 Red: a user table (F9, F17–F20):
  - a missing or inactive user gives `ErrAuthenticationRequired`, and the same proof succeeds once the
    user is reactivated;
  - a loader outage is a dependency failure, and the proof is not recorded;
  - a loader answering for another user is refused, with an ERROR record naming neither user;
  - a removed role is absent from the principal;
  - a cancellation inside the loader matches `context.Canceled`.

  Implement steps 5–6 of decision 4. Verify with a focused `go test -run`.
- [ ] 6.6 Red: a log-capture test (F26). No record, error text or event carries the token, the proof
  or the user ID. Implement it. Verify with a focused `go test -run`.

## 7. Binding and the bearer's grant-binding default (decisions 4, 6; F11, F12, F14–F16; spec binding and unbound requirements, sender-constrained-tokens delta)

- [ ] 7.1 Red: `TestBearer_GrantBackedDPoP`, a table test over the chain's real verifier, with each of
  the consumer's acceptance scenarios as a case:
  - accepted: a fresh proof by K;
  - refused with `ErrInvalidDPoPProof`: Bearer with no proof, DPoP with no `DPoP` header, another key,
    another method, another URL, `iat` ±61 s, a replay, a wrong `ath`, and an RS256 proof;
  - a missing nonce when nonces are on gives `ErrDPoPNonceRequired` and a fresh `DPoP-Nonce`.

  Verify with a focused `go test -run`.
- [ ] 7.2 Red: `TestBearer_GrantBackedProofRace` (F16): two goroutines behind a barrier with one
  proof, giving exactly one 200, run under `-race -count=20`. In the same table, a replay-store or
  nonce-cipher outage is a dependency failure (F15). Implement any gap.
- [ ] 7.3 Red: an unbound table (F11):
  - unbound Bearer under the default gives `ErrInvalidToken`, challenged under `DPoP`;
  - with `WithBearerUnboundGrantTokens` it gives 200;
  - the same with chain `Require` gives `ErrInvalidDPoPProof`;
  - unbound under `DPoP` gives `ErrInvalidDPoPProof`;
  - an unbound first-party token with `Require` off gives 200;
  - certificate-bound tokens are accepted with a matching cert, and refused with a wrong cert or with
    binding off.

  Implement `WithBearerUnboundGrantTokens` and `ErrInvalidToken`. Verify with a focused `go test -run`.
- [ ] 7.4 Red: `TestBearer_GrantBackedSignInUnaffected`. On one chain (form login, the provider, the
  bearer with the provider's verifier and a first-party route, and DPoP with `Require: false`):
  - a browser login with no proof issues an unbound token, which resumes `/oauth2/authorize/resume`;
  - a login with a proof issues a bound token;
  - a provider-token proof replayed at UserInfo is refused.

  Implement any gap. Verify with a focused `go test -run` and the 6.1 list.

## 8. Publication, policy phase, renewal, godoc (decision 8; F25, F31; spec publication and stateless policy requirements, http-security-chain renewal)

- [ ] 8.1 Red: a publication table (F25):
  - the principal's `Scopes` equals the token's scopes;
  - `AccessTokenFromContext` gives the client, scopes and grant, and a mutated read leaves the next
    unchanged;
  - nothing is published on refusal;
  - `HasAnyScope("employees:read")` gives 200 or 403;
  - a role rule allows.

  Implement `AccessTokenFromContext` and the publication. Verify with a focused `go test -run`.
- [ ] 8.2 Red: a policy table. A deny returns its reason, a challenge returns a `ChallengeError`, and an
  MFA-requirement policy does not challenge an `access-token` caller. Implement the stateless phase
  with `factor.AccessToken`. Verify with a focused `go test -run`.
- [ ] 8.3 Red: `TestRenewal_RefusesGrantBackedCaller` (F31): 401 `ErrAuthenticationRequired`, with the
  generator mock `.Times(0)`. Implement it. Verify with a focused `go test -run` and the 6.1 list.
- [ ] 8.4 Add godoc to `BearerTokenDeps`, covering when `Sessions` may be nil. Add godoc to
  `EnableBearerToken` (the grant-backed path), `WithBearerUnboundGrantTokens` (its default and
  override) and `AccessTokenFromContext`, plus lines F21, F22, F24 and F29. Add
  `ExampleEnableBearerToken_providerAccessTokens`, wiring the provider, form login, the bearer with
  the provider's verifier and a first-party route, and DPoP. Verify with
  `go test ./httpsec/ -run Example -count=1`.

## 9. Challenges (decision 7; spec challenge requirements and http-error-propagation)

- [ ] 9.1 Red: `TestBearer_GrantBackedChallenges`, a table test asserting the exact
  `WWW-Authenticate` values, exactly one per refusal:
  - `DPoP error="invalid_token", algs="ES256"`;
  - `DPoP error="invalid_dpop_proof", algs="ES256"`;
  - `Bearer error="invalid_token"` with DPoP off and unbound tokens allowed;
  - `invalid_request` with 400;
  - no token, with a grant-backed-only verifier and the binding default: `DPoP` only;
  - no token, with a first-party route and `Require` off: `DPoP` and `Bearer`;
  - a guard route gives the same values;
  - `WithErrorHandler` removing the header leaves no challenge;
  - a first-party rejected token gives no challenge, unchanged.

  Implement the fallback challenge interceptor and the `dpopChallenge` rules. Verify with a focused
  `go test -run`, then `go test ./httpsec/... -race -count=1`.
- [ ] 9.2 Red: in `httpsec/fibersec` and `httpsec/ginsec`, an adapter test per refusal kind of 9.1. A
  fiber `RefusalError` through `fibersec.ErrorHandler` keeps status and `WWW-Authenticate`. Add
  `ProviderTokenScenarios()` to `test/httpsecconformance` so all three adapters run the same cases.
  Verify with `go test ./... -count=1` in `httpsec/fibersec`, `httpsec/ginsec` and `test`.

## 10. Inactive-account disclosure on the chain (decision 12; spec http-security-chain and http-error-propagation deltas)

- [ ] 10.1 Red: a table across form login and Basic:
  - by default an inactive account with its correct password gives 401, with `ErrAccountInactive`
    beneath it;
  - under `WithInactiveDisclosure` it gives 403, the refusal is `ErrAccountInactive` alone, and Basic
    sends no `WWW-Authenticate`;
  - with a wrong password it gives 401 uniform;
  - account recovery still gives `recovery.ErrRefused`.

  Implement the option and the `StatusForError` row, with the concealed join still mapping to 401.
  Verify with a focused `go test -run` and `go test ./httpsec/... -count=1`.
- [ ] 10.2 Add godoc for `WithInactiveDisclosure`, naming the default, what it gives up and the 403.
  Verify with `go doc ./httpsec WithInactiveDisclosure`.

## 11. Release preparation (decision 13)

- [ ] 11.1 Add a `## [Unreleased]` entry in `CHANGELOG.md`:
  - *Added*: `Provider.AccessTokenVerifier`, `WithFirstPartyVerifier`, the grant-backed path of
    `EnableBearerToken`, `WithBearerUnboundGrantTokens`, `ErrInvalidToken`, `AccessTokenFromContext`,
    `token.TypedGenerator`, `factor.AccessToken`, `password.WithRule`,
    `authenticate.ErrAccountInactive` and `WithInactiveDisclosure`;
  - *Changed*: the inactive join, `BearerTokenDeps.Sessions` being optional for the provider's
    verifier, and `Principal.Scopes` on access-token callers.

  Verify with `git diff -- CHANGELOG.md`.
- [ ] 11.2 Run the release gate as `RELEASING.md` names it for `v0.2.0`, in a dry run with no tag, and
  record its output: `make` targets, `gofmt -l`, `go vet`, lint, `govulncheck`, and tests with
  `-race` across every module.
- [ ] 11.3 **(maintainer)** Date the changelog, require `v0.2.0` in every nested module, tag the nine
  modules at one commit, push, and run the outside probe, following `RELEASING.md`.

## 12. Whole-branch review

- [ ] 12.1 A fresh Opus reviewer checks the branch diff against every requirement and scenario in
  this change's seven spec files and the failure-modes table. It reports each finding as `REPRODUCED`
  with a failing test, or `UNREPRODUCED` with a reason. Fold the findings, then verify that
  `openspec validate provider-resource-server --strict` and `go test ./... -race -count=1` in every
  module pass.

## Workflow follow-up

- Report to the consumer: the module version, `AccessTokenVerifier` and its option, the
  `EnableBearerToken` wiring with `Sessions` optional, `WithBearerUnboundGrantTokens`,
  `AccessTokenFromContext`, the sentinels (`ErrInvalidToken`, `ErrInvalidDPoPProof`,
  `ErrDPoPNonceRequired`, `ErrAuthenticationRequired`, `ErrMalformedRequest`), `password.WithRule`
  and `WithInactiveDisclosure`.
- Note in `bff-resource-server`'s proposal that the embedded-provider resource server shipped here.
- Archive the change after the maintainer's release.
