## Why

The verification of `browser-session` (with `browser-session-hardening`) on PR #160 found the code
matching every requirement, but one spec sentence broader than the code and seven scenarios whose
tests do not assert the whole outcome. One of them is the composition the resource-server spec
describes and no test exercises with a real token: the provider on a cookie chain, and an API on a
token chain that trusts it. Both changes are archived on the PR branch, so the fixes land here,
before the PR merges.

## What Changes

- **Spec correction, no code change:** "Logout expires the cookie" says a successful logout on a
  cookie chain expires the cookie. The code expires it only when the request carried it, and a
  logout authenticated by another credential (Basic, an API key) sets no cookie. The established
  decision (browser-session design 11) and a test already say so; the requirement is reworded and
  gains the scenario.
- **End-to-end composition test:** one binary runs the provider on a cookie chain and, under
  `/api`, a token chain whose resource server trusts it through `FromProvider`. A DPoP-bound access
  token the provider issued through a cookie sign-in is accepted at `/api/orders` as the local
  user, and refused after its grant is revoked.
- **Scenario tests completed** (test-only; the code already behaves as specified):
  - a provider on a cookie chain without CSRF protection, with the provider's default browser
    sessions;
  - zero renewal grace: the pre-verification cookie is refused the way an unknown reference is;
  - an `Accept` q-value with an empty fraction, end to end through a sign-in;
  - the default and `SameSite=Strict` cookie, asserted on a real sign-in response;
  - a cross-site request, with refusal, no charge and no `Set-Cookie` in one test.
- **Test doubles moved to mockgen** where the project rule asks for it: `SessionDelivery` and
  `CSRFTokens` get generated mocks, and the fixed-answer stubs become them. Consumer delivery
  implementations whose logic is the test's subject, and decorators over a real store, stay, with
  the reason stated on each type.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `browser-session`: "Logout expires the cookie" states that only a logout whose request carried
  the cookie expires it.

## Impact

- `httpsec` tests only: `session_cookie_provider_test.go`, `resource_source_provider_test.go` (or a
  new composition test file), `session_cookie_rotation_test.go`, `session_cookie_answer_test.go`,
  `delivery_test.go`, `session_cookie_test.go`, and the tests that define hand-written doubles
  (`session_delivery_port_test.go`, `session_cookie_persistence_test.go`, `oidc_cookie_test.go`,
  `session_cookie_provider_ends_test.go`).
- `httpsec/session_delivery.go` and `httpsec/csrf.go`: `//go:generate mockgen` directives for
  `SessionDelivery` and `CSRFTokens`, and the generated `sessiondelivery_mock_test.go` and
  `csrftokens_mock_test.go`.
- No production behaviour, public API, dependency or migration changes.

## References

Reasoned from scrty's own settled specs and the established design.
