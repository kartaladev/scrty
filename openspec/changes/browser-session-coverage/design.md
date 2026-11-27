## Context

`browser-session` and `browser-session-hardening` are implemented and archived on the PR #160
branch. Their verification mapped every requirement and scenario to code and tests and found no
defect. It found one spec sentence broader than the code (logout), seven scenarios whose tests
assert only part of the outcome, and test doubles written by hand where the project's mockgen rule
applies. This change closes those gaps. It changes tests and one spec requirement; production code
stays as it is.

## Goals / Non-Goals

**Goals:**
- The settled `browser-session` spec says what the code and design 11 already do at logout.
- Every listed scenario has one test that asserts its whole THEN clause.
- The composition of a provider on a cookie chain and a token chain trusting it is exercised with a
  real, bound token.
- Test doubles follow `use-mockgen`, except where a double wraps a real implementation.

**Non-Goals:**
- Any change to production behaviour, error values or public API. If a red step shows the code does
  not behave as a scenario says, that is a defect: it is reported, proved per `defect-claims.md`,
  and put to the user, not fixed silently here.
- Reordering literal `Set-Cookie` strings in the settled spec (see decision 2).

## Decisions

### 1. Logout: the spec follows design 11

The settled requirement says any successful logout on a cookie chain expires the cookie. Design 11
of `browser-session` settled during implementation that only a logout whose request carried the
cookie expires it; a logout authenticated by Basic or an API key sets none, and a test pins it. The
code and design are right: a response to a request that did not carry the cookie has no reason to
touch a cookie the browser may hold for another sign-in. The requirement is reworded and gains the
"Logout by another credential" scenario.

- **Default:** unchanged code behaviour. **Override:** none needed; the consumer's logout responder
  is already replaceable.

### 2. Attribute order in a `Set-Cookie` header is not part of the contract

The spec's literal headers list `Secure; HttpOnly`, while `net/http` writes `HttpOnly; Secure`.
RFC 6265 gives cookie attributes no order, so the literal is a list of attributes, not a byte
string. New tests in this change assert attributes by parsing the header (`http.Response.Cookies`
or `http.ParseSetCookie`), not by string equality, except where an existing test already pins the
exact string `net/http` writes. The spec literals stay as they are.

### 3. "Refused as not found" is asserted by what the client observes

At zero grace, the scenario says the pre-verification cookie is "refused as not found". The
pipeline refuses every judged reference with a bare `ErrAuthenticationRequired`
(`httpsec/session_reference.go`), never wrapping `session.ErrNotFound`, so the error cannot carry
that distinction, and adding it would change error values (a non-goal). The test asserts the
outcome that distinguishes not-found from reuse: refused as an unknown reference is (401, charged
against the source, cookie expired), no reuse event, and the family intact, beside the existing
`ErrNotFound` from a direct store load.

### 4. The composition test uses a real session sign-in and a real token

The resource-server scenario "Provider on the cookie chain, API on the token chain" is tested with:
a provider served by a chain with `EnableSessionCookie` and CSRF protection; a second chain whose
resource server answers under `/api` (`EnableResourceServer` with `WithPathPrefix("/api/")` and
`FromProvider` naming the same provider); one mux routing `/api/` to the token chain and `/` to the
cookie chain. `WithBasePath("/api")` is not used: it moves only built-in endpoints, and a chain
with none refuses it at construction as a configuration that would move nothing. The access token
is obtained the way the existing provider-on-cookie-chain tests obtain one: a sign-in recorded in
the cookie chain's session store, a first-party authorization the provider's `Resume` completes
with that sign-in, and the code exchange through the cookie chain's token endpoint, bound by DPoP,
for the API resource. It reuses the existing helpers
(`newCookieOP`, `cookieAccessToken`, `psWorld`'s DPoP and resource setup) rather than new ones
where they fit. The scenario "Grant revoked, token checked on the other chain" runs on the same
composition.

### 5. Which test doubles become generated mocks

- `SessionDelivery` (`httpsec/session_delivery.go`) and `CSRFTokens` (`httpsec/csrf.go`) get
  `//go:generate mockgen ... -typed` directives, generating `sessiondelivery_mock_test.go` and
  `csrftokens_mock_test.go` in `httpsec_test`, as the other ports do.
- Become generated mocks, because they are fixed-answer stubs: `failingOIDCDelivery`
  (`oidc_cookie_test.go`, a `SessionDelivery` that fails) and `authRequiredTokens` and
  `outageTokens` (`session_cookie_test.go`, `CSRFTokens` that break their contract).
- Stay, with the reason stated in a comment on the type:
  - `auditDelivery` (`session_delivery_port_test.go`) and `persistentDelivery`
    (`session_cookie_persistence_test.go`) are consumer delivery implementations. The delivery-port
    scenarios are about what the chain does with a consumer's delivery, so the delivery's own logic
    (audit entries, `Max-Age` arithmetic, injected misbehaviour) is the test's subject. A mock would
    carry the same logic inside a `DoAndReturn` closure and add nothing.
  - `recordingBrowsers` (`session_cookie_provider_ends_test.go`) embeds the real
    `oidcprovider.MemoryBrowserSessionStore` and records calls; it is a decorator, as below.
  - Store decorators (`hidesSelector`, `callerSuccessorStore`, `roleSpyStore`, `selectingStore`,
    `cookieStore`, `browserStore`) wrap a real store to inject one fault or observe one call, which
    a mock would have to reimplement, losing the real store's behaviour the test depends on.
- Each converted test asserts the same outcomes as before. A conversion that would weaken an
  assertion is not made; the double stays and the reason is reported.

## Failure modes

The change adds tests, so the failures listed are the ones the new tests provoke, and the ones the
test work itself can introduce.

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Bound token from the cookie chain's provider sent to the token chain | Configuration and wiring | Tested (4) | accepted; caller is the local user the token names |
| Grant revoked through the provider, token re-sent to the token chain | State | Tested (4) | refused as an invalid token |
| Provider on a cookie chain, CSRF opted out, default browser sessions | Configuration and wiring | Tested (W2a) | construction fails with a configuration error |
| Pre-verification cookie at zero grace | State, time | Tested (3) | 401, charged, cookie expired, no reuse event, family intact |
| `Accept` q-value `1.` on a sign-in | Input | Tested | `303 See Other` |
| Default and strict cookie on a real sign-in | Configuration | Tested | `Set-Cookie` with the specified attributes |
| Unsafe cookie request without a CSRF token | Security | Tested | 403, not charged, no `Set-Cookie` |
| A mock conversion weakens a test's assertion | Observability (test) | Handled (5) | conversion not made; reported |
| A new scenario test fails on the current code | Any | Handled (non-goals) | reported as a defect claim with its failing output; not fixed in this change without the user |
| Logout by another credential | State | Already tested | logout succeeds, no `Set-Cookie` |

## Risks / Trade-offs

- [The composition test is slow or flaky because it runs a full authorization flow] → it reuses
  the fake clock and in-memory stores the existing provider tests use; no network or containers.
- [Mock conversions churn many tests for no behaviour gain] → limited to the doubles listed in
  decision 5; each test's assertions are kept, and a conversion that cannot keep them is skipped.

## Migration Plan

None. Tests and one spec sentence change; nothing a consumer sees.

## Open Questions

None.

## References

Reasoned from scrty's own settled specs and the established design.

**Primary documentation:**
- [RFC 6265, section 4.1.1](https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.1): `Set-Cookie` attributes as an unordered list (decision 2).
