# Design

> **On hold (2026-11-18).** Decisions are pending: see `pending-decisions.md`. This document
> describes the bearer-reuse design (D1-A there), which may be superseded. Do not apply the change
> until those decisions are made.

## Context

See `proposal.md` for the motivation. The tree on 2026-11-16 already has the parts this design
puts together:

- `Provider.VerifyAccessToken` (`oidcprovider/accesstoken.go`) reads JWT and opaque tokens, and
  refuses on every call a token whose grant is revoked, expired, gone or names another client or user.
  It answers a store outage with `ErrDependency`. It does not check the audience or the key binding.
  It refuses every `typ` but `at+jwt`, so it refuses ID tokens, first-party tokens and logout tokens.
- `EnableBearerToken` (`httpsec/bearer.go`) runs `Verify`, then `admitBinding` (the full DPoP or
  certificate check, before any store read), then `resolve`. `resolve` loads the session the `jti`
  names, judges the subject, records the proof and reloads the user. `BearerTokenDeps.Verifier` is a
  public port, and `token.NewClaimsWithConfirmation` lets a consumer's verifier report a binding.
- The UserInfo endpoint (`httpsec/oidc_userinfo.go`) is the only resource-server path today, and it
  is unchanged by this design.
- `EnableAPIKey` publishes a session-less caller through `WithCaller`, then runs the stateless policy
  phase. The grant-backed path follows it.
- The chain's DPoP challenge interceptor (`dpopChallenge`, `httpsec/dpop_nonce.go`) challenges
  `ErrInvalidDPoPProof`, `ErrDPoPNonceRequired` and a missing caller. It sets nothing for
  `authenticate.ErrAuthenticationFailed`, and it does not exist when DPoP is off.
- `DPoP.Require` applies to the whole chain, issuing endpoints included, so it refuses a browser's
  form login with no proof (pinned by `TestDPoP_ProofBeforeSpend`).
- First-party tokens are typed `scrty+jwt` (`token.TypeFirstParty`), and provider access tokens are
  typed `at+jwt` (`token.TypeAccessToken`). `token.WithTokenType` can retype a first-party generator.
- The established design has no resource-server mode, no inactive-account disclosure and no
  password composition rules. The only departure from it is decision 12.

## Goals / Non-Goals

**Goals:**
- One `EnableBearerToken` answers a provider access token and a first-party token side by side,
  while a browser form login works with no proof.
- The grant-backed path reuses the bearer's own binding judgement and replay recording. It does not
  copy them.
- Each acceptance scenario the consumer listed is a test in this change.

**Non-Goals:**
- Accepting tokens from issuers other than the chain's own provider (`bff-resource-server`).
- Accepting provider tokens under `EnableSessionBearer`. A chain runs one bearer mode, as settled.
- Reading a token from a form body.
- Inactive-account disclosure for login methods other than passwords.
- Changing first-party bearer refusals or challenges.

## Decisions

### 1. Reuse `EnableBearerToken`; add no new chain option (user decision, 2026-11-16)

- **History:** the first draft added `EnableProviderAccessTokens`. The user reversed that on
  2026-11-16, at the consumer's request: a second `Enable*` for "bearer tokens, but the provider's"
  would confuse consumers about which one to use.
- **How it fits:** the bearer already does everything a resource server needs except one step:
  1. `Verify`;
  2. `admitBinding` (proof or certificate) before any store read;
  3. the session lookup, the user reload and the proof recording.

  Only the session lookup assumes a first-party token. A provider token has a grant instead.
- **So:** the provider supplies the verifier, and the bearer skips that one step for tokens the
  verifier marks as grant-backed.
- **Alternative considered:** the separate feature. It was rejected by the user.

### 2. `Provider.AccessTokenVerifier`, routing by shape

```go
func (p *Provider) AccessTokenVerifier(audience string, opts ...AccessTokenVerifierOption) (*AccessTokenVerifier, error)
func WithFirstPartyVerifier(v token.Verifier) AccessTokenVerifierOption
// *AccessTokenVerifier implements token.Verifier.
```

- **Audience:** it is validated by the rule `validResource` already applies to `Client.Resources`
  (`oidcprovider/client.go:487`), so a URN is accepted. It may not be the issuer. A bad audience gives
  `ErrConfig`.
- **Routing:**
  - an `at.` prefix, or a JWT whose header `typ` is `at+jwt` or `application/at+jwt`, without regard to
    case (RFC 7515 §4.1.9), goes to `VerifyAccessToken` and then the exact audience check;
  - anything else goes to the first-party verifier, or `token.ErrInvalid` without one.
- **Bound on the peek:** the decoded header is read through a 4 KiB bound. A header that does not
  decode goes to the first-party route, which refuses it.
- **The verifier's errors:**
  - A provider refusal (`*oidcprovider.Error` with `invalid_token`) is returned as a `token.ErrInvalid`
    that is also marked as provider-routed (decision 7).
  - `ErrDependency` stays a dependency failure, and so matches neither.
  - The caller's own cancellation stays the context's error.
- **Default and override:** there is no default audience and no default first-party route.
  Both come from the consumer.
- **Why routing lives in the verifier:** opaque tokens have no `typ`. Only the provider knows its own
  prefix, so the verifier is the one place that can route both forms. No separate router type is
  needed.

### 3. The grant-backed mark is unforgeable

- **Where it lives:** a new `internal/grantclaims` package owns `type Mark struct{ payload any }` and
  its constructor. It imports nothing from scrty, so there is no cycle.
- **How it is carried:** `token.Claims` carries a `*grantclaims.Mark` through `WithGrant(m)` and
  `Grant()`. The payload is the verified `*oidcprovider.AccessToken`, held as an opaque value, because
  `token` cannot import `oidcprovider`.
- **Why it is unforgeable:** Go's `internal` rule stops any module outside scrty's import path from
  naming or building a `Mark`. A consumer can only pass nil, which marks nothing. That is the same
  guarantee `RefreshTokenStore` relies on.
- **The line it does not hold past:** package `unsafe`, as documented for `RefreshTokenStore`.
- **What consumers see:** `token.NewClaims` and `token.NewClaimsWithConfirmation` never set the mark.
- **Why it matters:** a consumer's verifier that could claim "grant-backed" would turn off session
  revocation. The mark must be a fact the library established, not a claim.

### 4. The bearer's grant-backed path, and its order

1. **Read the header.** With the provider's verifier, more than one `Authorization` header, or a query
   `access_token` beside the header, is refused with `ErrMalformedRequest` (400, `invalid_request`).
   This follows RFC 6750 §3.1, as UserInfo does.
2. **`Verify`.** The provider verifies, the audience is checked, and the mark is set.
3. **Refuse an unbound token** with `ErrInvalidToken`, unless `WithBearerUnboundGrantTokens` is set
   (decision 6).
4. **Run the existing `admitBinding`.** A key that does not fit the proof stays `ErrInvalidDPoPProof`,
   as the bearer already answers it.
5. **Reload the user.** `Users.LoadByUserID(subject)` is called, and the user must exist, be active and
   have `details.ID == subject`. Otherwise the refusal is `ErrAuthenticationRequired`. A loader
   failure goes through `classifyReload`.
6. **Record the proof** with `recordProof`.
7. **Publish** (decision 8).
8. **Run the stateless policy phase** under `factor.AccessToken`, as `EnableAPIKey` does.

Why this order and these rules:
- **Unbound check before binding:** the unbound refusal costs no proof work.
- **Proof recorded after the user:** a refused user consumes no proof, as the session path already
  guarantees.
- **No session at all:** the gates see no session, so they pass, as for an API key. The
  session-touch step does nothing.

### 5. `BearerTokenDeps.Sessions` becomes optional in one case

- **The rule:** `Sessions` may be nil only when `Verifier` is an `*oidcprovider.AccessTokenVerifier`
  with no first-party route. Every other verifier keeps the "all three required" error.
- **Hidden verifiers:** a verifier wrapped by the consumer cannot be seen, so it still needs
  `Sessions`. A nil-`Sessions` bearer that somehow meets unmarked claims at runtime fails closed with
  a configuration error.
- **Why:** a resource-server-only chain should not have to wire a session store it never reads.

### 6. The bearer's binding requirement for grant-backed tokens

- **Default:** a grant-backed token with an empty `cnf` is refused with `ErrInvalidToken`, challenged
  under `DPoP`, whatever `DPoP.Require` says.
- **Override:** `WithBearerUnboundGrantTokens()` accepts one under `Bearer`.
  - If `DPoP.Require` is on, the chain still refuses it.
  - Under the `DPoP` scheme it is refused with `ErrInvalidDPoPProof` (RFC 9449 §7.1).
- **Construction check:** keeping the default with the provider's verifier on a chain with neither
  `EnableDPoP` nor `EnableCertificateBinding` fails construction, because no grant-backed token could
  ever be accepted.
- **Sign-in is unaffected:** the requirement never reaches an issuing endpoint, and never touches
  first-party tokens.

### 7. `ErrInvalidToken` and its challenge

- **The sentinel:**
  `var ErrInvalidToken = fmt.Errorf("httpsec: invalid access token: %w", authenticate.ErrAuthenticationFailed)`.
  It is a 401 through the existing row.
- **Which refusals return it:**
  - a verifier error marked as provider-routed;
  - the unbound refusal of decision 6.
  An unmarked rejection keeps today's `errors.Join(ErrAuthenticationFailed, cause)`, with no
  challenge.
- **Where the challenge is written:** the chain's challenge path maps `ErrInvalidToken` to
  `error="invalid_token"`.
  - With DPoP on: the `DPoP` scheme with `algs` when the token came under `DPoP`, is bound, or the
    binding default applies; `Bearer` otherwise.
  - With DPoP off: an always-registered fallback challenge interceptor writes the `Bearer` form,
    because `dpopChallenge` does not exist then.
- **`ErrMalformedRequest` from step 1 of decision 4** gets `invalid_request` the same way.
- **The missing-caller challenge:** `dpopChallenge` stops offering `Bearer` when the bearer's verifier
  is grant-backed-only and binding is required by default. Then no `Bearer` token could be accepted.
- **Override:** a consumer's `WithErrorHandler` edits the headers, as for every challenge.

### 8. What is published

- **Caller:** `ex.Authentication` and `WithCaller(ctx, auth)`.
  - `auth.Principal` is `PrincipalFromDetails(details)` with `Scopes` a copy of the token's scopes.
  - `auth.Credentials` names `factor.AccessToken`.
  - `ex.Session` stays nil.
- **Token:** `httpsec.AccessTokenFromContext(ctx) (*oidcprovider.AccessToken, bool)` returns a deep
  copy.
- **`RecordPresentedToken`** is called, as for any bearer token.
- **The renewal endpoint** refuses a grant-backed caller with `ErrAuthenticationRequired`.
- **Construction refusals:** under `WithBearerUsernameSubject`, the provider's verifier is a
  configuration error, because provider tokens carry the user's identifier as `sub`.

### 9. Scopes on a user principal, and the `access-token` factor kind

- **Scopes:** `identity.Principal.Scopes` was documented as being for service principals only. It
  now also carries an access token's granted scopes, so `authorize.HasAnyScope` and `HasAllScopes`
  work on API routes unchanged. A session-authenticated principal still carries none.
- **The kind:** `factor.AccessToken` (`"access-token"`) has no channel and is exempt from an MFA
  requirement.
  - The grant was issued only after the provider's resume, which runs behind the chain's MFA gates,
    so the requirement was already judged.
  - Without the exemption, an MFA requirement policy would challenge every API call. There is no
    session on which to hold that challenge.
- **Alternative considered:** reporting `federated` and leaving it to federated-assurance rules. That
  would need the grant's `amr`/`acr` on `AccessToken`, which it does not carry today.

### 10. Construction refuses a first-party generator typed `at+jwt` beside the provider's verifier

- **New port:** an optional interface, `token.TypedGenerator { TokenType() string }`. The generator
  `token.NewGenerator` returns implements it.
- **The check:** while the bearer's verifier is the provider's, every generator the chain is given
  is checked in `validate`, beside the existing subject-mode check, because the verifier would route
  that generator's tokens to the provider and refuse them.
- **The documented line:** a generator that does not implement the interface cannot be seen. That is
  the same line the subject-mode check documents.

### 11. Password policy: consumer rules

```go
policy, err := password.NewPolicy(
    password.MinLength(10),
    password.WithRule("letters-and-digits", func(ctx context.Context, candidate string, _ *identity.Details) (bool, error) {
        return hasLetter(candidate) && hasDigit(candidate), nil // false refuses
    }),
    password.NoReuse(history, 1),
)
```

- **The API:** `WithRule(name Rule, check RuleFunc)`, where
  `type RuleFunc func(ctx context.Context, candidate string, user *identity.Details) (ok bool, err error)`.
- **Order:** consumer rules run after the lists and before the breach lookup. They are cheap, local
  checks that should not spend a network call.
- **Refusal:** a refusal is `RejectedError{Rule: name}`, so it matches `ErrPasswordRejected` and not
  `ErrReused`. That gives the consumer its distinct "weak" and "reused" reasons.
- **Failure:** an error from a rule fails closed, behind fixed text, with the error reachable.
- **Default:** no consumer rule. The library ships no composition rule, following NIST SP 800-63B.
  The settled `password-policy` requirement keeps its "SHALL NOT impose composition rules" wording,
  because the rule is the consumer's.

### 12. Inactive-account disclosure (departure from the established design)

- **The departure:** the established design always folds an inactive account into the uniform
  failure. scrty keeps that as the default status, headers and timing.
- **The new behaviour:**
  - The password provider now returns `errors.Join(ErrAuthenticationFailed, ErrAccountInactive)`, and
    only after the password has verified.
  - The new chain option `WithInactiveDisclosure()` turns that refusal into `ErrAccountInactive` alone,
    which `StatusForError` maps to 403.
- **Why:**
  - It mirrors `WithLockDisclosure`, which already exposes the lock beneath the uniform failure.
  - Inactive is only reported to a caller who proved the password, so it discloses no more than
    "this password is right".
  - The consumer's sign-in page needs a stable reason code.
- **Why 403:**
  - The caller is identified and refused. 401 would invite a retry with the same credentials.
  - 423 is WebDAV-specific.
  - A consumer maps it differently in its handler.
- **Basic:** a disclosed Basic refusal carries no `WWW-Authenticate` header, as for a disclosed lock.
- **Recovery:** account recovery keeps `recovery.ErrRefused`.
- **Compatibility:** a consumer that matched errors on `ErrAuthenticationFailed` sees no change. Only
  `errors.Is(err, ErrAccountInactive)` newly holds. This is recorded under *Changed* in the changelog.

### 13. Release

The next lockstep version is `v0.2.0`. Major version 0 promises no compatibility, but new API plus
one changed error identity is a minor release under the changelog's own convention. The change
prepares `CHANGELOG.md`, `SECURITY.md`, `README.md` and the nested `go.mod` requirements, and runs
the release gate. Tagging and pushing stay with the maintainer, as `RELEASING.md` says.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Empty, whitespace or scheme-only `Authorization` | Handled by the bearer today, tested | Not claimed; no caller |
| F2 | Two `Authorization` headers, with the provider's verifier | Handled, tested | 400, `invalid_request` |
| F3 | Query `access_token` beside the header, with the provider's verifier | Handled, tested | 400, `invalid_request` |
| F4 | JWT header oversized, not base64url, not JSON, or `typ` containing `at+jwt` only as a substring | Handled, tested | Routed to the first-party verifier, or refused as invalid |
| F5 | Altered signature, unknown key, wrong issuer on an `at+jwt` token; an ID token (`typ JWT`) | Handled, tested | 401 `invalid_token`; the ID token goes first-party and is refused there (401) |
| F6 | Expired token, including exactly at `exp` | Handled by the provider, tested | 401 `invalid_token` |
| F7 | Grant revoked, expired, swept, or naming another client or user | Handled by the provider, tested | 401 `invalid_token` |
| F8 | Grant store, access-token store or key source down | Handled, tested | Dependency failure, 500 by default, ERROR record sampled |
| F9 | Caller cancels during verification or user load | Handled, tested | Error matching the context's error; no ERROR record |
| F10 | Audience missing, another resource, or the issuer only | Handled, tested | 401 `invalid_token`; no proof recorded |
| F11 | Unbound grant-backed token under the default | Handled, tested | 401 `invalid_token` under `DPoP` |
| F12 | Bound token under Bearer, no proof, bad proof, stale `iat`, wrong `htm`/`htu`/`ath`, replay, wrong key | Handled by the existing bearer binding, tested | 401 `invalid_dpop_proof` |
| F13 | A consumer verifier tries to mark claims grant-backed | Handled by the compiler (`internal`), tested by a guard | Impossible outside scrty; unmarked claims take the session path |
| F14 | Nonce required or stale | Handled, tested | 401 `use_dpop_nonce`, fresh `DPoP-Nonce` |
| F15 | Nonce cipher or replay store down | Handled, tested | Dependency failure, not a refusal |
| F16 | Two requests race the same proof `jti` | Handled by the replay store's atomic record, tested | One accepted, one `invalid_dpop_proof` |
| F17 | User missing or inactive | Handled, tested | 401 auth-required, `DPoP` challenge; proof not consumed |
| F18 | User loader outage | Handled, tested | Dependency failure; proof not consumed |
| F19 | Loader answers for another user than the subject | Handled, tested | Refused as auth-required; ERROR record naming neither user |
| F20 | Token issued before a role was removed | Handled, tested | Principal has current roles |
| F21 | Token issued before a password-change mark was set | Accepted | The gates read a session, and a token caller has none. The token lives at most its lifetime (5 minutes by default), and a consumer who needs it ended at once calls `RevokeUserGrants` when it sets the mark. Documented on `AccessTokenVerifier`. |
| F22 | Offline-access grant survives logout | Accepted (settled `oidc-provider-tokens` behaviour) | The token is accepted until its grant ends; documented for consumers |
| F23 | Bad audience; nil `Sessions` with a non-provider verifier; username subject with the provider's verifier; binding default with no binding feature; generator typed `at+jwt` | Handled, tested | Construction error |
| F24 | Multi-replica deployment with the in-memory replay store | Accepted (settled DPoP behaviour) | A proof can be replayed once per replica; documented on `DPoP.Replay` |
| F25 | A consumer handler mutates the published token | Handled, tested | Each read is a copy |
| F26 | Token or user identifier in a log, error or event | Handled, tested | Fixed reasons only |
| F27 | Password consumer rule panics, errors or is typed-nil | Error: handled and tested, fails closed. Typed-nil: a construction error. Panic: accepted, propagates like any consumer port. | As stated |
| F28 | Inactive check reached before the password verifies | Handled, tested | Wrong password stays uniform under disclosure |
| F29 | Chain clock and provider clock disagree | Accepted | The provider's clock judges expiry and the chain's clock judges proof age. A consumer wires one `clock` to both; documented. |
| F30 | Unmarked claims reach a bearer with nil `Sessions` (a wrapped verifier slipped past construction) | Handled, tested | Fails closed with a configuration error, 500 |
| F31 | A grant-backed caller hits the renewal endpoint | Handled, tested | 401 auth-required; nothing issued |

## Risks / Trade-offs

- [The shape peek is new parsing of hostile input] → Bound the header at 4 KiB, use base64url without
  padding only, never grant on the peek, and fuzz the peek function.
- [Skipping the session lookup is a new branch in the bearer's hot path] → The branch is taken only on
  the internal mark, and a guard test proves a public-constructor claim never takes it.
- [Exempting `access-token` from MFA requirements trusts the provider's sign-in] → Documented on the
  kind. A provider wired on a chain without MFA gates gives tokens without a second factor, which is
  already true of its tokens at UserInfo.
- [Changing the bearer could change first-party behaviour] → The bearer's existing suites run
  unchanged as a safety net, before and after each dispatch.
- [The fallback challenge interceptor and `dpopChallenge` could both write a header] → One "already
  answered" mark, and a test asserting exactly one `WWW-Authenticate` value per refusal kind.
- [`ErrAccountInactive` newly reachable beneath the uniform failure] → It is reachable only after a
  correct password, and is recorded under *Changed*.

## Migration Plan

- The change is additive for consumers. A consumer upgrading from v0.1.1 who enables nothing new sees
  only the `ErrAccountInactive` join.
- Rollback is a downgrade to v0.1.1. No migration or stored data changes.

## References

**Researched** (consulted 2026-11-16 for the decisions named):
- The user's decision of 2026-11-16, at the consumer's request, to reuse `EnableBearerToken`
  (decision 1).
- Reasoned from scrty's own settled specs (`sender-constrained-tokens`, `oidc-provider-tokens`,
  `oidc-provider-userinfo`, `http-error-propagation`, `password-policy`, `authentication`) and the
  established design, for decisions 3, 4, 5, 9 and 12.

**Primary documentation** (relied on and cited as such, not re-checked on that date):
- [RFC 9449, OAuth 2.0 DPoP](https://www.rfc-editor.org/rfc/rfc9449): §4.3 proof checks, §7.1 the
  resource server's checks and its `invalid_token`/`invalid_dpop_proof` split, §7.2 challenges, §9
  nonces. Supports decisions 4–7.
- [RFC 6750, Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750): §2 one method per request,
  §3.1 error codes and statuses. Supports decisions 3 and 7.
- [RFC 9068, JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068): §2.1
  `typ at+jwt`, §4 the resource server validates the audience. Supports decisions 1 and 2.
- [RFC 8707, Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707): absolute-URI resources as
  audiences. Supports decision 1.
- [RFC 7515, JWS](https://www.rfc-editor.org/rfc/rfc7515): §4.1.9 `typ` matching without regard to
  case, and omitting `application/`. Supports decision 2.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html): §5.1.1.2 verifiers should not
  impose composition rules. Supports decision 11.
