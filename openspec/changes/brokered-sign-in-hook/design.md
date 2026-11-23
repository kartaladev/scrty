# Design

## Context

See `proposal.md` (Why). The current state that shapes the approach:

- `RelyingParty.Callback` (`authenticate/oidc/login.go`) completes the flow and exchanges the code.
  `exchange` decodes only `id_token` (`tokenResponse`). `Callback` then verifies the ID token and
  calls `IdentityBroker.Broker(ctx, ExternalIdentity)`. The broker is a port (`ports.go`), and
  `*oidc.Broker` is the library's implementation. `RelyingParty` already type-asserts optional broker
  interfaces (`Links()`, `ConfiguredProviders()`, `RoleSyncProviders()`).
- The library broker resolves only through `LinkStore` (`FindByExternal`, `Insert`, `DeleteByUser`).
  Without a link it provisions create-only, or refuses with `ErrNoLinkedAccount`. Its errors pass
  through `redact`, which scrubs subject, emails, names and bcrypt-shaped text. Refusals go through a
  sampled logger. The link table already has an index on `user_id`
  (`store/migrate/securitystate/…_security_state.sql`, `oidc_links_user`).
- Provider metadata (`remote.go`) has no `userinfo_endpoint`.
- In `httpsec`, a successful callback is conveyed by a handoff code (`conveyHandoff`) or by a
  consumer `CallbackSuccess`. `oidcInterceptor` holds no `identity.UserLoader`; the handoff manager
  holds its own, unexported. Redemption (`oidc_redeem.go`) runs, in order:
  1. the source throttle;
  2. the proof binding;
  3. `oidcRedemptionCheck`, the post-authentication policy on the stored details and password-change
     time;
  4. the issuing login tail;
  5. the redeemer's consume;
  6. `guardRedemption` and `guardFederatedAssurance`;
  7. `session.WithExternalSession`;
  8. `cancelHeldRecoveries`;
  9. commit.
- The provider's resume route (`oidc_resume.go`) is an *inner* route. It runs behind the chain's
  bearer and per-request policy, and refuses sessions that are not full or that have a raised
  challenge. It builds `oidcprovider.SignIn` with `oidcSignInOf(session, assurance)` and calls
  `Provider.Resume`. It charges an unknown handle to the source, and runs `confirmSignIn` **after**
  `Resume`. The provider's `LoginURL` is unexported (`oidcprovider/provider.go`), and `Resume` may
  answer a `login_required` redirect with a nil error.
- The established design discards the upstream access token, and has no sign-in hook.

## Goals / Non-Goals

**Goals:**
- One opt-in path for a consumer to see upstream access and UserInfo on every brokered sign-in.
- Library-owned link decisions, made before any consumer write.
- A standards-only client that completes a federated sign-in server-side whenever nothing is owed,
  with every check the script path applies.

**Non-Goals:**
- Upstream refresh tokens, upstream token storage, or calling upstream APIs after the callback.
- Signed or encrypted UserInfo.
- DPoP or mTLS toward the upstream provider.
- Choosing among upstream providers on the login page.
- A server-rendered step-up UI.

## Decisions

### D1. Upstream access goes to an optional broker interface, not into `ExternalIdentity`

`RelyingParty` calls
`UpstreamBroker { BrokerUpstream(ctx, ExternalIdentity, Upstream) (*identity.Principal, error) }`
when the broker implements it, and `Broker` otherwise.

- **Default:** unchanged for every existing broker.
- **Override:** implement the interface, or use the hook (D5).

Alternatives rejected:
- A field on `ExternalIdentity`: it is plain data and prints.
- A new `IdentityBroker` signature: breaking.

### D2. `Upstream` cannot print its token, even nested

`Upstream` is a struct whose only field is a pointer to an unexported state struct. The state holds
the token, the endpoint resolver, the confined client and the ID token's subject. `Upstream` has
`Format`, `String` and `LogValue` methods that write the package's `redacted` text.

The pointer matters. When `fmt` meets an unexported field of a consumer's struct, it cannot call
these methods and prints the field by reflection. Through the pointer, it then prints an address,
never the token.

`AccessToken()` is the escape hatch for non-standard APIs. Its godoc places the logging
responsibility on the caller (`library-design.md` §2: no fork needed). The library keeps no
reference once `Callback` returns, but a broker may keep the value it was handed; the godoc says so.

### D3. UserInfo: one GET, JSON only, subject-bound, bounded

The request is a `GET` with `Authorization: Bearer` through the confined client's `Get`, so origin,
scheme, timeout and size limits apply. The response must be a 200 with a JSON object, and its `sub`
must equal the ID token's subject (OIDC Core §5.3.2). `application/jwt` is refused.

The members are returned unchanged: numbers are decoded as `json.Number`, so a large numeric
identifier keeps every digit. An object that repeats a member name is refused. RFC 8259 §4 leaves
such objects with unpredictable meaning, and Go's `encoding/json/v2` refuses them by default; a
repeated `sub` would otherwise let the last value win. An `access_token` in the token response that
is not a JSON string is treated as absent (RFC 6749 §5.1 defines it as a string), so a malformed
field never fails a login that does not use it (F1). The `token_type` is not checked: the token is
always sent as a bearer credential (accepted, F40).

Every failure is `ErrUserInfoFailed` with fixed text. The body is never logged and never put in an
error. There is no caching. Assurance is still read only from the ID token.

- **Default:** the discovered endpoint and the client's bounds.
- **Override:** a pinned endpoint (D4), and the `outbound.Client` given to `WithOutboundClient`.

### D4. `userinfo_endpoint` is discovered, or pinned optionally

`metadata.UserInfoEndpoint` and an optional `Provider.UserInfoEndpoint` are added, the pin validated
like the other pinned endpoints. The pin is outside the all-three-pinned rule. A missing endpoint
fails only `UserInfo`.

A discovered endpoint that is off the issuer's origin or uses a refused scheme is **dropped with a
WARN**, and discovery succeeds. This departs from the other discovered endpoints, whose confinement
failure fails discovery, because the endpoint is optional: failing discovery would break every
login through a provider that works today, to protect a call no login needs. The token never leaves
the issuer's origin either way. A provider whose UserInfo is on another host works through a pin.
The godoc of `Provider.UserInfoEndpoint` says so.

### D5. The hook decides; it may write only after the library accepts

```go
type SignInDecision struct {
    User      identity.UserID
    Provision bool                            // User does not exist yet; Apply creates it (D13)
    Apply     func(ctx context.Context) error // optional, unless Provision; the consumer's writes
}
type SignInHook func(ctx context.Context, ext ExternalIdentity, up Upstream, linked identity.UserID) (SignInDecision, error)
func WithBrokerSignInHook(provider string, hook SignInHook) BrokerOption
```

`linked` is the user the identity is already linked to, or empty. The library `*Broker` implements
`UpstreamBroker`. For a hooked provider, it runs:

1. `FindByExternal`. A store fault is a broker failure, never "no link".
2. The hook. Its errors are classified (D10).
3. **Checks, with nothing written yet:**
   - the decision names a user;
   - an existing link names that user, otherwise refuse with WARN (provider and email domain only);
   - the user loads with that reference and is active, otherwise `ErrNoLinkedAccount`;
   - for a new link, the one-link rule (D11).
4. **Link:** insert a missing link.
   - On `ErrLinkExists`, re-read the link. A different user means refuse.
   - Then re-check the one-link rule, and on a violation delete this link and refuse (D11).
5. **Apply:** run `Apply`, if set, with the link now final.
6. **Reload and resolve:** reload the user. An inactive user is `ErrNoLinkedAccount`, and the link
   stays. Resolve as `resolveLinked` does, then `principalFor`.

Because the consumer's writes run only after step 4, a decision the library refuses writes nothing.
That covers a conflict, a lost race, a second link, and a missing or inactive user. It closes the
takeover the audit found, where a hook overwrote another account's password hash before the conflict
refusal.

`Broker()` for a hooked provider, without upstream access, is `ErrUpstreamRequired`, a broker
failure, and the hook is not called.

- **Default:** no hook.
- **Override:** a hook per provider.

Alternatives rejected:
- *A single hook that writes freely:* takeover by write-before-check.
- *Passing `linked` only:* safety then rests on every consumer honouring it.

### D6. Hook conflicts fail at construction

A hook on the same provider as JIT provisioning, claim mirroring or role sync is `ErrConfig`, because
two writers of one user would contradict each other. Hook providers join `ConfiguredProviders()`, so
an unregistered one fails `NewRelyingParty`. There is no override: the combination has no
non-overwriting meaning.

### D7. Server-side completion runs the redemption and the resume, step for step

`WithOIDCProviderCompletion()` on `EnableOIDCLogin`, plus a new `OIDCDeps.Users identity.UserLoader`
that completion requires. `oidcprovider.Provider` gains an exported `LoginURL() string` accessor,
which is read-only and changes no behaviour.

At the callback, after `RelyingParty.Callback` succeeds:

1. **Recognise.** `Next` equals `LoginURL()` in scheme, host, port and raw path, and its query is
   exactly one non-empty `req`. Otherwise use `conveyHandoff`, unchanged. An empty login URL path is
   compared as `/`, the equivalent http(s) form (RFC 3986 §6.2.3), so a login URL configured as
   `https://id.example` is still recognised. A URL carrying userinfo never qualifies.
2. **Pre-check the handle.** `Provider.PendingRequest(handle, OIDCFlowCookie)`, behind the resume
   endpoint's source throttle (over the limit: `ErrOIDCThrottled`, with no lookup). Unknown, expired
   or foreign: charge the source as the resume endpoint does, and answer `ErrOIDCUnknownHandle`. A
   genuine handle that is past its login stage also answers `ErrOIDCUnknownHandle`, but is not
   charged, because it is not a guess. A pending-request store failure is a dependency failure, not
   charged. Nothing else has happened yet.
3. **Load.** Load the user through `OIDCDeps.Users`, refusing a missing, disabled or mismatched user
   as `Handoff.Redeem` does.
4. **Post-authentication policy.** The `oidcRedemptionCheck` logic, on the stored details, the
   password-change time and the callback's assurance, with `guardFederatedAssurance`.
   - Deny: the policy's refusal, and no session.
   - A step is owed: D8.
5. **Session.** Build it through the login tail, with `session.WithExternalSession` and the federated
   assurance in the creating write. Run `cancelHeldRecoveries`, then commit. No credential leaves the
   server.
6. **Per-request policy.** Judge the stored session under the chain's per-request policy, with the
   full-session and raised-challenge checks the resume route applies. On a refusal: end the session,
   then refuse.
7. **Resume.** `Provider.Resume` with `oidcSignInOf(session, <the chain's sign-in assurance mapping>)`,
   the flow cookie, the browser-session cookie and the session manager's idle timeout. An error, or a
   result that carries no code (such as `login_required` from an `id_token_hint` mismatch), ends the
   session. On an error, refuse. On a result with no code, redirect to that client error response.
8. **Confirm.** `confirmSignIn` after `Resume`, as the resume route does. On a failure: end the
   session, refuse, and send no redirect.
9. **Answer.** Set `OIDCBrowserSessionCookie`, clear the login flow cookie, and answer 303 to
   `RedirectTo` with `no-store` and `no-referrer`.

Wherever this list says "end the session", a failure to end it is logged at ERROR. No credential for
the session exists, so it is unusable either way.

- **Default:** off.
- **Override:** enable it. For a custom response, use `WithOIDCCallbackSuccess`, which is exclusive
  with completion.

Alternatives rejected:
- A shipped `CallbackSuccess`: no handoff to fall back to.
- Auto-redirecting the login stage to the upstream: the login page also offers password login.

### D8. An owed step falls back to the handoff to the login page

A Challenge outcome of the policy issues a handoff code with the destination
`<LoginURL>?req=<handle>`, through the existing handoff conveyance (a 302, as today). The
redemption of that code answers the same destination under the same exact-match carve-out, so the
page's `next` is never `/`. This is the allowlist carve-out in the `oidc-login` delta. The page then
redeems it through the existing check-then-consume redemption, finishes the step and resumes.
Research is cited in the References.

There is no override: the alternatives refuse admitted users or skip required steps.

### D9. Departure: the upstream access token is kept in memory for one callback

The established design discards it. scrty keeps it in the `Upstream` value for one `Callback` call,
and hands it only to an `UpstreamBroker`. It never enters `CallbackResult`, `Flow`, `HandoffRecord`
or a session. This is reasoned from scrty's settled specs and the established design; no defect is
claimed.

### D10. Hook error classification and observability

- `ErrNoLinkedAccount` and `ErrProvisioningRefused` from the decision pass through as
  authentication failures.
- Every other decision or `Apply` error, and an empty user, becomes a broker failure wrapped in fixed
  text. The consumer's chain is kept only for `errors.As` on the consumer's own types; the library's
  other sentinels are cut out of it, so that a wrapped `ErrFlowUnspent` or `ErrExchangeFailed` is not
  misread.
- A broker failure from the hook carries fixed text only, never the consumer's text, scrubbed or
  not. That is stricter than scrubbing, and it follows the project's rule that a dependency's error
  text never reaches a returned error. The consumer's error stays reachable through `errors.As` for
  concrete types declared outside the library; library types and interface targets match nothing,
  so no library outcome can be read out of a consumer's chain. `errors.Is` matches nothing either:
  a consumer sentinel made with `errors.New` shares its type with the library's sentinels, so no
  filter can tell them apart. A consumer that needs its own text logs it inside the hook, or wraps
  it in its own concrete type. The failure prints its fixed text through every `fmt` verb, `%#v`
  included, as `Upstream` does (D2).
- `redact` is extended with the upstream access token, for the library's own store-fault paths.
- New sentinels: `ErrUserInfoFailed` (a provider failure) and `ErrUpstreamRequired` (a broker
  failure). `httpsec` registers both in its sentinel inventory: the first with the provider failures
  such as `ErrExchangeFailed`, and the second as a broker failure.
- Hook refusals emit `AuthnLoginFail` through `emitCallbackRefused`. A completed sign-in emits the
  same events the redemption's login tail emits.

### D11. One link per user per provider and issuer, by default

Keycloak enforces this with a database constraint, and Auth0 warns that e-mail-based linking lets
an attacker attach a look-alike account (see References).

Under a hook, scrty refuses a decision that would give a user a second link from the same provider
and issuer. It lists the user's links through a new **optional** interface:
`LinkLister { ListByUser(ctx, identity.UserID) ([]Link, error) }`.

- **Store support:** the memory, `sqlstore`, `pgxstore` and `gormstore` link stores implement it. The
  `oidc_links_user` index already exists, so there is no migration. `LinkStore` itself is unchanged,
  so a consumer's store does not break.
- **Race:** the rule is re-checked after the insert, and a duplicate link is deleted again before the
  login is refused. Two concurrent new subjects for one user therefore end with at most one link.
  The worst case is both refused, which is safe, and the next sign-in retries.
- **Default:** refuse. A hook over a store without `ListByUser` fails construction.
- **Override:** `WithBrokerSignInHookAllowManyLinks(provider)`, which also removes the need for the
  lister.

### D12. Accepted limits

- **One SSO login at a time per browser.** The relying party's flow cookie has a single name, so a
  second SSO login started before the first returns invalidates the first. The first callback
  answers an invalid state, and the user starts again. The README states this.
- **Held recoveries are cancelled before the resume.** They are cancelled before the session is
  stored (D7, step 5), as in the redemption. If the resume then fails, the user has signed in at the
  SSO but the recoveries are gone. The handle pre-check (step 2) makes this rare. The cancellation is
  what the user's successful first factor calls for in any case.

### D13. A decision may provision a new user, linked before it is created

A hook adopts existing users (D5), but a consumer also needs to create a user on a first sign-in
through a hooked provider. JIT provisioning cannot do it, because it shares the provider with the
hook (D6). So `SignInDecision.Provision` lets the decision name a user reference that does not
exist yet, with an `Apply` that creates it under that reference (for example `admin.Importer` with
a fresh UUID).

For a provisioning decision, D5 runs with these differences:

- **Step 3, checks:** `Apply` must be set, otherwise a broker failure. The named user must **not**
  load (`ErrUserNotFound`), unless the identity's own link already names it. A user that loads
  without that link is refused as `ErrNoLinkedAccount`: provisioning never adopts. A loader fault is
  a broker failure. The conflict check and the one-link rule (D11) apply unchanged.
- **Step 4, link:** the link is inserted **before** the user exists, with an empty username (no user
  exists yet to name). `ErrLinkExists` re-reads the link as in D5: a link naming another user
  refuses, and `Apply` never runs.
- **Step 5, apply:** `Apply` creates the user.
- **Step 6, reload:** a user that is still missing is a broker failure, and the link stays. A
  disabled or mismatched user is `ErrNoLinkedAccount`, as in D5.
- **Recovery:** on a later sign-in the hook receives the link's user as `linked`. Deciding to
  provision it again re-runs `Apply`, because a user named by the identity's own link may be absent.

Link-first is the safe order. Two concurrent first sign-ins of one identity pick two fresh
references. Only one link insert wins, and the loser is refused before its `Apply`, so no orphan
user is created. JIT provisioning orders it the other way (create, then link), and accepts an
orphan on a failed link. The hook path does not need that trade, because the link table has no
foreign key to the user tables.

- **Default:** a decision does not provision.
- **Override:** set `Provision` in the decision.

Alternatives rejected:
- *Allowing JIT beside a hook on one provider:* two writers of one user (D6).
- *Create in `Apply`, then link:* a lost race leaves an orphan user that the consumer wrote.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Token response has no `access_token`, or one that is not a string | Handled, tested | Login proceeds; `UserInfo` fails `ErrUserInfoFailed` |
| F2 | Access token reaches a log, error, event, record or response, including through a consumer struct | Handled, tested | Redacted `Upstream` behind a pointer; `redact` covers the token; log-capture tests |
| F3 | UserInfo endpoint unknown | Handled, tested | `UserInfo` fails; other logins are unaffected |
| F4 | UserInfo 401/5xx, slow, oversized, not JSON, JWT | Handled, tested | `ErrUserInfoFailed`; bounds from the confined client |
| F5 | UserInfo `sub` differs from the ID token's, or the object repeats a member name | Handled, tested | `ErrUserInfoFailed`, no members |
| F39 | UserInfo redirects to another origin | Handled, tested | Refused by the confined client before the token is resent; `ErrUserInfoFailed` |
| F40 | The token response names a `token_type` other than Bearer | Accepted | Sent as Bearer anyway; the provider answers 401 and `UserInfo` fails `ErrUserInfoFailed` |
| F41 | Discovered UserInfo endpoint off the issuer's origin or on a refused scheme | Handled, tested | Dropped with a WARN; discovery and logins proceed; `UserInfo` fails with no endpoint (D4) |
| F6 | Context cancelled in UserInfo, the hook or `Apply` | Handled, tested | The context's error; no link inserted if before step 4 |
| F7 | Decision empty, or a non-sentinel error | Handled, tested | Broker failure; nothing written |
| F8 | Hook error text holds the subject, email or token | Handled, tested | The returned error carries fixed text only, in every `fmt` verb; nothing of the consumer's text is logged or returned (D10) |
| F42 | The hook, or an `Is` method on its error, panics | Accepted | The request's panic recovery answers it, as for any consumer code on the request path |
| F43 | The link store returns a link with an empty user reference | Handled, tested | Broker failure; the hook is not called, since an empty `linked` would read as no link |
| F9 | Decided user missing, disabled or mismatched | Handled, tested | `ErrNoLinkedAccount`; `Apply` not run; no link |
| F10 | Existing link names another user | Handled, tested | `ErrNoLinkedAccount`; `Apply` not run; link unchanged; WARN |
| F11 | Two first sign-ins of one identity race | Handled, tested | One link; both resolve, or the loser refuses; `Apply` only after the link is final |
| F12 | Link store fault on find, insert, list or delete | Handled, tested | Broker failure, redacted; never "no link" |
| F13 | `Apply` fails after the link is inserted | Accepted | Broker failure; the link stays and is correct; the next sign-in re-applies |
| F14 | Hook plus JIT, mirroring or role sync on one provider | Handled, tested | Construction error |
| F15 | Hooked provider brokered without upstream access | Handled, tested | `ErrUpstreamRequired`; hook not called |
| F16 | A second identity of the same issuer decided for an already linked user | Handled, tested | `ErrNoLinkedAccount` before `Apply` (D11) |
| F17 | Two new subjects race for one user | Handled, tested | At most one link remains; refused logins never `Apply` |
| F18 | A hook's store lacks `ListByUser` | Handled, tested | Construction error, unless many links are allowed |
| F19 | `Apply` deactivates the user | Handled, tested | `ErrNoLinkedAccount`; the link stays |
| F20 | Completion: handle unknown, expired or foreign | Handled, tested | Unknown-handle refusal, source charged, nothing created (pre-check) |
| F38 | Completion: handle past its login stage, source over the throttle, or the pending-request store fails | Handled, tested | Unknown-handle refusal (not charged), `ErrOIDCThrottled`, or a dependency failure (not charged); nothing created |
| F21 | Completion: user missing, disabled or mismatched | Handled, tested | Refused as redemption refuses |
| F22 | Completion: post-auth policy denies, or owes a step | Handled, tested | The policy's refusal, or the handoff fallback (D8) |
| F23 | Completion: per-request policy refuses | Handled, tested | The session is ended; the refusal is returned; no code |
| F24 | Completion: resume error, resume without a code, or confirmation fails | Handled, tested | The session is ended; a refusal or the client's error response; no code |
| F25 | Completion: ending a session fails | Accepted | ERROR log; no credential exists, so the session is unusable |
| F26 | Completion: session store fails | Handled, tested | Dependency failure; nothing resumed |
| F27 | Completion: destination spoofed (host, port, path case, encoding, slash, extra or repeated parameter) | Handled, tested | Ordinary allowlisted handoff |
| F37 | Completion fallback: the handoff redemption re-resolves the parked destination against the allowlist | Handled, tested | The redemption answers the parked destination under the same exact-match carve-out, never `/` |
| F28 | Completion wiring: no provider, a callback success handler, a custom redeemer, no handoff, no loader, a foreign session manager, a callback off the issuer's origin, a login URL with a query, or a user loader without completion | Handled, tested | Assembly configuration error |
| F29 | Two SSO logins in one browser | Accepted (D12) | The first callback is an invalid state |
| F30 | A consumer that calls `AccessToken()` then logs the token | Accepted | Documented on the accessor |
| F31 | Hook or `Apply` is slow | Accepted | Bounded by the request context; documented |
| F32 | A provisioning decision names a user that exists and is not linked to the identity | Handled, tested | `ErrNoLinkedAccount`; `Apply` not run; no link (D13) |
| F33 | A provisioning decision has no `Apply` | Handled, tested | Broker failure; nothing written |
| F34 | A provisioning `Apply` fails, or returns without creating the user | Handled, tested | Broker failure; the link to the missing user stays; a later provisioning decision for it resumes |
| F35 | Two first sign-ins of one identity provision different references | Handled, tested | One link; the loser is refused before its `Apply`, so no orphan user |
| F36 | A provisioned link records an empty username | Accepted | The link's username is for operators only and never a lookup key (D13) |

## Follow-ups

Out of scope here; each is a separate change.

- **oidc-link-removal** (`identity-linking`, security administration): remove one link by provider,
  issuer and subject, so an operator can re-point a re-created SSO account. Today the only API is
  `LinkStore.DeleteByUser`, which removes every link a user holds.
- **hook-provisioning-port** (`identity-model`, `identity-linking`, security administration): a
  provisioning decision (D13) creates its user through a create-with-this-ID port, with `admin` as
  a thin adapter over it, instead of the consumer calling `admin.Importer` under an actor.
- **jit-as-hook** (`identity-linking`): one user-intake path. Just-in-time provisioning becomes a
  sign-in hook the library supplies, so JIT and a consumer's `Provision` decision share one pipeline
  (link first, then create). It depends on hook-provisioning-port. Until then, both paths exist, and
  D6 keeps them off the same provider.

## Risks / Trade-offs

- **[E-mail matching lives in consumer code.]** The library never matches by e-mail. The
  one-link-per-user default limits the blast radius. The godoc and README recommend requiring
  `email_verified` or a single trusted provider.
- **[`AccessToken()` can leak.]** It is the consumer's documented responsibility, and the examples
  use `UserInfo`.
- **[Two conveyance paths for one login.]** Both run the same policy and the same login tail, in the
  order D7 lists, and the fallback is today's tested path.
- **[The login URL is trusted without an allowlist entry.]** Only an exact match is trusted, on the
  issuer's origin, with a sole `req`. Wiring refuses a login URL that carries a query.

## Migration Plan

Additive and opt-in. `LinkLister` is optional, so consumer link stores keep compiling. No migration,
because the index exists. The changelog notes the new optional interface and the new
`OIDCDeps.Users` field. Rollback: remove the options.

## References

### Researched (accessed 2026-11-24)

**D8, the owed-step fallback:**
- [Red Hat build of Keycloak: Integrating identity providers](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/22.0/html/server_administration_guide/identity_broker): a post-login flow runs broker-side steps such as 2FA after an upstream login.
- [Keycloak forum: External IdP + Keycloak OTP](https://forum.keycloak.org/t/external-idp-keycloak-otp/16842): OTP in a post-broker-login flow. Secondary source.
- [Auth0 community: MFA with SSO through an upstream IdP](https://community.auth0.com/t/end-users-forced-to-use-mfa-when-using-sso-with-upstream-idp/163790): broker MFA unless the upstream asserted it. Secondary source.
- [Ory Kratos: Upstream MFA carry-over](https://www.ory.com/docs/kratos/social-signin/upstream-mfa): upstream MFA honoured only when asserted.

**D11, one link per user per provider:**
- [keycloak-dev: User with multiple IdPs of the same type](https://groups.google.com/g/keycloak-dev/c/5-8obq588aU): a user can hold one federated identity per provider ("User is already linked with provider"), enforced by the `(identity_provider, user_id)` key. Secondary source; the constraint was reported for 2018–2021 releases.
- [keycloak-user: How to delete a federated identity](https://lists.jboss.org/pipermail/keycloak-user/2018-September/015415.html): the primary-key violation on `FEDERATED_IDENTITY(IDENTITY_PROVIDER, USER_ID)` when a second link is inserted. Secondary source.
- [Auth0: User account linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking.md) and [Auth0 community: account linking issues](https://community.auth0.com/t/account-linking-issues/115750): automatic linking by e-mail lets a malicious user who registers the same e-mail get linked to the victim's account. Partly a secondary source.

**D3, assurance from the ID token only:**
- [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html): the RP sets the minimum assurance it accepts, and only the IdP knows the AAL. Search summary; the full text was not re-read.

**D5, D6, D7, D9, D10, D12, D13:** reasoned from scrty's own settled specs and code, and the established design.

### Primary documentation

- [OpenID Connect Core 1.0 §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo): D3, the UserInfo request and the §5.3.2 `sub` match.
- [RFC 6749 – OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) and [RFC 7636 – PKCE](https://www.rfc-editor.org/rfc/rfc7636): D7, the code flow on both legs.
- [RFC 9700 – OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700): D1, D2, D9, no upstream token in the front channel.
- [RFC 9449 – DPoP](https://www.rfc-editor.org/rfc/rfc9449): D7, the client's tokens from the application's own provider are unaffected.
- [RFC 8259 §4 – JSON objects](https://www.rfc-editor.org/rfc/rfc8259#section-4): D3, names within an object should be unique, and duplicates give unpredictable results.
- [RFC 6749 §5.1 – Successful token response](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): D3, `access_token` and `token_type` in the token response.
- [RFC 3986 §6.2.3 – Scheme-Based Normalization](https://www.rfc-editor.org/rfc/rfc3986#section-6.2.3): D7 step 1, an empty http(s) path is equivalent to `/`.
