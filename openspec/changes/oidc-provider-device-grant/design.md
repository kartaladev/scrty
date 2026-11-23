# Design: the device authorization grant

## Context

See `proposal.md` for why. The provider today:

- **Protocol and HTTP are separate layers.** `oidcprovider.Provider` is the protocol layer (`Authorize`, `Resume`, `Token`, …), and `httpsec` turns HTTP into calls to it. The chain owns paths, CSRF, CORS, throttles and cookies.
- **The token endpoint dispatches in `Provider.Token`.** It reads `grant_type`, refuses anything other than `authorization_code` and `refresh_token` with `unsupported_grant_type`, and refuses a grant the client is not registered for with `unauthorized_client`.
- **Login and consent are handed off to the consumer's pages.**
  - A pending request is parked under a handle, bound to the browser's flow cookie (`FlowDigest`).
  - The consumer's login and consent pages read it through `Provider.PendingRequest`.
  - The pages resume it through `Provider.Resume`, which moves it from `StageLogin` to `StageConsent` and then `StageDone` by conditional writes.
- **Consent is decided by one function** (`consentNeeded`). `FirstParty` skips consent, and `offline_access` asks unless the client is `OfflinePreAuthorized` or consent to it is remembered.
- **Grants carry their sign-in.** `Grant.SignInFamily` names the sign-in the grant came from. `Grant.EndsWithSignIn` and the `offline_access` flag decide what an end of that sign-in revokes, through `Client.EndGrantsWithSignIn` and `KeepPublicWebGrantsPastSignIn`. A grant records `CodeID`, the code that created it.
- **Metadata is built in `httpsec`**, and `grant_types_supported` is hard-coded there.
- **Throttles live only in the chain**, each under its own namespace from `WithRateLimiterFactory`. The token endpoint's budget is 10 failed client authentications per source in 15 minutes.
- **The established design has no OpenID Provider side**, so there is no inherited behaviour to follow or depart from. Every decision below rests on the standards and practice in References, and on scrty's own settled provider specs.

## Goals / Non-Goals

**Goals:**

- The device grant, as RFC 8628 defines it, behind the provider's existing client authentication, login and consent handoff, grant model, DPoP binding and stores, adding as little new machinery as the flow allows.
- Every RFC 8628 §5 threat that the provider can act on is handled, tested, or accepted in writing (see Failure modes).
- Only additions: no existing exported signature changes, so the change fits a minor release.

**Non-Goals:**

- **A client-side helper.** `golang.org/x/oauth2` (v0.37.0, read 2026-11-20) has `Config.DeviceAuth` and `Config.DeviceAccessToken`, which poll and honour `slow_down`. The README shows a CLI using them, loopback first.
- **Rendering any page.** The chain still answers with status codes and redirects. The code-entry form, its error text and the "device approved" message are the consumer's.
- **Proximity checks, trusted-network rules and user-code deny lists** (RFC 10027 §6.1.1, 6.1.4, 6.1.8). These are left to the consumer's own pages and policies. A follow-up could add a hook.
- **Delivering a denial to a device before its next poll.** The device learns on its next poll, as RFC 8628 §3.5 defines.

## Decisions

### D1. Opt in twice: the provider, then the client

- **Default:** the device grant is off. The provider enables it with one option, `WithDeviceAuthorization(entryURL string, opts ...DeviceOption)`, which names the consumer's code-entry page. Each client then opts in through `Client.GrantTypes` with the new constant `GrantDeviceCode`.
- **Override:** the option's own settings (D3, D4, D6) cover the provider, and the client fields (D8, D9) cover each client.
- **Why provider-level too:**
  - Without the code-entry page there is no `verification_uri`, so a client registered for the grant on such a provider is a wiring mistake. It fails construction, or makes a registry's client unknown, as every other invalid client is treated.
  - Metadata can then advertise the grant exactly when it is usable.
- **Alternatives considered:**
  - Per-client only, with the URL in `Deps`. Rejected: every consumer would have to supply a URL for a feature they don't use.
  - Advertise the grant when any registered client lists it. Rejected: a durable registry is read lazily, so the provider cannot know that at construction.
- **Practice:** Keycloak, zitadel/oidc, Okta and GitHub all make the grant opt-in per client.

### D2. One provider call enters a user code, and the chain endpoint uses it (decided by the user 2026-11-20: "both")

- **The call.** `Provider.EnterUserCode(ctx, DeviceEntryInput{UserCode, FlowSecret, BrowserSessionSecret, Source, IdleTimeout}) (AuthorizeResult, error)`. It returns the same shape the authorization endpoint does: where the browser goes, with status 303, and the flow secret to set.
- **What it does, in order:**
  1. check the throttle;
  2. normalise the code (D5);
  3. look up an unexpired authorization by the code's digest;
  4. claim it for this browser with one conditional write;
  5. park a pending request bound to the browser's flow cookie;
  6. send the browser to the login page, or to the consent page when a browser session already answers.
- **Default:** the chain's `/oauth2/device` endpoint accepts GET with `user_code` and form POST. It applies the authorization endpoint's flow-cookie rule, where a POST without the cookie is turned into a 303 GET. It calls this method.
- **Override:** a consumer's own handler calls the same method. That gives them full control of the URL and page while keeping the throttle and binding, because both live inside the call (D6).
- **Alternative considered:** a consumer page backed by a store port, with the consumer doing the claim. Rejected: every consumer would have to reimplement the conditional claim and the throttle, which RFC 8628 §5.1 makes security-critical.

### D3. The device authorization record and its lifecycle

```
                 issue (device authorization endpoint)
                                 |
                                 v
   +-------- expired <------ [issued] --enter code (one CAS)--> [claimed] --+
   |   (any state but spent,     ^                                  |       |
   |    judged by the provider's |   poll: authorization_pending    |       |
   |    clock at each step)      |   or slow_down (CAS on           |       |
   |                             +-- last-poll time and interval)   |       |
   |                                                      consent (one CAS)  |
   |                                                       /             \   |
   |                                                [approved]        [denied]
   |                                                     |                |
   |                                     poll: spend (one CAS)   poll: access_denied
   |                                                     v
   |                                                 [spent] --replay--> revoke grant
   v
 poll: expired_token; sweep after expiry, spent records kept until
 expiry + 1 minute for replay detection
```

- **Record fields.** It is new, kept apart from `PendingRequest`, because its key and lifetime differ:
  - `ID`;
  - `DeviceCodeDigest`, the primary key;
  - `UserCodeDigest`, looked up among unexpired records only;
  - `ClientID`, `Scopes`, `Resources`;
  - `IssuedAt`, `ExpiresAt`;
  - `Interval` and `LastPolledAt`;
  - `State`;
  - `ClaimFlowDigest`, the browser that claimed it;
  - the approval: `User`, `GrantedScopes` and the approving `SignIn`;
  - `PollCount`, the version a poll's compare-and-set reads, so no write compares timestamps whose precision a database may truncate;
  - `GrantFamily`, assigned at approval, with the approval's `Offline`, `EndsWithSignIn` and `SurvivesSignInEnd` (D8). Assigning it at approval, not at the spend, lets an end of the sign-in or a consent revocation reach an approval the device has not exchanged yet (see "Reaching an unexchanged approval" below).
- **Reaching an unexchanged approval (refined while planning, 2026-11-22).** A code grant is reached before its exchange because the grant store asks the code store for outstanding families (`UnspentCodes`) and records a revocation for each. `DeviceAuthorizationStore` embeds `UnspentCodes` over its approved records, and the provider joins the grant store to a comparable union of the code store and the device store. `EndSignIn`, `RevokeUserGrants` and `RevokeConsent` then record a revocation for an approved device authorization's family. The exchange creates its grant over that revocation, finds it revoked, and answers `invalid_grant`. The union is a value type, so a second provider sharing the same stores joins an equal value, as `UseCodes` requires.
- **The pending request and the device record together.** The pending request parked at claim time (D2) is an ordinary `PendingRequest` that also names the device authorization's `ID`. Its stages run as usual. When the consent stage finishes, the provider approves or denies the device record instead of issuing a code.
- **Order inside one consent answer.** The provider writes the device record first, then spends the pending request's stage. If the second write fails, the device record is already decided, and the user's re-entry of the code is answered as invalid (D5). That is safe, because nothing is issued twice and nothing is half-applied.
- **Defaults:** lifetime 600 s and interval 5 s. Both are bounded as the spec says, and set by `WithDeviceLifetime` and `WithDevicePollInterval`.
- **Store port:** `DeviceAuthorizationStore`, with `Create(ctx, record, now)`, `LoadByDeviceCode`, `LoadByUserCode(ctx, digest, now)`, `Claim`, `Decide`, `RecordPoll`, `Spend` and `DeleteExpired`, and the two `UnspentCodes` methods. Each transition is keyed by the record's `ID` and is a compare-and-set on `State`, on `ExpiresAt` against the `now` the provider passes, and, for polls, on `PollCount`. A lost compare answers `ErrNotFound` and writes nothing. Its doc follows `PendingRequestStore`'s: the store never sees a secret, judges no expiry by its own clock, and puts no digest in an error.
  - **`Create` and live uniqueness.** `Create` first releases the user-code digest of any expired record holding it, judged by `now`, then inserts. A live record holding the digest makes it answer `ErrUserCodeTaken`, so the provider regenerates (D4). A SQL adapter does this in one transaction under a unique index on the user-code digest, so two concurrent issuers of one code cannot both succeed. The expired record keeps its device-code digest, and with it the replay window.
- **Defaults and overrides:** `MemoryDeviceAuthorizationStore` by default, replaced with `WithDeviceAuthorizationStore`, with `sqlstore`, `pgxstore` and `gormstore` adapters.
- **Alternative considered:** reuse `PendingRequest` with a device stage. Rejected:
  - a pending request is keyed by a browser handle, while a device authorization exists before any browser has seen it;
  - widening the existing port would change a contract other stores implement.

### D3a. The SQL device store (lane B1, 2026-11-23)

Departures from the plan, judged sound by the B1 review, and shared by the three durable stores through `internal/pgschema`:
- **A plain unique index on `user_code_digest`,** not a partial one. Create releases an expired holder's digest in the same unit, so only an unexpired holder blocks, as the port says, and a plain index serves a generic prepared plan.
- **`interval_ns`,** not `interval_ms`, matching the `*_ns` duration columns on `op_clients` with no precision lost.
- **The pending request's device authorization link is `uuid NULL`,** not `text DEFAULT ''`, following the existing `code_id` convention.
- **The approving sign-in is stored as `jsonb`, with its selector columns copied beside it** by the same statement, as pending requests store a sign-in and as authorization codes are indexed.
- **`op_clients` gains `device_complete_uri` and `device_grants_outlive_sign_in`,** without which a durable client registry would lose both client settings.
- **Create inserts with `ON CONFLICT DO NOTHING` and then checks whether the key is held,** rather than mapping a unique-violation error: that error would abort the caller's transaction without a savepoint, and the driver's detail would carry the digest.
- **The store refuses on write and on read** a zero grant family, an unknown state or grant origin, and negative counts or intervals.

### D4. Codes

- **Device code.** 32 bytes from the provider's random source, base64url-encoded, and stored as its SHA-256 digest, as handles are. That is more than the 128-bit floor.
- **User code.** The default alphabet is RFC 8628 §6.1's `BCDFGHJKLMNPQRSTVWXZ`, 8 characters, drawn uniformly by rejection sampling from the random source and shown as `XXXX-XXXX` (about 34.6 bits).
  - The format can be replaced with `WithUserCodeFormat(alphabet string, length int)`. Construction refuses fewer than 2^29 possible codes, which still allows zitadel's and Ory's 9-digit preset, and refuses repeated or non-printable characters. It also refuses non-ASCII characters, whitespace and `-`, because normalisation strips the last two and would make such a code impossible to enter. Length is bounded at 32. A code is shown in groups of 4 when its length divides by 4, otherwise in groups of 3 when it divides by 3, and otherwise ungrouped.
  - The user code is stored as a digest, so it has to be unique among live records. A collision regenerates the code. The provider tries at most 5 codes in all, then fails as a server error.
  - The digest is a keyed HMAC under a per-provider key from the random source, not a bare SHA-256. With about 34.6 bits, a bare hash could be reversed offline from a database leak. An in-memory key means codes in flight become invalid after a restart, which is safe and only costs the user starting again. A durable deployment supplies a stable key, with `WithUserCodeKey`, or every replica fails to find the others' codes. Construction fails when the device authorization store is durable and no key is given. As with `WithRefreshTokenStore`, any store given through `WithDeviceAuthorizationStore` other than a `*MemoryDeviceAuthorizationStore` counts as durable.
- **Why digests at all:** the project rule that no durable store holds a credential in clear, and the existing handle pattern.

### D5. Normalisation and the single refusal

- **Normalisation.** Strip whitespace and `-`, then upper-case when the alphabet has no lower-case letters. A character outside the alphabet, or the wrong length, is refused without a lookup, but still charged to the throttle.
- **One refusal.** Unknown, expired, claimed by another browser, decided and spent codes all return `ErrInvalidUserCode`. The chain maps it to 400 with no body. The consumer's handler renders "that code didn't work".
- **Why one answer:** RFC 8628 §5.1, and the chain's rule of no oracle. A second browser being refused is also the defence against the screen-watcher of §5.5: the real user's later entry fails, and they start again.

### D6. The provider throttles failed entries itself

- **Default:** a `ratelimit.SourceGuard` inside the provider, with an in-memory limiter allowing 5 failures per source in 10 minutes.
  - It runs before the lookup. A throttled source is refused with `ErrThrottled`, which maps to 429, even when the code is valid. Otherwise a throttled source would learn that a code is valid.
  - **It charges before the lookup, and refunds what was not a failure (decided 2026-11-23, after a security review).** A guard that checks with `Exceeded` and records afterwards lets a concurrent burst from one source through: every attempt may pass the check before any records, so a limit of 5 admits as many guesses as the burst is wide (the guard's own godoc states this bound). The entry instead charges the source with `ratelimit.Charger.Charge` before normalising or looking anything up, and refunds the receipt for any outcome other than `ErrInvalidUserCode` (a claim, a re-entry, a dependency or configuration error). The guard still supplies the key and the unattributable-source refusal. This is the pattern recovery codes already use for the same reason: a short secret open to guessing.
  - The entry guard has no IPv6 aggregate, so only the source key is charged. Adding an aggregate later needs a charge for it in `ratelimit`, because recording it through `SourceGuard.RecordFailure` would count the source twice.
  - It fails closed when the limiter errors, as `SourceGuard` does.
- **Override:** `WithUserCodeEntryLimiter(limiter ratelimit.Limiter)`. A `ratelimit.Limiter` carries its own rate, so the consumer sets the rate by building the limiter. The defaults are exported as `DefaultUserCodeEntryLimit` (5) and `DefaultUserCodeEntryWindow` (10 minutes), for a factory to be asked with.
  - **How the chain passes its limiter (decided while planning, 2026-11-22).** The provider is built before the chain, so the chain hands the limiter over with `(*Provider).UseUserCodeEntryLimiter(limiter) error`, the way `GrantStore.UseCodes` joins its code store. `EnableOIDCProvider` calls it in the chain's `New`, before any traffic, when a `WithRateLimiterFactory` is configured. A limiter the consumer gave with `WithUserCodeEntryLimiter` is never replaced: the call answers nil and changes nothing. A second call with the same limiter changes nothing. A different one is refused with `ErrConfig`, so the chain's `New` fails instead of silently splitting the counts. A nil limiter is refused, and the call is safe for concurrent use. The chain passes a limiter from its `WithRateLimiterFactory` under the namespace `oidc-device-entry` when the consumer configured one, so shared (Redis or Postgres) limits cover the device flow too.
  - **The hand-over carries the factory and the source keying (decided by the user 2026-11-23, after the C1 review).** Two defects were reproduced against the limiter-only hand-over. First, the chain's `WithIPv6SourcePrefix` never reached the entry guard, which keyed IPv6 by its default /64, so a deployment keying by /48 gave one /48 65,536 entry budgets. Second, a durable factory (Redis, SQL, pgx) returns a new limiter handle on every `NewLimiter`, so a second chain over the same provider was always refused by the identity comparison. The chain now hands over its `ratelimit.LimiterFactory`, the namespace `oidc-device-entry` and its `*ratelimit.SourceKeyer`. The provider asks the factory for its limiter once, at the default rate, and builds its guard with that keyer. A later hand-over with the same factory (compared as a value, so the same factory pointer), the same namespace and the same IPv6 prefix changes nothing. A different one is refused with `ErrConfig`, as before. A consumer who gave `WithUserCodeEntryLimiter` keeps its limiter, and may set the keying with `WithUserCodeEntryKeyer`; without that option the chain's keyer still applies to the consumer's limiter, so the keying stays the chain's wherever a chain exists. Two factory values that reach the same backend but are not equal are refused; such a deployment gives the provider its limiter with `WithUserCodeEntryLimiter`.
- **Why in the provider, against the project's pattern of throttles in the chain:** D2's consumer path has no chain endpoint in front of it, and a throttle the consumer can forget is not a default.
- **The device authorization endpoint** is throttled in the chain like the token endpoint: failed client authentications only, 10 per 15 minutes, under its own namespace `oidc-device-authorization`.
- **Accepted:** the number of open authorizations is not capped per client. See Failure modes.

### D7. Consent always asks, and records as usual

- **Default:** `consentNeeded` returns true for any device-origin pending request, before the `FirstParty` and pre-authorization checks.
- **Override:** none on purpose. Always showing consent is the RFC 10027 §6.1.14 mitigation for consent phishing, the attack seen in 2025. A consumer who wants a one-click page can render it that way, but cannot skip it.
- **What the consent page sees.** The pending view gains `Device *DeviceView`, holding the user code as issued, the request time and the client. The page can then show "a device asked at 10:42 for access to your account — did you start this? Code BCDF-GHJK", with Deny as prominent as Approve.
  - The view holds the user code's display form. That form is kept on the pending request at claim time, not on the device record. It is the code the user just typed, and showing it back is the RFC 8628 §3.3.1 confirmation.
  - **Held in clear once claimed (decided by the user 2026-11-22).** The pending request gains `DeviceAuthorizationID` and `DeviceUserCode`, and the migration adds both columns to the pending-request table. A claimed code is no longer a credential: it is bound to one browser's flow cookie, every other browser is refused, and it never yields a token. A copy of the store therefore gives an attacker nothing to use. The rule is "no store holds a device code, or a user code not yet claimed, in clear".
  - **Alternatives considered.** Not storing the code removes the confirmation, a mitigation RFC 8628 §3.3.1 and RFC 10027 §6.1.14 recommend. Sealing it adds key handling and a construction-time dependency to protect a value that is no longer secret.
- **Approval is remembered** as any consent is, so the existing revocation and "apps with access" features reach device grants unchanged.

### D8. The approving sign-in and the grant's life (decided by the user 2026-11-20: option C)

- **Default (option A):** a device grant follows Back-Channel Logout §2.7, as code grants do. `Grant.SignInFamily` is the approving sign-in. A grant without `offline_access` is revoked when that sign-in ends, and one with it survives.
- **Override (the new part):**
  - `Client.DeviceGrantsOutliveSignIn` keeps device grants without `offline_access` past that end.
  - The existing `EndGrantsWithSignIn` still ties every grant to its sign-in, so the two contradict each other and setting both fails construction.
  - The public-web default of `EndGrantsWithSignIn` counts too, unless `KeepPublicWebGrantsPastSignIn` turns it off.
- **Mechanics:** one rule decides whether a grant, or an approval not yet exchanged, ends with its sign-in: `EndsWithSignIn || (!Offline && !SurvivesSignInEnd)`. `EndsWithSignIn` wins over everything. Under the new setting, a device grant is recorded with `SurvivesSignInEnd`, so the end of its sign-in does not select it: it behaves as if `Offline` were true for that purpose only. For every code grant `SurvivesSignInEnd` is false, so the rule reduces to the existing `!Offline || EndsWithSignIn` and no existing row changes meaning. The grant store's end, the device store's `UnspentBySignIn`, the grant's lifetime cap and the sign-in-end event all apply this one rule.
- **A refinement worth keeping:**
  - Under the default, an approval without `offline_access` whose sign-in ends before the device polls gets `invalid_grant`, as a code does in that case.
  - The grant's absolute lifetime is capped at the sign-in's absolute deadline, as for code grants, unless it survives the sign-in.
- **Why A as the default:** OIDC Back-Channel Logout §2.7 is the only rule in any standard, and scrty already applies it. Providers that keep device tokens alive after logout (Okta, Auth0, Google, GitHub, Hydra) do so for every flow, not for the device flow specifically. Okta and Auth0 require `offline_access` for a device refresh token. A CLI that wants to stay signed in asks for `offline_access`, and always-on consent (D7) makes that request visible.
- **`Grant.CodeID`.** A device grant records its device authorization's `ID` there, and gains `Origin` (code or device) so that reports and the sweep's "kept until every code that could name it expired" rule look at the right record.

### D9. `verification_uri_complete` is a per-client opt-in

- **Default:** off.
- **Override:** `Client.DeviceCompleteURI`. When it is on, the URI is the consumer's code-entry page with `user_code=<code>`. Opening that link claims nothing: the page pre-fills the code and shows it, and the user submits it to the chain's endpoint.
  - The chain's endpoint claims on a GET carrying `user_code` only when the browser reports the navigation as its own (decided by the user 2026-11-23, after the C1 review): `Sec-Fetch-Site` of `same-origin`, `same-site` or `none`, or no header at all (a non-browser client, or a browser too old to send it). The 303 conversion of a cookieless POST needs the GET, and its redirected GET is `same-origin` or `same-site` when the entry page is the deployment's own. Any other GET carrying a code claims nothing and is redirected with 303 to the consumer's code-entry page with the code prefilled, capped in length, so the user confirms and submits it there (a POST, under the chain's CSRF check). The gate is always on, whether or not `EnableCSRFProtection` is given, because a claim is a state change a link must not make.
    - **Why:** the C1 review reproduced a cross-site link to `/oauth2/device?user_code=X` claiming the code and landing a signed-in victim on consent in one click, which is the Storm-2372 pattern this decision exists to stop.
    - **The redirect cannot loop.** An entry page on another site than the chain would bounce a cookieless POST to a `cross-site` GET, which would send the browser back to the page. Such a configuration, and an entry page that is the chain's own code-entry endpoint, fail construction with `ErrConfig`, unless a narrower rule that keeps the guarantee is found during C2 and recorded here.
  - The README tells consumers not to auto-submit, because the user's confirmation that the code matches the device is the RFC 8628 §3.3.1 defence.
- **Why off:** a prefilled link is what makes device-code phishing one click (Storm-2372 sent links). A TV or QR client turns it on knowingly.

### D10. Polling: `slow_down` only while pending, under one conditional write

- **The rule.** A poll of a pending authorization compares `now` with `LastPolledAt + Interval`.
  - Too soon: one conditional write records the poll and adds 5 s, and the answer is `slow_down`.
  - Otherwise: one conditional write records the poll, and the answer is `authorization_pending`.
  - A write that loses its compare (a concurrent poll) is answered `slow_down`, so two simultaneous polls never both pass.
- **Other states.** Approved, denied and expired authorizations are answered by their state, without the pace check. A client that polled too fast is not made to wait for tokens it is owed.
- **Override:** none. RFC 8628 §3.5 fixes the +5 s, and the interval itself is set by D3's option.

### D11. Exchange, replay and binding

- **Exchange order:**
  1. authenticate the client, or name a public one;
  2. load by the device code's digest;
  3. check the client, state and expiry;
  4. load and check the user;
  5. check the approving sign-in's end where it matters (D8);
  6. check the binding requirement;
  7. spend with one conditional write;
  8. create the grant and tokens through the existing `newGrant` and issuer path.

  Every refusal before step 7 leaves the record unspent, following the project's check-then-consume rule.
- **Replay.** A spent device code presented by the client it was issued to revokes the grant named by `GrantFamily`, if the key binding holds when the grant is bound. For a public client there is nothing else to prove: possession of the device code was always enough to take the tokens, so letting it end the grant adds no power. Ory does the same.
  - Detection lasts until one minute past the authorization's expiry, the same window the code-replay rule uses. Spent records are kept that long.
- **Binding.** A DPoP proof binds the grant through `newGrant`'s existing public-client path. `RequireBinding` is checked before the spend.
- **ID token.** No `nonce`. `auth_time`, `acr` and `amr` come from the approving sign-in, through the grant, as for code grants.

### D12. Endpoints, CSRF, CORS and metadata

- **Paths:** `OIDCDeviceAuthorization` at `/device-authorization` and `OIDCDeviceEntry` at `/device`, both under the provider prefix and movable by `WithOIDCProviderPath`. They are registered only when the provider has the grant enabled, so `Chain.Endpoints()` and the collision check see them only then.
- **CSRF:** the device authorization endpoint joins `providerEndpointsExempt`, because it is client-authenticated and uses no cookie. The code-entry endpoint is not exempt. Its GET is gated by fetch metadata (D9).
- **CORS:** neither device endpoint gets CORS headers. No browser client has a reason to call them cross-origin.
- **Metadata:** `grant_types_supported` is derived from the provider's capabilities instead of hard-coded. `device_authorization_endpoint` is added when the grant is enabled.
- **TLS:** both endpoints refuse plain HTTP unless the provider has the loopback issuer.

### D13. Events and redaction

- **Events:** `DeviceAuthorizationIssued`, `DeviceAuthorizationClaimed`, `DeviceAuthorizationApproved`, `DeviceAuthorizationDenied`, `DeviceCodeExchanged`, `DeviceCodeReplayed` and `UserCodeEntryThrottled`, named in the OWASP vocabulary style the existing events use.
- **No secrets in output.** No event, log line or error carries a device code, user code, digest, handle or flow secret. New input and result types implement `Format` and `LogValue` redaction, as `AuthorizeInput` does.

## Failure modes

Each relevant failure, its state, and what the caller sees.

| Category | Failure | State | Outcome |
|---|---|---|---|
| Input | device authorization request with no or an empty `scope` | handled, tested | `invalid_request`, as at the authorization endpoint. RFC 8628 makes `scope` optional, and RFC 6749 §3.3 lets the server refuse a request without one rather than assume a default, which scrty's settled authorization rules already do. |
| Input | user code with wrong case, spaces, dashes | handled, tested | normalised (D5) |
| Input | user code with a character outside the alphabet or the wrong length | handled, tested | `ErrInvalidUserCode`, charged to throttle |
| Input | repeated or empty parameter, NUL or invalid UTF-8, oversized scope | handled, tested | `invalid_request`, nothing issued |
| Input | unknown, expired, decided, spent or other-browser user code | handled, tested | one refusal (D5) |
| Security | user-code brute force from one source | handled, tested | 5 failures per 10 min, then 429 before lookup (D6) |
| Concurrency | more legitimate entries in flight from one source than the limit (for example behind one NAT) | accepted | the excess is answered as throttled until an in-flight entry finishes and is refunded; the cost of charging first |
| Security | a concurrent burst of wrong codes from one source | handled, tested | the charge is taken before the lookup in one indivisible step, so no more codes are looked up than the limit allows (D6) |
| Security | distributed brute force across many sources | accepted | about 34.6 bits, a 10-minute life and the per-source limit bound it. A global ceiling would let an attacker lock out every user. The consumer may supply a limiter with a global key. Stated in the README. |
| Security | consent phishing (attacker sends their code to a victim) | handled, tested (consent always shown, completion URI off) / accepted (residual) | No protocol fully prevents it (RFC 10027 §4.1). The always-shown, device-aware consent and short lifetime are the mitigations. The rest is user education, which is the consumer's. |
| Security | screen-watcher enters the code first (§5.5) | handled, tested | first claim wins. The real user's entry is refused, and they start again. |
| Security | cross-site POST makes a victim claim a code | handled, tested | CSRF protection on code entry (D12) |
| Security | leaked spent device code replayed | handled, tested | `invalid_grant` and the grant revoked (D11) |
| Security | offline reversal of user-code digests from a DB dump | handled, tested | keyed HMAC (D4) |
| Security | public client credentials extracted from a CLI | accepted | RFC 8628 §5.6: no new capability beyond starting one's own flow |
| Concurrency | the claiming browser submits its code twice at once | handled, tested | the entry that loses the claim reloads the record, finds its own flow digest, and parks too; nothing charged |
| State | the store applies a claim but reports a failure | handled, tested | dependency error carrying the flow secret, so the browser's re-entry reaches its claim |
| State | the claiming browser re-enters | handled, tested | a new pending request is parked (a pending request cannot be found by device ID without widening `PendingRequestStore`); the older one stays bound to the same flow, and `Decide` is a compare-and-set, so either deciding is safe |
| Concurrency | a browser with no flow cookie submits its code twice at once | accepted | each entry mints its own flow secret, so they are two browsers to the provider: one claims and the other is refused and charged. The user's page holds the winner's cookie and carries on. |
| Configuration | `UseUserCodeEntryLimiter` given a limiter whose value cannot be compared | handled, tested | never counted as the same as an earlier limiter, so a second hand-over is refused with `ErrConfig` rather than panicking |
| Concurrency | two browsers claim one code | handled, tested | one CAS wins (store race suite) |
| Concurrency | approval races denial | handled, tested | one CAS wins |
| Concurrency | concurrent polls | handled, tested | at most one `authorization_pending` per interval. A concurrent approved poll spends once. |
| Concurrency | consent answer and expiry at the same instant | handled, tested | the provider's clock is judged once, inside the decide call. After expiry nothing is approved. |
| State | device record decided but pending stage spend fails | handled, tested | device record wins. Re-entry is refused, and nothing is issued twice (D3). |
| State | spend succeeds but grant creation fails | handled, tested | the grant store has no row for the record's `GrantFamily`. The poll fails as a dependency error, and the device starts again. Tokens are never issued without a grant. |
| State | claim succeeds but parking the pending request fails | handled, tested | the entry fails as a dependency error. The claiming browser's re-entry finds its own claim (same flow digest) and parks again. Every other browser is still refused. |
| State | the browser session is gone when consent is answered, after the device record is decided | handled, tested | a revocation is recorded for the approval's `GrantFamily` (the approval cannot be withheld from the device as a code can), the stage is left unspent, and the exchange answers `invalid_grant` |
| State | the browser-session check fails as a dependency after the device record is decided | handled, tested | the approval is withdrawn as for a session that is gone, and the caller gets a dependency error |
| State | recording the withdrawal's revocation fails | accepted | logged by error type, and the approval stands until its sign-in's absolute deadline, or until a later `EndSignIn` for that sign-in reaches it through the device store's `UnspentCodes`. The exchange does not re-judge whether the sign-in ended: scrty keeps no store of ended sign-ins. Retrying the revocation would need a durable outbox the design does not have. |
| State | the user re-authenticates after a withdrawal | accepted | their next answer to the same pending request is refused as an unknown handle, because the device record is already decided; they start again from the device |
| Time | a revocation recorded for a family with no grant yet (a withdrawal, or a sign-in end or consent revocation reaching an unexchanged approval) | handled, tested | grant sweeps keep revocations for the longest device lifetime plus a minute, not only the longest code lifetime, so the revocation outlives every exchange the approval allows |
| Configuration | entry URL whose query already carries `result` | handled, tested | construction error naming `WithDeviceAuthorization` and `result`, since the resume redirect sets it |
| State | a sign-in passed in `ResumeInput.SignIn` ends between the chain's check and the decision, swept before the approval is written | handled, tested (A8, C1) | the sweep missed the approval, so the chain, re-reading the sign-in after the resume, calls `EndSignIn` again; through the device store's `UnspentCodes` that reaches the approval and revokes its family, and the poll answers `invalid_grant`. A browser-session sign-in needs no second call: consent decides first and checks the session second, as the code flow does. |
| State | sign-in ended or consent revoked between approval and poll | handled, tested | a revocation is recorded for the approval's `GrantFamily` through the union `UnspentCodes`. The exchange's grant is created revoked, and the poll answers `invalid_grant` with no token. |
| State | user disabled or deleted between approval and poll | handled, tested | `invalid_grant`, nothing recorded |
| State | approving sign-in ends before poll | handled, tested | `invalid_grant` unless the grant would survive (D8) |
| State | consent revoked after exchange | handled, tested | grant revoked through the existing consent revocation |
| Time | poll exactly at `ExpiresAt` | handled, tested | expiry is `now >= ExpiresAt`, matching the pending-request rule. The answer is `expired_token`. |
| Time | provider restarted with in-memory store or HMAC key | accepted | flows in progress are lost. The device gets `expired_token` or `invalid_grant` and restarts. Documented. |
| Dependencies | random source errors, short-reads, or yields only bytes rejection sampling discards | handled, tested | the draw fails with no partial code; a user-code draw stops after 256 bytes (an internal bound only a broken source reaches) and a device-code draw on the first short read |
| Dependencies | random source fails while the default user-code key is drawn | handled, tested | `New` fails with `ErrConfig` naming `WithUserCodeKey`, without the source's error text |
| Concurrency | the caller's context is cancelled while a device authorization is issued, including between collision attempts | handled, tested | no further attempt and nothing stored; the error matches `context.Canceled` |
| Security | a spent code (device or authorization) replayed without the client certificate a public client's grant is bound to | handled, tested | revokes nothing: a replay needs whatever binds the grant, the DPoP key or the certificate, judged as a refresh judges it. **This tightens the existing authorization-code replay path too** (found reproduced while reviewing the device path): before, a code replay checked only the DPoP key, so a certificate-bound grant could be ended by a replay without the certificate. A code replay whose grant cannot be read now answers a dependency error instead of revoking blind. |
| Security | a spent device code replayed in the instant between its spend and its grant's creation | accepted | no grant row records the key binding yet, so the replay revokes without a key proof. The holder of a leaked code can end the grant but never receive its tokens, and the window is one exchange's duration. The authorization-code replay path behaves the same; closing it would need the key thumbprint stored on the device record at the spend. |
| Dependencies | the grant store fails while a replay revokes | handled, tested | dependency error rather than `invalid_grant`, nothing revoked; the next presentation tries again |
| State | the grant is not created after a successful spend | handled, tested | dependency error and no token; the device's retry is answered as a replay (`invalid_grant`), leaving only a revocation record for a family with no grant |
| Dependencies | device store errors on a poll | handled, tested | dependency failure (5xx), never `authorization_pending` |
| Dependencies | limiter errors | handled, tested | fail closed: refused as throttled (`SourceGuard`) |
| Dependencies | consumer store judges expiry by its own clock | handled, tested | conformance suite fails, naming the case |
| Resources | many open authorizations per client (store growth) | accepted | each lives at most 30 minutes and is swept. The device authorization endpoint's client-authentication throttle doesn't cap a public client's issuance. A per-client cap is a follow-up if needed. |
| Resources | collision loop | handled, tested | at most 5 regenerations, then a server error |
| Configuration | entry URL not absolute, on another origin, or with a fragment or user information | handled, tested | construction error naming `WithDeviceAuthorization`, without repeating the value |
| Configuration | entry URL with whitespace, a control character, invalid UTF-8 or a malformed query | handled, tested | construction error naming `WithDeviceAuthorization`; such a URL cannot be typed or extended |
| Configuration | entry URL whose query already carries `user_code` | handled, tested | construction error naming `WithDeviceAuthorization` and `user_code`, since `verification_uri_complete` appends it (D9) |
| Configuration | two providers share one grant store, one with the device grant and one without | handled, tested | the second `New` fails with `ErrConfig`: the grant store joins one `UnspentCodes`, and joining the code store alone would stop sign-in ends and consent revocations reaching device approvals not yet exchanged. Providers sharing a grant store enable the device grant alike. |
| Configuration | client lists the grant on a provider without it | handled, tested | construction error, or unknown when read from a registry |
| Configuration | contradictory sign-in settings | handled, tested | construction error naming both |
| Configuration | durable store with no stable user-code key | handled, tested | construction error |
| Configuration | lifetime, interval or format out of bounds | handled, tested | construction error naming the option |
| Observability | a code in logs or errors | handled, tested | redaction tests on every new type |
| Observability | a device decision whose consent-stage spend fails | handled, tested | `DeviceAuthorizationApproved` or `Denied` is reported as soon as the device record is decided (its compare-and-set makes it once), because the device can exchange the decision whatever became of the stage; the consent store's own `ConsentGiven`/`ConsentDenied` follow the stage spend as for codes |
| Time | an `ExpiresAt` carrying nanoseconds, stored by PostgreSQL to the microsecond | accepted | a durable store treats the record as expired up to 1 µs early, never late, as every scrty SQL store truncates; the provider judges from the truncated value it reads back |
| Concurrency | a caller's own transaction at REPEATABLE READ or stronger around a device store call | accepted | a concurrent conflicting write surfaces as SQLSTATE 40001, which the provider answers as a dependency failure (5xx) without retrying; the caller retries the transaction. The stores document READ COMMITTED as the supported level. |
| State | a rollback of the device migration | accepted | it deletes every device authorization in flight, and each device grant's `origin` and `survives_sign_in_end`. A device grant without `offline_access` that outlived its sign-in then ends with it, the safe direction. |
| Input | a durable row holding a state, poll count, interval or grant origin this version does not know (a newer version wrote it, then the deployment rolled back) | handled, tested | the store refuses the row with fixed text rather than read a value it cannot mean |
| Concurrency | the sweep deleting an expired holder of a user code between a refused insert and the store's held-key check | handled | answered as `ErrUserCodeTaken`, so the provider draws another code |
| Observability | a claim the store applied but reported as failed | accepted | no `DeviceAuthorizationClaimed` is reported, as the claim was not known to stand; the browser's re-entry takes the already-claimed path, which reports nothing. Under-reported, never reported twice. |
| Observability | a replay whose revocation cannot be stored | accepted | no `DeviceCodeReplayed`, as nothing stands revoked; the caller gets a dependency failure and the next presentation reports it |
| Observability | user-code entry refused before any limit was asked (an unattributable source, a caller who left) | handled, tested | refused as throttled but not reported as `UserCodeEntryThrottled`, which names only a source over its limit or a limiter that could not decide |
| Observability | an approval withdrawn because the browser session was gone after the decision | accepted | `DeviceAuthorizationApproved` is reported and the resume answers `ErrReauthenticate`; the revocation recorded for the family reports no `GrantRevoked`, as no grant exists yet. The exchange then refuses the grant, so nothing is issued unseen. |
| Security | a link from another site to code entry with a user code, followed by a signed-in user | handled, tested | nothing claimed; 303 to the consumer's entry page with the code prefilled (D9) |
| Security | a GET from a browser that sends no `Sec-Fetch-Site` (older than 2023) | accepted | claimed as a non-browser request would be; consent still asks and shows the client and the code. Refusing absent headers would break every non-browser client and older browsers. |
| Security | an attacker controlling a sibling site of the deployment's registrable domain | accepted | its link passes as `same-site`; the threat is narrower than any site, and the POST check still applies |
| Configuration | the chain keys IPv6 by a prefix other than /64 | handled, tested | the entry guard keys by the chain's prefix (D6) |
| Configuration | two chains over one provider with the same durable factory | handled, tested | both build, and their entries count together (D6) |
| Configuration | two chains over one provider with different factories, namespaces or prefixes | handled, tested | the second `New` fails with `ErrConfig` (D6) |
| Configuration | an entry page on which the GET gate's redirect would loop | handled, tested | construction fails with `ErrConfig` (D9) |
| Observability | silent throttling | handled, tested | `UserCodeEntryThrottled` event and the sampled refusal log |

## Risks / Trade-offs

- **[Consent phishing remains possible]** → The defaults make it as visible as the protocol allows. The README's "CLI clients" section says loopback first, and to enable the device grant only for clients that need it (RFC 10027 §6.2.1).
- **[The user-code HMAC key is new key material to manage]** → It is used only for lookups, can be rotated at any time at the cost of flows in progress, and is required only for durable stores. Construction fails without it, so it cannot be forgotten.
- **[A throttle in the provider breaks the "throttles live in the chain" pattern]** → It's necessary for the consumer-handler path (D2). The chain passes its factory's limiter, so a deployment still configures limits in one place.
- **[Device records hold a second copy of approval state beside the pending request]** → The order is fixed: device record first, then pending stage. The failure-mode table pins the half-applied case.
- **[A new `Grant` field (`SurvivesSignInEnd`, `Origin`) touches every grant store]** → It is a new nullable column with a default, added by the same migration. Existing rows mean what they meant.

## Migration Plan

- **Implementation order.** It starts after `harden-chain-boundary` and `split-ci-jobs` are archived (proposal).
- **The migration.** One additive security-state migration creates the device authorization table and adds the grant columns with defaults. Rollback drops them, with the data loss stated in Failure modes.
- **Rollout.** Turning the feature on is the consumer's own deploy: enable the option and register a client. Turning it off removes the endpoints. Records left in flight expire and are swept.
- **Release.** A minor version, with additions only. The CHANGELOG lists the new option, fields, store port and migration.

## Open Questions

- The default per-source failure budget for code entry (5 per 10 minutes) is a judgement between the RFC's guidance and GitHub's per-app 50 per hour. It can be tuned during implementation without changing the specs' shape, because the spec's scenario names the default and the option.

## References

All accessed 2026-11-20.

### D1, D3, D4, D5, D10, D11: the protocol

**Researched:**
- [RFC 8628, OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628): the request and response (§3.1–3.2), the errors and +5 s `slow_down` (§3.5), metadata (§4), threats (§5.1–5.7), and user-code advice (§6.1).
- [golang.org/x/oauth2 v0.37.0, `deviceauth.go`](https://pkg.go.dev/golang.org/x/oauth2): the client side exists (`Config.DeviceAuth`, `Config.DeviceAccessToken`), so there is no client-side helper. Read from the local module cache.

**Primary documentation:**
- [RFC 6749, §3.3 Access Token Scope](https://www.rfc-editor.org/rfc/rfc6749#section-3.3): a server may refuse a request that omits `scope` rather than apply a default. It supports answering a device authorization request without `scope` with `invalid_request`, as scrty's authorization endpoint does.

### D2, D5, D6, D7, D9: entry, throttle, consent and phishing

**Researched:**
- [RFC 10027 / BCP 247, Cross-Device Flows](https://www.rfc-editor.org/rfc/rfc10027): use the device grant only with mitigations (§6.2.1, §6.2.4), rate limits (§6.1.11), UX showing who asked and why with deny as prominent (§6.1.14), short-lived codes (§6.1.2).
- [Microsoft Security Blog, Storm-2372 device code phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) (13 Feb 2025): the attack is live, and links and fake invites deliver it.
- [Microsoft Entra, block authentication flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows) (updated 2026-04-07): the vendor's defence is to allow the flow only where it is needed.
- [GitHub, authorizing OAuth apps: device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps): per-app opt-in, 15-minute codes, 5 s interval, 50 code submissions per hour per app.
- [Ory Hydra, device authorization](https://www.ory.com/docs/oauth2-oidc/device-authorization): user-code presets (the 9-digit low preset), confirm-the-code UX, single-use device codes with replay revoking.
- [zitadel/oidc `op` package](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op): per-client grant opt-in, base-20 and digit user-code presets, a 128-bit device code.
- [Keycloak OAuth 2.0 device grant design](https://github.com/keycloak/keycloak-community/blob/main/design/oauth2-device-authorization-grant.md): per-client opt-in, 600 s and 5 s defaults, a consent screen always shown. A design draft, which may be stale.
- [Okta, device authorization grant](https://developer.okta.com/docs/guides/device-authorization-grant/main/), [Auth0, device authorization flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow) and [Google, limited-input devices](https://developers.google.com/identity/protocols/oauth2/limited-input-device): lifetimes from 600 to 1800 s, a 5 s interval, opt-in clients, and an ID token for `openid`.

### D8: device grants and the approving sign-in

**Researched:**
- [OpenID Connect Back-Channel Logout 1.0, §2.7](https://openid.net/specs/openid-connect-backchannel-1_0.html): refresh tokens without `offline_access` SHOULD be revoked at logout, and those with it normally SHOULD NOT be.
- [OpenID Connect Core 1.0, §11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess): `offline_access` means access while the user is not logged in, and needs consent.
- [RFC 9700, §4.14](https://www.rfc-editor.org/rfc/rfc9700): a server MAY revoke refresh tokens on a security event such as logout. It ties nothing to a session.
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): silent on tokens at logout.
- [Okta, logout endpoint and token revocation](https://support.okta.com/help/s/article/using-the-logout-endpoint-and-revoking-user-tokens) and [Auth0, refresh tokens](https://auth0.com/docs/secure/tokens/refresh-tokens): logout does not invalidate refresh tokens, and a refresh token needs `offline_access`.
- [Google, refresh token expiration](https://developers.google.com/identity/protocols/oauth2#expiration) and [Ory, OIDC logout](https://www.ory.com/docs/oauth2-oidc/oidc-logout): tokens survive browser sign-out.
- [Microsoft Entra, refresh tokens](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens): revocation on sign-out depends on the token class.
- [Keycloak server administration, offline access](https://www.keycloak.org/docs/latest/server_admin/) and [a Keycloak forum report on device logins](https://forum.keycloak.org/t/login-via-device-grant-also-logs-into-browser/27556): offline tokens survive the SSO session. How device grants specifically behave there is unverified (forum report only).
- ZITADEL community threads ([1](https://questions.zitadel.com/m/1483818197328203877), [2](https://questions.zitadel.com/m/1512060624044298270)): ending the session leaves refresh tokens valid. Forum evidence only.

**Primary documentation:**
- [RFC 8414, OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414): the metadata document `device_authorization_endpoint` is added to (D12).
- [RFC 9449, DPoP](https://www.rfc-editor.org/rfc/rfc9449): the binding reused at the exchange (D11).

### D12, D13, failure modes: reasoned from scrty's own settled specs and the established design

No external source. They follow `oidc-provider-authorization`, `oidc-provider-tokens`, `csrf-protection`, `cors`, `security-state-stores` and `security-events` as settled.

### D6, charging before the lookup (2026-11-23): reasoned from scrty's own code

No external source. It follows the contract of `ratelimit.Charger` (charge first, refund on success, one indivisible step) and `SourceGuard`'s stated burst bound, and matches how recovery codes already throttle a short guessable secret.

### D6 hand-over and D9 GET gate (2026-11-23)

**Primary documentation:**
- [W3C Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/): `Sec-Fetch-Site` values `same-origin`, `same-site`, `cross-site` and `none`, and how a redirect chain is judged (D9).
- [RFC 8628 §3.3.1 and §5.4](https://www.rfc-editor.org/rfc/rfc8628): `verification_uri_complete` and remote phishing, which make a code-carrying link something an attacker can always produce (D9).
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): a GET must not change state, and fetch metadata as a defence (D9).

The hand-over change (D6) is reasoned from scrty's own code: `ratelimit.LimiterFactory`, `SourceKeyer` and `WithSourceGuardKeyer`, and the chain's login throttles in `httpsec/throttle.go`.
