# scrty

Authentication and authorization for Go applications.

## Modules

| Module | Contents |
|---|---|
| `github.com/kartaladev/scrty` | Core packages. Production builds import only the standard library. |
| `github.com/kartaladev/scrty/test` | Shared test helpers and conformance suites. No other scrty module imports it; run the suites from your own tests to check your implementations. |
| `github.com/kartaladev/scrty/<integration>` | One nested module per framework, driver, scheduler or DI container, added as scrty grows. |

Importing the core module adds no framework, driver or test tooling to your module graph. A test in
this repository enforces that.

## Supported Go versions

scrty requires **Go 1.27** or later. Every module declares `go 1.27`.

The floor is 1.27, not 1.26, because scrty's JOSE stack reads and writes JSON through
`encoding/json/v2`, which reaches the standard library in Go 1.27. On Go 1.26 it builds only under
`GOEXPERIMENT=jsonv2`, and scrty does not ask the applications that embed it to set a
build-environment flag.

## Identifiers are not secrets

`pkg/id` identifiers are sortable UUIDv7 values. They embed a timestamp and a partly predictable
counter, so never use one as a credential, session token or link secret. Those come from
`crypto/rand` in the packages that mint them.

## OIDC

`oidc` logs users in through external OpenID Connect providers; `httpsec.EnableOIDCLogin` answers
the HTTP endpoints for it. Wire the pieces in order:

```go
registry, err := oidc.NewRegistry(oidc.Provider{
	Name:         "corp",
	Issuer:       "https://idp.example.com",
	ClientID:     "scrty",
	ClientSecret: corpClientSecret,
	RedirectURL:  "https://app.example.com/login/oauth2/callback/corp",
})

broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
relyingParty, err := oidc.NewRelyingParty(registry, broker)
handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), users)

chain, err := httpsec.New(
	// ... your other chain options ...
	httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: relyingParty, Handoff: handoffs},
		httpsec.WithOIDCTokens(tokens),
		httpsec.WithOIDCSessions(sessions),
	),
)
```

`users` is your `identity.UserLoader` (and `identity.UserProvisioner`, if you enable just-in-time
provisioning with `oidc.WithBrokerJIT`); `tokens` and `sessions` are the `token.Generator` and
`*session.Sessions` the rest of your chain already issues through. `oidc.NewMemoryLinkStore` and
`oidc.NewMemoryHandoffStore` are the zero-configuration, per-process defaults; a multi-replica
deployment supplies durable stores instead. Every constructor's godoc names its remaining defaults,
and every option names the default it replaces.

### Endpoints

| Default path | Method | Purpose | Replace with |
|---|---|---|---|
| `/oauth2/authorization/{provider}` | GET | starts a login | `httpsec.WithOIDCAuthorizePath` |
| `/login/oauth2/callback/{provider}` | GET | the provider's callback | `httpsec.WithOIDCCallbackPath` |
| `/login/oauth2/handoff` | POST | redeems the handoff code | `httpsec.WithOIDCHandoffPath` |
| `/logout/oauth2/backchannel/{provider}` | POST | back-channel logout | `httpsec.WithOIDCBackchannelLogoutPath` |

`{provider}` is the one path segment naming a provider registered with `oidc.NewRegistry`.

### The handoff landing page

By default the callback does not create a session. It redirects the browser to your allowlisted
destination (`httpsec.WithOIDCAllowedRedirects`, `httpsec.WithOIDCAllowedOrigins`) with a single-use
`handoff` code appended to the URL. The page that destination loads must, before loading any
third-party resource (an analytics script, a font, an image from another origin — anything that
could read the URL through its own request or the `Referer` header):

1. read the `handoff` query parameter, and
2. remove it from the visible URL with `history.replaceState`, for example:

   ```js
   const url = new URL(window.location.href);
   const handoff = url.searchParams.get("handoff");
   url.searchParams.delete("handoff");
   history.replaceState(null, "", url);
   ```

and only then POST the code as the `handoff` form field to `/login/oauth2/handoff` (or your
`httpsec.WithOIDCHandoffPath`), which answers with the session's access token, refresh token and
the destination to send the user on to. A consumer who conveys the login another way (a
backend-for-frontend, say) replaces this whole step with `httpsec.WithOIDCCallbackSuccess`, and no
handoff code is issued.

### The order a credential is issued in

Everywhere the chain hands out a credential (form login and the other first factors, magic-link and
OIDC handoff redemption, session renewal, re-proof, and account recovery), it issues the credential
before it stores a session or spends anything: the session is built and marked, the credential is
issued, the session is stored in one write, and only then is the credential handed out. A credential
that cannot be issued (a key source that is down, a generator that fails) is a dependency failure,
never a refusal, and is not counted as a failed guess. It stores nothing, supersedes nothing and
spends nothing: a login stores no session that nobody holds, a renewal leaves the presented
credential with the standing it had (it is not later read as reuse), and a one-time code or link
stays usable. The one exception is a passkey login's challenge, which any attempt spends. Your own
code follows the same order through `session.Sessions.Prepare` and
`session.Prepared.Commit` (`CreateIssuing` and `RotateWithGraceIssuing` wrap it).

### Logout

`httpsec.EnableLogout` on the same chain, with no `LogoutDeps.EndSession` of its own, automatically
gains RP-initiated logout: ending a session that a federated login created also returns the
provider's end-session URL, for the client to send the browser to next
(`httpsec.WithOIDCRPInitiatedLogout(false)` turns this off). A provider that supports OpenID
Connect back-channel logout can be configured with an end-session and back-channel logout URL that
points at `/logout/oauth2/backchannel/{provider}`; scrty verifies the logout token and ends the
matching sessions without any browser involved.

### Second factor and provider assurance

A login through OIDC is not exempt from the second factor by its kind. For a user who is required
to use one (`policy.WithMFARequiredForAll`, or your own rule), the login needs evidence of a second
factor: either the provider asserted one in the ID token, or the user answers scrty's own
challenge. Only `api-key` logins are exempt by kind.

**What counts as the provider's assertion.** Only the `amr` and `acr` claims of the ID token that
passed verification are read, and they are matched exactly (case-sensitive) as configured. By
default a provider is trusted when its `amr` contains `mfa` (RFC 8176's value for "more than one
authentication method"); single-method values such as `otp` or `hwk` are not accepted by default,
because on their own they do not show that a second factor was used. Replace the default per
provider, as a whole, with `oidc.WithProviderAssurance`:

```go
relyingParty, err := oidc.NewRelyingParty(registry, broker,
	oidc.WithProviderAssurance("corp", oidc.Assurance{
		AcceptedAMR: []string{"mfa", "hwk"},
		AcceptedACR: []string{"gold"},
		RequestACR:  []string{"gold"},
		Match:       oidc.AssuranceMatchAny,
	}),
)
```

- `Match` is `AssuranceMatchAny` by default (any configured criterion is enough) or `AssuranceMatchAll`.
- `acr` is matched as a set, never as a minimum: its values are the provider's and have no order
  scrty knows. To accept "silver or above", list every value at or above silver.
- `RequestACR` is sent to the provider as `acr_values`. It is a request the provider may ignore,
  never evidence: the returned token is always checked against `AcceptedAMR` and `AcceptedACR`.
- A provider configured with neither accepted set never meets assurance, which is valid and means
  "always use the local second factor". A claim that is absent, empty or malformed counts as
  nothing asserted, so providers that emit no `amr` fall back to the local second factor.
- A configuration for a provider that is not registered, an empty value in a list, a `RequestACR`
  value containing whitespace, or an unknown `Match` fails `oidc.NewRelyingParty` with `oidc.ErrConfig`.

**Per-user rules.** `oidc.WithAssuranceEvaluator` replaces the matching step with your own rule,
for example "administrators need `hwk`". It receives the user, the provider, the verified issuer
and the asserted values, never the raw token, and cannot widen where the values come from. It
runs on every request of a federated session, so it must be fast and free of side effects, and an
error it returns denies:

```go
type adminsNeedAHardwareKey struct{ admins []identity.UserID }

func (e adminsNeedAHardwareKey) MeetsAssurance(_ context.Context, in oidc.AssuranceInput) (bool, error) {
	if slices.Contains(e.admins, in.User) {
		return slices.Contains(in.AMR, "hwk"), nil
	}

	return slices.Contains(in.AMR, "mfa"), nil
}

evaluator := adminsNeedAHardwareKey{admins: []identity.UserID{"root"}}

relyingParty, err := oidc.NewRelyingParty(registry, broker, oidc.WithAssuranceEvaluator(evaluator))
```

**What happens when assurance is not met.** The requirement policy has three modes for a required
user's OIDC login, chosen with `policy.WithMFARequirementFederatedAssurance`:

| Mode | Assurance met | Assurance not met |
|---|---|---|
| `FederatedAssuranceChallenge` (default) | allowed | challenged for the local second factor; a user with no usable enrolment goes to the enrolment path if it admits OIDC, otherwise is refused with enrolment required |
| `FederatedAssuranceRefuse` | allowed | refused with `policy.ErrFederatedAssuranceNotMet` (403); the handoff code is not consumed |
| `FederatedAssuranceExempt` | allowed | allowed |

Choose Refuse when the provider must be the only authority for the second factor. Choose Exempt
only when you accept the bypass it is: a required user is let in on the provider's word alone,
whatever the provider asserted, with no look at the requirement, the assurance or any enrolment.
A provider that does not enforce a second factor then lets required users in without one. Marking
`factor.OIDC` exempt with `policy.WithMFAExemption` is the same bypass. The mode governs the
requirement policy only; `policy.WithMFAFederatedChallengeWhenUnmet(true)` on the second-factor
challenge policy separately challenges an enrolled user's unmet OIDC login, required or not.

**Wire the source into the requirement policy.** Policy matches nothing itself: the OIDC relying party
is the `policy.FederatedAssuranceSource`. Give it to the policies you build, then put them in the
chain's engine:

```go
source := policy.WithFederatedAssuranceSource(relyingParty)

requirement, err := policy.NewMFARequirement(nil, lookups,
	policy.WithMFARequiredForAll(),
	policy.WithMFARequirementFederatedAssurance(mode),
	source,
)
```

`httpsec.New` refuses to assemble a chain with OIDC login enabled and a requirement policy in
Challenge or Refuse mode that has no source. Fix it with `WithFederatedAssuranceSource(relyingParty)`,
with Exempt mode, or with a `WithMFAExemption` rule that exempts `oidc`. Wire `httpsec.EnableMFA`
on the same chain, since the policies can raise a challenge.

**Per-request re-matching.** The redemption stores the provider's asserted values on the session;
it does not store a verdict. Every request of a federated session matches them again against the
provider's current configuration. Tightening a provider's accepted set therefore takes effect on
existing sessions at their next request, and a provider removed from the registry never matches.
A session whose local second factor was satisfied stays allowed. A consumer who creates sessions
in `httpsec.WithOIDCCallbackSuccess` records all three of `session.WithFirstFactor(factor.OIDC)`,
`session.WithExternalSession` (the result's provider, issuer, session ID and ID token) and
`session.WithFederatedAssurance` (its `AMR` and `ACR`). Without any one of them the session carries
no assurance, so a required user is challenged or refused on every request.

**Limits to know.**

- **Freshness is not checked.** `auth_time` and `max_age` are not read, so an `mfa` that a
  long-lived provider SSO session asserted hours ago is accepted.
- **Providers that emit no `amr`** meet no assurance under the default. Their required users are
  challenged locally, or refused with enrolment required if they have no usable enrolment.
  Exempt mode restores the old behaviour explicitly.
- **Account recovery.** `recovery.WayBackDeps.Admits` replaces the old exemption rule. A linked
  OIDC identity counts as a way back only when its login would be admitted without a local second
  factor; with no `Admits`, it never counts. Wire the requirement policy's own answer so the two
  cannot disagree:

  ```go
  deps.Admits = requirement.AdmitsWithoutLocalSecondFactor
  ```

  That answer is the requirement policy's alone, so under `WithMFAFederatedChallengeWhenUnmet(true)`
  the check may count a login the challenge policy then challenges; wire an `Admits` that answers
  false for such users.

### Security limits

- Provider configuration is trusted operator input: whoever writes it directs the client secret,
  and every outbound request, to whatever host they name.
- The discovery/key-set cache, the default flow store and the default handoff rate limiter are
  per process; a multi-replica deployment needs a shared `oidc.FlowStore` and a shared
  `httpsec.WithOIDCHandoffLimiter`.
- A handoff code is fixed at 60 seconds and travels in a URL; a refused code stays redeemable for
  the rest of that window.
- Back-channel logout-token replay is bounded by the token's issued-at time, not a used-once store,
  so a captured token is replayable within `oidc.WithLogoutTokenMaxAge`.
- A provider's `amr`/`acr` is accepted without a freshness check: see "Second factor and provider
  assurance" above for what that lets through and how to opt out of trusting it.
- Role sync and password-hash claim mirroring, both off by default, hand the provider ongoing
  influence over local roles and a standby credential; see their godoc before enabling them.

The full list, with the reasoning behind each one, is in the `oidc` package's "Limits" godoc
(`go doc github.com/kartaladev/scrty/authenticate/oidc`).

## Letting required users enrol

By default, a user who must use a second factor and has none is refused outright: enrolment is a
Go API (`BeginEnrolment` / `ConfirmEnrolment` on the method, e.g. `mfa.TOTP`) the consumer puts
behind their own authorised route, reached however they choose. The enrolment path is the
alternative: turned on explicitly, it lets such a user bind a second factor themselves, from a
session confined to that one purpose, right after they sign in. The path enrols every configured
method that implements `mfa.Enroller` over a store that keeps device proofs, or those you name
with `httpsec.WithEnrolmentMethods`; `httpsec.EnableMFAEnrolment` checks that for you.

Because a password alone would otherwise be enough to bind a second factor of an attacker's
choosing, the path is off unless both halves are turned on together:

```go
methods := []mfa.Method{totp} // one mfa.Method per second factor offered, e.g. mfa.NewTOTP

lookups, err := mfa.LookupsFor(methods...)

requirement, err := policy.NewMFARequirement(requirementLookup, lookups,
	policy.WithMFAEnrolmentPath(), // policy.WithEnrolmentFirstFactors, policy.WithEnrolmentPathUntil
)

chain, err := httpsec.New(
	// ... your other chain options (login, sessions) ...
	httpsec.EnableMFA(methods), // each method verifies at "/mfa/verify/<name>" (httpsec.WithMFAVerifyPrefix);
	// a challenge method also begins at "/mfa/begin/<name>" (httpsec.WithMFABeginPrefix);
	// httpsec.WithMFAMethodListing turns on GET /mfa/methods, off by default
	httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
		Users:  users,        // identity.UserLoader
		Sender: queuedSender, // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
	}),
)
```

### Flow

1. **Begin** (`POST /mfa/enrol/begin/<name>`, e.g. `/mfa/enrol/begin/totp`) provisions a secret and
   returns it, with a QR-code URI, to the confined session the login just received.
2. **Confirm** (`POST /mfa/enrol/confirm/<name>`, e.g. `/mfa/enrol/confirm/totp`, form field
   `code`) proves the device with a code from it. The device is proven, but the enrolment does not
   count yet.
3. **Emailed code** (`POST /mfa/enrol/confirm-email/<name>`, e.g. `/mfa/enrol/confirm-email/totp`,
   form field `code`) — by default, an out-of-band code is sent to the user's address once the
   device is proven, and entering it here is what completes the enrolment. This is what stops a
   password holder from binding an authenticator the account's owner never sees: the mailbox owner
   takes part in every binding.
4. **Verify** (`POST /mfa/verify/<name>`, e.g. `/mfa/verify/totp`, `httpsec.EnableMFA`'s own
   endpoint) resolves the session's pending second-factor challenge with a fresh code, exactly as
   it would for an enrolment made out of band. Only this step marks the session satisfied and
   rotates its handle. After a valid code, verification judges the post-authentication phase again
   with the second factor counted as met, because a challenge registered after the second-factor
   policy was hidden behind it at login. A deny refuses verification with the policy's reason and
   leaves the session pending, under the credential the caller arrived with. A challenge that
   surfaces (a password change, say) is completed as a login completes one: the session is satisfied,
   rotated and marked with it, and verification answers with a `*httpsec.ChallengeError` of that kind
   carrying the rotated session and its credential, instead of calling the responder. The caller's
   old credential is superseded, so the consumer's error handler must deliver `ce.Token`; the default
   handler writes only the status, so a chain without `WithErrorHandler` leaves the caller without a
   working credential, as at a login challenge. The same
   line as at re-authentication holds: a consumer policy that raises `policy.ChallengeMFA` without
   reading `policy.Input.MFASatisfied` hides whatever is registered after it. The begin endpoint
   (`POST /mfa/begin/<name>`) and verification both refuse a caller other than the session's own
   user, which only a consumer's interceptor can publish, before anything is counted or issued.

Every other request a confined session makes — the password-change endpoint, a consumer route,
the authorizer, the handler — is refused with the enrolment challenge until verification succeeds;
only logout is let through as well.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Endpoint path prefixes | `/mfa/enrol/begin`, `/mfa/enrol/confirm`, `/mfa/enrol/confirm-email`, each with `/<name>` appended per method | `httpsec.WithEnrolmentBeginPrefix`, `WithEnrolmentConfirmPrefix`, `WithEnrolmentEmailConfirmPrefix` |
| Methods enrolled | every method `EnableMFA` was given that implements `mfa.Enroller` and supports the path | `httpsec.WithEnrolmentMethods` |
| First factors admitted | `password`, `magic-link`, unrecorded | `policy.WithEnrolmentFirstFactors` |
| Confined session lifetime | 15 minutes | `httpsec.WithEnrolmentSessionLifetime` |
| Begin limit | 5 per hour, per user, in-memory | `httpsec.WithEnrolmentBeginLimiter` |
| Confirmation failure limit | 5 per 15 minutes, per user, in-memory | `httpsec.WithEnrolmentConfirmLimiter` |
| Emailed-code confirmation | on | `httpsec.WithoutEnrolmentEmailConfirmation` |
| Notification on completion | on | `httpsec.WithoutEnrolmentNotification` |
| Contact address / provisioning label | the username | `httpsec.WithEnrolmentContactResolver` / `WithEnrolmentLabelResolver` |
| Rollout deadline | none (path stays open) | `policy.WithEnrolmentPathUntil` |

### Stated limits

- **OIDC is off the first-factor allowlist.** A stolen provider account usually includes its
  mailbox, so the emailed code would add no assurance, and the notification might reach the
  attacker too. The same limit, less starkly, applies to `magic-link`, which is on the allowlist by
  default: a consumer who finds that unacceptable takes it off.
- **A password holder can spend a user's begin budget.** Every begin is counted, not only failed
  ones, because it generates a secret and can send an email; whoever holds the password alone can
  therefore lock a user out of the path for up to an hour.
- **Confined sessions still count toward the concurrent-session cap**, when one is configured. Each
  occupies a slot for at most the confined lifetime.
- **The in-memory limiters are per replica.** A multi-replica deployment needing an exact,
  shared count supplies its own `ratelimit.Limiter`.
- **There is no route allowlist.** Every path a confined session may reach is a fixed option; there
  is no way to add another. A consumer interceptor placed between the bearer slot and the gate
  still runs, and sees the session's principal, exactly as it would for a session pending MFA.

### A lost authenticator

`mfa.ResetEnrolment` is the operator's undo: it removes the user's enrolment on every method it is given, ends every session of the
user (so one already satisfied by the lost authenticator stops working), and notifies the user by
default. It is a Go API, not an HTTP endpoint — put it behind whatever authorised administrative
route the rest of the operator surface already uses. With the enrolment path on, the user's next
login goes straight back into the confined state above; with it off, they are refused until
enrolled out of band.

## Account recovery

`recovery` lets a user who has lost every authenticator their account depends on get back in with
two independent proofs, never one; `httpsec.EnableAccountRecovery` answers the HTTP endpoints for
it. Wire the pieces in order:

```go
codes, err := recovery.NewCodes() // WithCodesSetSize, WithCodesLowThreshold, WithCodesStore, WithCodesLimiter, ...

mfaReset, err := recovery.MFAEnrolments(totp) // one AuthenticatorKind per kind of authenticator recovery resets

chain, err := httpsec.New(
	// ... your other chain options, including a binding route (see below) ...
	httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
		Users:    users,        // identity.UserLoader
		Sessions: sessions,     // *session.Sessions
		Sender:   queuedSender, // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
		Codes:    codes,
	},
		httpsec.WithRecoveryTokens(tokens), // required unless EnableFormLogin is also on the chain
		httpsec.WithRecoveryCore(
			recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
			recovery.WithRepudiationContact("Contact support@example.com if you did not request this."),
			recovery.WithAuthenticatorKinds(mfaReset),
		),
	),
)
```

`recovery.WithProofs`, `recovery.WithRepudiationContact` and `recovery.WithAuthenticatorKinds` have
no default: a chain that enables recovery names at least these. A recovery completes with two
proofs of different kinds, at least one of them a recovery code (`recovery.ProofSaved`,
`recovery.ProofIssued`); `recovery.ProofPassword` also needs `httpsec.EnableFormLogin` on the same
chain, and `recovery.ProofMFA` needs `recovery.WithMFAMethods`.

### Endpoints

| Default path | Method | Purpose | Enabled when |
|---|---|---|---|
| `/recovery/start` (`httpsec.WithRecoveryStartPath`) | POST | emails an issued code | `recovery.ProofIssued` |
| `/recovery/complete` (`httpsec.WithRecoveryCompletePath`) | POST | completes a recovery with two proofs | always |
| `/recovery/finish` (`httpsec.WithRecoveryFinishPath`) | POST | finishes a held recovery | a delay or a risk hook is configured |
| `/recovery/cancel` (`httpsec.WithRecoveryCancelPath`) | POST | cancels a held recovery | a delay or a risk hook is configured |
| `/recovery/codes` (`httpsec.WithRecoveryCodesPath`) | GET / POST | counts / regenerates saved codes | `recovery.ProofSaved` |

### A binding route

A completed recovery does not produce a full session: it produces a recovery-pending session,
confined to the endpoints that can bind a new authenticator, following the enrolment path's own
confinement pattern (above). `EnableAccountRecovery` fails construction without one of:

- the MFA enrolment path (`httpsec.EnableMFAEnrolment`), whose verify endpoint resolves the
  binding, exactly as it does for an ordinary enrolment; or
- a password-change resolve endpoint (`httpsec.EnablePasswordChangeGate` with
  `httpsec.WithPasswordChangeEndpoint`), whose success clears the confinement without rotating the
  session — the recovery minted it for this caller already.

Passkey registration (see [Passkeys](#passkeys)) is a third binding route.

A recovery issues the recovery session's access token before it spends anything, and stores the
session, already recovery-pending, as the last step. A token generator that fails is a dependency
failure, not a refusal: the proofs stay unspent, nothing is removed, ended or replaced, no source or
user is charged, a held recovery stays pending, and the same request succeeds once the generator
does. The core's own hook is `recovery.WithCredentialIssuer`, optional on a bare `recovery`
recoverer (the result then carries no credential, and issuing one afterwards costs the user the
spent proofs if it fails); the chain supplies its own, which replaces one passed through
`httpsec.WithRecoveryCore`.

### The MFA reset kind

By default a recovery removes every authenticator the user holds, except one they proved
possession of in that same recovery. `recovery.MFAEnrolments(totp, ...)` is the
`recovery.AuthenticatorKind` that reaches MFA enrolments: it lists a user's confirmed enrolments and
removes them through each method's `mfa.EnrolmentRemover`. Register it, and any of a consumer's own
`recovery.AuthenticatorKind` implementations, with `recovery.WithAuthenticatorKinds`.
`recovery.WithResetReported` removes only what the user names as lost instead, and
`recovery.WithResetPolicy` hands the decision to a consumer function.

### "Is there another way back in?"

`recovery.NewWayBackCheck` reports whether a user could still recover their account without the
saved codes they have not generated yet — a saved code already held, a password or enrolled
authenticator paired with an issued code, or a linked login that `WayBackDeps.Admits` says would
be admitted without a local second factor (see "Second factor and provider assurance"):

```go
check, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
	Users:       users, // identity.UserLoader
	Codes:       codes,
	Kinds:       []recovery.AuthenticatorKind{mfaReset},
	IssuedCodes: true, // recovery.ProofIssued is enabled
})

ok, err := check.HasWayBack(ctx, userID)
```

The passkey manager calls it before letting a passwordless-only user register their first
passkey without saved codes: such a user's passkey stays pending until they have generated a set and
proved they kept it.

### Holds, cool-down and regeneration

- **No waiting period by default.** A recovery that presents its two proofs completes at once.
  `recovery.WithHoldDelay` holds every recovery for a fixed time before it can complete, and
  `recovery.WithCancelLink` is required with any hold — a delay or `recovery.WithRisk`'s hook: the
  held-recovery notice links to it, so a normal login, a password re-authentication, or the link
  itself, cancels a recovery the real user did not make.
- **A cool-down after recovery.** `httpsec.EnableRecoveryCooldown(records, d, routes...)` refuses
  the routes a consumer marks as sensitive — changing the account's email address, say — for `d`
  after the user's latest completed recovery. It is per user, not per session, so logging out and
  back in does not end it, and it is independent of `EnableAccountRecovery`: it only reads the
  record store.
- **Regeneration.** `GET`/`POST /recovery/codes` count and regenerate a user's saved codes for a
  full session. A `POST` needs a session whose authentication time (sign-in, satisfied second
  factor or re-authentication) is within the freshness window, its end included, and is refused
  with `recovery.ErrReauthenticationRequired` (403) otherwise. A stale session becomes fresh by a
  re-proof (`httpsec.EnableReauthentication`) or by signing in again; on a chain with the MFA slot
  and without re-authentication, signing in again is the only way, so a stale session regenerates
  its codes only after signing in again.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Codes per set | 10 | `recovery.WithCodesSetSize` |
| Issued code lifetime | 15 minutes | `recovery.WithIssuedCodeTTL` |
| Recovery-pending session lifetime | 15 minutes | `recovery.WithPendingSessionLifetime` (via `httpsec.WithRecoveryCore`) |
| Regeneration freshness window | 15 minutes | `httpsec.WithRecoveryRegenerationFreshness` |
| Authenticator reset | everything held, except what was proved | `recovery.WithResetReported`, `recovery.WithResetPolicy` |
| Other sessions of the user | ended on recovery | `recovery.WithoutSessionRevocation` |
| Waiting period | none | `recovery.WithHoldDelay`, `recovery.WithRisk` |
| Cool-down after recovery | off | `httpsec.EnableRecoveryCooldown` |
| Recovery record store (`RecoveryDeps.Records`) | in-memory, one process only | `recovery.NewMemoryRecordStore` replaced by a durable `recovery.RecordStore` |
| Issued-code token store | in-memory, one process only | `recovery.WithIssuedCodeStore` |
| Hold token store | in-memory, one process only | `recovery.WithHoldTokenStore` |

Each in-memory default above holds its state in the process that created it and forgets it on
restart; a second replica never sees the first one's records or tokens. A deployment running more
than one replica supplies durable stores instead: `pgxstore.NewRecoveryRecordStore`,
`gormstore.NewRecoveryRecordStore` or `sqlstore.NewRecoveryRecordStore` for `RecoveryDeps.Records`, and
`pgxstore.NewOneTimeStore`, `gormstore.NewOneTimeStore` or `sqlstore.NewOneTimeStore` — the same `onetime.Store`
implementation — for both `recovery.WithIssuedCodeStore` and `recovery.WithHoldTokenStore`.

## Passkeys

`passkey` adds WebAuthn passkeys: registration and management, passwordless login, the passkey as a
second factor, and clone handling. The core package has no WebAuthn dependency; the verifier
behind the `passkey.Verifier` port lives in the nested module
`github.com/kartaladev/scrty/authenticate/passkey/webauthn`, which you add to your own `go.mod` and pass in.
Each snippet below is mirrored by an `Example` function in `authenticate/passkey` and `authenticate/passkey/webauthn` that
compiles and runs in this repository's tests.

### The relying party

The relying party has no default. Its ID is a bare host (no scheme, port, path or trailing dot, and
not an IP address), its origins are `https` origins on that host or a subdomain of it (`http` only
on `localhost`), and a malformed one is an error wrapping `passkey.ErrConfig` at construction:

```go
rp := passkey.RelyingParty{
	ID:      "example.com",
	Name:    "Example Co",
	Origins: []string{"https://example.com", "https://app.example.com"},
}
```

**Changing the relying-party ID orphans every registered passkey**, because authenticators scope
their credentials to it. Choose it once, and keep it.

Advise your users to keep **two passkeys, one of them synced** (held by a platform or password
manager that backs it up), so losing a device does not lock them out. Saved recovery codes and
account recovery (above) are the way back when both are gone.

### Wiring the adapter and the manager

```go
verifier, err := webauthn.New(rp) // github.com/kartaladev/scrty/authenticate/passkey/webauthn

manager, err := passkey.New(passkey.Deps{
	Verifier: verifier,
	Users:    users,       // identity.UserLoader
	Sender:   queuedSender, // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
	Sessions: sessions,     // the *session.Sessions the chain uses (httpsec.PasskeyDeps.Sessions)
},
	passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
)
```

`Verifier`, `Users`, `Sender`, `Sessions` and the repudiation contact have no default (`Sessions` may be
left out only with both `passkey.WithoutSessionRevocationOnRemoval` and
`passkey.WithoutSessionRevocationOnClone` given); everything else does:

| What | Default | Replaced by |
|---|---|---|
| Credential store | in-memory, one process only | `passkey.Deps.Credentials` |
| User-handle store | in-memory, one process only | `passkey.Deps.Handles` |
| Challenge store | in-memory, one process only | `passkey.Deps.Challenges` |
| Attestation | off: none requested, every authenticator accepted, only its AAGUID kept | `webauthn.WithAttestationRecord`, `webauthn.WithTrustedAttestation` |
| Response to a suspected clone | refuse, suspend the credential, end the user's sessions, notify | `passkey.WithCloneResponse`, `passkey.WithClonePolicy` |
| Other sessions of the user when a passkey is removed | ended; the removing session stays | `passkey.WithoutSessionRevocationOnRemoval`, or per request the posted `other_sessions` field (`keep` or `end`; anything else, an empty value or a repeated field is a 400, `httpsec.ErrMalformedRequest`) |
| Sessions of the user when a passkey is suspended as a clone | every session ended | `passkey.WithoutSessionRevocationOnClone` |
| Second factor at a passwordless login | a user-verified passkey meets it | `passkey.WithoutSecondFactorAtLogin` |
| Endpoint paths | `/passkey/register`, `/passkey/credentials`, `/passkey/login` | `httpsec.WithPasskeyRegistrationPrefix`, `WithPasskeyCredentialsPrefix`, `WithPasskeyPasswordlessPrefix` |
| Challenge lifetime | 5 minutes (also the timeout in the creation options) | `passkey.WithChallengeTTL` |
| Registration challenges per user | 10 per hour; the window is fixed | `passkey.WithRegistrationChallengeLimit` |
| Passkeys per user | 25, every state counted | `passkey.WithPerUserLimit` |
| Freshness to register or remove a passkey | the session's authentication time (sign-in, satisfied second factor or re-authentication) within 15 minutes, the end included | `passkey.WithManagementFreshness` |
| Second factor a session must have met to register or remove a passkey | any MFA method usable against the session's first factor: inside a chain with an MFA slot, the slot's methods (the passkey method among them when it is on the slot); otherwise `passkey.Deps.MFAMethods`. The user's own active passkeys count too, whatever the first factor, when the passkey method is among those methods or the chain serves passwordless login that proves the second factor. A password session that owes a challenge steps up through the passkey method at `/mfa/verify`; a passkey-first session cannot meet the second factor through it (same channel; a re-proof at `/reauth` with the passkey refreshes freshness only) and signs in again with user verification, by password then the passkey step-up, or by a re-proof at `/reauth` with a second factor on another channel. Accepted fail-closed limit: `WithoutSecondFactorAtLogin`, the passkey method on the slot, and a policy completing a passkey-first session without a second factor leave that session unable to manage passkeys until it meets the second factor on another channel; a user whose only second factor is the passkey cannot. The method is recognised by identity, so a wrapped passkey method opens no route. A failed MFA or passkey lookup refuses with fixed text | `passkey.RegistrationContext.MFAMethods` and `PasswordlessLogin`, for a direct caller of the manager; the own-passkeys rule itself has no override |
| User verification | required | `passkey.WithUserVerification` |
| Resident (discoverable) key | required; a non-resident passkey serves only as a second factor | `passkey.WithResidentKey` |
| Emailed confirmation code | 6 digits, valid 10 minutes, 5 attempts | not configurable: the store contract fixes the attempts (`passkey.MaxEmailCodeAttempts`) |
| Request body caps | 64 KiB registration (`passkey.RegistrationBodyLimit`), 16 KiB assertion (`passkey.AssertionBodyLimit`) | not configurable |
| A consumer challenge kind raised on a passkey request (`WithChallengeEnforcer`) | refused with a `ChallengeError` of that kind on every passkey registration and management endpoint | `httpsec.WithPasskeyRegistrationResolving(kinds...)`: the four registration endpoints serve the named kinds under every other rule, nothing is marked, and listing, rename and removal still refuse them; no kinds, `ChallengeNone`, a built-in kind or an undeclared kind is `ErrConfig` at `New` |
| Passwordless begin throttle | 30 per 15 minutes per source, in this process's memory | `httpsec.PasswordlessLimiter` |
| Passwordless ceremony cookie | `passkey_ceremony` (`httpsec.DefaultPasswordlessCookieName`) | `httpsec.PasswordlessCookieName` |
| Log sampling | each refusal, clone or queue failure reason at most once a minute | `passkey.WithLogInterval` |

The removal endpoint (`POST <prefix>/remove`) reads the optional `other_sessions` field from the same
form body as `id`: `keep` keeps the user's other sessions, `end` ends them, and absent applies the
manager's default (end). Asking to end them on a manager wired with no `Sessions` is a
`passkey.ErrConfig` refusal and changes nothing.

Three overrides, compiled as `ExampleWithCloneResponse`, `ExampleWithoutSessionRevocationOnRemoval`
and `ExampleWithoutSecondFactorAtLogin` in `passkey/example_test.go` (`ExampleKeepOtherSessions` shows the
per-call `Remove` options):

```go
// Allow a suspected clone and only warn; or decide each one yourself (the policy wins).
passkey.WithCloneResponse(passkey.CloneSignalOnly)
passkey.WithClonePolicy(func(_ context.Context, s passkey.CloneSignal) passkey.CloneAction {
	if s.BackupState { // a synced passkey's counter is unreliable
		return passkey.CloneAllow
	}

	return passkey.CloneRefuseSuspend
})

// Keep the user's other sessions on removal, and on a suspected clone (each has its own option).
passkey.WithoutSessionRevocationOnRemoval()
passkey.WithoutSessionRevocationOnClone()

// A direct Remove call chooses per call: passkey.KeepOtherSessions() or passkey.EndOtherSessions().

// A passwordless login no longer meets the second factor; MFA follows where policy requires it.
passkey.WithoutSecondFactorAtLogin()
```

The in-memory stores hold one process's records and forget them on restart; behind several replicas
a ceremony must also finish on the replica that began it. A deployment that runs more than one
replica supplies durable stores. The credential store seals the emailed confirmation code at rest,
so it takes a `seal.Cipher`; `sqlstore`, `pgxstore` and `gormstore` each have the two constructors:

```go
credentials, err := sqlstore.NewPasskeyCredentialStore(db, cipher) // cipher: seal.NewAEADCipher over a seal.Keyring
handles, err := sqlstore.NewPasskeyHandleStore(db)

manager, err := passkey.New(passkey.Deps{
	Verifier:    verifier,
	Credentials: credentials,
	Handles:     handles,
	Users:       users,
	Sender:      queuedSender,
	Sessions:    sessions,
},
	passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
)
```

### Recovery codes and the way-back check

A user who signs in with passkeys alone has no password to fall back on. So, by default, a first
passkey registered by a user with no other way back in stays **pending** until they have generated
a set of saved recovery codes and confirmed they kept it, and passwordless login refuses a manager
with no recovery wired. The way-back check needs the passkey recovery kind and is part of the
manager's own dependencies, so build the kind first with `passkey.NewRecoveryKind`, over the same
credential store the manager will use (create the in-memory store yourself, with
`passkey.NewMemoryCredentialStore`, so both share it):

```go
contact := passkey.WithRepudiationContact("Contact support@example.com if you did not do this.")

credentials := passkey.NewMemoryCredentialStore() // or your own store; the manager must get this one

deps := passkey.Deps{Verifier: verifier, Credentials: credentials, Users: users, Sender: queuedSender, Sessions: sessions} // and your other stores

codes, err := recovery.NewCodes()

wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
	Users:       users,
	Codes:       codes,
	Kinds:       []recovery.AuthenticatorKind{passkey.NewRecoveryKind(credentials)},
	IssuedCodes: true, // recovery.ProofIssued is enabled
})

deps.Recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack}

manager, err := passkey.New(deps, contact)
```

Register `manager.RecoveryKind()` with `recovery.WithAuthenticatorKinds` too, so a recovery removes
the passkeys a user lost; do not also pass the passkey MFA method to `recovery.MFAEnrolments`.

`passkey.WithOptionalRecoveryCodes` is the alternative for accounts only the operator can recover:
a passkey is active at once, and the registration result reports that recovery is not set up so
your interface can prompt for it. It trades the safety net for convenience; the default is the safe
one.

```go
optional, err := passkey.New(deps, contact, passkey.WithOptionalRecoveryCodes())
```

### Enabling registration, passwordless login and the MFA method

```go
chain, err := httpsec.New(
	// ... your other chain options (sessions, login) ...
	httpsec.EnableMFA([]mfa.Method{totp, manager.MFAMethod()}, // each verified at /mfa/verify/<name>
		httpsec.WithMFATokens(tokens),
	),
	httpsec.EnablePasskeys(
		httpsec.PasskeyDeps{Passkeys: manager, Sessions: sessions, Users: users},
		httpsec.WithPasskeyPasswordlessLogin(httpsec.PasswordlessTokens(tokens)),
	),
	// Required beside EnableMFA and EnablePasskeys: the step-up a session uses
	// before it manages passkeys.
	httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(tokens)),
)
```

- `EnablePasskeys` alone serves registration and management for a signed-in session:
  `POST /passkey/register/begin` and `/finish` (plus `/confirm` and `/confirm-email`
  for a pending passkey), and `GET /passkey/credentials` with `POST .../rename` and `.../remove`.
- `WithPasskeyPasswordlessLogin` is off unless given. It adds `POST /passkey/login/begin` and `/finish`,
  tied together by an `HttpOnly`, `Secure`, `SameSite=Strict` ceremony cookie, and signs a user in
  with a discoverable passkey alone. `PasswordlessTokens` names the token generator, and may be
  left out when the chain has form login to take one from.
- A consumer challenge kind raised on the request (declared with `httpsec.WithChallengeEnforcer`)
  is refused with a `ChallengeError` of that kind on every registration and management endpoint,
  because the gate enforcing it is yours and may sit after the passkey slot. A gate that lets
  registration through so that the binding resolves its kind names the kind in
  `httpsec.WithPasskeyRegistrationResolving(kinds...)`; the four registration endpoints then serve it,
  and listing, rename and removal still refuse it. See the defaults table below.
- The passkey is a second-factor method named `passkey`, beside TOTP: `EnableMFA` serves it at
  `/mfa/begin/passkey` and `/mfa/verify/passkey`. A user-verified passkey login already meets the
  second factor, so it is not asked again.
- A passkey is also a binding route for a recovered or enrolment-only session, once the passkey
  method is among the enrolling methods.

### Attestation

Attestation is **off by default**: no statement is requested and any authenticator is accepted,
which is what lets synced passkeys register. Two options in the adapter change that:

```go
webauthn.New(rp, webauthn.WithAttestationRecord()) // record the format and statement, accept every authenticator
```

Recording collects data that can identify the user's authenticator model and batch, which the
default does not. To **require** trusted attestation, give the verifier a FIDO metadata source. The
metadata is fetched through scrty's confined outbound client, never the verification library's
own, and that client's response cap must be raised, because the production BLOB is several
megabytes and the default is 1 MiB:

```go
client, err := outbound.New(
	outbound.WithAllowedOrigins("https://mds3.fidoalliance.org"),
	outbound.WithMaxResponseBytes(32<<20),
)

verifier, err := webauthn.New(rp, webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(client)))
```

The source caches the BLOB until its `nextUpdate` and for at most 24 hours, and a failed refresh
refuses every trusted registration rather than trusting stale data. Trusted mode excludes synced
passkeys, which carry no attestation. `webauthn.MetadataBlob` takes a BLOB you fetch yourself.

### Stated limits

- **The relying-party ID cannot change** without orphaning every passkey (above).
- **Only discoverable credentials sign a user in.** Passwordless login never asks for a username,
  so it cannot be used to learn which usernames exist.
- **A passkey is never a recovery proof.** It is an authenticator recovery can reset, and a way back
  only while it is active.
- **Counters are judged by the store's write.** Authenticators that always report zero, as synced
  passkeys do, are never treated as clones.

## Per-route guards

`httpsec.NewGuards` builds the guards a consumer puts in front of one net/http route, on top of
the chain's rules. Every guard fails closed: a request with no caller is refused 401, one with no
authorizer 403, and only then is the guard's own question asked.

### Recent authentication

`RequireRecentAuthentication()` lets a route run only when the caller proved their identity
recently: the session's authentication time (sign-in, satisfied second factor or
re-authentication) is within the window, its end included. `RequireAuthenticationWithin(d)` sets
the window for one route. A stale session, a session with no recorded authentication time, and a
caller with no session at all (an API key, Basic) are refused with a
`*httpsec.ReauthenticationRequiredError` (403, `httpsec.ErrReauthenticationRequired`) that carries
the window, so an error handler can tell the client how recent a proof it needs.

- **The window is fixed.** Calling the route does not extend it, nor does a session renewal; only
  an authentication moves the time.
- **Stack it inside the privilege guards**, `privileged(recent(route))`, so a caller who may not
  act at all is told access denied rather than sent to re-authenticate.
- **Use the chain's clock.** A consumer who sets `httpsec.WithClock` passes the same clock to
  `httpsec.WithGuardClock`.
- **A window longer than the session's absolute lifetime is never reached**: the session ends
  first.

```go
guards, err := httpsec.NewGuards(nil, httpsec.WithChainAuthorizer())
if err != nil {
	return err
}

privileged := guards.ResourcePrivileges("projects", "project").RequireAny("delete")
mux.Handle("DELETE /projects/{id}", privileged(guards.RequireRecentAuthentication()(deleteProject)))
```

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Recency window | 15 minutes (`httpsec.DefaultRecentAuthenticationWindow`) | `httpsec.WithRecentAuthenticationWindow`, per route `RequireAuthenticationWithin` |
| Guard clock | system clock | `httpsec.WithGuardClock` |
| Authentication time | the request's session | `httpsec.WithAuthenticationTime` |
| Refusal response | the refusal's status, no body | `httpsec.WithGuardErrorHandler` |

## Re-authentication

`httpsec.EnableReauthentication()` lets a signed-in session prove its user again, so a stale session
becomes fresh for the recency guard without signing in again. It is off by default; without it a
stale user signs in again. It has no factor of its own: second factors are the MFA slot's
(`httpsec.EnableMFA`), under its per-user verification throttle, and the password is form login's
(`httpsec.EnableFormLogin`), under the account lockout and the password-login source guard. At
least one of the two must be enabled. A re-proof challenge store (`httpsec.WithReauthenticationChallengeStore`)
on a chain without the MFA slot is a configuration error from `httpsec.New`, since nothing there issues
re-proof challenges; a slot of TOTP alone accepts one.

```go
chain, err := httpsec.New(
	httpsec.EnableBearerToken(bearerDeps),
	httpsec.EnableFormLogin(loginDeps),
	httpsec.EnableMFA([]mfa.Method{totp}, httpsec.WithMFATokens(tokens)),
	httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(tokens)),
)
```

### Endpoints

Only a full session is served: a resolved caller, no pending challenge of any kind, and not confined
to enrolment or recovery. Anything else is refused: a session owing a challenge is refused by that
challenge's gate with its challenge error, not by these endpoints, and a request with no resolved
caller is refused as authentication required.

| Request | What it does | Default response |
|---|---|---|
| `GET /reauth/methods` | how the session's user may re-prove | `{"methods":[{"name":…,"channel":…,"begins":…}],"password":…}` |
| `POST /reauth/begin/{method}` | begins a second factor that has a begin step (a passkey) | the method's begin data as JSON |
| `POST /reauth/verify/{method}` | re-proves with a second factor | the login document: `access_token`, `refresh_token`, `valid_until` |
| `POST /reauth/password` | re-proves with the password, read from the `password` form field or JSON member | the login document |

Every default response is marked `Cache-Control: no-store`, and each has a replaceable responder;
a consumer's responder owns its headers. The password endpoint checks the password of the session's
own user: a `username` in the request is ignored. A successful re-proof sets the session's
authentication time to now on the chain's clock (a second factor on a different channel from the
session's first factor also records the second factor as satisfied; a same-channel re-proof, such as a
passkey session re-proved with the passkey, refreshes freshness only), rotates the session, and answers with the rotated session's credential; the credential
the caller arrived with stops working. The credential is issued inside the rotation, before anything
is stored, so a re-proof or an MFA verification whose credential cannot be issued (a token generator
that fails) stores nothing and leaves the credential the caller arrived with working. A re-proof that
loses a race with a renewal of the same session, or with a concurrent re-proof or MFA verification
of it (through this server or any other manager sharing the session store), is refused 409
(`httpsec.ErrSessionRenewalConflict`) inside the winner's in-flight window, and a failed re-proof
changes nothing. A password re-proof runs the chain's post-authentication phase like a login, with
the input marked as a re-authentication, so a session cap admits it rather than counting it as a new
session.

A second-factor re-proof runs the same phase after the response verifies, with the input a login of the
session's user and first factor builds, also marked as a re-authentication: it carries the login's own
second-factor proof when the session met its second factor at sign-in (a user-verified passkey login),
and the evidence the provider asserted when the session is federated. Every deny refuses with the policy's
reason, the same-channel refusal included, and any challenge other than a second factor's refuses as it
does at the password re-proof. A second-factor challenge does not refuse, since one was just verified,
but what it hid is judged: the engine answers with the first challenge in registration order, so the
phase is asked again with the second factor counted as met (`policy.Input.MFASatisfied`, beside
`Reauthenticating`), and a deny or another challenge that surfaces then refuses the same way. A
password change owed behind the second-factor policy therefore still refuses the re-proof. The
library's policies answer that second judgement: `policy.NewMFA` allows, and `policy.NewMFARequirement`
allows, in its challenge mode, an enrolled user's federated session whose provider did not meet its requirement, while its refusals, the refuse
mode's included, stand. The line: a consumer policy that raises `policy.ChallengeMFA` without reading
`MFASatisfied` raises it again, the challenge is dropped, and whatever is registered after it stays
hidden. A caller other than the session's own user, which only a consumer's interceptor can publish,
is refused as authentication required before anything is counted or judged, at the begin endpoint as
at verification, so no challenge is issued for them. A refusal leaves the session as it was.

### The factor policy

A user re-proves with the strongest factor they hold. A user enrolled on any of the MFA slot's
methods re-proves with one of them, whatever its channel (a passkey sign-in re-proves with the
passkey), and is refused the password with `httpsec.ErrReauthenticationMethodNotUsable` (403)
before the body is read. A user with no second factor re-proves with the password. The password
endpoint looks the methods up in configuration order and stops at the first one the user is enrolled
on, which alone refuses the password; the listing asks every method. An enrolment lookup that fails
refuses the request; it never falls back to the password.
`httpsec.RequireSecondFactorForReauthentication()` refuses the password to everyone.

**There is no "any factor" option.** A password re-proof by a user who holds a second factor would
make the session fresh at single-factor strength, and freshness is what admits registering a
passkey and regenerating recovery codes. A phisher who holds the password and the session cookie
could then plant an authenticator that later meets both factors. The option would weaken a
guarantee the library makes, so it does not exist.

**Users without a password.** Whether a user has a password is not known without loading them, so
the listing offers the password to every user with no second factor. A user who signed in only
through an OIDC provider then fails a password re-proof as a wrong password would. A deployment
with such users filters the password out in `httpsec.WithReauthenticationMethodsResponder`, which
receives the decision and runs on the request carrying the session.

### Stated limits

- **The default re-proof challenge store serves one process.** A challenge begun on one replica
  cannot be answered on another. A deployment running more than one replica passes a shared
  `onetime.Store` to `httpsec.WithReauthenticationChallengeStore`, as it does for the MFA
  challenges.
- **Re-proof has no budget of its own.** Second-factor failures share the MFA slot's per-user
  throttle with login, and password failures the account lockout, so a stolen session can spend the
  user's allowance there, as anyone who knows the username already can at login.

### "Re-authentication required", from three places

Three refusals mean the caller must re-authenticate: `httpsec.ErrReauthenticationRequired` (the
recency guard, carried by `*httpsec.ReauthenticationRequiredError`),
`recovery.ErrReauthenticationRequired` (recovery-code regeneration) and
`passkey.ErrReauthenticationRequired` (passkey registration and management). Each names its own
condition, and all three map to 403. A consumer who wants to send the client to re-authenticate
matches them together:

```go
if errors.Is(err, httpsec.ErrReauthenticationRequired) ||
	errors.Is(err, recovery.ErrReauthenticationRequired) ||
	errors.Is(err, passkey.ErrReauthenticationRequired) {
	// send the client to GET /reauth/methods
}
```

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Endpoints | off | `httpsec.EnableReauthentication` |
| Prefix | `/reauth` (`httpsec.DefaultReauthenticationPrefix`) | `httpsec.WithReauthenticationPrefix` |
| Chain slot | 655 (`httpsec.OrderReauthentication`) | — |
| Factor policy | strongest held: a second factor if enrolled, else the password | `httpsec.RequireSecondFactorForReauthentication` (stricter only) |
| Re-proof challenge lifetime | 5 minutes | `httpsec.WithReauthenticationChallengeTTL` |
| Re-proof challenges issued | 10 per user, per method, per hour | `httpsec.WithReauthenticationChallengeLimit` |
| Re-proof challenge store | in-memory, one process only; required whenever the MFA slot was given a store and has a method with a begin step (give both the same one); giving one on a chain without the MFA slot fails `New` with `ErrConfig` | `httpsec.WithReauthenticationChallengeStore` |
| MFA challenge store, beside re-authentication | in-memory, one process only; giving one without `httpsec.WithReauthenticationChallengeStore`, while the MFA slot has a method with a begin step, fails `New` with `ErrConfig` naming both (a slot of TOTP alone builds without a re-proof store) | `httpsec.WithMFAChallengeStore` |
| Re-proof of a second factor | runs the post-authentication phase with the login's own input; every deny refuses; a second-factor challenge does not refuse, but the phase is judged again with the second factor counted as met, and what surfaces then refuses; the session's own user only, at begin and verify | a consumer policy reads `policy.Input.Reauthenticating` and `MFASatisfied` and decides what a re-proof means; no switch turns the phase off |
| Re-proof whose credential cannot be issued | stores nothing; the caller's credential keeps working | — |
| Lost rotation race, through any manager sharing the store | 409 `httpsec.ErrSessionRenewalConflict` inside the winner's in-flight window: 30 seconds for a strict rotation (`session.DefaultRenewalGrace`), the renewal's grace for a renewal; after it, 401 (`ErrExpired` until the store's sweep, `ErrNotFound` after) | `httpsec.WithRenewalGrace` (a renewal winner only) |
| Re-proof response | the login document, `Cache-Control: no-store` | `httpsec.WithReauthenticationResponder` |
| Begin response | the method's data, `Cache-Control: no-store` | `httpsec.WithReauthenticationBeginResponder` |
| Method listing response | the JSON above, `Cache-Control: no-store` | `httpsec.WithReauthenticationMethodsResponder` |

## Session management

Users can see where they are signed in and sign out other devices. A sign-in is a session family:
renewals do not show as extra devices, and a sign-in's handle is its family identifier, which is not
a secret and never a session identifier.

```go
sessions, err := session.New(session.WithSessionMetadata()) // record address and user agent

chain, err := httpsec.New(
	httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
	httpsec.EnableSessionManagement(),
	httpsec.EnableSignInNotice(queuedSender), // optional: tell the user about a new device
	// ...
)
```

### Endpoints

| Request | Answer |
|---|---|
| `GET /sessions` | 200 `{"sessions":[{"handle","created_at","last_used_at","first_factor","pending","current","client_ip","user_agent"}]}` |
| `DELETE /sessions/{handle}` | 204; ends that sign-in's whole family. The current sign-in's own handle ends it, as a logout does |
| `DELETE /sessions` | 204; ends every sign-in but the current one, keeping a successor a racing renewal inserts |

- Only a full session reaches them. A session owing a second factor, an enrolment, a recovery step
  or a password change is refused with the challenge it owes, as on any other route.
- Ending needs a recent authentication, judged as the recency guard judges it (`httpsec.ErrReauthenticationRequired`,
  403). Listing does not.
- The request's own sign-in is marked `current`, also when it presents a predecessor still inside
  its renewal grace window. A sign-in owing a second factor or a recovery step is listed with
  `pending` set, because an unknown pending sign-in is what a user most needs to see.
- A malformed, unknown or foreign handle is `httpsec.ErrSessionHandleNotFound` (404), and nothing
  is revoked.
- Every response to a request under the prefix carries `Cache-Control: no-store`, including a
  refusal from an earlier layer, such as a bearer refusing a revoked session reference.
- A store failure is 500 with fixed text (`session.ErrListUnavailable` for the listing). A request
  whose own context ended fails with the context's error.
- `client_ip` and `user_agent` are empty unless the manager records sign-in metadata, which is off
  by default because both are personal data.

### Notices

- **Passkey removal** notifies the user by default, naming the passkey and the time, never its
  credential ID. `httpsec.WithoutPasskeyRemovalNotification` turns it off for the removal endpoint
  (`passkey.WithoutRemovalNotice` for a single `Remove` call). A refused removal sends nothing, and
  a failure to send keeps the removal.
- **Sign-in from an unseen device** is opt-in (`httpsec.EnableSignInNotice`). After a login stores
  a sign-in, it is compared with the user's other live sign-ins. When none matches, and the
  consumer's `httpsec.SeenDevices` port (if any) has not seen the device either, the user is sent a
  notice with the time and the device's browser and platform family ("Firefox on Linux", or "an
  unrecognised device"). It never carries a token, a handle, the client address or the raw user
  agent.
  - A user's first sign-in is not notified.
  - A sign-in whose session was never stored is not notified.
  - All of its work runs after the sign-in, off the request path, so it never delays the response.
    It runs on a context the request's end does not cancel, bounded by a timeout, and a panic in it
    is recovered.
  - At most 32 notices are in progress at once. A sign-in that completes while that many are is
    not notified: its notice is dropped, never queued, and the drop is logged at WARN, sampled,
    naming no user. The sign-in's response is the same either way.
  - A failure, a timeout or a panic is logged without its text and does not affect the sign-in.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Endpoints | off | `httpsec.EnableSessionManagement` |
| Prefix | `/sessions` (`httpsec.DefaultSessionManagementPrefix`) | `httpsec.WithSessionManagementPrefix` |
| Recency to end a sign-in | 15 minutes (`httpsec.DefaultRecentAuthenticationWindow`) | `httpsec.WithSessionManagementRecency` |
| Session manager | the chain's (`httpsec.WithSessions`, or the first built-in's); none fails `New` | `httpsec.WithSessions` |
| Listing response | the JSON above, `Cache-Control: no-store` | `httpsec.WithSignInListResponder` |
| End response | 204, `Cache-Control: no-store` | `httpsec.WithSignInEndResponder` |
| Caching under the prefix | `Cache-Control: no-store` on every response | none: a listing of sign-ins is never cacheable |
| Sign-in metadata | not recorded | `session.WithSessionMetadata` |
| Unseen-device notice | off; needs metadata recording and a sender, or `New` fails | `httpsec.EnableSignInNotice` |
| Same device | equal user agents | `httpsec.WithSignInMatcher` |
| Device history beyond live sign-ins | none | `httpsec.WithSeenDevices` |
| Notice recipient | the principal's username | `httpsec.WithSignInNoticeRecipient` |
| Notice text | plain English, no brand | `httpsec.WithSignInNoticeMessage` |
| Notice work timeout | 30 seconds (`httpsec.DefaultSignInNoticeTimeout`) | `httpsec.WithSignInNoticeTimeout` |
| Notices in progress at once | 32 (`httpsec.DefaultSignInNoticeConcurrency`); beyond it a notice is dropped and logged | `httpsec.WithSignInNoticeConcurrency` |
| Notice device text | browser and platform family, never the raw user agent | `httpsec.WithSignInNoticeMessage` (it receives only the family text) |
| Passkey removal notice | on | `httpsec.WithoutPasskeyRemovalNotification` |

## Behind a reverse proxy

By default the chain attributes a request to its TCP peer, judges it secure only over TLS, and takes
its host from the `Host` header. Forwarded headers are neither read nor removed. That is the safe
answer when nothing sits in front of the application, and the wrong one behind a proxy: every client
shares the proxy's rate-limit bucket.

`httpsec.EnableTrustedProxies` names the proxies whose forwarded headers are believed, the one header
family they write, and the fields of it to trust:

```go
chain, err := httpsec.New(
	httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, // the proxies, never 0.0.0.0/0
		Headers: httpsec.XForwarded(
			httpsec.ForwardedFor,
			httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com"), // the allowlist is required
		),
		MaxHops: 1, // the default: only the peer is a trusted hop
	}),
	// ...
)
```

The same configuration answers the client, the scheme and the host on net/http, gin and fiber. The
adapters hand the chain the raw peer and headers; gin's `SetTrustedProxies` and fiber's
`TrustProxy`/`ProxyHeader` have no effect on it. A handler reads the resolved values with
`httpsec.ClientFromContext`.

Two limits to know. A custom adapter that does not remove the consumed headers hides them from the
chain's interceptors, but not from its framework's own handlers, which still see what the client
and proxy sent. And a proxy connected over a Unix socket has no IP address, so no prefix can trust
it: its forwarded headers are ignored, and there is no override today.

### Defaults

| Behaviour | Default | Override |
|---|---|---|
| Forwarded headers | ignored | `EnableTrustedProxies` |
| Trusted hops skipped | 1 | `TrustedProxies.MaxHops` |
| A catch-all prefix (`0.0.0.0/0`, `::/0`) | refused at construction | `TrustAllProxies()` |
| A forwarded host outside the allowlist | refused 400 (`ErrHostNotAllowed`), before any interceptor | none: name the host in `ForwardedHost` |
| Consumed headers (`Forwarded`, `X-Forwarded-*`, the certificate header) | removed from every request | `KeepForwardedHeaders()` |
| TLS ending upstream with no forwarded headers | requests are plain HTTP | `WithHTTPSDeployment()` (not with trusted proxies) |

### nginx

```nginx
location / {
    proxy_pass http://app:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
}
```

`$proxy_add_x_forwarded_for` appends the peer nginx saw to whatever the client sent. The chain reads
the list from the right, so a client's own entries are never reached. `proxy_set_header` replaces
the client's `X-Forwarded-Proto` and `X-Forwarded-Host`; a header nginx does not set is passed
through as the client sent it, which is why each field is trusted only when named.

### Traefik

```yaml
entryPoints:
  web:
    address: ":80"
    forwardedHeaders:
      insecure: false   # do not pass through forwarded headers from untrusted clients
      # trustedIPs: ["10.30.0.0/16"]  # only when another proxy sits in front of Traefik
```

Traefik writes `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` itself. Whether it
replaces a `X-Forwarded-Proto` or `X-Forwarded-Host` the client sent in every configuration and
version is **not verified** here. Before trusting `ForwardedHost` or `ForwardedProto` behind Traefik,
send a request with forged `X-Forwarded-Host: evil.example` and `X-Forwarded-Proto: https` through
your deployment and check that the chain refuses the host and sees the scheme Traefik terminated.
Until then, trust `ForwardedFor` alone.

## Passwords

`password.NewPolicy()` decides whether a new password may be set. With no options it requires 15 to
128 characters (counted in code points, never trimmed or normalised) and refuses the bundled list of
common passwords; it is safe to use as it stands. Each option adds or replaces one rule and leaves
the others alone.

| Behaviour | Default | Override |
|-----------|---------|----------|
| Length | 15 to 128 code points | `password.MinLength`, `password.MaxLength` (floors 8 and 64) |
| Common passwords | the bundled list, case-insensitive | `password.CommonPasswords`, `password.WithoutCommonPasswords` |
| Words tied to the user or the service | none | `password.ContextWords` |
| Breached passwords | no check | `password.Breached(password.PwnedPasswords(client), password.Refuse)` |
| Reuse | no history | `password.NoReuse(history, depth)` |
| Encoder for a change | Argon2id at its defaults | `password.WithEncoder` |

Rules run cheapest first and the first refusal ends the check, so a short or common candidate never
causes a breach lookup or a history read. A refusal matches `password.ErrPasswordRejected` (422) and
names its rule; its text never carries the candidate, a hash or a context word.

An encoder with a byte limit, as bcrypt's 72 bytes, has a longer candidate refused as too long by
the check, so a check and a change agree. The built-in bcrypt encoder states its limit through the
optional `password.InputLimiter` method `MaxInputBytes() int`; your own encoder implements it the
same way to get the same answer from the check. An encoder that states none gets no byte check, and
`Policy.Change` answers its `password.ErrTooLong` as a too-long refusal (422), never as a failure.

### The breach check says what a failed lookup means

The breach check is opt-in, and it has no default failure mode, because the safe answer and the
convenient one differ and the choice is yours. Only the first five characters of the password's
SHA-1 leave the process, through the confined outbound client.

- `password.Refuse` fails the check with `password.ErrLookupUnavailable` (500) while the corpus
  cannot be asked: no password is set during an outage.
- `password.Accept` lets the candidate through that rule and the next rule runs: an outage never
  stops a password change.
  It is not silent: each such candidate writes one ERROR record with fixed text and the failure's
  Go type, never the candidate, its hash or the error's text. The record goes to `slog.Default()`
  as it is when the policy is built; `password.WithPolicyLogger(l)` replaces it with your logger.

Either way, a caller who cancelled the request gets the context's own error, not a lookup failure.

### Upgrading outdated hashes at login

The built-in encoders implement `password.Upgrader`, so they can say a stored hash was made with
weaker parameters: any one parameter below the encoder's (Argon2id memory, iterations, threads,
salt or key length; scrypt N, r, p, salt or key length; bcrypt cost) is enough, even if another is
above, and the new hash has exactly the encoder's parameters. By default nothing is rehashed. Give
form login (`httpsec.WithLoginRehash`), Basic (`httpsec.WithBasicAuthRehash`) or the password
re-proof (`httpsec.WithReauthenticationRehash`) a write, and a request whose password verified asks
the current encoder; when it says so, the password is encoded again (one more key derivation on
that request) and the write receives the user, the hash it replaces and the new hash. A login
challenged for a second factor still upgrades; one refused after the password verified does not.
The write's error is logged, without any hash, and never changes the outcome.

Rehashing does not move users between algorithms. The upgrade is reached only once the password
verified, and a built-in encoder does not verify another algorithm's hash, so moving users from,
say, bcrypt to Argon2id at login needs a consumer encoder that verifies both and encodes with the
new one.

Write the new hash only while the replaced one is still stored, or a password change that landed
meanwhile is undone. `password.ConditionalProvisionerRehash(store)` does that for the library's
identity stores:

```go
rehash, err := password.ConditionalProvisionerRehash(identityStore) // a nil store is an error here
if err != nil {
	return err
}

httpsec.EnableFormLogin(deps, httpsec.WithLoginRehash(rehash))
```

It is one call to the store: an update conditional on the replaced hash
(`identity.WithUserPasswordIf`), which the store decides in the `UPDATE`'s own `WHERE`. When the
stored hash changed meanwhile, nothing is written, the store reports `identity.ErrNotUpdated`, and
the write treats that as done: the newer password stays, and the next login upgrades it. The
password's age is not moved, because a rehash is not a password change. A consumer store must
honour the condition too; the identity conformance suite (`test/identity`) checks it.

## Security headers

`httpsec.EnableSecurityHeaders` is off until you enable it. Once enabled, with no
options, every response the chain produces, its own refusals included, carries:

- `Content-Security-Policy` with a fresh per-response nonce, `'strict-dynamic'`,
  `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: strict-origin-when-cross-origin`;
- `Cross-Origin-Opener-Policy: same-origin-allow-popups`, so a popup-based OIDC
  login keeps working;
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`, only on a
  request the chain judges secure (TLS, `WithHTTPSDeployment`, or a trusted
  proxy's forwarded scheme).

`X-XSS-Protection`, `X-Frame-Options`, `Cross-Origin-Embedder-Policy` and
`Origin-Agent-Cluster` are never sent unless you add them with `WithHeader`.
The layer does not wrap the response writer, so a handler's own value for a
header wins and flushing and hijacking work as without it.

The layer is outside every built-in interceptor. A consumer interceptor you
register ahead of it (`httpsec.Before(httpsec.OrderSecurityHeaders)`) runs outside
it, and a response that interceptor writes carries no security headers; register
yours at or after the layer's slot to have its responses marked.

```go
chain, err := httpsec.New(
    httpsec.EnableSecurityHeaders(
        httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'", "data:"))),
        httpsec.WithHeaderProfile(httpsec.APIHeaders(), httpsec.PathPrefix("/api/")),
    ),
)
```

Every profile is editable with the same editors (`WithHeader`, `WithoutHeader`,
`WithCSP`): `APIHeaders(opts...)` edits the API profile, and
`NewHeaderProfile(opts...)` starts a profile of your own from nothing. The first
profile whose matcher selects a request applies. `WithHSTS`, `WithCSPReportOnly`
and the reporting options belong to the layer, not to a profile, and a profile
given one fails construction.

A policy with no directive is refused at construction, whether it is the zero
`CSPPolicy` given to `WithCSP` or an empty (or blank) value given to
`WithHeader("Content-Security-Policy", "")`. The same holds for
`Content-Security-Policy-Report-Only`. To send no policy, use
`WithoutHeader("Content-Security-Policy")`. This is a breaking change before the
first tag: an empty policy used to be sent as it was.

### Rolling a policy out

`WithCSPReportOnly()` sends the policy as `Content-Security-Policy-Report-Only`,
so browsers report what it would block and block nothing.
`WithCSPReportOnlyPolicy(p)` sends a stricter candidate beside the enforced
policy, with the same nonce. `WithReportingEndpoint("csp", "https://reports.example.com/csp")`
adds `Reporting-Endpoints`, `report-to` and `report-uri`; the endpoint must be an
absolute `https` URL, and receiving the reports is up to you.

### A static page: hashes instead of a nonce

A page that is cached cannot carry a per-response nonce. `HashCSP("sha256-...")`
lists the script hashes you supply, which your build computes, and generates no
nonce. `HashCSP(...).With(httpsec.CSPDirective(...))` adds directives.

### Giving the nonce to a page

The handler reads the nonce with `httpsec.CSPNonce(r.Context())`. It finds none
on a route a profile without a nonce serves.

**`html/template`.** Pass the nonce as data and put it on each script you own;
do not inject it into every tag a template or a proxy can find (OWASP's advice).

```go
nonce, _ := httpsec.CSPNonce(r.Context())
err := page.Execute(w, struct{ Nonce string }{nonce})
```

```html
<script nonce="{{.Nonce}}" src="/app.js"></script>
```

**Vite.** Vite's `html.cspNonce` option adds a `nonce` attribute to the `<script>`
and `<style>` tags it emits, and a placeholder
`<meta property="csp-nonce" nonce="PLACEHOLDER" />` whose nonce Vite uses when
it needs one, in development and in the build. Vite's documentation says the
placeholder must be replaced with a unique value for each request. Serve the
built `index.html` through a handler that does so (the placeholder text is
whatever you set `html.cspNonce` to):

```go
nonce, _ := httpsec.CSPNonce(r.Context())
w.Header().Set("Content-Type", "text/html; charset=utf-8")
_, _ = io.WriteString(w, strings.ReplaceAll(indexHTML, "PLACEHOLDER", nonce))
```

**Next.js.** The Next.js guide has its own proxy generate the nonce, put it in
the request's `Content-Security-Policy` header and an `x-nonce` request header,
and has Next.js read the nonce from the `'nonce-{value}'` in that header while
rendering. It requires dynamic rendering for nonces. So a Next.js application
owns its own policy: where a route's pages are rendered by Next.js, give that
route a profile that sends no `Content-Security-Policy`, so the two policies do
not meet, and keep the other headers:

```go
httpsec.WithHeaderProfile(
    httpsec.NewHeaderProfile(
        httpsec.WithHeader("X-Content-Type-Options", "nosniff"),
        httpsec.WithHeader("Referrer-Policy", "strict-origin-when-cross-origin"),
    ),
    httpsec.PathPrefix("/app/"),
)
```

Sources: the [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html),
[web.dev: Strict CSP](https://web.dev/articles/strict-csp),
[Vite's CSP section](https://vite.dev/guide/features#content-security-policy-csp) and
[Next.js's CSP guide](https://nextjs.org/docs/app/guides/content-security-policy).

## CORS

`httpsec.EnableCORS` is off until you enable it, and then needs an explicit list
of origins. It runs inside the chain, in `OrderCORS`, so it behaves the same on
net/http, gin and fiber, and answers a preflight before any authentication or
the authorizer could refuse it.

```go
chain, err := httpsec.New(
    httpsec.EnableSecurityHeaders(),
    httpsec.EnableCORS(httpsec.CORSPolicy{
        AllowedOrigins: []string{"https://app.example.com"},
        AllowedHeaders: []string{"Authorization", "Content-Type"},
        ExposedHeaders: []string{"WWW-Authenticate"},
    }, httpsec.WithOriginPattern("https://*.preview.example.com")),
)
```

Once enabled:

- an origin is allowed only when it equals one on the list, after both are
  lower-cased and stripped of a default port, or matches a `WithOriginPattern`
  pattern, whose `*` is one whole host label followed by at least two more;
- `*` alone allows every origin without credentials: any request carrying an
  `Origin`, `null` included, gets `Access-Control-Allow-Origin: *`, and no
  origin is ever reflected;
- every response the layer or an interceptor behind it answers carries
  `Vary: Origin`, allowed or not. `Origin` is added to any `Vary` your
  middleware or an earlier interceptor set, never in place of it. A consumer
  interceptor you register ahead of the layer (`httpsec.Before(httpsec.OrderCORS)`)
  runs outside it, and a response that interceptor writes carries no
  `Vary: Origin` unless it adds one; register yours at or after the layer's
  slot to have its responses marked;
- an allowed origin gets `Access-Control-Allow-Origin` with its own origin and,
  on actual responses, the exposed headers, also on the chain's own refusals,
  so a page can read a 401's `WWW-Authenticate`;
- a preflight gets 204: with the allow headers when its origin, method (default
  `GET`, `HEAD`, `POST`) and every requested header are allowed, and with no
  CORS header otherwise. `Access-Control-Max-Age` defaults to 600 seconds;
  `WithoutPreflightCaching()` sends `0` instead;
- with DPoP enabled, `DPoP` is allowed and `DPoP-Nonce` and `WWW-Authenticate`
  are exposed; with CSRF protection reading a token header, that header is
  allowed. `WithoutAutomaticCORSHeaders()` turns these additions off.

Construction refuses no origins, `null`, a scheme other than http or https, an
origin with a path, query, fragment or userinfo, `*` with `AllowCredentials` or
beside other origins, a wildcard outside `WithOriginPattern`, a pattern with
fewer than two labels after its wildcard (`https://*.com`), and a `MaxAge`
below one second or set beside `WithoutPreflightCaching()`. scrty holds no
public-suffix list, so `https://*.co.uk` is accepted like
`https://*.example.com`; do not name a pattern under a public suffix.

`ResponseWriter` requires `AddHeader(name, value)`, which keeps the values
already set (net/http's `Header().Add`). An adapter of your own must implement
it; the CORS layer uses it to extend `Vary`.

## CSRF protection

`httpsec.EnableCSRFProtection` refuses state-changing requests another site
makes the user's browser send. It is off until you enable it, and required as
soon as an interceptor authenticates by a cookie: `New` fails unless you give
`EnableCSRFProtection` or say plainly that you opt out with
`WithoutCSRFProtection()`.

```go
chain, err := httpsec.New(
    httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example.com"}}),
    httpsec.EnableCSRFProtection(
        httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/payments"),
    ),
)
```

Every request whose method is not exactly `GET`, `HEAD` or `OPTIONS` is judged
in `OrderCSRF`, before any authentication:

- `Sec-Fetch-Site: same-origin` or `none` passes; any other value is refused
  unless the `Origin` is trusted;
- without `Sec-Fetch-Site`, an `Origin` that differs in scheme, host or port
  from the request's own is refused unless it is trusted, and `Origin: null`
  never matches;
- a request with neither header is not a browser's, and passes.

Trusted origins are every origin `EnableCORS` lists or matches by a pattern (a
CORS `*` trusts none), plus those `WithCSRFTrustedOrigins` adds;
`WithoutCORSOriginsTrustedForCSRF()` stops trusting the CORS ones. The refusal
is `httpsec.ErrCrossSiteRequest`, answered 403.

**Behind a proxy that ends TLS**, the request's own origin is the one the chain
resolves. Without `EnableTrustedProxies` or `WithHTTPSDeployment()`, the chain
sees a plain-HTTP request for the proxy's upstream address, so an older browser
that sends no Fetch Metadata, only `Origin: https://app.example.com`, is refused.
Configure one of them.

### The token

A request authenticated by a cookie must also carry its sign-in's token, in the
`X-CSRF-Token` header or the `csrf_token` field of a URL-encoded form
(`WithCSRFTokenNames` renames both). A request authenticated only by an
`Authorization` header needs none. The page reads the token from the request it
was served on:

```go
func page(w http.ResponseWriter, r *http.Request) {
    token, ok := httpsec.CSRFToken(r.Context())
    // render token into a <meta> tag or a hidden csrf_token field
}
```

- By default the token is 32 random bytes made when the sign-in is created and
  stored on it. It survives renewal and rotation, and a new
  sign-in gets a new one. It is compared in constant time.
- A sign-in made before CSRF protection was enabled holds no token, and its
  unsafe cookie requests are refused until the user signs in again.
- The header is read first, then the form field of an
  `application/x-www-form-urlencoded` body of at most 1 MiB, never the query
  string. A multipart form must send the token in the header. A body over
  1 MiB that carries the token only in the field is refused (403).
- `WithCSRFTokens` replaces the source, for example with an HMAC over the
  sign-in's family under your own key. `CSRFToken` and the check then both read
  through it, and sign-ins no longer store a token.

An interceptor of your own that authenticates by a cookie implements
`httpsec.CookieAuthenticator` and calls `httpsec.CheckCSRFToken(ex, session)`
before handing the session on. A check that passes also makes that sign-in the
one `CSRFToken` reads, so your page gets its token with nothing more to
publish.

- Register it **after** `OrderCSRF` (at `OrderBearerToken`, for example). With
  `EnableCSRFProtection`, `New` refuses a cookie authenticator at or before
  `OrderCSRF`: it would run before the request was judged, and its token would
  go unchecked. There is no override.
- `CheckCSRFToken` fails closed when CSRF protection never judged the request,
  for example when it is called outside the chain: the error wraps
  `httpsec.ErrConfig`, is answered 500, and your interceptor publishes no
  session. On a chain built with `WithoutCSRFProtection()` it passes.
- On a `GET`, `HEAD` or `OPTIONS`, and on an exempt route, it checks no token
  and passes.

### Exemptions

`WithCSRFExemption(method, path)` exempts one route, such as a provider's
webhook, from both checks. Every other protection still applies to it.

- The method and the path are matched exactly, against the path as the client
  sent it (`Request.EscapedPath`), neither decoded nor cleaned. Write the
  pattern as clients send it. `/webhooks/payments/`, `/Webhooks/payments`,
  `/webhooks/payments/../../settings` and any other encoding, such as
  `/webhooks%2Fpayments` or `/webhooks/p%61yments`, are other routes and are
  judged, whatever your framework's router decodes them to.
- A `*` segment matches exactly one path segment that, decoded, is not empty,
  `.` or `..` and holds no `/`: `/webhooks/*/events` matches
  `/webhooks/stripe/events`, not `/webhooks/a/b/events` or
  `/webhooks/a%2Fb/events`.
- Construction refuses an exemption with no method, of `GET`, `HEAD` or
  `OPTIONS`, of `/` alone, with an empty pattern, a relative path, dot or empty
  segments, a `*` inside a segment, or no segment but wildcards. No option
  exempts every route; that is `WithoutCSRFProtection()`.
- Construction also refuses a fixed segment that is a malformed percent-encoding
  (`%zz`), decodes to `.`, `..` or something holding `/` (`%2e%2e`, `%2E`,
  `a%2Fb`), or holds a character a request always escapes, such as a space or
  `é` (`/webhooks/café`): it could never match, so write it in its escaped form
  (`/webhooks/caf%C3%A9`, `/webhooks/a%20b`). An escaped segment is kept and
  matches only that escaped form.
- With OIDC login, `POST` to the back-channel logout endpoint (the
  `WithOIDCBackchannelLogoutPath` prefix followed by one provider name) is
  exempt by default, because the provider calls it server to server. The
  prefix is matched as a literal, never as a pattern, so a `*` in it widens
  nothing. A prefix that cannot be exempt as written (one holding a
  percent-encoding, a character a request escapes such as `/idp/déconnexion`,
  or an empty or dot segment) fails construction; fix the
  path or give `WithoutBackchannelLogoutExemption()`, which removes the
  exemption.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Protection | off; required with a cookie authenticator | `httpsec.EnableCSRFProtection`, or `httpsec.WithoutCSRFProtection` |
| Trusted origins | the CORS layer's, never `*` | `httpsec.WithCSRFTrustedOrigins`, `httpsec.WithoutCORSOriginsTrustedForCSRF` |
| Token names | header `X-CSRF-Token`, field `csrf_token` | `httpsec.WithCSRFTokenNames` |
| Token source | 32 random bytes stored on the sign-in | `httpsec.WithCSRFTokens` |
| Exempt routes | the OIDC back-channel logout endpoint only | `httpsec.WithCSRFExemption`, `httpsec.WithoutBackchannelLogoutExemption` |

## DPoP

`httpsec.EnableDPoP` binds the tokens the chain issues to a key the client
holds (RFC 9449). The client signs a short proof for every request, so a token
copied out of a log, a proxy or a browser extension is of no use without the
private key. It needs a feature that verifies bound credentials (today
`EnableBearerToken` or `EnableSessionBearer`; your own handler that checks
proofs does not count), and is off until you enable it. It also needs the host
your proofs name, declared by you: `PublicURL`, or trusted proxies that name
their allowed hosts with `ForwardedHost`. The chain never takes it from the
request's own `Host` header, which the client chooses, so a chain with neither
is a construction error:

```go
chain, err := httpsec.New(
    httpsec.EnableFormLogin(loginDeps),
    httpsec.EnableBearerToken(bearerDeps), // or EnableSessionBearer
    httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://app.example.com"}),
)
```

Behind a reverse proxy, you may declare the host through the proxy instead:
`EnableTrustedProxies` with `ForwardedHost("app.example.com")`. Trusted
proxies without `ForwardedHost` do not count.

Once enabled:

- both bearer modes accept `Authorization: DPoP <token>` with one `DPoP` proof
  header; unbound tokens still work as `Bearer`, unless `Require` is set;
- every issuing endpoint (login, second factor, passkey login, magic link, OIDC
  handoff, recovery, re-authentication, renewal) checks a request's proof
  before it spends anything, and binds the sign-in and the token to the
  proof's key (`cnf.jkt`). The token response says `"token_type": "DPoP"`;
- a bound token presented as `Bearer`, or with a proof from another key, is
  refused (401, `ErrInvalidDPoPProof`) with
  `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`. A request
  with no token gets a `DPoP` and a `Bearer` challenge, or only the `DPoP` one
  when DPoP is required. The challenge is always on with `EnableDPoP`; to
  change it, remove or replace the header in a `WithErrorHandler` (or a
  guard's `WithGuardErrorHandler`);
- a sign-in's binding is fixed when it is created: a second factor and a
  renewal keep it, and a re-authentication may bind a sign-in that was not.

### Defaults

| Field | Default |
|---|---|
| `Require` | `false`: accepted, not required |
| `ProofMaxAge` | 60 seconds either side of the chain's clock |
| `Algorithms` | `ES256` only; `none` and HMAC are refused at construction |
| `MaxProofSize` | 8 KiB, refused before anything is parsed |
| `Replay` | in memory, per process |
| `Nonce` | off |
| `NonceLifetime` | 5 minutes, when nonces are on; the floor is 10 seconds (`MinDPoPNonceLifetime`) |
| `PublicURL` | none, and none is refused at construction unless trusted proxies name their allowed hosts (`ForwardedHost`; see "Behind a reverse proxy") |

With more than one replica, give `Replay` a store they share, or a proof can be
replayed once on each replica within its lifetime.

### Server nonces

Nonces are off by default: the 60-second lifetime and the replay store already
bound replay, and a nonce costs the client a round trip whenever it has none.
When you turn them on, they are sealed with your key material, so every
replica accepts a nonce any of them issued without a shared store. The chain
holds no key of its own, so `NonceCipher` is required (a construction error
without it). The cipher your sessions already seal with serves, and nonces are
sealed with their own additional data, so a nonce never opens as anything else;
a keyring kept for nonces alone is better, so rotating it touches nothing else:

```go
kr, err := seal.NewKeyring(seal.WithKeyringEncryptionKey("2026-11", key))
// ...
c, err := seal.NewAEADCipher(kr)
// ...
httpsec.EnableDPoP(httpsec.DPoP{
    PublicURL:   "https://app.example.com",
    Nonce:       true,
    NonceCipher: seal.SessionCipher(c),
})
```

A proof without a current nonce is refused (401, `ErrDPoPNonceRequired`, which
also matches `ErrInvalidDPoPProof`) with `error="use_dpop_nonce"` and a fresh
nonce in `DPoP-Nonce`. The client signs a new proof with it and retries. A
response to a proof whose nonce is past half its lifetime carries the next
one. Every response that hands out a nonce is `Cache-Control: no-store`, and
each replica issues one nonce at a time, shared by its requests. With
`EnableCORS`, `DPoP` is allowed and `DPoP-Nonce` and
`WWW-Authenticate` are exposed for you.

A client with `Nonce: true` keeps the last `DPoP-Nonce` it saw, from the
`use_dpop_nonce` 401 and from later responses, puts it in the next proof's
`nonce` claim, and retries once on that 401:

```js
let nonce; // the last DPoP-Nonce seen; headersFor signs a proof with it and sets Authorization and DPoP
let res = await fetch(url, { headers: await headersFor(url, nonce) });
nonce = res.headers.get("DPoP-Nonce") ?? nonce;
if (res.status === 401 && res.headers.get("WWW-Authenticate")?.includes("use_dpop_nonce")) {
  res = await fetch(url, { headers: await headersFor(url, nonce) }); // a new proof, nonce set
  nonce = res.headers.get("DPoP-Nonce") ?? nonce;
}
```

### In the browser

The browser's WebCrypto makes the key pair and signs the proofs. The private
key is generated non-extractable, so no script can read it out; keep the
`CryptoKeyPair` in IndexedDB so the same key signs every request of the
sign-in it is bound to. A key that is lost leaves its token unusable, and the
user signs in again.

```ts
// dpop.ts
const encoder = new TextEncoder();

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function createDPoPKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

export interface ProofOptions {
  accessToken?: string; // the token sent as "Authorization: DPoP"; none at sign-in
  nonce?: string;       // the last DPoP-Nonce the server sent
}

export async function dpopProof(
  keys: CryptoKeyPair,
  method: string,
  url: string,
  options: ProofOptions = {},
): Promise<string> {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const target = new URL(url, globalThis.location?.href);

  const header = { typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } };
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: target.origin + target.pathname,
    iat: Math.floor(Date.now() / 1000),
  };
  if (options.accessToken) {
    claims.ath = base64url(await crypto.subtle.digest("SHA-256", encoder.encode(options.accessToken)));
  }
  if (options.nonce) {
    claims.nonce = options.nonce;
  }

  const input = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(claims)))}`;
  // WebCrypto's ECDSA signature is r || s, the encoding JWS uses for ES256.
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, encoder.encode(input));

  return `${input}.${base64url(signature)}`;
}
```

`htu` is the URL as the browser sends it, without query or fragment, and the
chain compares the path as sent, percent-encoding intact. When the page calls
the API through another host, such as a frontend server's rewrite, set
`PublicURL` to the origin the browser sees.

The test module signs in with a proof this file produced
(`test/testdata/dpop/`), so a change on either side that breaks the other
fails there.

#### React

One fetch wrapper signs every request and retries once when the server asks
for a nonce:

```ts
// dpopFetch.ts
import { createDPoPKey, dpopProof } from "./dpop";

let keys: Promise<CryptoKeyPair> | undefined; // load from IndexedDB in a real app
let nonce: string | undefined;

export async function dpopFetch(url: string, init: RequestInit = {}, accessToken?: string): Promise<Response> {
  keys ??= createDPoPKey();
  const method = init.method ?? "GET";

  const send = async () => {
    const headers = new Headers(init.headers);
    headers.set("DPoP", await dpopProof(await keys!, method, url, { accessToken, nonce }));
    if (accessToken) headers.set("Authorization", `DPoP ${accessToken}`);
    return fetch(url, { ...init, headers });
  };

  let res = await send();
  nonce = res.headers.get("DPoP-Nonce") ?? nonce;
  if (res.status === 401 && res.headers.get("WWW-Authenticate")?.includes('error="use_dpop_nonce"')) {
    res = await send(); // a new proof, with the nonce just received
    nonce = res.headers.get("DPoP-Nonce") ?? nonce;
  }
  return res;
}
```

```tsx
import { useEffect, useState } from "react";
import { dpopFetch } from "./dpopFetch";

export function Orders({ accessToken }: { accessToken: string }) {
  const [orders, setOrders] = useState<{ id: string }[]>([]);

  useEffect(() => {
    dpopFetch("/api/orders", {}, accessToken).then((r) => r.json()).then(setOrders);
  }, [accessToken]);

  return <ul>{orders.map((o) => <li key={o.id}>{o.id}</li>)}</ul>;
}

// Sign-in: the response's token_type is "DPoP".
export async function signIn(username: string, password: string): Promise<string> {
  const res = await dpopFetch("/login", { method: "POST", body: new URLSearchParams({ username, password }) });
  return (await res.json()).access_token;
}
```

A retry sends the body again, so pass one that can be read twice, such as a
string or `URLSearchParams`, not a stream.

#### Next.js

The private key lives in the browser, so proofs are signed in client
components; a Server Component or a route handler holds no key and cannot sign
one. Use the same `dpopFetch` from a component marked `"use client"`:

```tsx
"use client";

import { useEffect, useState } from "react";
import { dpopFetch } from "@/lib/dpopFetch";

export default function Orders({ accessToken }: { accessToken: string }) {
  const [orders, setOrders] = useState<{ id: string }[]>([]);

  useEffect(() => {
    dpopFetch(`${process.env.NEXT_PUBLIC_API_ORIGIN}/api/orders`, {}, accessToken)
      .then((r) => r.json())
      .then(setOrders);
  }, [accessToken]);

  return <ul>{orders.map((o) => <li key={o.id}>{o.id}</li>)}</ul>;
}
```

Calling the API's own origin keeps `htu` equal to the URL the chain sees. If
requests go through a Next.js rewrite instead, the browser signs the frontend's
URL, and the chain needs `PublicURL` set to that origin.

#### htmx

This sample assumes server nonces are off; with `Nonce: true`, add the nonce
the client last saw to the proof, as in "Server nonces".

A proof is signed asynchronously, and `htmx:configRequest`, where headers are
set, is not. `htmx:confirm` fires before every request and can hold it:
`preventDefault()` stops it, and `detail.issueRequest()` sends it later, so the
proof is made there and added in `htmx:configRequest`:

```js
import { createDPoPKey, dpopProof } from "./dpop.js";

const keys = createDPoPKey(); // load from IndexedDB in a real app
const proofs = new WeakMap();
let accessToken; // set after sign-in

document.body.addEventListener("htmx:confirm", (evt) => {
  if (!accessToken || proofs.has(evt.detail.elt)) return;

  evt.preventDefault();
  keys
    .then((k) => dpopProof(k, evt.detail.verb, evt.detail.path, { accessToken }))
    .then((proof) => {
      proofs.set(evt.detail.elt, proof);
      evt.detail.issueRequest(true); // true skips hx-confirm's window.confirm()
    });
});

document.body.addEventListener("htmx:configRequest", (evt) => {
  const proof = proofs.get(evt.detail.elt);
  if (!proof) return;

  proofs.delete(evt.detail.elt);
  evt.detail.headers["Authorization"] = `DPoP ${accessToken}`;
  evt.detail.headers["DPoP"] = proof;
});
```

`issueRequest(true)` skips the `window.confirm()` of `hx-confirm`; on an element
that has one, ask the question in the `htmx:confirm` handler first. Each
request gets a new proof, because a proof is accepted once.

## Automation challenge

`httpsec.EnableAutomationChallenge` puts a challenge of your choosing, a
CAPTCHA, a managed challenge or a proof of work, in front of the chain's
unauthenticated flows, so credential stuffing and enumeration cost more. scrty
bundles no vendor: you implement `httpsec.ChallengeVerifier` over the service
you use, and the chain asks it. Nothing asks for a challenge until you enable
it.

```go
// stubVerifier shows the shape of a verifier. It is a stub, not an
// integration: a real one sends the response token to your challenge
// service, with your secret, and reads its verdict.
type stubVerifier struct {
    check func(ctx context.Context, token string) (bool, error)
}

func (v stubVerifier) Verify(
    ctx context.Context, r httpsec.Request, s httpsec.ChallengeSignals,
) (httpsec.ChallengeDecision, error) {
    // Ordinary traffic is not asked; a source with recent failures is, and so
    // is a fresh IPv6 /64 inside an aggregate others failed from. The
    // identifier signal is not a reason to challenge on its own: it can tell
    // a known account from an unknown one (see the stated limits below), so
    // read it only together with other evidence of automation.
    if !s.SourceHasFailures && !s.SourceAggregateHasFailures {
        return httpsec.ChallengeNotNeeded, nil
    }

    token := r.Header("X-Challenge-Response") // wherever your page puts it
    if token == "" {
        return httpsec.ChallengeRefuse, nil
    }

    ok, err := v.check(ctx, token)
    if err != nil {
        return 0, err // an outage, not a refusal: answered 500
    }
    if !ok {
        return httpsec.ChallengeRefuse, nil
    }

    return httpsec.ChallengePass, nil
}

chain, err := httpsec.New(
    httpsec.EnableFormLogin(loginDeps),
    httpsec.EnableAutomationChallenge(stubVerifier{check: myService.Check}),
)
```

Once enabled:

- form login, the magic-link request, the passwordless passkey begin and the
  recovery start ask the verifier, after their source limit and before their
  own work and any account lookup. Basic is not in that default: it carries
  credentials on every request, so a challenge would be consulted on every API
  call. Name it to challenge it, as in
  `WithChallengeFlows(httpsec.ChallengeFlowBasicAuth, httpsec.ChallengeFlowFormLogin)`;
  the option replaces the default selection with the flows it names, and may
  name only flows the chain enables. A flow it does not enable, or the default
  selection over a chain that enables none of the four default flows (a chain
  with only Basic, say), fails `New` with `ErrConfig` naming `WithChallengeFlows`
  or the flow, because the verifier would never be asked and the chain would
  look protected when it is not;
- `ChallengePass` and `ChallengeNotNeeded` let the request through;
  `ChallengeRefuse` refuses it with `ErrChallengeRequired` (403). The refusal
  counts against the flow's source limit like a failed attempt, never against
  the username's lockout; `WithoutChallengeRefusalCounting()` stops the count.
  The magic-link request has no source limit, so a refusal there is counted
  nowhere;
- a verifier error is a dependency failure: `ErrChallengeUnavailable` (500)
  with fixed text, the verifier's error reachable through `errors.Is` and
  `errors.As` but never in the text or a log record, charged to nothing. A
  client that hangs up while the verifier runs fails with its context's error;
- the verifier is told (`ChallengeSignals`):
  - `SourceHasFailures`: whether the source has recent failures;
  - `SourceAggregateHasFailures`: whether the IPv6 aggregate holding the source
    (`WithIPv6Aggregate`, a /56 by default) has recent failures, from any
    source inside it. A client rotating through the /64s of its allocation
    arrives at each one clean, so this is what shows it. It is reported apart
    from the source's own signal, which keeps its meaning, and is false for
    IPv4 (IPv4-mapped addresses included) and for a guard with no aggregate
    (`WithoutIPv6Aggregate`);
  - `IdentifierHasFailures`, at form login and Basic (when named) only: whether
    the username has failures within the failure window of the chain's lockout
    policy (`lockout.WithFailureWindow`), so the challenge and the lockout
    agree on what "recent" means.

  Whatever cannot answer, a limiter or attempt store that fails, or a limiter
  that does not implement `ratelimit.RecentFailureReporter`, reads as having
  failures, so the verifier asks.

### Defaults

| Setting | Default |
|---|---|
| Verifier | none: the seam is off |
| Flows | form login, magic-link request, passwordless begin and recovery start; Basic only when named (`WithChallengeFlows`) |
| Refusal | counted against the source limit (`WithoutChallengeRefusalCounting`) |
| Aggregate signal | the source's IPv6 aggregate, the chain's `WithIPv6Aggregate` prefix (/56); false for IPv4 and with `WithoutIPv6Aggregate` |
| Identifier signal | form login and Basic only: a failed login for the username within the lockout policy's failure window (24 hours when the chain's engine holds no lockout policy; `lockout.WithFailureWindow`). Always false at the other three flows |

### Stated limits

- The in-memory limiter and the shared limiters of `redisstore`, `sqlstore` and
  `pgxstore` all report recent failures (`ratelimit.RecentFailureReporter`). A
  limiter you write yourself reports them by implementing that one optional
  method; without it, every source reads as having failures, which can only
  make the verifier ask more. A shared limiter that cannot reach its store, or
  that is answering for an outage, reports failures too.
- The magic-link request has no source limit, so a refusal there is counted
  nowhere. Adding one to that endpoint is outside this seam.
- The identifier signal is withheld at the recovery start, the magic-link request
  and the passwordless begin. A sign-in by an account's owner clears its recorded
  failures and nobody clears an unknown name's, so at a flow that answers alike
  for both, the signal would let a verifier answer whether an account exists. At
  form login and Basic it stays, with that residual: after one failed attempt
  each, an unknown username reports failures and a known one whose owner has since
  signed in does not. The lockout reset already lifts a known account's lockout
  and not an unknown name's, so the signal tells a client no more than that.
  Do not refuse on the identifier signal alone.
- The passwordless begin's limiter counts every begin, so there
  `SourceHasFailures` means the source has begun before in the window.

## Certificate-bound tokens (mTLS)

`httpsec.EnableCertificateBinding` binds the tokens the chain issues to the
TLS client certificate the client signed in with (RFC 8705). It suits
service-to-service callers that already hold a certificate and no browser key:
a token copied out of a log is of no use without the certificate's private
key. Like DPoP, it needs a feature that verifies bound credentials
(`EnableBearerToken` or `EnableSessionBearer`), and it is off until you enable
it:

```go
chain, err := httpsec.New(
    httpsec.EnableFormLogin(loginDeps),
    httpsec.EnableBearerToken(bearerDeps), // or EnableSessionBearer
    httpsec.EnableCertificateBinding(),
)

srv := &http.Server{
    Handler: chain.Middleware()(app),
    TLSConfig: &tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert, // the TLS server judges the certificate
        ClientCAs:  clientCAs,
        MinVersion: tls.VersionTLS12,
    },
}
```

Once enabled:

- every issuing endpoint (login, second factor, passkey login, magic link, OIDC
  handoff, recovery, re-authentication of an unbound sign-in) whose request
  presents a client certificate binds the sign-in and the token to the
  certificate's thumbprint, `cnf.x5t#S256`: base64url of the SHA-256 of its
  DER encoding. A request without a certificate gets an unbound token. The
  token is still presented as `Bearer`, and the token response says
  `"token_type": "Bearer"`;
- a certificate-bound token, or session reference, is accepted only on a
  request presenting the same certificate. Another certificate, or none, is
  refused with `ErrCertificateBinding` (401). The request's certificate is read
  once, in the `OrderMTLS` slot;
- with DPoP enabled too, a sign-in that carries a valid proof is bound to the
  DPoP key only, whether or not it also presents a certificate. A token carries
  one confirmation, and a DPoP key survives proxies that do not forward
  certificates;
- a token carrying `cnf.x5t#S256` presented while certificate binding is off
  is refused with `ErrCertificateBinding`, never accepted as a plain bearer
  token, by `EnableBearerToken` and `EnableSessionBearer` alike and whatever
  scheme (`Bearer` or `DPoP`) carried it;
- `EnableCertificateBinding` together with `EnableDPoP(httpsec.DPoP{Require:
  true})` is refused by `New` with an error wrapping `httpsec.ErrConfig` that
  names both options: with a proof required, every issuing request would carry
  one and be bound to its key, so no certificate binding could be made.

**The library compares thumbprints and nothing else.** It does not check the
certificate's chain, dates, key usage or revocation; that is the TLS server's
job (`tls.Config.ClientAuth` and `ClientCAs` above) or the job of the proxy
that terminates TLS. A server that asks for a certificate without verifying it
still binds soundly, since only the holder of the private key can present the
certificate again, but then any self-signed certificate can sign in.

### Behind a proxy that terminates TLS

The application then never sees the client's TLS connection. Name the header
the proxy forwards the certificate in, on the trusted-proxy configuration:

```go
httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
    Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
    Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
}, httpsec.WithClientCertificateHeader("X-Client-Cert", nil)) // nil: URL-encoded PEM
```

- The header is read only from a trusted proxy, and only when it is sent once;
  on two lines it is ignored, and the request has no certificate. A peer that
  is not a trusted proxy has its header ignored, and its own TLS connection's
  certificate, if any, is used. A trusted proxy's own connection certificate is
  never taken for the client's.
- The header is removed with the other forwarded headers before the first
  interceptor (unless `KeepForwardedHeaders()`). Its value is kept, from a
  trusted proxy only, and decoded once: `Request.ClientCertificate()` answers
  the forwarded certificate to every interceptor, whether or not certificate
  binding is enabled, so an interceptor of your own that judges the client by
  its certificate sees the same answer the binding does.
- **Whichever proxy you run, it must overwrite or strip the header on every
  request**, a request that arrives without a client certificate included. A
  proxy that sets the header only when it has a certificate passes on a copy
  the client sent itself, and the library cannot tell it from the proxy's own.
  The client could then present anybody's certificate, which is public, as its
  own, and a token bound to that certificate would be accepted from it.
- The default decoder reads URL-encoded PEM, as nginx's
  `$ssl_client_escaped_cert` writes it. The decoded text must be exactly one
  `CERTIFICATE` PEM block, with nothing but whitespace before and after it.
  Several blocks, text before or after the block, or a block that does not
  parse mean the request has no certificate, so a certificate-bound token on
  it is refused. A value that does not decode means the same.
- A proxy that forwards another format needs a decoder of your own, handed the
  header's value as received:

```go
// The proxy forwards the DER certificate, base64-encoded.
decodeDER := func(v string) (*x509.Certificate, error) {
    der, err := base64.StdEncoding.DecodeString(v)
    if err != nil {
        return nil, err
    }
    return x509.ParseCertificate(der)
}

httpsec.WithClientCertificateHeader("X-Client-Cert", decodeDER)
```

#### nginx

```nginx
server {
    listen 443 ssl;
    # ssl_certificate and ssl_certificate_key as usual.

    ssl_client_certificate /etc/nginx/client-ca.pem; # the CAs client certificates are verified against
    ssl_verify_client      optional;                 # or on, to refuse clients without one

    location / {
        proxy_pass http://app:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Client-Cert   $ssl_client_escaped_cert;
    }
}
```

`$ssl_client_escaped_cert` is the client certificate as URL-encoded PEM, which
the default decoder reads. `proxy_set_header` redefines the header, so an
`X-Client-Cert` the client sent itself is not passed on, and a field whose
value is empty is not passed at all; that meets the rule above for requests
with and without a certificate. nginx verifies the certificate against
`ssl_client_certificate`; the outcome is in `$ssl_client_verify`. With
`ssl_verify_client optional_no_ca`, nginx asks for a certificate but does not
require it to be signed by a trusted CA, and verification is left to another
service: the library does none, so choose it only when that service exists.
Do not forward the deprecated `$ssl_client_cert`, whose lines are joined with
tabs; the default decoder does not read it.

Other proxies are not listed here because their forwarded format has not been
checked against their documentation. Write a decoder for the format yours
documents, and test it with a certificate forwarded through your deployment.

### Defaults

| Behaviour | Default | Override |
|---|---|---|
| Certificate binding | off; a certificate-bound token is refused | `EnableCertificateBinding()` |
| Where the certificate comes from | the TLS connection | `WithClientCertificateHeader` behind a trusted proxy |
| Forwarded certificate format | URL-encoded PEM | the decoder given to `WithClientCertificateHeader` |
| Certificate validation | none in the library | the TLS server's `ClientAuth`/`ClientCAs`, or the proxy |
| A sign-in with a DPoP proof and a certificate | bound to the DPoP key | none: a token carries one confirmation |
| `DPoP{Require: true}` beside certificate binding | refused at construction (`ErrConfig`) | none: no certificate binding could be made |
| Forwarded certificate header sent on two lines, or a value that is not exactly one PEM certificate | no certificate | none |

## Security events

`httpsec.EnableSecurityEvents` reports every security outcome the chain decides
to a sink you supply, as a `security.Event` named from the
[OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)
where it names the outcome, and under a `scrty_` prefix where it does not. It
is off until you enable it: with no sink, nothing is reported.

```go
logger := slog.Default()

chain, err := httpsec.New(
    httpsec.EnableFormLogin(loginDeps),
    httpsec.EnableSecurityEvents(func(ctx context.Context, e security.Event) {
        logger.LogAttrs(ctx, slog.LevelInfo, "security event",
            slog.String("event", e.Name),
            slog.String("outcome", e.Outcome),
            slog.String("user", string(e.User)),
            slog.String("client_ip", e.ClientIP),
            slog.String("factor", string(e.Factor)),
            slog.String("session", e.Session),
            slog.Time("at", e.At),
        )
    }),
)
```

`go doc github.com/kartaladev/scrty/security` lists every name and when it is
reported; `security.Names()` returns them. Among them: `authn_login_success`,
`authn_login_fail`, `authn_login_fail_max` and `authn_login_lock` (the failure
that locks an identifier, once per lock; under the default escalating wait, a
failure after a wait has run out locks the identifier again, for longer, and
is reported again), `authn_token_created`,
`authn_token_reuse` (a superseded session presented again), `session_created`,
`session_renewed`, `session_logout`, `authz_fail`, `excess_rate_limit_exceeded`,
`malicious_csrf`, and the `scrty_` names for second factors, passkeys,
recovery, re-authentication, session management, host, DPoP, certificate-binding
and automation-challenge refusals, and signing-key rotation.

The lockout observer (`lockout.WithObserver`) and the session-reuse observer
(`session.WithReuseObserver`) keep working; their outcomes also reach the sink,
as `authn_login_lock` and `authn_token_reuse`. A lock is reported by the
lockout policy's view, so give form login and Basic `lockout.Policy.Attempts()`
as their `Attempts`.

A component you also call outside a chain takes a sink of its own, which
defaults to none: `apikey.WithSecurityEvents`, `lockout.WithSecurityEvents`,
`mfa.WithThrottleSecurityEvents`, `mfa.WithResetSecurityEvents`,
`recovery.WithSecurityEvents`, `session.WithSecurityEvents` and
`signingkey.WithSecurityEvents`. On a request a chain reports for, the
component reports through the chain and its own sink is not called, so one
outcome is reported once.

### The sink's contract

- It is called synchronously, on the request that decided the outcome, with a
  context from which the request's cancellation has been removed, so a client
  that hangs up does not cut the delivery short.
- It cannot change the outcome, the status or the error. It returns nothing,
  and a panic in it is recovered and logged without the event's contents.
- **A sink that blocks holds the request, and that is yours to manage.** A
  sink that does slow work, such as a network write, hands the event to its
  own queue and returns. The library keeps no queue: bounding memory or losing
  events is your trade-off to make.
- It should do no work that depends on whether an account exists. A recovery
  start is reported alike for a username that names an account and one that
  names none, so its latency does not tell them apart; a sink that looks the
  user up only when an event names one would tell them apart again.
- It may be called concurrently, from every request at once.

### What an event carries, and what it never does

An event carries its name, its time from the deciding component's clock, its
outcome, the user when one is known, the client address the chain resolved
(through trusted proxies when they are configured), the first factor where one
applies, and `Session`, the SHA-256 digest of the session's identifier, never
the identifier. No event carries a password, token, code, link secret, key,
DPoP proof, certificate, CSRF token or stored hash. Only what happened is
reported: a credential issued and then discarded reports no creation, and a
dependency that failed or a client that hung up before a verdict reports no
failure.

### Stated limits

- A magic-link redemption and an OIDC handoff answer a refusal and an outage
  with one error, by design, so their failures are not reported.
- A second factor's refusal is reported only when the method's error wraps one
  of `mfa`'s refusal sentinels (`ErrInvalidCode`, `ErrVerifyThrottled`,
  `ErrAuthenticatorRefused`, `ErrSameChannel`); any other error is taken for an
  outage and reports nothing.
- `Session` is a digest. To correlate it with a session, digest the identifier
  the same way; the event never names the session itself.
- A lock is reported once within one process. With an attempt store several
  replicas share, failures on different replicas at the same moment may each
  report it. A failure for which the attempt store could not say whether the
  identifier was already locked loses its event, which the lockout policy
  logs; the failure itself is recorded and counts.

### Defaults

| Behaviour | Default | Override |
|---|---|---|
| Security events | off; nothing is reported | `httpsec.EnableSecurityEvents(sink)` |
| A component's own sink, outside a chain | none | the component's `WithSecurityEvents` option |
| A nil sink, or an option given twice | refused at construction | none |
| Delivery | synchronous, on the deciding request | your sink hands events to its own queue |

## Development

```sh
make tools   # install pinned golangci-lint, mockgen and govulncheck into ./.bin
make check   # pin check, tools tests, gofmt, go vet, golangci-lint, go test -race, govulncheck, go generate
```

`make check` is what continuous integration runs.

### Supply chain

`make vuln` runs `govulncheck` over every published module with the workspace off, so each module is
scanned against the versions its own `go.mod` requires, as a consumer gets them. `make pincheck`
fails a workflow that references an action by anything but a full commit SHA, and `make sbom` writes
a CycloneDX SBOM per module.

`.github/dependabot.yml` configures Dependabot **version** updates for each module. Security updates
are a separate repository setting that no file can enable: the repository requires **Dependabot
security updates** to be enabled (Settings, Advanced Security) so that a published advisory opens a
pull request without waiting for the weekly schedule.

## License

[Apache-2.0](LICENSE).
