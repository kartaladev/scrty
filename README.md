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
manager, err := oidc.NewManager(registry, broker)
handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), users)

chain, err := httpsec.New(
	// ... your other chain options ...
	httpsec.EnableOIDCLogin(manager, handoffs,
		httpsec.WithOIDCTokens(tokens),
		httpsec.WithOIDCSessions(sessions),
	),
)
```

`users` is your `identity.UserLoader` (and `identity.UserProvisioner`, if you enable just-in-time
provisioning with `oidc.WithJIT`); `tokens` and `sessions` are the `token.Generator` and
`*session.Manager` the rest of your chain already issues through. `oidc.NewMemoryLinkStore` and
`oidc.NewMemoryHandoffStore` are the zero-configuration, per-process defaults; a multi-replica
deployment supplies durable stores instead. Every constructor's godoc names its remaining defaults,
and every option names the default it replaces.

### Endpoints

| Default path | Method | Purpose | Replace with |
|---|---|---|---|
| `/oauth2/authorization/{provider}` | GET | starts a login | `httpsec.WithOIDCAuthorizePath` |
| `/login/oauth2/callback/{provider}` | GET | the provider's callback | `httpsec.WithOIDCCallbackPath` |
| `/login/oauth2/handoff` | POST | redeems the handoff code | `httpsec.WithOIDCHandoffPath` |
| `/logout/oauth2/backchannel/{provider}` | POST | back-channel logout | `httpsec.WithBackchannelLogoutPath` |

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
backend-for-frontend, say) replaces this whole step with `httpsec.WithCallbackSuccess`, and no
handoff code is issued.

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
manager, err := oidc.NewManager(registry, broker,
	oidc.WithProviderAssurance("corp", oidc.Assurance{
		AcceptedAMR: []string{"mfa", "hwk"},
		AcceptedACR: []string{"gold"},
		RequestACR:  []string{"gold"},
		Match:       oidc.MatchAny,
	}),
)
```

- `Match` is `MatchAny` by default (any configured criterion is enough) or `MatchAll`.
- `acr` is matched as a set, never as a minimum: its values are the provider's and have no order
  scrty knows. To accept "silver or above", list every value at or above silver.
- `RequestACR` is sent to the provider as `acr_values`. It is a request the provider may ignore,
  never evidence: the returned token is always checked against `AcceptedAMR` and `AcceptedACR`.
- A provider configured with neither accepted set never meets assurance, which is valid and means
  "always use the local second factor". A claim that is absent, empty or malformed counts as
  nothing asserted, so providers that emit no `amr` fall back to the local second factor.
- A configuration for a provider that is not registered, an empty value in a list, a `RequestACR`
  value containing whitespace, or an unknown `Match` fails `oidc.NewManager` with `oidc.ErrConfig`.

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

manager, err := oidc.NewManager(registry, broker, oidc.WithAssuranceEvaluator(evaluator))
```

**What happens when assurance is not met.** The requirement policy has three modes for a required
user's OIDC login, chosen with `policy.WithFederatedAssurance`:

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
requirement policy only; `policy.WithFederatedChallengeWhenUnmet(true)` on the second-factor
challenge policy separately challenges an enrolled user's unmet OIDC login, required or not.

**Wire the source into the requirement policy.** Policy matches nothing itself: the OIDC manager
is the `policy.FederatedAssuranceSource`. Give it to the policies you build, then put them in the
chain's engine:

```go
source := policy.WithFederatedAssuranceSource(manager)

requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
	policy.WithMFARequiredForAll(),
	policy.WithFederatedAssurance(mode),
	source,
)
```

`httpsec.New` refuses to assemble a chain with OIDC login enabled and a requirement policy in
Challenge or Refuse mode that has no source. Fix it with `WithFederatedAssuranceSource(manager)`,
with Exempt mode, or with a `WithMFAExemption` rule that exempts `oidc`. Wire `httpsec.EnableMFA`
on the same chain, since the policies can raise a challenge.

**Per-request re-matching.** The redemption stores the provider's asserted values on the session;
it does not store a verdict. Every request of a federated session matches them again against the
provider's current configuration. Tightening a provider's accepted set therefore takes effect on
existing sessions at their next request, and a provider removed from the registry never matches.
A session whose local second factor was satisfied stays allowed. A consumer who creates sessions
in `httpsec.WithCallbackSuccess` must pass `CallbackResult.AMR` and `ACR` on
(`session.WithFederatedAssurance`), or the session carries no assurance.

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
  deps.Admits = requirement.(policy.LoginAdmission).AdmitsWithoutLocalSecondFactor
  ```

  That answer is the requirement policy's alone, so under `WithFederatedChallengeWhenUnmet(true)`
  the check may count a login the challenge policy then challenges; wire an `Admits` that answers
  false for such users.

### Security limits

- Provider configuration is trusted operator input: whoever writes it directs the client secret,
  and every outbound request, to whatever host they name.
- The discovery/key-set cache, the default flow store and the default handoff rate limiter are
  per process; a multi-replica deployment needs a shared `oidc.FlowStore` and a shared
  `httpsec.WithHandoffLimiter`.
- A handoff code is fixed at 60 seconds and travels in a URL; a refused code stays redeemable for
  the rest of that window.
- Back-channel logout-token replay is bounded by the token's issued-at time, not a used-once store,
  so a captured token is replayable within `oidc.WithLogoutTokenMaxAge`.
- A provider's `amr`/`acr` is accepted without a freshness check: see "Second factor and provider
  assurance" above for what that lets through and how to opt out of trusting it.
- Role sync and password-hash claim mirroring, both off by default, hand the provider ongoing
  influence over local roles and a standby credential; see their godoc before enabling them.

The full list, with the reasoning behind each one, is in the `oidc` package's "Limits" godoc
(`go doc github.com/kartaladev/scrty/oidc`).

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

requirement, err := policy.NewMFARequirementPolicy(requirementLookup, lookups,
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
   rotates its handle.

Every other request a confined session makes — the password-change endpoint, a consumer route,
the authorizer, the handler — is refused with the enrolment challenge until verification succeeds;
only logout is let through as well.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Endpoint path prefixes | `/mfa/enrol/begin`, `/mfa/enrol/confirm`, `/mfa/enrol/confirm-email`, each with `/<name>` appended per method | `httpsec.WithEnrolmentBeginPrefix`, `WithEnrolmentConfirmPrefix`, `WithEnrolmentEmailConfirmPrefix` |
| Methods enrolled | every method `EnableMFA` was given that implements `mfa.Enroller` and supports the path | `httpsec.WithEnrolmentMethods` |
| First factors admitted | `password`, `magic-link`, unrecorded | `policy.WithEnrolmentFirstFactors` |
| Confined session lifetime | 15 minutes | `httpsec.WithEnrolmentSessionTTL` |
| Begin limit | 5 per hour, per user, in-memory | `httpsec.WithEnrolmentBeginLimiter` |
| Confirmation failure limit | 5 per 15 minutes, per user, in-memory | `httpsec.WithEnrolmentConfirmLimiter` |
| Emailed-code confirmation | on | `httpsec.WithoutEmailConfirmation` |
| Notification on completion | on | `httpsec.WithoutEnrolmentNotification` |
| Contact address / provisioning label | the username | `httpsec.WithContactResolver` / `WithLabelResolver` |
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
codes, err := recovery.NewCodes() // WithSetSize, WithLowThreshold, WithCodeStore, WithCodeLimiter, ...

mfaReset, err := recovery.MFAEnrolments(totp) // one AuthenticatorKind per kind of authenticator recovery resets

chain, err := httpsec.New(
	// ... your other chain options, including a binding route (see below) ...
	httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
		Users:    users,        // identity.UserLoader
		Sessions: sessions,     // *session.Manager
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
  `httpsec.WithChangePasswordEndpoint`), whose success clears the confinement without rotating the
  session — the recovery minted it for this caller already.

Passkey registration (see [Passkeys](#passkeys)) is a third binding route.

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
  `recovery.WithDelay` holds every recovery for a fixed time before it can complete, and
  `recovery.WithCancelLink` is required with any hold — a delay or `recovery.WithRisk`'s hook: the
  held-recovery notice links to it, so a normal login, or the link itself, cancels a recovery the
  real user did not make.
- **A cool-down after recovery.** `httpsec.EnableRecoveryCooldown(records, d, routes...)` refuses
  the routes a consumer marks as sensitive — changing the account's email address, say — for `d`
  after the user's latest completed recovery. It is per user, not per session, so logging out and
  back in does not end it, and it is independent of `EnableAccountRecovery`: it only reads the
  record store.
- **Regeneration.** `GET`/`POST /recovery/codes` count and regenerate a user's saved codes for a
  full session. A `POST` needs a session whose latest authentication is within the freshness window
  and is refused with `recovery.ErrReauthenticationRequired` (403) otherwise.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Codes per set | 10 | `recovery.WithSetSize` |
| Issued code lifetime | 15 minutes | `recovery.WithIssuedCodeTTL` |
| Recovery-pending session lifetime | 15 minutes | `recovery.WithSessionLifetime` (via `httpsec.WithRecoveryCore`) |
| Regeneration freshness window | 15 minutes | `httpsec.WithRegenerationFreshness` |
| Authenticator reset | everything held, except what was proved | `recovery.WithResetReported`, `recovery.WithResetPolicy` |
| Other sessions of the user | ended on recovery | `recovery.WithoutSessionRevocation` |
| Waiting period | none | `recovery.WithDelay`, `recovery.WithRisk` |
| Cool-down after recovery | off | `httpsec.EnableRecoveryCooldown` |
| Recovery record store (`RecoveryDeps.Records`) | in-memory, one process only | `recovery.NewMemoryRecordStore` replaced by a durable `recovery.RecordStore` |
| Issued-code token store | in-memory, one process only | `recovery.WithIssuedCodeStore` |
| Hold token store | in-memory, one process only | `recovery.WithHoldTokenStore` |

Each in-memory default above holds its state in the process that created it and forgets it on
restart; a second replica never sees the first one's records or tokens. A deployment running more
than one replica supplies durable stores instead: `pgx.NewRecoveryRecordStore`,
`gorm.NewRecoveryRecordStore` or `sqlstore.NewRecoveryRecordStore` for `RecoveryDeps.Records`, and
`pgx.NewOneTimeStore`, `gorm.NewOneTimeStore` or `sqlstore.NewOneTimeStore` — the same `onetime.Store`
implementation — for both `recovery.WithIssuedCodeStore` and `recovery.WithHoldTokenStore`.

## Passkeys

`passkey` adds WebAuthn passkeys: registration and management, passwordless login, the passkey as a
second factor, and clone handling. The core package has no WebAuthn dependency; the verifier
behind the `passkey.Verifier` port lives in the nested module
`github.com/kartaladev/scrty/passkey/webauthn`, which you add to your own `go.mod` and pass in.
Each snippet below is mirrored by an `Example` function in `passkey` or `passkey/webauthn` that
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
verifier, err := webauthn.New(rp) // github.com/kartaladev/scrty/passkey/webauthn

manager, err := passkey.New(passkey.Deps{
	Verifier: verifier,
	Users:    users,       // identity.UserLoader
	Sender:   queuedSender, // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
	Sessions: sessions,     // the *session.Manager the chain uses (httpsec.PasskeyDeps.Sessions)
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
| Endpoint paths | `/passkey/register`, `/passkey/credentials`, `/passkey/login` | `httpsec.WithPasskeyRegistrationPrefix`, `WithPasskeyCredentialsPrefix`, `WithPasswordlessPrefix` |
| Challenge lifetime | 5 minutes (also the timeout in the creation options) | `passkey.WithChallengeTTL` |
| Registration challenges per user | 10 per hour; the window is fixed | `passkey.WithRegistrationChallengeLimit` |
| Passkeys per user | 25, every state counted | `passkey.WithPasskeyLimit` |
| Freshness to register or remove a passkey | latest authentication within 15 minutes | `passkey.WithManagementFreshness` |
| Second factor a session must have met to register or remove a passkey | any MFA method usable against the session's first factor: inside a chain with an MFA slot, the slot's methods (the passkey method among them when it is on the slot); otherwise `passkey.Deps.MFAMethods`. The user's own active passkeys count too, whatever the first factor, when the passkey method is among those methods or the chain serves passwordless login that proves the second factor. A password session steps up through the passkey method; a passkey-first session cannot (same channel) and signs in again with user verification, or by password then the passkey step-up. Accepted fail-closed limit: `WithoutSecondFactorAtLogin`, the passkey method on the slot, and a policy completing a passkey-first session without a second factor leave that session unable to manage passkeys. The method is recognised by identity, so a wrapped passkey method opens no route. A failed MFA or passkey lookup refuses with fixed text | `passkey.RegistrationContext.MFAMethods` and `PasswordlessLogin`, for a direct caller of the manager; the own-passkeys rule itself has no override |
| User verification | required | `passkey.WithUserVerification` |
| Resident (discoverable) key | required; a non-resident passkey serves only as a second factor | `passkey.WithResidentKey` |
| Emailed confirmation code | 6 digits, valid 10 minutes, 5 attempts | not configurable: the store contract fixes the attempts (`passkey.MaxEmailCodeAttempts`) |
| Request body caps | 64 KiB registration (`passkey.RegistrationBodyLimit`), 16 KiB assertion (`passkey.AssertionBodyLimit`) | not configurable |
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
so it takes a `seal.Cipher`; `sqlstore`, `pgx` and `gorm` each have the two constructors:

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
		httpsec.WithPasswordlessLogin(httpsec.PasswordlessTokens(tokens)),
	),
)
```

- `EnablePasskeys` alone serves registration and management for a signed-in session:
  `POST /passkey/register/begin` and `/finish` (plus `/confirm` and `/confirm-email`
  for a pending passkey), and `GET /passkey/credentials` with `POST .../rename` and `.../remove`.
- `WithPasswordlessLogin` is off unless given. It adds `POST /passkey/login/begin` and `/finish`,
  tied together by an `HttpOnly`, `Secure`, `SameSite=Strict` ceremony cookie, and signs a user in
  with a discoverable passkey alone. `PasswordlessTokens` names the token generator, and may be
  left out when the chain has form login to take one from.
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

## Development

```sh
make tools   # install pinned golangci-lint, mockgen and govulncheck into ./.bin
make check   # gofmt, go vet, golangci-lint, go test -race, govulncheck, go generate
```

`make check` is what continuous integration runs.

## License

[Apache-2.0](LICENSE).
