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
- Federated logins are exempt from MFA entirely by default; override the classification with
  `policy.WithMFAExemption` and wire `httpsec.EnableMFA`.
- Role sync and password-hash claim mirroring, both off by default, hand the provider ongoing
  influence over local roles and a standby credential; see their godoc before enabling them.

The full list, with the reasoning behind each one, is in the `oidc` package's "Limits" godoc
(`go doc github.com/kartaladev/scrty/oidc`).

## Letting required users enrol

By default, a user who must use a second factor and has none is refused outright: enrolment is a
Go API (`mfa.Enroller`) the consumer puts behind their own authorised route, reached however they
choose. The enrolment path is the alternative: turned on explicitly, it lets such a user bind a
second factor themselves, from a session confined to that one purpose, right after they sign in.

Because a password alone would otherwise be enough to bind a second factor of an attacker's
choosing, the path is off unless both halves are turned on together:

```go
requirement, err := policy.NewMFARequirementPolicy(requirementLookup, lookup,
	policy.WithMFAEnrolmentPath(), // policy.WithEnrolmentFirstFactors, policy.WithEnrolmentPathUntil
)

chain, err := httpsec.New(
	// ... your other chain options (login, sessions) ...
	httpsec.EnableMFA(totp), // an mfa.Enroller, e.g. mfa.NewTOTP
	httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
		Users:  users,        // identity.UserLoader
		Sender: queuedSender, // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
	}),
)
```

### Flow

1. **Begin** (`POST /mfa/enrol/begin`) provisions a secret and returns it, with a QR-code URI, to
   the confined session the login just received.
2. **Confirm** (`POST /mfa/enrol/confirm`, form field `code`) proves the device with a code from
   it. The device is proven, but the enrolment does not count yet.
3. **Emailed code** (`POST /mfa/enrol/confirm-email`, form field `code`) — by default, an
   out-of-band code is sent to the user's address once the device is proven, and entering it here
   is what completes the enrolment. This is what stops a password holder from binding an
   authenticator the account's owner never sees: the mailbox owner takes part in every binding.
4. **Verify** (`POST /mfa/verify`, `httpsec.EnableMFA`'s own endpoint) resolves the session's
   pending second-factor challenge with a fresh code, exactly as it would for an enrolment made
   out of band. Only this step marks the session satisfied and rotates its handle.

Every other request a confined session makes — the password-change endpoint, a consumer route,
the authorizer, the handler — is refused with the enrolment challenge until verification succeeds;
only logout is let through as well.

### Defaults

| What | Default | Replaced by |
|---|---|---|
| Endpoint paths | `/mfa/enrol/begin`, `/mfa/enrol/confirm`, `/mfa/enrol/confirm-email` | `httpsec.WithEnrolmentBeginPath`, `WithEnrolmentConfirmPath`, `WithEnrolmentEmailConfirmPath` |
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

`mfa.ResetEnrolment` is the operator's undo: it removes the enrolment, ends every session of the
user (so one already satisfied by the lost authenticator stops working), and notifies the user by
default. It is a Go API, not an HTTP endpoint — put it behind whatever authorised administrative
route the rest of the operator surface already uses. With the enrolment path on, the user's next
login goes straight back into the confined state above; with it off, they are refused until
enrolled out of band.

## Development

```sh
make tools   # install pinned golangci-lint, mockgen and govulncheck into ./.bin
make check   # gofmt, go vet, golangci-lint, go test -race, govulncheck, go generate
```

`make check` is what continuous integration runs.

## License

[Apache-2.0](LICENSE).
