// Package oidc logs users in through external OpenID Connect providers.
//
// It holds the provider registry, the login flow and its store, ID and logout
// token verification, the identity broker that resolves a verified external
// identity to one of the application's own users, and the single-use handoff
// that conveys a completed login to an ordinary session. It imports no HTTP
// framework, and every request it sends goes through an outbound.Client.
//
// Provider configuration is trusted operator input. It is validated when a
// Registry is built, before any request, and a wiring mistake is refused there
// with ErrConfig rather than discovered at first use.
//
// # Wiring
//
// A Registry names the trusted providers; a Broker resolves and, where
// enabled, provisions the users they assert; a Manager drives the login
// against the registry through the broker; a HandoffManager conveys a
// completed login to httpsec, which answers the four HTTP endpoints:
//
//	registry, err := oidc.NewRegistry(oidc.Provider{
//		Name:         "corp",
//		Issuer:       "https://idp.example.com",
//		ClientID:     "scrty",
//		ClientSecret: corpClientSecret,
//		RedirectURL:  "https://app.example.com/login/oauth2/callback/corp",
//	})
//
//	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
//
//	manager, err := oidc.NewManager(registry, broker)
//
//	handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), users)
//
//	chainOpt := httpsec.EnableOIDCLogin(manager, handoffs,
//		httpsec.WithOIDCTokens(tokens),
//		httpsec.WithOIDCSessions(sessions),
//	)
//
// users is the application's identity.UserLoader (and identity.UserProvisioner,
// for just-in-time provisioning); tokens and sessions are the same
// token.Generator and *session.Manager the rest of the chain issues through.
// Every constructor's godoc names what it defaults to when an option is left
// out, and every option names the default it replaces.
//
// # Limits
//
// Provider configuration is trusted, not sanitised. Whoever can write a
// Registry's Provider values directs every outbound request this package
// makes, including the client secret sent to the token endpoint, to whatever
// host they name: loopback, link-local and private hosts are accepted,
// because development and internal corporate providers live there. See
// Provider.
//
// The discovery and key-set cache, the default FlowStore and the default
// handoff redemption rate limiter each hold their state in one process. Behind
// several replicas, each keeps its own copy: up to N replicas each refetch a
// provider's metadata on their own schedule, a login flow begun on one replica
// cannot complete on another without a shared FlowStore, and a redemption
// limiter counts a source's failures per replica rather than across the fleet.
// A deployment of more than one replica supplies a shared FlowStore
// (WithFlowStore) and, for the handoff endpoint, a shared rate limiter
// (httpsec.WithHandoffLimiter); the discovery cache has no shared alternative
// yet.
//
// The first request after a discovery document or key set's cache entry
// expires waits for one fetch, bounded by the outbound client's timeout, once
// per provider per resource per replica; concurrent callers of that fetch are
// coalesced rather than each sending their own request. A longer
// WithDiscoveryTTL, or calling Manager.Prefetch at start-up, moves that wait
// off the login path.
//
// A handoff code travels in a URL, so it is fixed at HandoffTTL (60 seconds)
// and not configurable: widening the window is a security decision the
// library does not make on a consumer's behalf. Within that window, a code
// whose redemption was refused — by policy, by a consumer check, or because
// the redeemer was rate limited — stays exactly as live as it was: refusing a
// redemption never spends the code, so a copy of the URL can redeem it again
// once the refusing condition clears, until the code expires or is spent.
// httpsec's handoff redemption limiter (10 failures per source per 5 minutes
// by default) bounds how often a source may try.
//
// Back-channel logout-token replay is bounded by the token's issued-at time
// alone: no jti is recorded, so a captured, still-valid token can be replayed
// until its issued-at is older than WithLogoutTokenMaxAge (2 minutes by
// default) plus the clock leeway (WithClockSkew). For a token naming only a
// subject, each replay ends the sessions established since. Widening the
// maximum age widens the replay window by exactly as much.
//
// A federated login is not exempt from multi-factor authentication by its
// kind. For a required user, the login needs evidence of a second factor: the
// provider's amr or acr, read from the verified ID token alone and matched
// exactly against the provider's Assurance (WithProviderAssurance; by default
// amr "mfa"), or the library's own challenge. Policy matches nothing itself:
// the Manager is the policy.FederatedAssuranceSource, and the policies are
// given it through policy.WithFederatedAssuranceSource. The asserted values
// are stored beside the session and matched again on every request, so a
// tightened configuration reaches existing sessions.
//
// Freshness is not checked. auth_time and max_age are not read, so an amr of
// "mfa" that a provider's long-lived SSO session asserted hours ago is
// accepted. A provider that emits no amr never meets the default, and its
// required users are challenged locally, or refused with enrolment required
// when they have no usable enrolment. Assurance.RequestACR is sent as
// acr_values, which a provider may ignore: it is never evidence.
//
// What happens when assurance is not met is the requirement policy's mode
// (policy.WithFederatedAssurance): challenge (the default), refuse, or exempt.
// Exempt is a bypass: a required user is let in on the provider's word alone,
// whatever it asserted, as is marking factor.OIDC exempt with
// policy.WithMFAExemption. Per-user rules go through WithAssuranceEvaluator.
//
// Role sync (WithRoleSync) re-derives a federated user's roles from a
// provider claim on every login and never persists them, so a provider
// misconfiguration that empties or renames the claim removes every synced
// role from every affected user on their next login, and a provider that lets
// end users edit the claim hands them any local role the login is not
// restricted from by WithAllowedRoles.
//
// A password-hash claim mapped with WithPasswordClaim (see also
// WithClaimMirror) becomes a standby local credential: it authenticates a
// user against the application's own password check independently of the
// provider, so it is not revoked by disabling or reconfiguring the user
// there. Mirroring keeps it current only when the provider's claim keeps
// returning the same stored hash; a provider that re-hashes per token should
// not be mirrored, since every login would then write a spurious change. The
// mirror never names the password-changed time, so writing a mirrored hash
// never moves it; a time a local change already recorded stays in place, and
// password-age policy keeps applying to it.
//
// Just-in-time provisioning creates a user and links it in two separate
// writes (Broker.Broker), because the two ports may live in different
// stores. A crash between them leaves a provisioned user with no link, and
// every later login of that identity is refused with ErrNoLinkedAccount until
// an operator inserts the missing Link by hand. A consumer whose provisioner
// and link store share one database can close the window by running both
// writes in one transaction, using each adapter's own transaction resolver
// around the sequence Broker.Broker documents.
//
// Every error this package returns is meant for a log, not a response body: a
// caller must not render an error's Error() text to the client that caused
// it, since a wrapped cause can repeat configuration detail or a provider's
// own error text. Match a sentinel and answer with the status the chain's
// table already assigns it (or, outside httpsec, your own fixed mapping).
package oidc
