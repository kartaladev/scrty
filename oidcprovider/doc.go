// Package oidcprovider makes an application embedding scrty an OpenID Provider
// for its own other applications.
//
// It holds the protocol's domain logic and has no HTTP framework dependency: it
// registers and authenticates clients, and every endpoint lives in httpsec, which
// imports this package and never the reverse.
//
// # Wiring
//
// A consumer states its issuer, its clients, the keys that sign what it issues, how
// to load a user, and its own pages. Everything else has a default.
//
//	provider, err := oidcprovider.New(oidcprovider.Deps{
//		Issuer: "https://id.example.com",
//		Clients: []oidcprovider.Client{{
//			ID:           "billing-web",
//			Name:         "Billing",
//			Type:         oidcprovider.Confidential,
//			Secret:       billingSecret, // at least 32 bytes
//			RedirectURIs: []string{"https://billing.example.com/callback"},
//		}},
//		Keys:         keys,
//		Users:        users,
//		LoginURL:     "https://id.example.com/login",
//		ConsentURL:   "https://id.example.com/consent",
//		LogoutURL:    "https://id.example.com/logout",
//		LoggedOutURL: "https://id.example.com/signed-out",
//	})
//
// A wiring mistake fails here, with an error matching [ErrConfig] that names the
// setting and the client, and not at the first request.
//
// # Clients
//
// By default the clients live in memory, built from [Deps].Clients. [Deps].Registry
// replaces that with a consumer's own [ClientRegistry], whose clients get the same
// validation as they are read, because they could not be checked at construction. One
// that fails is treated as unknown, and logged with the setting.
//
// Each client registers one authentication method, and [Provider.AuthenticateClient]
// accepts no other: a client allowed several could be attacked through the weakest.
//
//	client_secret_basic  a confidential client's default
//	client_secret_post   the secret in the form body
//	private_key_jwt      an assertion signed by a key the client registered or publishes
//	none                 a public client's only method
//
// client_secret_jwt is not supported: both sides could sign with its secret, so the
// secret could be used for forgery.
//
// # Secrets and assertions
//
// A registry holds a secret's SHA-256 digest and never the secret. A supplied secret is
// at least 32 bytes, and a generated one carries 256 bits and is shown once. A client
// may hold two, each with an expiry, to rotate without downtime.
//
// An assertion is signed with an asymmetric algorithm, names the client as iss and sub,
// names the issuer as its one audience, expires within 5 minutes
// ([WithClientAssertionMaxLifetime] raises that to at most 1 hour), and carries a jti
// that is recorded once, only after its signature has been checked.
// [WithClientAssertionAudience] also accepts the token endpoint as the audience, for
// clients built to OIDC Core's older recommendation.
//
// A jwks_uri is fetched through the outbound client ([WithOutbound]), used for 15 minutes
// ([WithClientKeysTTL]), and fetched again for an unknown kid at most once per 30 seconds
// ([WithClientKeysRefetchCooldown]). A fetch that fails is a dependency failure and
// no verdict on the client.
//
// # Tokens
//
// [Provider.Token] mints what a code's exchange answers with, signed by an issuer New builds
// over [Deps].Keys for each algorithm they hold. The keys and the provider's issuer are all it
// takes, so sub is always the grant's user identifier, on a chain reading usernames too.
//
// A token is signed before its code is spent, so a key failure is a dependency failure with
// the code unspent, and the client may try again. Two racing exchanges may both sign, and the
// one that loses the spend discards what it signed.
//
// An ID token has header typ JWT, and is signed with [Client].IDTokenAlg, RS256 by default. It
// lasts 5 minutes ([Client].IDTokenLifetime), and carries iss, sub, aud and azp naming the
// client, iat, exp, jti, auth_time, sid, and nonce, amr and acr when the request or the sign-in
// had them. auth_time and sid are the sign-in's, never the exchange's, and sid stays the same
// across the sign-in's renewals.
//
// An access token is by default a JWT with header typ at+jwt, signed like the client's ID
// tokens. It lasts 5 minutes ([Client].AccessTokenLifetime), and carries iss, sub, aud,
// client_id, scope, iat, exp, jti, gid naming its grant, auth_time, amr and acr, and cnf when
// the request proved a key. A proof makes its token_type DPoP, and it is otherwise Bearer.
//
// Its audience is the request's resource values, each of which the client may ask for
// ([Client].Resources) and which the code granted when it granted any. Anything else is
// invalid_target with the code unspent. The token narrows and the grant keeps them all, so a
// later refresh may ask for another. What was asked for is exactly the audience: a client that
// also wants the issuer, to use the token at UserInfo, lists the issuer in [Client].Resources
// and names it beside the resource.
//
// With no resource named, a code granted one resource gets exactly that one, with no issuer even
// for openid; a code granted several is invalid_target with the code unspent, and the same code
// naming one then succeeds; and a code granted none gets [Client].DefaultAudience, plus the
// issuer for an openid token so it stays usable at UserInfo, or the issuer alone when there is
// no default. [Client].Resources is never a default. No option allows any audience.
//
// expires_in is the token's own lifetime and is not cut at its grant's end, so a resource
// server verifying a JWT offline may accept it until its exp.
//
// [Client].OpaqueAccessTokens replaces the JWT with at.<id>.<secret>, whose secret carries 256
// bits and is stored only as a digest, in the [AccessTokenStore] from [WithAccessTokenStore],
// or a [MemoryAccessTokenStore] by default. A code's exchange stores it last, after the grant and
// lineage. A refresh stores it before rotating, so an outage of that store rotates nothing, and
// ends it again when the refresh then answers an error.
//
// [Provider.VerifyAccessToken] reads both kinds, and refuses anything else as invalid_token: a
// first-party, ID or logout token under the same keys, a refresh token, or a code. A token whose
// grant is revoked, expired or gone is refused too, as a JWT carries gid so its grant can be
// read. A resource server verifying a JWT offline makes no such read, so for it a token lasts
// until its exp. A store or key source that cannot answer is no verdict on the token.
//
// # Refresh
//
// A client registered for the refresh grant gets rt.<family>.<secret>, whose secret carries 256
// bits. A durable [RefreshTokenStore], which no sign-in reads, holds only its digest; the default
// memory store holds it in process memory, where the provider handles it anyway. The family is not
// a secret: a value naming a real family and a secret never issued changes nothing.
//
// Each refresh supersedes the token presented and answers a new one, which is derived from it under
// a key ([WithRefreshSuccessorKey]). The old one works again within its grace, 30 seconds by default
// ([Client].RefreshGrace, at most 5 minutes), for a client that lost the response, and for two tabs
// presenting it at once. Within 10 seconds of its rotation ([WithRefreshSuccessorWindow]), each of
// those gets tokens and the same successor, or the head it has since rotated to, with nothing written,
// so one head remains, and a client may store whichever answer lands last.
//
// After that window, inside the grace, a token presented again is rotated again under a random
// successor, with tokens answered and the grant live, which knocks out the successor issued before.
// So does a replica with no shared key, or a key that has changed, as it derives different successors.
// Holders then keep the token answered last. The window is short because the same successor hides two
// holders from each other: a thief staying inside it goes undetected, and one missing it once diverges
// from the victim, which reveals both.
//
// A superseded token presented later is reuse, which revokes the whole grant and reports nothing to
// the presenter but invalid_grant. So is a token whose successor was knocked out, or has moved on with
// no same answer to give. A store failure while marking the revocation is a dependency failure instead,
// and presenting the token again tries again. No option weakens this, and an unused successor is
// never recovered. A holder keeping a token inside its grace, once another has rotated on, cannot be
// told from a thief, and is caught when it presents that token past its grace.
//
// A grant ends when it goes unrefreshed for 30 days ([Client].GrantIdleTimeout), 90 days after it
// was created ([Client].GrantAbsoluteLifetime), and by its sign-in's deadline unless it holds
// offline_access. A client's lifetimes are read as the client stands at each refresh, so shortening
// one reaches grants already issued, and no rotation extends either deadline.
// [Client].DisableRotation answers the presented token back unchanged, and is only for a
// confidential client required to bind its tokens.
//
// A refresh may narrow scope within the grant, and name another of its resources. A scope the
// client is no longer allowed is left out and reported, and returns when it is allowed again. The
// refresh token stays bound to the whole grant. A refreshed ID token keeps auth_time, amr, acr
// and sid, and has no nonce. A bound grant needs its key, and a confidential client's refresh
// token is bound by its client authentication rather than to a key.
//
// # Revocation and introspection
//
// [Provider.Revoke] ends a token for its client (RFC 7009): a refresh token ends its whole grant, an
// opaque access token ends itself, and a public client may name its client_id alone. A JWT, an unknown
// or an expired token answers success with nothing revoked, and so does a real family beside a secret
// it never issued, because a family is no credential. A token whose secret proves it another client's
// is invalid_grant. The grant's row is marked before its family is deleted, so a failure answers an
// error and presenting the token again finishes the work.
//
// [Provider.Introspect] says what a token is, to a confidential client (RFC 7662): one issued to it,
// or an access token whose audience includes its [Client].ResourceIdentifier, which is never the
// issuer, and is only for a confidential client. A public client is invalid_client whatever it names.
// Anything else, and anything unknown, expired or revoked, a JWT of a revoked grant included, answers
// {"active": false}. A refresh token's exp is the first of its grant's end and its own and the
// client's limits as they stand.
//
// Neither is a refresh: presenting a superseded refresh token to either is no reuse. Introspection
// answers it inactive and writes nothing, and revocation ends its grant as its client asked.
//
// # UserInfo
//
// [Provider.UserInfo] answers for an access token read by [Provider.VerifyAccessToken], holding openid
// and for the issuer. A token for a named resource alone has no issuer, and is refused. The answer
// holds sub, and by default for the scope profile the user's name and preferred_username. For the
// scope email, a username that is exactly an email address is released as email, with email_verified
// always false, as a username proves nothing about who controls that address. "Ada <ada@example.com>"
// and "ada" release neither claim, and the address is never used to look up a user.
// [identity.Details] holds no email of its own, so a consumer with a verified email, phone, address or
// claims of its own supplies a [ClaimSource] through [WithClaimSource]. Its values are returned unchanged, except that
// a claim whose value is null or the empty string is left out, as OIDC Core 5.3.2 asks. A missing or disabled user is invalid_token, and a store or
// source that cannot answer is a dependency failure.
//
// # Ending grants
//
// [Provider.EndSignIn] ends the grants of the sign-ins a [SignInSelector] names, deletes their browser
// sessions, and returns the clients to notify. A grant holding offline_access survives, unless its
// client is registered with [Client].EndGrantsWithSignIn. Each store is written on a budget of its own,
// so one that hangs spares no other. A provider handed to session.WithEndObserver
// does the same for each end its session manager reports, choosing its selector from what the report
// names, so a cause added later needs nothing here. A failure there is logged, and never undoes the
// end. A sign-in that merely expires is not reported, and ends nothing.
//
// [Provider.RevokeUserGrants] revokes every grant of a user with a cause, offline_access included, for
// what a security event leaves in doubt. [Provider.RevokeConsent] forgets a user's consent for a client
// and revokes that user's and client's grants, a first-party client's included though it holds no
// consent, and [Provider.Consents] lists what a user has allowed.
//
// # Errors
//
// A refusal the protocol names is an [*Error], whose text is its code and holds no
// request value. A failing store, registry, key source or fetch matches [ErrDependency]
// behind fixed text, and a caller who left matches its own context's error. No log line
// or error carries a secret, a digest, an assertion or a token.
package oidcprovider
