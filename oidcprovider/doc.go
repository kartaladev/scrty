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
// later refresh may ask for another. With no resource, the audience is
// [Client].DefaultAudience, plus the issuer for an openid token so it stays usable at UserInfo,
// and with no default it is the issuer alone. No option allows any audience.
//
// [Client].OpaqueAccessTokens replaces the JWT with at.<id>.<secret>, whose secret carries 256
// bits and is stored only as a digest, in the [AccessTokenStore] from [WithAccessTokenStore],
// or a [MemoryAccessTokenStore] by default. It is stored last, after the grant and lineage.
//
// [Provider.VerifyAccessToken] reads both kinds, and refuses anything else as invalid_token: a
// first-party, ID or logout token under the same keys, a refresh token, or a code. A token whose
// grant is revoked, expired or gone is refused too, as a JWT carries gid so its grant can be
// read. A resource server verifying a JWT offline makes no such read, so for it a token lasts
// until its exp. A store or key source that cannot answer is no verdict on the token.
//
// # Errors
//
// A refusal the protocol names is an [*Error], whose text is its code and holds no
// request value. A failing store, registry, key source or fetch matches [ErrDependency]
// behind fixed text, and a caller who left matches its own context's error. No log line
// or error carries a secret, a digest, an assertion or a token.
package oidcprovider
