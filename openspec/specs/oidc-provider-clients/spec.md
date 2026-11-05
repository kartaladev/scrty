# oidc-provider-clients Specification

## Purpose
Defines the relying parties an embedded OpenID Provider serves: how the consumer registers them, which settings each carries, how their secrets are kept, and how a client proves who it is at the provider's endpoints.

## Requirements

### Requirement: Clients come from a registry the consumer owns
The provider SHALL take its clients from a client registry. By default the registry SHALL be an in-memory one built from the consumer's configuration. A consumer SHALL be able to supply a durable registry instead. The provider SHALL NOT create, change or delete clients on its own. An unknown `client_id` SHALL be treated as an unknown client at every endpoint.

#### Scenario: Configured client found
- **WHEN** the provider is built with a client `billing-web` in its configuration and a request names `client_id=billing-web`
- **THEN** the provider uses that client's registered settings

#### Scenario: Unknown client
- **WHEN** a request names a `client_id` the registry does not hold
- **THEN** it is treated as an unknown client

#### Scenario: Consumer supplies a durable registry
- **WHEN** the consumer supplies a durable registry holding client `billing-ios`
- **THEN** the provider uses it, and the in-memory default is not used

### Requirement: A consumer's client is validated when it is read
A client read from a consumer's registry SHALL pass the same validation as a configured one when it is read, because it could not be checked at construction. One that fails SHALL be treated as an unknown client, and logged with the setting it fails on.

#### Scenario: Durable registry returns an invalid client
- **WHEN** a consumer's registry returns a client with the redirect URI `https://*.example.com/cb`
- **THEN** that client is treated as unknown, and the log names the setting

### Requirement: A client is confidential or public, and web or native
Every client SHALL be registered as either confidential or public, and with an application type of web or native, web by default. A public client SHALL authenticate with no secret and SHALL be refused any client authentication method that needs one. A confidential client SHALL declare a method that proves possession of a credential.

#### Scenario: Public client with a secret method
- **WHEN** a public client is registered with `client_secret_basic`
- **THEN** construction fails with a configuration error naming the client

#### Scenario: Confidential client without a credential
- **WHEN** a confidential client is registered with the method `none`
- **THEN** construction fails with a configuration error naming the client

### Requirement: Redirect URIs are compared exactly
A request's redirect URI SHALL be compared with the client's registered ones by exact string comparison. The one exception SHALL be a native client's loopback IP redirect URI, whose port SHALL be allowed to differ, and nothing else.

#### Scenario: Exact match required
- **WHEN** a client registered `https://rp.example.com/cb` and a request sends `https://rp.example.com/cb/`
- **THEN** the redirect URI does not match

#### Scenario: Native loopback port varies
- **WHEN** a native client registered `http://127.0.0.1/cb` and a request sends `http://127.0.0.1:51004/cb`
- **THEN** the redirect URI matches

#### Scenario: Loopback path still exact
- **WHEN** a native client registered `http://127.0.0.1/cb` and a request sends `http://127.0.0.1:51004/other`
- **THEN** the redirect URI does not match

#### Scenario: Port not relaxed for a web client
- **WHEN** a web client registered `https://rp.example.com/cb` and a request sends `https://rp.example.com:8443/cb`
- **THEN** the redirect URI does not match

### Requirement: Redirect URIs are registered in full
Every client that uses the authorization endpoint SHALL register at least one redirect URI. Each SHALL be an absolute URI without a fragment or wildcard. A web client's redirect URIs SHALL use `https`. A native client's SHALL use `https`, a private-use scheme containing a period, or `http` to a loopback IP literal, `127.0.0.1` or `[::1]`. None SHALL carry user information, and the schemes `javascript`, `data`, `vbscript` and `file` SHALL be refused for every client.

#### Scenario: Wildcard refused
- **WHEN** a client registers `https://*.example.com/cb`
- **THEN** construction fails with a configuration error

#### Scenario: Fragment refused
- **WHEN** a client registers `https://rp.example.com/cb#x`
- **THEN** construction fails with a configuration error

#### Scenario: Plain http for a web client refused
- **WHEN** a web client registers `http://rp.example.com/cb`
- **THEN** construction fails with a configuration error

#### Scenario: Private-use scheme without a period
- **WHEN** a native client registers `myapp:/cb`
- **THEN** construction fails with a configuration error

#### Scenario: Script scheme refused
- **WHEN** a native client registers `javascript:alert(1)`
- **THEN** construction fails with a configuration error

#### Scenario: Native loopback accepted
- **WHEN** a native client registers `http://127.0.0.1/cb`
- **THEN** the client is accepted

### Requirement: Post-logout redirect URIs follow the same rules
A client MAY register post-logout redirect URIs. They SHALL follow the rules for redirect URIs, and SHALL be compared by exact string comparison.

#### Scenario: Post-logout wildcard refused
- **WHEN** a client registers the post-logout redirect URI `https://rp.example.com/*`
- **THEN** construction fails with a configuration error

### Requirement: Each client declares exactly one authentication method
Each client SHALL declare exactly one token endpoint authentication method, from `client_secret_basic`, `client_secret_post`, `private_key_jwt` and `none`. A confidential client's default SHALL be `client_secret_basic`. A request authenticating with any other method SHALL be refused as `invalid_client`. A request using more than one method at once, or naming one `client_id` in the header and another in the body, SHALL be refused as `invalid_request`. `client_secret_jwt` SHALL NOT be supported.

#### Scenario: Default method
- **WHEN** a confidential client is registered without a method
- **THEN** its method is `client_secret_basic`

#### Scenario: Wrong method
- **WHEN** a client registered for `client_secret_basic` sends its secret in the request body
- **THEN** the request is refused as `invalid_client`

#### Scenario: Two methods at once
- **WHEN** a request carries both an `Authorization: Basic` header and a `client_assertion`
- **THEN** the request is refused as `invalid_request`

#### Scenario: Two identifiers
- **WHEN** a request's `Authorization: Basic` header names `billing-web`, and its body names `client_id=crm-web`
- **THEN** the request is refused as `invalid_request`

#### Scenario: Symmetric assertion method refused
- **WHEN** a client is registered with `client_secret_jwt`
- **THEN** construction fails with a configuration error

### Requirement: Client secrets are kept only as digests
A secret the provider generates SHALL carry 256 bits from a cryptographically secure source, SHALL be returned once when generated, and SHALL be stored only as a digest. A secret the consumer supplies SHALL be at least 32 bytes long. A shorter one SHALL fail construction. Secrets SHALL be compared in constant time against the stored digest. No secret or digest SHALL appear in logs or error text.

#### Scenario: Generated secret shown once
- **WHEN** the consumer asks the registry to generate a secret for a client
- **THEN** the secret is returned once, and the registry afterwards holds only its digest

#### Scenario: Short supplied secret
- **WHEN** the consumer registers a client with a 20-byte secret
- **THEN** construction fails with a configuration error naming the client

#### Scenario: Wrong secret
- **WHEN** a client authenticates with a secret whose digest does not match
- **THEN** the request is refused as `invalid_client`

### Requirement: A client secret can be rotated without downtime
A client MAY hold a second secret during a rotation, and a secret MAY carry an expiry. Either live secret SHALL authenticate, and an expired one SHALL NOT.

#### Scenario: Rotation with two secrets
- **WHEN** a client holds an old secret expiring tomorrow and a new one, and authenticates with either
- **THEN** the client is authenticated

#### Scenario: Rotated secret expired
- **WHEN** a client authenticates with a secret whose expiry has passed
- **THEN** the request is refused as `invalid_client`

### Requirement: Basic client credentials are decoded as the standard requires
For `client_secret_basic`, the provider SHALL URL-decode the client identifier and secret after Base64-decoding the `Authorization` header. A header that does not decode SHALL be refused as `invalid_client`.

#### Scenario: Encoded characters in the secret
- **WHEN** a client's secret contains `+` and the client sends it form-URL-encoded inside the Basic header
- **THEN** the client is authenticated

### Requirement: Private-key JWT assertions are verified strictly
For `private_key_jwt`, the provider SHALL accept an assertion only when:
- it is signed with an asymmetric algorithm by a key from the client's registered key set or key-set URL;
- its `iss` and `sub` both equal the `client_id`;
- its `aud` is the provider's issuer identifier, and nothing else;
- its `exp` is present, in the future, and within the lifetime bound;
- its `jti` has not been seen before for that client;
- its `typ` header, when present, is `client-authentication+jwt` or `JWT`.

#### Scenario: Valid assertion
- **WHEN** a client sends an assertion meeting every condition
- **THEN** the client is authenticated

#### Scenario: Token endpoint as audience
- **WHEN** a client sends an assertion whose `aud` is the token endpoint URL, under the default
- **THEN** the request is refused as `invalid_client`

#### Scenario: Audience array with another value
- **WHEN** an assertion's `aud` is an array holding the issuer and another value
- **THEN** the request is refused as `invalid_client`

#### Scenario: Access token offered as an assertion
- **WHEN** a client sends a JWT with `typ` `at+jwt` as its assertion
- **THEN** the request is refused as `invalid_client`

#### Scenario: Replayed assertion
- **WHEN** a client sends an assertion whose `jti` was already accepted, before it expires
- **THEN** the second request is refused as `invalid_client`

#### Scenario: Consumer accepts the token endpoint audience
- **WHEN** the consumer configures the compatibility audience rule, and a client sends an assertion whose `aud` is the token endpoint URL
- **THEN** the client is authenticated

### Requirement: Client assertions have a bounded lifetime
An assertion's `exp` SHALL lie no more than 5 minutes ahead by default. A consumer MAY raise the bound to at most 1 hour. A larger value SHALL fail construction.

#### Scenario: Assertion lives too long
- **WHEN** an assertion's `exp` lies 10 minutes ahead, under the default
- **THEN** the request is refused as `invalid_client`

### Requirement: Client key sets are fetched through the confined outbound client
A client's key-set URL SHALL be fetched through the provider's outbound HTTP client, under the same confinement as other outbound calls, and cached. An assertion naming a `kid` the cache does not hold SHALL refetch the set, at most once per cooldown, 30 seconds by default and replaceable by the consumer. A key-set fetch failure SHALL be reported as a dependency failure, not as a client authentication failure.

#### Scenario: Client rotates its key
- **WHEN** a client's new key is published at its key-set URL, and its assertion names that `kid`
- **THEN** the set is refetched, and the client is authenticated

#### Scenario: Unknown kid repeated
- **WHEN** one client sends many assertions naming an unknown `kid` within the cooldown
- **THEN** the set is fetched at most once, and those requests are refused as `invalid_client`

#### Scenario: Key set unavailable
- **WHEN** a client's key-set URL cannot be fetched while verifying its assertion
- **THEN** the token request fails as a server error, and the failure is not recorded as a wrong credential

### Requirement: Client authentication failures are throttled
Failed client authentication at the token, revocation and introspection endpoints SHALL be charged to the request's source by the chain's throttling, as a failed credential is.

#### Scenario: Repeated wrong secrets
- **WHEN** one source sends wrong client secrets past the throttle's limit
- **THEN** its further requests are refused by the throttle before the secret is checked

### Requirement: A client may be marked first-party
A client MAY be registered as first-party. The flag SHALL only change when consent is asked (`oidc-provider-consent`), and SHALL change nothing about authentication or token contents. It SHALL default to off.

#### Scenario: Default
- **WHEN** a client is registered without the flag
- **THEN** it is treated as a third party for consent

### Requirement: Client wiring mistakes fail at construction
Building the provider SHALL fail with a configuration error naming the client and setting when:
- two clients share an identifier;
- a client needs redirect URIs and has none;
- a client names an ID token signing algorithm the provider's keys cannot produce;
- a client requires sender-constrained tokens while neither DPoP nor certificate binding is enabled;
- a token lifetime exceeds what the signing keys allow;
- a setting reserved for another client type is given.

#### Scenario: Duplicate identifier
- **WHEN** two clients are registered as `billing-web`
- **THEN** construction fails with a configuration error

#### Scenario: Algorithm the keys cannot produce
- **WHEN** a client asks for ES256 ID tokens and the key manager holds only RS256 keys
- **THEN** construction fails with a configuration error
