## Purpose

Lets an application behind a reverse proxy or API gateway learn the real client address, scheme and host from the proxy's forwarded headers, believing them only when they come from proxies the consumer lists, and hands the resolved values to the chain and the handler alike.

## ADDED Requirements

### Requirement: Forwarded headers are ignored until trusted proxies are configured
Without trusted-proxy configuration, the chain SHALL resolve a request's client address from its transport peer, its scheme from its transport, and its host from its `Host` header, and SHALL NOT read `Forwarded` or any `X-Forwarded-*` header.

#### Scenario: Default deployment
- **WHEN** no trusted proxies are configured and a request from 198.51.100.7 carries `X-Forwarded-For: 203.0.113.9` and `X-Forwarded-Proto: https` over plain HTTP
- **THEN** the client is 198.51.100.7 and the request is not secure

### Requirement: Trusted-proxy configuration is explicit and refuses unsafe settings
Enabling trusted proxies SHALL require a list of proxy address prefixes and exactly one header family, either RFC 7239 `Forwarded` or `X-Forwarded-*`, with the fields to trust named individually: client address, scheme, host. Construction SHALL fail with a configuration error, naming the setting, when:
- the prefix list is empty;
- a prefix covers all IPv4 or all IPv6 addresses, unless the consumer states explicitly that every peer is trusted;
- no header family or no field is named;
- the host field is named and no allowed host is configured;
- the hop limit is less than one;
- trusted proxies and the declaration that every request is secure are both configured.

#### Scenario: Trust everyone by accident
- **WHEN** the consumer lists `0.0.0.0/0` as a trusted proxy without the explicit trust-all option
- **THEN** building the chain fails with a configuration error naming the proxy prefixes

#### Scenario: Forwarded host without an allowlist
- **WHEN** the consumer trusts the forwarded host field and configures no allowed hosts
- **THEN** building the chain fails with a configuration error naming the allowed hosts

### Requirement: Forwarded values are read only from a trusted peer, right to left
When the transport peer is not within a trusted prefix, every forwarded header SHALL be ignored. When it is, the chain SHALL join all occurrences of the named header into one list and read it from the right: each entry added by a trusted proxy SHALL be skipped, and the first entry whose address is not trusted SHALL be the client. No more trusted hops than the hop limit, one by default, SHALL be skipped; once the limit is reached, the next entry SHALL be the client. The scheme and host SHALL be taken from the same hop as the client. A header the chain cannot parse SHALL be ignored, leaving the transport values.

#### Scenario: Forged client address
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-For: 1.2.3.4, 203.0.113.7` and `X-Forwarded-Proto: https`
- **THEN** the client is 203.0.113.7 and the request is secure

#### Scenario: Proxy bypassed
- **WHEN** 10.20.0.2 is trusted and a request arrives directly from 198.51.100.9 carrying `X-Forwarded-For: 203.0.113.7`
- **THEN** the client is 198.51.100.9 and the forwarded header is ignored

#### Scenario: Two trusted hops
- **WHEN** the hop limit is 2, 10.20.0.0/16 is trusted, and a request from 10.20.0.2 carries `X-Forwarded-For: 203.0.113.7, 10.20.5.5`
- **THEN** the client is 203.0.113.7

### Requirement: Only the named header family and fields are read
The chain SHALL read only the header family the consumer named, and only the fields named. A header of the other family, or an unnamed field, SHALL be ignored, even from a trusted peer.

#### Scenario: Other family injected
- **WHEN** the consumer named `X-Forwarded-*` and a trusted proxy passes through a client's `Forwarded: for=1.2.3.4;proto=https`
- **THEN** the `Forwarded` header has no effect on the resolved client, scheme or host

#### Scenario: Host not named
- **WHEN** the consumer named only the client-address and scheme fields and a request carries `X-Forwarded-Host: evil.example`
- **THEN** the resolved host is the request's `Host` header

### Requirement: A forwarded host must be an allowed host
When the host field is trusted, a resolved host that is not one of the consumer's allowed hosts SHALL cause the request to be refused with the host-not-allowed error before any handler runs.

#### Scenario: Unknown host
- **WHEN** `app.example.com` is the only allowed host and a trusted proxy forwards `X-Forwarded-Host: evil.example`
- **THEN** the request is refused with the host-not-allowed error

### Requirement: Consumed forwarded headers are removed by default
After resolving, the chain SHALL remove from the request every header of both families, so later code cannot read them again with looser rules. The consumer SHALL be able to keep them with an option. The chain SHALL NOT change the request's transport address or `Host` header.

#### Scenario: Default removal
- **WHEN** trusted proxies are configured and a handler behind the chain reads `X-Forwarded-For`
- **THEN** the header is absent

#### Scenario: Consumer keeps the headers
- **WHEN** the consumer opts to keep forwarded headers
- **THEN** the handler reads them unchanged

### Requirement: The resolved client is available to the handler
The chain SHALL make the resolved client address, scheme, host, and whether a trusted proxy supplied them readable from the request context. These SHALL be the same values every interceptor in the chain used, including rate limiting, HSTS, CSRF and DPoP.

#### Scenario: Handler reads the client
- **WHEN** a request from trusted proxy 10.20.0.2 forwards client 203.0.113.7 over HTTPS, and the handler reads the resolved client from its context
- **THEN** it reads address 203.0.113.7, secure, and that a proxy supplied them

### Requirement: A deployment can declare itself HTTPS without forwarded headers
The consumer SHALL be able to declare that every request reached the deployment over HTTPS, for a deployment whose TLS ends upstream and which forwards no headers. With the declaration, every request SHALL be judged secure.

#### Scenario: TLS ends at the load balancer
- **WHEN** the consumer declares the deployment HTTPS and a request arrives over plain HTTP with no forwarded headers
- **THEN** the request is judged secure
