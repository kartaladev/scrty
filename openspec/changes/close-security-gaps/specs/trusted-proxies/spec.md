## Purpose

Lets an application behind a reverse proxy or API gateway learn the real client address, scheme and host from the proxy's forwarded headers, believing them only when they come from proxies the consumer lists, and hands the resolved values to the chain and the handler alike.

## ADDED Requirements

### Requirement: Forwarded headers are ignored until trusted proxies are configured
Without trusted-proxy configuration, the chain SHALL resolve a request's client address from its transport peer, its scheme from its transport, and its host from its `Host` header, and SHALL NOT read `Forwarded` or any `X-Forwarded-*` header.

#### Scenario: Default deployment
- **WHEN** no trusted proxies are configured and a request from 198.51.100.7 carries `X-Forwarded-For: 203.0.113.9` and `X-Forwarded-Proto: https` over plain HTTP
- **THEN** the client is 198.51.100.7 and the request is not secure

#### Scenario: Default deployment leaves the headers alone
- **WHEN** no trusted proxies are configured and a handler behind the chain reads `X-Forwarded-For`
- **THEN** it reads the value the client sent, because without the feature the chain neither reads nor removes forwarded headers

### Requirement: Trusted-proxy configuration is explicit and refuses unsafe settings
Enabling trusted proxies SHALL require a list of proxy address prefixes and exactly one header family, either RFC 7239 `Forwarded` or `X-Forwarded-*`, with the fields to trust named individually: client address, scheme, host. Construction SHALL fail with a configuration error, naming the setting, when:
- the prefix list is empty, or a prefix is not a valid prefix;
- a prefix covers all IPv4 or all IPv6 addresses, unless the consumer states explicitly that every peer is trusted;
- no header family or no field is named;
- the host field is named without at least one allowed host, or an allowed host is empty, carries a scheme, a path or userinfo;
- the hop limit is less than one;
- trusted proxies and the declaration that every request is secure are both configured;
- trusted proxies are enabled more than once.

#### Scenario: Trust everyone by accident
- **WHEN** the consumer lists `0.0.0.0/0` as a trusted proxy without the explicit trust-all option
- **THEN** building the chain fails with a configuration error naming the proxy prefixes

#### Scenario: IPv6 catch-all
- **WHEN** the consumer lists `::/0` as a trusted proxy without the explicit trust-all option
- **THEN** building the chain fails with a configuration error naming the proxy prefixes

#### Scenario: Forwarded host without an allowlist
- **WHEN** the consumer trusts the forwarded host field and gives it no allowed host
- **THEN** building the chain fails with a configuration error naming the forwarded host field

#### Scenario: Allowed host given as a URL
- **WHEN** the consumer gives `https://app.example.com` as an allowed host
- **THEN** building the chain fails with a configuration error naming the forwarded host field

#### Scenario: HTTPS declaration beside trusted proxies
- **WHEN** the consumer enables trusted proxies and declares the deployment HTTPS
- **THEN** building the chain fails with a configuration error naming both settings

### Requirement: Forwarded values are read only from a trusted peer, right to left
When the transport peer is not within a trusted prefix, every forwarded header SHALL be ignored. A peer given as an IPv4-mapped IPv6 address SHALL be compared as its IPv4 address, and a zone SHALL be ignored for the comparison. When the peer is trusted, the chain SHALL join all occurrences of the named header, in the order received, into one list and read it from the right: each entry whose address is within a trusted prefix SHALL be skipped, and the first entry whose address is not trusted SHALL be the client. No more trusted hops than the hop limit, one by default, SHALL be skipped; once the limit is reached, the next entry SHALL be the client. When every entry is trusted and the limit is not reached, the leftmost entry SHALL be the client.

Only the entries the walk reaches SHALL be parsed, so a malformed entry to the left of the client has no effect. An entry the walk reaches that is not a single IP address, including an obfuscated identifier, `unknown`, an empty entry or a value the chain cannot parse, SHALL leave the request with no client address, so that the chain's refusal of unattributable addresses applies; it SHALL NOT fall back to the proxy's own address. An entry MAY carry a port, and an IPv6 entry MAY be bracketed; the port SHALL be discarded.

#### Scenario: Forged client address
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-For: 1.2.3.4, 203.0.113.7` and `X-Forwarded-Proto: https`
- **THEN** the client is 203.0.113.7 and the request is secure

#### Scenario: Proxy bypassed
- **WHEN** 10.20.0.2 is trusted and a request arrives directly from 198.51.100.9 carrying `X-Forwarded-For: 203.0.113.7`
- **THEN** the client is 198.51.100.9 and the forwarded header is ignored

#### Scenario: Two trusted hops
- **WHEN** the hop limit is 2, 10.20.0.0/16 is trusted, and a request from 10.20.0.2 carries `X-Forwarded-For: 203.0.113.7, 10.20.5.5`
- **THEN** the client is 203.0.113.7

#### Scenario: Hop limit reached
- **WHEN** the hop limit is 1, 10.20.0.0/16 is trusted, and a request from 10.20.0.2 carries `X-Forwarded-For: 203.0.113.7, 10.20.5.5`
- **THEN** the client is 10.20.5.5, because no more than one trusted hop is skipped

#### Scenario: Every entry trusted
- **WHEN** the hop limit is 3, 10.20.0.0/16 is trusted, and a request from 10.20.0.2 carries `X-Forwarded-For: 10.20.9.9, 10.20.5.5`
- **THEN** the client is 10.20.9.9

#### Scenario: Repeated header lines
- **WHEN** 10.20.0.2 is trusted and a request from it carries two `X-Forwarded-For` lines, `1.2.3.4` and then `203.0.113.7`
- **THEN** the lines are joined in order and the client is 203.0.113.7

#### Scenario: IPv4-mapped peer
- **WHEN** 10.20.0.0/16 is trusted and a request arrives from peer `::ffff:10.20.0.2` carrying `X-Forwarded-For: 203.0.113.7`
- **THEN** the peer is trusted and the client is 203.0.113.7

#### Scenario: Bracketed IPv6 entry with a port
- **WHEN** the consumer named `Forwarded`, 10.20.0.2 is trusted, and a request from it carries `Forwarded: for="[2001:db8::7]:4711";proto=https`
- **THEN** the client is 2001:db8::7 and the request is secure

#### Scenario: Obfuscated client
- **WHEN** the consumer named `Forwarded`, 10.20.0.2 is trusted, and a request from it carries `Forwarded: for=unknown`
- **THEN** the request has no client address, and a throttled flow refuses it as unattributable rather than charging 10.20.0.2

#### Scenario: Garbage left of the client
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-For: not-an-ip, 203.0.113.7`
- **THEN** the client is 203.0.113.7

#### Scenario: Garbage where the client should be
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-For: 203.0.113.7, not-an-ip`
- **THEN** the request has no client address, not 10.20.0.2

#### Scenario: Trusted peer sends no header
- **WHEN** 10.20.0.2 is trusted and a request from it carries no forwarded header
- **THEN** the client is 10.20.0.2, and the scheme and host are the transport's

### Requirement: The scheme and host come from the client's hop
The scheme and host SHALL be taken from the same hop as the client. With `Forwarded`, they SHALL be the `proto` and `host` parameters of the element that named the client. With `X-Forwarded-*`, a scheme or host list holding one value SHALL be that value, as the nearest trusted proxy set it; a list with as many values as the address list SHALL be read at the client's position; a list of any other length SHALL be ignored. A scheme SHALL be accepted only as `http` or `https`, compared case-insensitively; any other value SHALL be ignored. An ignored or absent value SHALL leave the transport's scheme or the `Host` header in place. `X-Forwarded-Port` and `X-Forwarded-Prefix` SHALL NOT be read.

#### Scenario: Mismatched list lengths
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-For: 1.2.3.4, 203.0.113.7, 10.20.0.9` with a hop limit of 2, and `X-Forwarded-Proto: https, http`
- **THEN** the scheme is the transport's, because the scheme list matches neither one value nor the address list's length

#### Scenario: Unknown scheme
- **WHEN** 10.20.0.2 is trusted and a request from it carries `X-Forwarded-Proto: wss`
- **THEN** the scheme is the transport's

#### Scenario: Port header ignored
- **WHEN** 10.20.0.2 is trusted for the host field and a request from it carries `X-Forwarded-Host: app.example.com` and `X-Forwarded-Port: 8443`
- **THEN** the resolved host is `app.example.com`, with no port

### Requirement: Only the named header family and fields are read
The chain SHALL read only the header family the consumer named, and only the fields named. A header of the other family, or an unnamed field, SHALL be ignored, even from a trusted peer.

#### Scenario: Other family injected
- **WHEN** the consumer named `X-Forwarded-*` and a trusted proxy passes through a client's `Forwarded: for=1.2.3.4;proto=https`
- **THEN** the `Forwarded` header has no effect on the resolved client, scheme or host

#### Scenario: Host not named
- **WHEN** the consumer named only the client-address and scheme fields and a request carries `X-Forwarded-Host: evil.example`
- **THEN** the resolved host is the request's `Host` header

### Requirement: A forwarded host must be an allowed host
When the host field is trusted, a host taken from a forwarded header SHALL be compared with the consumer's allowed hosts by its host name, case-insensitively, without a trailing dot, and ignoring any port it carries. A forwarded host that matches none SHALL cause the request to be refused with the host-not-allowed error before any interceptor or handler runs. The refusal's text SHALL NOT contain the forwarded host. A host taken from the request's own `Host` header, because no forwarded host was supplied, SHALL NOT be judged against the list.

#### Scenario: Unknown host
- **WHEN** `app.example.com` is the only allowed host and a trusted proxy forwards `X-Forwarded-Host: evil.example`
- **THEN** the request is refused with the host-not-allowed error and the handler does not run

#### Scenario: Case and port
- **WHEN** `app.example.com` is the only allowed host and a trusted proxy forwards `X-Forwarded-Host: App.Example.COM:8443`
- **THEN** the host is allowed, and the resolved host is `app.example.com:8443`

#### Scenario: Look-alike host
- **WHEN** `app.example.com` is the only allowed host and a trusted proxy forwards `X-Forwarded-Host: app.example.com.evil.example`
- **THEN** the request is refused with the host-not-allowed error

#### Scenario: Host from an untrusted peer
- **WHEN** `app.example.com` is the only allowed host and an untrusted peer sends `X-Forwarded-Host: evil.example`
- **THEN** the header is ignored, the request is not refused, and the resolved host is the `Host` header

### Requirement: Consumed forwarded headers are removed by default
Once trusted proxies are configured, the chain SHALL remove from every request, whether or not its peer is trusted, the `Forwarded` header, every `X-Forwarded-*` header, and the forwarded client-certificate header when one is named, so later code cannot read them again with looser rules. The consumer SHALL be able to keep them with an option. The chain SHALL NOT change the request's transport address or `Host` header.

#### Scenario: Default removal
- **WHEN** trusted proxies are configured and a handler behind the chain reads `X-Forwarded-For`
- **THEN** the header is absent

#### Scenario: Removed from an untrusted peer too
- **WHEN** trusted proxies are configured and an untrusted peer sends `X-Forwarded-Host: evil.example`
- **THEN** a handler behind the chain reads no `X-Forwarded-Host`

#### Scenario: Consumer keeps the headers
- **WHEN** the consumer opts to keep forwarded headers
- **THEN** the handler reads them unchanged

### Requirement: The resolved client is available to the handler
The chain SHALL make the resolved client address, scheme, host, and whether a trusted proxy supplied them readable from the request context, and the request's client-address, host and secure accessors SHALL return the same values. These SHALL be the values every interceptor in the chain uses, including rate limiting, HSTS, CSRF, DPoP, sign-in metadata and security events. Without trusted proxies, the context SHALL carry the transport values, marked as not supplied by a proxy.

#### Scenario: Handler reads the client
- **WHEN** a request from trusted proxy 10.20.0.2 forwards client 203.0.113.7 over HTTPS, and the handler reads the resolved client from its context
- **THEN** it reads address 203.0.113.7, secure, and that a proxy supplied them

#### Scenario: Rate limiting keys on the resolved client
- **WHEN** two clients, 203.0.113.7 and 203.0.113.8, log in through trusted proxy 10.20.0.2 and the first exhausts its source limit
- **THEN** the second is not throttled

#### Scenario: Without trusted proxies
- **WHEN** no trusted proxies are configured and the handler reads the resolved client
- **THEN** it reads the transport peer, marked as not supplied by a proxy

### Requirement: A deployment can declare itself HTTPS without forwarded headers
The consumer SHALL be able to declare that every request reached the deployment over HTTPS, for a deployment whose TLS ends upstream and which forwards no headers. With the declaration, every request SHALL be judged secure, and the client address and host SHALL still come from the transport and the `Host` header.

#### Scenario: TLS ends at the load balancer
- **WHEN** the consumer declares the deployment HTTPS and a request arrives over plain HTTP with no forwarded headers
- **THEN** the request is judged secure
