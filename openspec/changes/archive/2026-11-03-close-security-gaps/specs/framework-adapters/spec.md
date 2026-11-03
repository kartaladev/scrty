## MODIFIED Requirements

### Requirement: Adapters take the client address from the framework's trusted configuration only
Every adapter SHALL attribute a request to its transport peer by default, and SHALL resolve the client address, scheme and host through the chain's own trusted-proxy configuration when the consumer configures it, reading the raw peer address and headers from the framework. No adapter SHALL take the client address, scheme or host from its framework's own proxy settings: gin's trusted proxies and client-IP opt-in, and fiber's proxy trust, SHALL have no effect on the chain. The documentation of each adapter SHALL say so, and SHALL state that an in-memory or Unix-socket transport reports an unspecified peer.

The chain's refusal of empty, malformed or unspecified addresses SHALL apply to whatever address is resolved.

#### Scenario: gin default ignores forwarded headers
- **WHEN** a gin app behind the chain receives `X-Forwarded-For: 203.0.113.9` from a peer at 198.51.100.7, with no trusted proxies configured on the chain
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: gin's own trusted proxies do not change the chain
- **WHEN** the consumer sets gin's trusted proxies to every address, configures no trusted proxies on the chain, and a peer at 198.51.100.7 sends `X-Forwarded-For: 203.0.113.9`
- **THEN** the chain attributes the request to 198.51.100.7

#### Scenario: Same answer on every adapter
- **WHEN** the chain trusts 10.0.0.2 for `X-Forwarded-For` and that proxy forwards a client at 198.51.100.7 to a net/http, a gin and a fiber app
- **THEN** all three attribute the request to 198.51.100.7

#### Scenario: Opting into gin's client address
- **WHEN** the consumer configures the chain to trust 10.0.0.2 for `X-Forwarded-For`, and that proxy forwards a client at 198.51.100.7 to a gin app
- **THEN** the request is attributed to 198.51.100.7, with no gin-specific option involved

#### Scenario: fiber with a trusted proxy
- **WHEN** the consumer configures the chain to trust 10.0.0.2 for `X-Forwarded-For`, leaves fiber's own proxy trust off, and that proxy forwards a client at 198.51.100.7
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: fiber in-memory transport
- **WHEN** a request to a throttled flow arrives through fiber's in-memory test transport with no trusted proxies configured
- **THEN** it is refused as an unspecified client address

## ADDED Requirements

### Requirement: Every adapter supplies the request's host and transport security
The gin and fiber adapters SHALL supply the request's host from its `Host` header and whether it arrived over TLS from the transport, before any trusted-proxy resolution, so the chain resolves both identically on every adapter.

#### Scenario: fiber over TLS
- **WHEN** a fiber app serves a request over TLS for host `app.example.com` with no trusted proxies
- **THEN** the chain sees host `app.example.com` and a secure request, as the net/http adapter would

#### Scenario: gin's proxy settings do not make a request secure
- **WHEN** gin is configured to trust every proxy, no trusted proxies are configured on the chain, and a plain-HTTP request carries `X-Forwarded-Proto: https`
- **THEN** the chain sees an insecure request

#### Scenario: fiber's proxy header does not change the host
- **WHEN** fiber's own proxy header settings name `X-Forwarded-Host`, no trusted proxies are configured on the chain, and a request carries `X-Forwarded-Host: evil.example` with `Host: app.example.com`
- **THEN** the chain sees host `app.example.com`

### Requirement: Removing forwarded headers reaches the framework's request
When the chain removes consumed forwarded headers, every adapter SHALL remove them from the request its framework hands to the handlers after the chain, so a gin or fiber handler cannot read them either.

#### Scenario: gin handler after the chain
- **WHEN** trusted proxies are configured with default removal and a gin handler after the chain reads `X-Forwarded-For`
- **THEN** the header is absent

#### Scenario: fiber handler after the chain
- **WHEN** trusted proxies are configured with default removal and a fiber handler after the chain reads `X-Forwarded-Host`
- **THEN** the header is absent
