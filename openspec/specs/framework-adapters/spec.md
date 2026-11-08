# framework-adapters Specification

## Purpose

Lets a consumer on gin or fiber use the same security chain as a net/http consumer, with the same outcomes, the security state readable through the framework's own request context, and refusals delivered through the framework's own error channel.

## Requirements

### Requirement: Every adapter produces the same outcome
The net/http, gin and fiber integrations SHALL run the same chain built from the same options. For the same request and configuration they SHALL produce the same status, the same library-set headers, the same session and attempt side effects, and the same refusal error. A shared conformance suite SHALL run every chain scenario through all three. The scenarios SHALL cover:
- login success and failure;
- lockout;
- bearer token verification;
- rule and guard allow and deny;
- a challenge;
- an endpoint answered by the chain;
- context propagation;
- an unattributable address.

#### Scenario: Same refusal on every framework
- **WHEN** the same request with a wrong password is sent to form login through net/http, gin and fiber, each with no error handling configured
- **THEN** all three answer 401 with no error text and record one failed attempt

#### Scenario: Same configuration mistakes
- **WHEN** a chain enabling form login without a session manager is built for gin or for fiber
- **THEN** construction fails with the same error as for net/http

### Requirement: The chain is framework-neutral and each framework adapts natively
The chain's interceptors SHALL read requests and write responses only through a framework-neutral request and response abstraction. The net/http integration SHALL be the default implementation, and gin SHALL reuse it. The fiber integration SHALL implement the abstraction directly over fiber's own request context, and SHALL NOT convert a secured request into a net/http request. A consumer SHALL be able to run the chain on another framework by implementing the abstraction, without changing any interceptor.

#### Scenario: fiber without conversion
- **WHEN** a secured request is served through the fiber integration
- **THEN** no net/http request is constructed for it

#### Scenario: Consumer adapter for another framework
- **WHEN** a consumer implements the request and response abstraction for their own framework and runs the chain through it
- **THEN** form login and bearer authentication produce the same outcomes as on net/http

### Requirement: Security state reaches the framework's request context
Each adapter SHALL start the chain from the framework's incoming request context. Before the downstream handler runs, each adapter SHALL make everything the chain added readable through that framework's standard way of reading the request context. That covers the principal, the authentication result, the session and the authorizer. Values and cancellation already on the incoming context SHALL be preserved.

#### Scenario: gin handler reads the principal
- **WHEN** a gin route handler behind the chain reads the principal from the request's context
- **THEN** it receives the authenticated principal

#### Scenario: fiber handler reads the principal
- **WHEN** a fiber route handler behind the chain reads the principal from the handler context's request context
- **THEN** it receives the authenticated principal

#### Scenario: Upstream value on fiber
- **WHEN** fiber middleware before the chain stores a trace identifier in the request context
- **THEN** the route handler behind the chain still reads it

### Requirement: gin refusals reach the error channel and fail closed
On gin, a refused request SHALL:
1. register the refusal error on gin's error channel;
2. stop the remaining gin handlers, so the route never runs;
3. set the mapped status without committing the response, when nothing has written it yet, so a request is never answered 200 when no error middleware handles it.

Setting that status SHALL leave the headers and body open to a later error middleware. When the response was already written, the adapter SHALL only stop the remaining handlers. gin guards SHALL follow the same rules.

One case is committed instead: a refusal mapped to 404 on a request gin matched no route for, such as a path owned by a chain endpoint. gin's own no-route fallback writes its default 404 body whenever a 404 reaches it with no body written, so leaving that status open would give gin a body the other adapters do not send. The adapter SHALL commit the 404 with an empty body in that case, and a consumer's gin error middleware cannot re-render it. Every other refusal, and every 404 on a matched route, keeps the rule above.

#### Scenario: No error middleware
- **WHEN** a gin request is refused as access denied and no error middleware is registered
- **THEN** the response is 403 with an empty body and the route handler did not run

#### Scenario: Consumer error middleware renders
- **WHEN** the consumer registers gin error middleware that reads the error channel and writes a JSON body with its own `Content-Type`
- **THEN** the response carries the consumer's body, its `Content-Type` and the status it chose

#### Scenario: gin guard without error middleware
- **WHEN** a gin guard refuses a principal without the required privilege and no error middleware is registered
- **THEN** the response is 403 and the route handler did not run

#### Scenario: Not-found refusal on an unrouted path
- **WHEN** a gin request to `/sso/login/nope`, which no gin route matches, is refused because `nope` names no registered provider
- **THEN** the response is 404 with an empty body, as on the other adapters, and not gin's default not-found text

### Requirement: gin endpoints answered by the chain stop the gin chain
When an interceptor answers a gin request itself without an error, the adapter SHALL stop the remaining gin handlers without committing a status of its own. A matched route or a consumer's no-route handler SHALL NOT run, and SHALL NOT overwrite the status or append to the body. Examples are login, logout and the key set endpoint. The adapter documentation SHALL state that gin middleware registered after the chain does not run for such requests.

#### Scenario: Status set by the chain survives
- **WHEN** a gin app registers the chain and a route that writes 201 on the logout path, and a client logs out
- **THEN** the response is 200 and the route did not run

#### Scenario: No-route handler does not append
- **WHEN** a gin app has a consumer no-route handler and a client requests the key set path
- **THEN** the response body is exactly the key set

### Requirement: fiber refusals are returned to fiber's error handler
On fiber, a refused request SHALL return an error from the chain's handler, and the route SHALL NOT run. That error SHALL be identifiable as the original refusal by error identity or type. It SHALL carry the mapped status in the form fiber's error handling reads. Its own text SHALL be only the standard status text for that status, so fiber's built-in error handler cannot place internal error text in a response. fiber guards SHALL return their refusals the same way. The fibersec module SHALL provide:
- an error handler that answers with the bare mapped status and an empty body;
- a mapping helper that returns the status and a minimal body holding only the standard status text.

#### Scenario: Consumer fiber error handler
- **WHEN** the consumer's fiber error handler extracts the challenge error from a refused login and renders its own prompt
- **THEN** the consumer's prompt is the response and the challenge kind and token were available to it

#### Scenario: fiber's built-in handler
- **WHEN** a fiber app with no error handler configured refuses a request whose cause is `connection refused to db-primary:5432`
- **THEN** the response carries status 500 and at most the text `Internal Server Error`, never the cause

#### Scenario: Bare-status handler
- **WHEN** the consumer sets fibersec's error handler as fiber's error handler and a request is refused as unauthenticated
- **THEN** the response is 401 with an empty body

#### Scenario: Mapping helper
- **WHEN** the consumer's fiber error handler logs the error and then uses the mapping helper for an access-denied refusal
- **THEN** the helper returns 403 and a body holding only `Forbidden`

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

### Requirement: Every adapter reads a form field with the same precedence
Reading a form field through the framework-neutral request abstraction SHALL look in the posted form first and fall back to the URL query, on every adapter the library provides. Only POST, PUT and PATCH requests carry a posted form; for any other method the field SHALL be read from the URL query alone. Reading a field SHALL NOT consume the body: reading the body before or after a form field SHALL return the same bytes. Reading a field SHALL NOT change the size limit a later body read applies, and each body read SHALL refuse a body longer than its own limit whatever an earlier read on the same request read or refused. The form read SHALL read at most 10 MiB of a URL-encoded body and 32 MiB of a multipart body; a larger body, an unparseable content type or an unparseable body SHALL be answered from the query. A consumer interceptor that reads a field SHALL therefore get the same value on net/http, gin and fiber. The abstraction's documentation SHALL state the precedence, and that the library's own credential reads never take the query, apart from the OIDC authorization response, whose `code` and `state` the protocol delivers in the query.

#### Scenario: Body and query both carry the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `body` on net/http, gin and fiber

#### Scenario: Only the query carries the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose body lacks it and whose query carries `x=query`
- **THEN** it reads `query` on every adapter

#### Scenario: Multipart body and query both carry the field
- **WHEN** a consumer interceptor reads field `x` from a POST whose multipart body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `body` on net/http, gin and fiber

#### Scenario: A GET with a body reads the query
- **WHEN** a consumer interceptor reads field `x` from a GET whose body carries `x=body` and whose query carries `x=query`
- **THEN** it reads `query` on net/http, gin and fiber

#### Scenario: Reading a field leaves the body readable
- **WHEN** a consumer interceptor reads field `x` from a POST with a URL-encoded body and then reads the body
- **THEN** the body it reads is the full posted body on net/http, gin and fiber

#### Scenario: A field read does not widen a body limit
- **WHEN** a consumer interceptor reads a form field from a POST whose URL-encoded body is 8 KiB, and a library endpoint then reads the body with a 4 KiB limit
- **THEN** the endpoint's read is refused as too large on net/http, gin and fiber

#### Scenario: An oversized upload is left intact
- **WHEN** a consumer interceptor reads field `x` from a POST whose multipart body is larger than 32 MiB, and the handler then parses the upload
- **THEN** the interceptor reads the query's `x`, and the handler parses the whole upload

#### Scenario: An earlier, larger body read does not widen a later limit
- **WHEN** a consumer interceptor reads the body of an 8 KiB POST with a 64 KiB limit, and a library endpoint then reads it with a 4 KiB limit
- **THEN** the endpoint's read is refused as too large on net/http, gin and fiber

### Requirement: A fiber route's own error keeps its meaning
On fiber, an error returned by the route or by middleware after the chain SHALL pass through the chain unchanged, and SHALL NOT become a refusal. fibersec's error handler SHALL answer an error carrying a fiber status with that status, and a refusal with its mapped status.

#### Scenario: Route returns a client error
- **WHEN** a route behind the chain returns a fiber error with status 422 and text `bad item`, on an app using fiber's built-in error handler
- **THEN** the response is 422 with `bad item`

#### Scenario: Unrouted path with the bare-status handler
- **WHEN** the consumer sets fibersec's error handler and a request reaches no route
- **THEN** the response is 404

### Requirement: fiber request cancellation reaches the chain
On fiber, the chain SHALL run with a context derived from fiber's request context that is cancelled when the request's handling ends, as net/http cancels a request's context when its handler returns, so work the chain started for a request that has ended stops. fiber gives a handler no signal when a client disconnects mid-request, so on fiber a disconnect does not cancel the chain's context before the handler returns; fibersec's documentation SHALL state this limit.

#### Scenario: Chain context ends with the request
- **WHEN** an interceptor keeps the chain's context and the fiber request's handling ends
- **THEN** that context is cancelled

### Requirement: Adapter ownership guards fail at wiring
Building a gin or fiber ownership guard with a nil ownership checker or a nil identifier extractor SHALL panic at wiring time with a message naming the missing dependency, as the core guard does.

#### Scenario: fiber guard with a nil checker
- **WHEN** the consumer builds a fiber ownership guard with a nil checker
- **THEN** building it panics before any request is served

### Requirement: Adapter guards are built with an authorizer or a declared reliance on the chain
Building gin or fiber guards SHALL follow the core guards' construction rule. They SHALL be built either with an authorizer, or with an explicit option declaring that they rely on the chain's authorizer alone. Building them with neither, including an interface holding a nil value, SHALL fail with a configuration error. On fiber, a guard's refusal SHALL still be rendered by fiber's error handler.

#### Scenario: fiber guards built with no authorizer
- **WHEN** the consumer builds fiber guards with a nil authorizer and without the option declaring reliance on the chain's authorizer
- **THEN** building them fails with a configuration error

#### Scenario: gin guards rely on the chain
- **WHEN** the consumer builds gin guards with the option declaring reliance on the chain's authorizer, and a guarded route is called through the gin chain with authorization enabled by a principal holding the privilege
- **THEN** the guard judges with the chain's authorizer and the route runs

#### Scenario: fiber guard refusal reaches the consumer's error handler
- **WHEN** fiber guards built with an authorizer refuse a principal without the required privilege, in an app whose error handler renders its own body
- **THEN** the consumer's error handler renders the refusal

### Requirement: Adapter recency guards match the core recency guard
The gin and fiber guards SHALL offer the recency guard with the same default window, the same guards-wide and per-route windows, the same time-source and authentication-time options, and the same construction and wiring failures as the core guards, and SHALL produce the same outcome for the same request. Their refusals SHALL reach the consumer as every other adapter guard refusal does.

#### Scenario: gin stale session
- **WHEN** a gin route under the default recency guard is called by a session that authenticated 16 minutes ago
- **THEN** the route handler is not called, the reauthentication-required refusal reaches gin's error channel, and the default response is 403

#### Scenario: fiber stale session
- **WHEN** a fiber route under the default recency guard is called by a session that authenticated 16 minutes ago
- **THEN** the route handler is not called, and fiber's error handler receives the reauthentication-required refusal carrying the 15-minute window

#### Scenario: Fresh session on every adapter
- **WHEN** a session that authenticated 5 minutes ago calls the same recency-guarded route on net/http, gin and fiber
- **THEN** the route is called on all three

#### Scenario: Per-route window on gin
- **WHEN** a gin route is guarded with a 5-minute window and a session that authenticated 6 minutes ago calls it
- **THEN** it is refused with the reauthentication-required refusal carrying the 5-minute window

#### Scenario: fiber guards with an absent time source
- **WHEN** fiber guards are built with a nil time source
- **THEN** construction fails with a configuration error

#### Scenario: gin per-route window of zero
- **WHEN** a gin route's recency guard is built with a window of zero
- **THEN** building it fails at wiring with a message naming the window

#### Scenario: One wiring mistake, one error on every adapter
- **WHEN** guards are built on net/http, gin and fiber with a recency window of zero and no authorizer
- **THEN** each adapter refuses construction naming the recency window, not the missing authorizer

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

### Requirement: Every adapter can stream a response
The framework-neutral response writer SHALL let an interceptor stream a response: each event it writes and flushes SHALL reach the client while the response stays open. The net/http, gin and fiber adapters SHALL each support it. A response writer of the consumer's own SHALL implement it, or report that it cannot stream, in which case the stream endpoint answers 501.

#### Scenario: Flushed event arrives before the response ends
- **WHEN** an interceptor writes one event, flushes, and keeps the response open, on any of the three adapters
- **THEN** the client receives the event while the response is still open

#### Scenario: Consumer adapter that cannot stream
- **WHEN** a consumer's own response writer reports that it cannot stream and a client requests the signal stream
- **THEN** the response is 501

### Requirement: A writer that cannot flush is reported as unable to stream
A response writer that cannot flush, such as a consumer's wrapper hiding the underlying writer, or a server timeout handler, SHALL be reported as unable to stream, not treated as a client that left.

#### Scenario: A wrapper that hides the writer
- **WHEN** a consumer's middleware wraps the response writer with no way to reach the one beneath, and a client requests the signal stream
- **THEN** the response is 501, nothing else is written, and no reconnection loop follows

### Requirement: Starting a stream sends the response head once
Starting a stream SHALL send the status and every header set before it, on every adapter. Starting a stream after the response has begun, or a second time, SHALL fail and write nothing. Once a stream has started successfully, its body SHALL run exactly once, so that what it holds is always released. On an adapter that runs the body after the chain has returned, a chain that refused SHALL get its refusal sent, and the body SHALL run on an already-ended context.

#### Scenario: Headers set before streaming are sent
- **WHEN** an interceptor sets `Cache-Control: no-store` and a CORS header, and then starts a stream, on any of the three adapters
- **THEN** the client receives both headers with the streamed response

#### Scenario: Refused after starting, where the body runs later
- **WHEN** an interceptor refuses the request after a stream was started, on fiber
- **THEN** the client receives the refusal and no stream, and the body runs once on an already-ended context

#### Scenario: Refused after starting, where the body runs inline
- **WHEN** an interceptor refuses the request after a stream was started, on net/http or gin
- **THEN** the body has already run once and its stream has been sent, and the refusal changes nothing the client received

#### Scenario: Stream after the response began
- **WHEN** an interceptor has already written a body and then starts a stream
- **THEN** starting the stream fails and nothing more is written

#### Scenario: The content type goes with the stream
- **WHEN** an interceptor starts a stream with a content type, on any of the three adapters
- **THEN** the client receives that type with the streamed response

#### Scenario: A refusal carries no stream type
- **WHEN** starting a stream is refused, or on fiber the chain refuses after starting one
- **THEN** the refusal does not carry the stream's content type, and a type the framework or the error handler sets is what the client receives

#### Scenario: A consumer's own type stays on a refusal
- **WHEN** a consumer sets `Content-Type` itself and starting a stream is then refused
- **THEN** the refusal carries the consumer's type, not the stream's

#### Scenario: A refusal after the head has gone carries the stream's type
- **WHEN** on net/http or gin a wrapper above the bottom of the writer chain refuses to flush only once the status has been named
- **THEN** the client has received status 200 and the stream's type, because the head was sent before the refusal could be known

### Requirement: A streamed response is not ended by the server's write deadline
While a response is streamed, each adapter SHALL keep a configured write deadline from ending it, by extending the deadline as each write is made. A response that is not streamed SHALL keep the deadline as configured.

#### Scenario: Stream outlives the write timeout
- **WHEN** a server on any of the three adapters has a 3-second write timeout and a stream sends a heartbeat every 5 seconds for 30 seconds
- **THEN** the stream stays open for the 30 seconds

#### Scenario: Ordinary response keeps the deadline
- **WHEN** the same server answers an ordinary request that takes longer than 3 seconds to write
- **THEN** the write deadline ends it as before

### Requirement: A streamed response learns when its client leaves
On every adapter, a streamed response SHALL learn promptly that its client has disconnected, and SHALL then stop writing and release what it holds.

#### Scenario: Client closes the tab
- **WHEN** a client with an open stream disconnects, on any of the three adapters
- **THEN** the stream stops within one heartbeat interval and its place under the stream caps is freed

#### Scenario: Server shuts down on fiber
- **WHEN** a fiber server with an open stream shuts down
- **THEN** the stream stops, and the shutdown is not held open by it
