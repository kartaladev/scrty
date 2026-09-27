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
- **WHEN** a gin request to `/oauth2/authorization/nope`, which no gin route matches, is refused because `nope` names no registered provider
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
The gin integration SHALL attribute a request to its transport peer by default. An opt-in, offered only by the gin integration, SHALL use gin's own proxy-aware client address instead. The opt-in's documentation SHALL state that gin trusts every proxy until the consumer sets a trusted proxy list, and that until then a client chooses its own address.

The fiber integration SHALL use fiber's own client address. That is the transport peer unless the consumer enables fiber's proxy trust. Its documentation SHALL state the fiber configuration under which forwarded addresses are trustworthy, and SHALL state that an in-memory or Unix-socket transport reports an unspecified peer.

The chain's refusal of empty, malformed or unspecified addresses SHALL apply to whatever address an adapter returns.

#### Scenario: gin default ignores forwarded headers
- **WHEN** a gin app behind the chain receives `X-Forwarded-For: 203.0.113.9` from a peer at 198.51.100.7
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: Opting into gin's client address
- **WHEN** the consumer sets gin's trusted proxies to 10.0.0.2, opts into gin's client address, and the proxy forwards a client at 198.51.100.7
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: fiber in-memory transport
- **WHEN** a request to a throttled flow arrives through fiber's in-memory test transport with no proxy trust configured
- **THEN** it is refused as an unspecified client address

#### Scenario: fiber with a trusted proxy
- **WHEN** the consumer enables fiber's proxy trust for 10.0.0.2 with address validation, and that proxy forwards a client at 198.51.100.7
- **THEN** the request is attributed to 198.51.100.7

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
