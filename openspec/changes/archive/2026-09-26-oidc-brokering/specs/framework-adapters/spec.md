## MODIFIED Requirements

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
