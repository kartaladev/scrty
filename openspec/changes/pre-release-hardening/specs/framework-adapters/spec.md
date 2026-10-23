# Spec Delta

## ADDED Requirements

### Requirement: A fiber route's own error keeps its meaning
On fiber, an error returned by the route or by middleware after the chain SHALL pass through the chain unchanged, and SHALL NOT become a refusal. fibersec's error handler SHALL answer an error carrying a fiber status with that status, and a refusal with its mapped status.

#### Scenario: Route returns a client error
- **WHEN** a route behind the chain returns a fiber error with status 422 and text `bad item`, on an app using fiber's built-in error handler
- **THEN** the response is 422 with `bad item`

#### Scenario: Unrouted path with the bare-status handler
- **WHEN** the consumer sets fibersec's error handler and a request reaches no route
- **THEN** the response is 404

### Requirement: fiber request cancellation reaches the chain
On fiber, the chain SHALL run with a context that ends when the client's request ends, as it does on net/http and gin, so store lookups and limiter calls made for a request that went away stop.

#### Scenario: Client disconnects during a store lookup
- **WHEN** a fiber client disconnects while the chain waits on a session store lookup
- **THEN** the lookup's context is cancelled

### Requirement: Adapter ownership guards fail at wiring
Building a gin or fiber ownership guard with a nil ownership checker or a nil identifier extractor SHALL panic at wiring time with a message naming the missing dependency, as the core guard does.

#### Scenario: fiber guard with a nil checker
- **WHEN** the consumer builds a fiber ownership guard with a nil checker
- **THEN** building it panics before any request is served
