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
On fiber, the chain SHALL run with a context derived from fiber's request context that is cancelled when the request's handling ends, as net/http cancels a request's context when its handler returns, so work the chain started for a request that has ended stops. fiber gives a handler no signal when a client disconnects mid-request, so on fiber a disconnect does not cancel the chain's context before the handler returns; fibersec's documentation SHALL state this limit.

#### Scenario: Chain context ends with the request
- **WHEN** an interceptor keeps the chain's context and the fiber request's handling ends
- **THEN** that context is cancelled

### Requirement: Adapter ownership guards fail at wiring
Building a gin or fiber ownership guard with a nil ownership checker or a nil identifier extractor SHALL panic at wiring time with a message naming the missing dependency, as the core guard does.

#### Scenario: fiber guard with a nil checker
- **WHEN** the consumer builds a fiber ownership guard with a nil checker
- **THEN** building it panics before any request is served
