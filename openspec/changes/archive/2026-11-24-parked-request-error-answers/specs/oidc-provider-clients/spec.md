## ADDED Requirements

### Requirement: A consumer can answer a throttled client source with 429
A consumer MAY choose that a source throttled at the token, revocation, introspection or device-authorization endpoint is answered 429 with a `Retry-After` header in whole seconds, instead of `invalid_client`. It is off by default. The body SHALL be the endpoint's JSON error shape with no code that names a client.

#### Scenario: Default answer
- **WHEN** a throttled source calls the token endpoint and the consumer made no choice
- **THEN** the response is 401 with `invalid_client`, as without this change

#### Scenario: Consumer chooses 429
- **WHEN** the consumer chose 429, and a throttled source calls the token endpoint
- **THEN** the response is 429 with a `Retry-After` header, and the client's credentials are not checked
