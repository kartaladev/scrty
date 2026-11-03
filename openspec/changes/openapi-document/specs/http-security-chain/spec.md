# Spec Delta

## ADDED Requirements

### Requirement: Each JSON responder has a typed form
For every replaceable responder that writes a JSON result, the chain SHALL offer a typed form: the consumer's function receives the endpoint's result and returns a Go value, and the chain writes that value as JSON with the status the consumer chose and a JSON content type. The chain SHALL record the returned type in the endpoint's description.

#### Scenario: Typed login response
- **WHEN** the consumer's typed login response returns `LoginView{Token: "t"}` with status 201
- **THEN** a successful login answers 201 with `Content-Type: application/json` and the body `{"token":"t"}`
- **AND** the login endpoint's description records `LoginView` as its 201 response type

#### Scenario: A non-success status
- **WHEN** the consumer gives a typed login response the status 400
- **THEN** construction fails with a configuration error naming the option, because a refusal belongs to an error, not a response

#### Scenario: The typed function refuses
- **WHEN** the consumer's typed function returns an error
- **THEN** the error propagates up the chain exactly as a plain responder's error does, and nothing is written

### Requirement: The endpoint list describes requests, responses and refusals
Each entry in the chain's endpoint list SHALL also describe:
- its request: the media types it accepts and the field names it reads, as configured;
- its success responses: status, and the Go type of the body, or none when the body cannot be known;
- the refusals it can return, each with the status the library maps it to;
- the authentication schemes that can satisfy it.

#### Scenario: Default login description
- **WHEN** form login is enabled with its defaults
- **THEN** its entry lists the form and JSON media types with the fields `username` and `password`, a 200 response whose type is the default login document, and refusals that include the 401 for invalid credentials

#### Scenario: Plain responder makes the body unknown
- **WHEN** the consumer replaces the login responder with a plain function
- **THEN** the login entry's 200 response has no body type

### Requirement: A registered interceptor can finish building once the chain is assembled
An interceptor registered on the chain that declares it needs the assembled chain SHALL be called once, after every option has been applied and every path resolved, and before construction returns. An error it returns SHALL fail construction with that error.

#### Scenario: Interceptor reads the endpoint list
- **WHEN** a consumer interceptor that needs the assembled chain is registered beside form login
- **THEN** it is called once during construction and sees the login endpoint in the chain's endpoint list

#### Scenario: Interceptor fails
- **WHEN** that interceptor returns an error
- **THEN** construction fails and returns no chain

### Requirement: The document endpoint has a named slot
The chain SHALL name a slot for the OpenAPI document endpoint, inside the key set's slot and outside every authentication slot and the authorization stage.

#### Scenario: Slot order
- **WHEN** the named slots are compared
- **THEN** the document slot is greater than the key set's slot and less than the OIDC login slot, and so less than every authentication slot and the authorization slot
