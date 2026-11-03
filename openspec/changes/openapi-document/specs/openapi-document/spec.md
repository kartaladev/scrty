# Spec Delta

## Purpose

Describes the built-in endpoints a chain actually answers as an OpenAPI document, so a consumer can generate clients and documentation that match their configuration without writing that description by hand.

## ADDED Requirements

### Requirement: The document is opt-in
The library SHALL generate and serve no OpenAPI document unless the consumer enables it on the chain or asks for one from a built chain. A chain built without either SHALL answer no document path and SHALL do no document work.

#### Scenario: Not enabled
- **WHEN** a chain enables form login and nothing else
- **THEN** a request to `/openapi.json` passes through to the handler

### Requirement: The document is served publicly under the base path
When enabled, the chain SHALL answer GET and HEAD at `/openapi.json`, joined to the chain's base path, with a 200 and a JSON document, without calling the handler. No credential or authorization rule SHALL refuse the request. The consumer SHALL be able to change the path, which stays relative to the base path.

#### Scenario: Served at the default path
- **WHEN** the document is enabled on a chain with no base path
- **THEN** `GET /openapi.json` returns 200 with a JSON OpenAPI document

#### Scenario: Under the base path
- **WHEN** the document is enabled on a chain with the base path `/auth`
- **THEN** `GET /auth/openapi.json` returns the document and `GET /openapi.json` passes through

#### Scenario: Stale credential and deny-by-default rules
- **WHEN** a client sends an expired bearer token to the document path on a chain whose authorization rules allow nothing else
- **THEN** the document is returned with 200

#### Scenario: Consumer path
- **WHEN** the consumer sets the document path to `/spec.json` on a chain with the base path `/auth`
- **THEN** the document is served at `/auth/spec.json`

### Requirement: The document is built once, at construction
The document SHALL be built while the chain is built. Any failure to build it SHALL fail construction with a configuration error naming its cause. Once built, the served bytes SHALL never change for the life of the chain. Responses SHALL carry a strong entity tag, and a request presenting it in `If-None-Match` SHALL receive 304 with no body.

#### Scenario: Same bytes every time
- **WHEN** the document is requested twice
- **THEN** both responses carry identical bodies and identical entity tags

#### Scenario: Conditional request
- **WHEN** a client repeats the request with the entity tag it received in `If-None-Match`
- **THEN** the response is 304 with no body

#### Scenario: Build failure
- **WHEN** the consumer's document hook returns an error
- **THEN** building the chain fails with a configuration error carrying that error

### Requirement: The document can be built without serving it
A consumer SHALL be able to obtain the document's bytes from a built chain without enabling the endpoint. For one configuration, those bytes SHALL equal what the endpoint would serve.

#### Scenario: Private document
- **WHEN** a consumer builds a chain without enabling the endpoint and asks for its document
- **THEN** they receive the document, and no document path is answered

### Requirement: The document is OpenAPI 3.1.2
The document SHALL declare OpenAPI version `3.1.2` and use JSON Schema 2020-12 for every schema, and SHALL validate as an OpenAPI 3.1 document.

#### Scenario: Version and validity
- **WHEN** a chain with every built-in enabled produces its document
- **THEN** the document declares `openapi: 3.1.2` and passes OpenAPI 3.1 validation

### Requirement: The document describes exactly the enabled built-in endpoints
The document SHALL contain one operation per enabled built-in endpoint and method, at its path after the base path is applied. Each operation's `operationId` SHALL be the endpoint's operation identifier, and it SHALL be tagged with its feature. Endpoints not enabled, consumer interceptors and consumer routes SHALL NOT appear.

#### Scenario: Only what is enabled
- **WHEN** a chain with the base path `/auth` enables form login and MFA with TOTP
- **THEN** the document has `POST /auth/login` with `operationId` `scrty.login` and `POST /auth/mfa/verify/{method}` with `scrty.mfa.verify`
- **AND** it has no logout, passkey or recovery operation

### Requirement: Requests are described as configured
Each operation's request body SHALL list the media types the endpoint accepts and the field names it reads, as the consumer configured them. Each path segment an endpoint reads SHALL be a path parameter. When the segment names a configured method or provider, it SHALL enumerate exactly the configured names.

#### Scenario: Renamed login fields
- **WHEN** the consumer configures login to read `email` and `secret`
- **THEN** the login request schema has the properties `email` and `secret` for both the form and the JSON media types, and no `username` or `password`

#### Scenario: Configured methods enumerated
- **WHEN** MFA is enabled with TOTP and passkey methods
- **THEN** the `method` parameter of `scrty.mfa.verify` enumerates exactly `totp` and `passkey`

### Requirement: Security requirements follow the enabled authenticators
The document SHALL declare a security scheme for each enabled authenticator: HTTP Basic, HTTP bearer (with the JWT format when the chain issues tokens), and an API key in the configured header. Each operation SHALL require a scheme only when its endpoint needs a session or principal.

#### Scenario: Login needs nothing
- **WHEN** form login and bearer authentication are enabled
- **THEN** `scrty.login` declares no security requirement, and `scrty.logout` requires the bearer scheme

#### Scenario: API key header
- **WHEN** API key authentication reads the header `X-Service-Key`
- **THEN** the document declares an `apiKey` scheme in the header `X-Service-Key`

### Requirement: Default responses are described from what the library writes
For each endpoint left with the library's default responder, the success response's schema SHALL describe the body that responder writes, and a body that responder actually writes SHALL validate against it.

#### Scenario: Default login response
- **WHEN** form login uses its default responder
- **THEN** the 200 response schema of `scrty.login` requires `access_token`, `refresh_token` and `valid_until`
- **AND** a real login response body validates against it

### Requirement: A typed JSON response is inferred
When the consumer replaces a responder with the library's typed JSON form, returning a Go value, the operation's success response SHALL use the consumer's chosen status and a schema reflected from the returned type.

#### Scenario: Consumer login document
- **WHEN** the consumer's typed login response returns a struct with the JSON fields `token` and `expires`, with status 201
- **THEN** `scrty.login` has a 201 response whose schema has the properties `token` and `expires`, and no 200 response

### Requirement: A response can be declared by type
The consumer SHALL be able to declare, for an operation identifier and status, a Go type whose reflected schema describes that response. A declaration SHALL replace an inferred or default schema for the same operation and status.

#### Scenario: Declared for a plain responder
- **WHEN** the consumer replaces the login responder with a plain function and declares the type `LoginView` for `scrty.login` and status 200
- **THEN** the 200 response of `scrty.login` uses the schema reflected from `LoginView`

### Requirement: An undescribed replaced response carries no schema
When the consumer replaces a responder with a plain function and declares nothing for it, the operation SHALL keep its success status with no schema, and its description SHALL say the application defines the body.

#### Scenario: Plain responder, nothing declared
- **WHEN** the consumer replaces the login responder with a plain function and declares nothing
- **THEN** the 200 response of `scrty.login` has no content schema and says the application defines the body

### Requirement: Refusals are listed by status, and their body is declared
Each operation SHALL list a response for every status its endpoint's refusals map to, by default with no content, as the library's default rendering sends. When the consumer declares an error body type and media type, every refusal response SHALL carry that schema under that media type.

#### Scenario: Default refusals
- **WHEN** form login is enabled with nothing declared
- **THEN** the responses of `scrty.login` include 400, 401 and 429, each with no content

#### Scenario: Problem details declared
- **WHEN** the consumer declares the error body type `Problem` with media type `application/problem+json`
- **THEN** every refusal response carries the `Problem` schema under `application/problem+json`

### Requirement: A document hook has the last word
The consumer SHALL be able to give a hook that receives the complete document and may change any part of it, after every inferred, declared and default schema has been applied. Its changes SHALL be served exactly. An error from it SHALL fail construction.

#### Scenario: Hook adds a description
- **WHEN** the consumer's hook sets the description of `scrty.login`
- **THEN** the served document carries that description

### Requirement: Document metadata has neutral defaults
By default the document's title SHALL be `Security endpoints` and its version `1`, and it SHALL declare no server, so clients resolve paths against the origin that served it. The consumer SHALL be able to set the title, the version and one or more server URLs.

#### Scenario: Defaults
- **WHEN** the document is enabled with no metadata options
- **THEN** its title is `Security endpoints`, its version `1`, and it lists no servers

#### Scenario: Public server behind a proxy
- **WHEN** a proxy strips `/public` and the consumer declares the server `https://example.com/public`
- **THEN** the document lists that server, and its paths stay as the chain answers them

### Requirement: Response types are reflected faithfully or refused
Named types SHALL become reusable component schemas, and a type that refers to itself SHALL be described by reference. Struct-tag constraints on a consumer type, such as an enumeration or a length bound, SHALL appear in its schema. A type that cannot be described SHALL fail construction, naming the operation and the type.

#### Scenario: Recursive consumer type
- **WHEN** a declared response type has a field holding a slice of itself
- **THEN** the document builds, and the field refers back to the type's component schema

#### Scenario: Tagged constraint
- **WHEN** a declared response type tags its `status` field with an enumeration of `active` and `locked`
- **THEN** that property's schema enumerates exactly `active` and `locked`

#### Scenario: Undescribable type
- **WHEN** a declared response type contains a channel field
- **THEN** building the chain fails with a configuration error naming the operation and the type

### Requirement: Method-owned begin data is described by its method
The success response of a begin step whose data belongs to the method SHALL use the schema that method describes, when it describes one. Otherwise that response SHALL carry no schema.

#### Scenario: Passkey begin with the WebAuthn verifier
- **WHEN** passkeys are enabled with the WebAuthn verifier
- **THEN** `scrty.passkey.register.begin` has a 200 response schema describing the credential creation options

#### Scenario: A method that describes nothing
- **WHEN** a consumer's challenge method describes no begin data
- **THEN** `scrty.mfa.begin` has a 200 response with no schema
