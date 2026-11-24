## ADDED Requirements

### Requirement: A 401 on a chain with a built-in bearer carries a challenge
On a chain with a built-in bearer, every 401 the chain answers outside the provider's endpoints SHALL carry one `Bearer` challenge; with DPoP required, one `DPoP` challenge instead; and with DPoP optional, one of each. With DPoP off, a `Bearer` token a built-in bearer refused SHALL get `error="invalid_token"`, and any other 401 no error code. A consumer MAY turn this off. A chain with no built-in bearer SHALL be unaffected.

#### Scenario: Expired token at a consumer's route
- **WHEN** a request presents an expired `Bearer` token at a consumer's protected route, with DPoP off
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="invalid_token"`, once

#### Scenario: No credential at a consumer's route
- **WHEN** a request presents no credential at a consumer's protected route, with DPoP off
- **THEN** the response is 401 with a `Bearer` challenge carrying no error code

#### Scenario: Consumer turns the challenge off
- **WHEN** the consumer turned the challenge off, and a request presents an expired `Bearer` token at a consumer's route
- **THEN** the response is 401 with no challenge

#### Scenario: Chain without a bearer
- **WHEN** a chain with session cookies and no built-in bearer refuses a request with 401
- **THEN** the response carries no challenge from the library

#### Scenario: Consumer's own challenge kept
- **WHEN** the consumer's error handler sets its own `WWW-Authenticate` on a 401
- **THEN** the library adds no second challenge for the same scheme

## MODIFIED Requirements

### Requirement: A 401 at the resume and consent endpoints carries a challenge
Every 401 at the provider's resume, consent listing and consent revocation endpoints SHALL carry one `WWW-Authenticate` challenge per scheme, whichever part of the chain refused the request. With DPoP off, a `Bearer` token a built-in bearer refused SHALL get `error="invalid_token"`, and any other 401 no error code. With DPoP on, the challenge SHALL name the `DPoP` scheme. A 401 elsewhere SHALL follow the requirement on chains with a built-in bearer.

#### Scenario: Unknown bearer token at the resume endpoint
- **WHEN** a resume presents a `Bearer` token the chain refuses, with DPoP off
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="invalid_token"`, once

#### Scenario: A custom bearer scheme
- **WHEN** a chain's bearer reads a scheme of the consumer's, and a resume presents a token that scheme refuses
- **THEN** the response is 401 with a `Bearer` challenge carrying no error code

#### Scenario: An invalid DPoP proof at the consent listing
- **WHEN** a consent listing presents an invalid DPoP proof
- **THEN** the response is 401 with one `DPoP` challenge naming `invalid_dpop_proof`, and no other challenge

#### Scenario: No credential at the consent listing
- **WHEN** a consent listing presents no credential, with DPoP off
- **THEN** the response is 401 with a `Bearer` challenge carrying no error code

#### Scenario: Unknown bearer token at a consumer's route
- **WHEN** a request presents a `Bearer` token the chain refuses, at a path that is not one of those endpoints, with DPoP off
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="invalid_token"`, once
