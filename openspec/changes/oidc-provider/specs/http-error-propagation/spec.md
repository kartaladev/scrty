# Spec Delta

## MODIFIED Requirements

### Requirement: Refusals propagate as errors, unrendered
Interceptors and guards SHALL report every refusal by returning an error. The library SHALL NOT write a response body for a refusal. The error reaching the consumer's error handling SHALL be the refusal error itself, or an error wrapping it, so the consumer can identify the refusal by error identity or type. The library SHALL NOT include a problem-details or other body renderer. The one exception SHALL be the OpenID Provider's protocol endpoints: authorization, resume, token, revocation, introspection, UserInfo, end-session and its confirmation. They SHALL answer protocol errors in the form their standards fix, as the `oidc-provider-*` capabilities state. They SHALL report through the chain's error handling only the failures the protocol does not let them answer themselves: an invalid client or redirect URI at the authorization endpoint, a refused `id_token_hint` at the end-session endpoint, and dependency failures.

#### Scenario: Consumer identifies the refusal
- **WHEN** a request is refused because the account is locked
- **THEN** the error reaching the consumer's error handler is identifiable as the account-locked refusal

#### Scenario: No body from the library
- **WHEN** any refusal occurs and the consumer's error handler writes nothing
- **THEN** no bytes written by the library appear in the response body

#### Scenario: Provider token endpoint error
- **WHEN** a token request presents an expired authorization code and no error handler is configured
- **THEN** the response is 400 with the JSON body `{"error":"invalid_grant"}` and `Cache-Control: no-store`

#### Scenario: Unredirectable authorization error
- **WHEN** an authorization request names an unregistered redirect URI and the consumer's error handler renders a page
- **THEN** the consumer's error handler receives the refusal, and the library writes no body of its own

## ADDED Requirements

### Requirement: The provider's request refusals are public errors mapped to 400
The library SHALL expose distinguishable public refusal errors, each mapped to 400 in the public status table, for:
- an invalid client or redirect URI at the authorization endpoint;
- an unknown, expired, spent or unbound pending-request handle;
- a consent answer that grants scopes not requested.

#### Scenario: Unknown handle
- **WHEN** a resume presents an unknown handle and no error handler is configured
- **THEN** the response is 400 with an empty body

### Requirement: The provider's other refusals are public errors with their own statuses
The library SHALL expose a public refusal error for a resume whose sign-in is not fresh enough for `prompt` or `max_age`, mapped to 401 as a re-authentication challenge. It SHALL expose one for a consent revocation or listing for a user other than the signed-in one, mapped to 404. A provider dependency failure SHALL map to 500 with no error text in the body.

#### Scenario: Re-authentication needed
- **WHEN** a resume's sign-in authenticated before the request's `max_age` allows
- **THEN** the error reaching the consumer's error handler is identifiable as the provider's re-authentication refusal, and maps to 401

### Requirement: A 401 at the resume and consent endpoints carries a challenge
Every 401 at the provider's resume, consent listing and consent revocation endpoints SHALL carry one `WWW-Authenticate` challenge per scheme, whichever part of the chain refused the request. With DPoP off, a `Bearer` token a built-in bearer refused SHALL get `error="invalid_token"`, and any other 401 no error code. With DPoP on, the challenge SHALL name the `DPoP` scheme. A 401 elsewhere SHALL be unaffected.

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
- **WHEN** a request presents a `Bearer` token the chain refuses, at a path that is not one of those endpoints
- **THEN** the response is 401 with no challenge from the provider
