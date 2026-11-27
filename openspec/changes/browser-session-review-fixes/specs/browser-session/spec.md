## ADDED Requirements

### Requirement: A CSRF refusal is a refusal whatever its shape
On a cookie chain, an unsafe request whose CSRF token the token source refuses SHALL be refused as a cross-site request, whatever the shape of the source's error: nil or typed-nil entries anywhere in its error tree SHALL NOT turn the refusal into an admitted request, and SHALL NOT panic the request. The request SHALL NOT be charged to its source, and the cookie SHALL be left in place.

#### Scenario: Refusal with a nil entry in a joined error
- **WHEN** the consumer's token source refuses an unsafe cookie request with an error joining the authentication-required error and a nil entry
- **THEN** the request is refused as a cross-site request with `403`, the handler does not run, nothing is charged, and no cookie is set

#### Scenario: Refusal with a typed-nil entry
- **WHEN** the token source refuses with an error whose tree holds the authentication-required error and a typed-nil error value
- **THEN** the request is refused as a cross-site request, and nothing panics

#### Scenario: Refusal that carries a dependency failure
- **WHEN** the token source refuses with the authentication-required error joined to a store outage
- **THEN** the request fails as that dependency failure, as before

### Requirement: A delivery that alters the session cookie is refused
A consumer's session delivery SHALL set the cookie the chain built, with every attribute it would write unchanged, including whether the value is quoted. A delivery that sets the cookie with any attribute changed SHALL fail the sign-in as an issuing failure, and the sign-in SHALL be ended.

#### Scenario: Quoted cookie value
- **WHEN** the consumer's delivery sets the chain's session cookie exactly, except that it marks the value as quoted
- **THEN** the sign-in fails as an issuing failure, the response carries no session cookie, and the session is ended

### Requirement: A role switch after its handler has returned is refused
A role switch on a cookie chain SHALL be refused, storing nothing, once its request's handler has returned. A switch in progress SHALL complete before the handler's return completes. A switch waiting behind another SHALL give up when its own context ends.

#### Scenario: Switch after the handler returned
- **WHEN** a role switch is made with the context of a request whose handler has already returned
- **THEN** it fails with a configuration error, no session is rotated, and the old cookie keeps working

#### Scenario: Handler returns while a switch is in progress
- **WHEN** a role switch started by the handler on another goroutine is in progress, and the handler returns before the switch's rotation is stored
- **THEN** the handler's return completes only after the switch completes, the response re-sets the cookie with the successor's identifier, and an interceptor that reads the request's session after the handler sees the successor

#### Scenario: Queued switch whose context ends
- **WHEN** a second role switch on the same request waits behind one in progress, and its context is cancelled
- **THEN** it fails with the context's error and stores nothing

## MODIFIED Requirements

### Requirement: Cookie overrides that break a guarantee fail at construction
Building a cookie chain SHALL fail with a configuration error when the cookie name is empty or not a valid cookie name, when a name without a `Domain` lacks the `__Host-` prefix, when a `__Host-` name is given a `Domain`, when a `Domain` is given with a name that lacks the `__Secure-` prefix, or when the same-site mode is `None`. The prefixes SHALL be matched in their canonical spelling only: a name that starts with `__Host-` or `__Secure-` in any other letter case SHALL fail with a configuration error naming the canonical spelling. `HttpOnly` and `Secure` SHALL have no override.

#### Scenario: Domain with a __Host- name
- **WHEN** the consumer keeps the default name and sets the domain `example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Shared domain with a __Secure- name
- **WHEN** the consumer names the cookie `__Secure-scrty-session` and sets the domain `example.com`
- **THEN** the chain builds, and the cookie is set with `Domain=example.com`

#### Scenario: Host-only name without the __Host- prefix
- **WHEN** the consumer names the cookie `sid`, or `__Secure-sid`, and sets no domain
- **THEN** construction fails with a configuration error naming the `__Host-` rule

#### Scenario: Custom __Host- name
- **WHEN** the consumer names the cookie `__Host-app` and sets no domain
- **THEN** the chain builds, and the cookie is set under that name

#### Scenario: Prefix in another letter case
- **WHEN** the consumer names the cookie `__host-app` or `__HOST-app` and sets no domain, or names it `__secure-app` and sets the domain `example.com`
- **THEN** construction fails with a configuration error naming the canonical spelling of the prefix

#### Scenario: Same-site None
- **WHEN** the consumer sets the same-site mode to none
- **THEN** construction fails with a configuration error
