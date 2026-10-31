# Spec Delta

## MODIFIED Requirements

### Requirement: Per-endpoint guards fail closed
Per-endpoint guards SHALL be able to require an authenticated principal, a set of resource privileges (any of, or all of) or ownership of a resource. They SHALL be enforced in addition to any centralized rule. A guard SHALL refuse without calling the route when any of these holds:
- no principal is present, refused with the authentication-required error;
- no authorizer is available, refused with the access-denied error;
- the resource identifier cannot be extracted, refused with the extractor's error;
- the authorizer refuses, refused with the authorizer's error.

A guard SHALL use the authorizer from the request context, falling back to the one it was built with. Guards SHALL be built either with an authorizer, or with an explicit option declaring that they rely on the chain's authorizer alone. Building guards with neither, including an interface holding a nil value, SHALL fail with a configuration error. An interface holding a nil value given together with that option SHALL be treated as no authorizer, never called.

#### Scenario: Missing privilege
- **WHEN** a route guarded by "any of read on admin/user" is called by a principal without that privilege
- **THEN** the route is not called and the request is refused with the access-denied error

#### Scenario: Guard on top of a permissive rule
- **WHEN** a centralized rule permits the request but the route's guard refuses it
- **THEN** the route is not called

#### Scenario: Identifier extraction fails
- **WHEN** an ownership guard's identifier extractor returns an error
- **THEN** the route is not called and the extractor's error is the refusal

#### Scenario: Guards built with no authorizer
- **WHEN** guards are built with a nil authorizer and without the option declaring reliance on the chain's authorizer
- **THEN** building them fails with a configuration error

#### Scenario: Consumer relies on the chain's authorizer
- **WHEN** guards are built with the option declaring reliance on the chain's authorizer, and a guarded route is called through a chain with authorization enabled by a principal holding the privilege
- **THEN** the guard judges with the chain's authorizer and the route is called

#### Scenario: Typed-nil authorizer beside the declared reliance
- **WHEN** guards are built with an interface holding a nil authorizer and the option declaring reliance on the chain's authorizer, and a guarded route is called where no authorizer is in the request context
- **THEN** the route is not called, the request is refused with the access-denied error, and nothing panics

#### Scenario: Declared reliance with no chain authorizer
- **WHEN** guards are built with the option declaring reliance on the chain's authorizer, and a guarded route is called where no authorizer is in the request context
- **THEN** the route is not called and the request is refused with the access-denied error
