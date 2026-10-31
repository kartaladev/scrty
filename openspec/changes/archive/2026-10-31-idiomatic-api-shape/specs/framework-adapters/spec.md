# Spec Delta

## ADDED Requirements

### Requirement: Adapter guards are built with an authorizer or a declared reliance on the chain
Building gin or fiber guards SHALL follow the core guards' construction rule. They SHALL be built either with an authorizer, or with an explicit option declaring that they rely on the chain's authorizer alone. Building them with neither, including an interface holding a nil value, SHALL fail with a configuration error. On fiber, a guard's refusal SHALL still be rendered by fiber's error handler.

#### Scenario: fiber guards built with no authorizer
- **WHEN** the consumer builds fiber guards with a nil authorizer and without the option declaring reliance on the chain's authorizer
- **THEN** building them fails with a configuration error

#### Scenario: gin guards rely on the chain
- **WHEN** the consumer builds gin guards with the option declaring reliance on the chain's authorizer, and a guarded route is called through the gin chain with authorization enabled by a principal holding the privilege
- **THEN** the guard judges with the chain's authorizer and the route runs

#### Scenario: fiber guard refusal reaches the consumer's error handler
- **WHEN** fiber guards built with an authorizer refuse a principal without the required privilege, in an app whose error handler renders its own body
- **THEN** the consumer's error handler renders the refusal
