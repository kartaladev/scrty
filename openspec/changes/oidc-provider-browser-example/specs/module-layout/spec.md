## ADDED Requirements

### Requirement: An example is a workspace module that is never published
A module under `examples/` SHALL be in the workspace and pass its format, vet, lint and vulnerability gates. It SHALL NOT be tagged, be in the release gate or the SBOM, or be imported by any other module, and it SHALL NOT import the `test` module.

#### Scenario: A guard
- **WHEN** a module under `examples/` is not on the guard's list of examples, or another module imports it
- **THEN** the layout guard fails

#### Scenario: The core's dependencies
- **WHEN** an example requires a browser driver
- **THEN** neither the core module's nor the `test` module's dependencies gain it

#### Scenario: A release
- **WHEN** the release tags and SBOM for a version are listed
- **THEN** they hold no example
