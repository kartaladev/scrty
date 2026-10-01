# Spec Delta

## ADDED Requirements

### Requirement: Federated assurance is recorded in the creating write and kept apart from consumer data
The manager SHALL let a caller record, at creation, the `amr` values and `acr` a provider asserted, and SHALL persist them in the same store write that creates the session. They SHALL be held in fields only the library writes, SHALL be carried over when the session is rotated, and SHALL NOT be stored in, or read from, consumer data. Recording them SHALL NOT change the session's second-factor state or its met-by-first-factor marker. A session created without them SHALL report none.

#### Scenario: Recorded at creation
- **WHEN** a session is created recording the OIDC first factor, `amr` `["mfa"]` and `acr` `urn:corp:loa:2`, and is then loaded
- **THEN** the loaded session reports `amr` `["mfa"]` and `acr` `urn:corp:loa:2`
- **AND** its second-factor state is none and the met-by-first-factor marker is unset
- **AND** the store received exactly one write for the creation

#### Scenario: Rotation keeps the assurance
- **WHEN** such a session is rotated after resolving an MFA challenge
- **THEN** the rotated session still reports `amr` `["mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Consumer data cannot forge assurance
- **WHEN** a consumer stores the entry `{"amr": ["mfa"]}` in the consumer data of a session created without assurance
- **THEN** the session reports no `amr`
