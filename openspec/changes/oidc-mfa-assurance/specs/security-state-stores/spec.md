# Spec Delta

## ADDED Requirements

### Requirement: Asserted federated assurance survives a durable store
Durable handoff and session stores SHALL store and return unchanged the asserted `amr` values, in order, and the asserted `acr`. A record stored without them SHALL read back with an empty list and an empty `acr`. The values SHALL be stored unsealed.

#### Scenario: Handoff round trip across backends
- **WHEN** a handoff record carrying `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2` is stored through one supported backend and redeemed through another
- **THEN** the redeemed record carries `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Session round trip across backends
- **WHEN** a federated session recording `amr` `["mfa"]` and `acr` `urn:corp:loa:2` is saved through one supported backend and loaded through another
- **THEN** it loads with `amr` `["mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Nothing asserted
- **WHEN** a password session is saved and loaded
- **THEN** it loads with an empty `amr` list and an empty `acr`
