## ADDED Requirements

### Requirement: A sign-in's proof survives every durable store
Durable stores of pending requests, browser sessions, authorization codes, device authorizations and grants SHALL store and return unchanged a sign-in's second-factor marker and its federated evidence (provider, issuer, `amr` in order, `acr`). A record stored without them SHALL read back with no marker and no evidence. The values SHALL be stored unsealed.

#### Scenario: Grant round trip across backends
- **WHEN** a grant recording a verified second factor and the federated evidence `corp`, `https://idp.example`, `["mfa"]`, `urn:corp:loa:2` is stored through one supported backend and loaded through another
- **THEN** it loads with the same marker and evidence

#### Scenario: Code carries it to the grant
- **WHEN** an authorization code is stored with a sign-in whose second factor was verified, and is redeemed through another backend
- **THEN** the grant it makes records the verified second factor

#### Scenario: Record from before the upgrade
- **WHEN** a grant written before these values existed is loaded
- **THEN** it reads back with no marker and no evidence
