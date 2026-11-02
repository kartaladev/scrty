# Spec Delta

## ADDED Requirements

### Requirement: An upstream back-channel logout also ends provider grants of the sessions it ends
When the OpenID Provider is in use, a verified back-channel logout from an upstream provider that ends sessions SHALL also end, through the provider, each ended sign-in as a logout does. Grants without `offline_access` created from those sign-ins SHALL be revoked, and the relying parties holding them SHALL be told. The back-channel response SHALL stay as it is, revealing nothing about sessions, users or grants.

#### Scenario: Upstream logout of a federated sign-in
- **WHEN** a verified upstream logout token ends sign-in `s-1`, from which `billing-web` holds a grant without `offline_access`
- **THEN** that grant's refresh token is refused with `invalid_grant`, and `billing-web` receives a logout token

#### Scenario: Offline grant survives
- **WHEN** a verified upstream logout token ends sign-in `s-1`, from which `billing-ios` holds a grant holding `offline_access`
- **THEN** that grant keeps working
