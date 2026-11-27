# Spec Delta

## ADDED Requirements

### Requirement: A passkey verifier may describe its options
The library SHALL accept from a passkey verifier an optional description of the shape of the registration options and the sign-in options it renders. A verifier that gives none SHALL keep working exactly as before. A description SHALL NOT change what the verifier renders or how it verifies.

#### Scenario: Verifier gives no description
- **WHEN** a consumer's passkey verifier gives no description
- **THEN** registration and sign-in behave exactly as they do today, and their options are documented as unknown

### Requirement: The WebAuthn verifier describes its options
The WebAuthn integration's verifier SHALL describe its registration options as WebAuthn credential creation options and its sign-in options as credential request options, each requiring the members that verifier always renders. No type of the WebAuthn library SHALL appear in the integration's exported API as a result.

#### Scenario: Rendered options match the description
- **WHEN** the WebAuthn verifier renders registration options for a user
- **THEN** the rendered JSON validates against the description it gives for registration options

#### Scenario: Sign-in options described
- **WHEN** the WebAuthn verifier's sign-in options description is read
- **THEN** it describes an object that requires a `challenge` member
