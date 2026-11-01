# Spec Delta

## MODIFIED Requirements

### Requirement: The sealed-column suite proves secrets are unusable at rest
Every durable store with sealed columns SHALL pass a sealed-column suite. Using out-of-band database access, the suite SHALL show that:
- the stored value, after undoing any text encoding, neither equals nor contains the plaintext;
- a sealed value copied into another record fails to open;
- reading with a keyring that lacks the sealing key is reported as an error, never as absence;
- a value re-sealed on read opens with a keyring holding only the active key;
- every seal and open the store makes carries the context of the store operation it serves.

The suite SHALL be shown to fail against a cipher that returns its input unchanged, and against a store that seals or opens with a context of its own.

#### Scenario: Plaintext absent from the column
- **WHEN** an MFA secret `SENTINEL-TOTP` is enrolled and its column is read out of band and decoded
- **THEN** neither the stored text nor the decoded bytes equal or contain `SENTINEL-TOTP`

#### Scenario: Pass-through cipher caught
- **WHEN** the suite runs against a store configured with a cipher that returns its input unchanged
- **THEN** the suite fails

#### Scenario: Missing key is not absence
- **WHEN** an enrolment sealed under key `k1` is read through a store whose keyring does not contain `k1`
- **THEN** the read returns an error and does not report the user as not enrolled

#### Scenario: The cipher carries the operation's context
- **WHEN** the suite writes and reads every sealed column of a store, including the passkey credential's emailed code, through a cipher that records its context, under a context carrying a value
- **THEN** every seal and open the cipher received carries that value
