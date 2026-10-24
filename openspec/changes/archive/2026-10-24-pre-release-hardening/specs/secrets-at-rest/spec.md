# Spec Delta

## MODIFIED Requirements

### Requirement: A sealed value is bound to its row
A sealed value SHALL open only for the record it was sealed for: an MFA secret for its user reference and enrolment generation, an emailed enrolment code for its user reference and enrolment generation, a session ID token for its session identifier, and a signing key's private material for its key id, each within its own table. The emailed code's binding SHALL differ from the MFA secret's, so neither opens in the other's column. Opening a value that was copied to another record or another column, moved to another table, or whose record now names a different user, generation or key id SHALL fail. Opening a value whose stored bytes were altered SHALL fail. An MFA secret sealed before its binding included the generation SHALL NOT open; the documentation SHALL state that upgrading across this change requires affected users to enrol again.

#### Scenario: Secret copied to another user's row
- **WHEN** the sealed MFA secret of user `victim` is copied, out of band, into the enrolment of user `attacker`
- **THEN** reading `attacker`'s enrolment returns an error

#### Scenario: Enrolment reassigned to another user
- **WHEN** the user reference on `attacker`'s enrolment is changed, out of band, to `victim`
- **THEN** reading `victim`'s enrolment returns an error

#### Scenario: Value moved between tables
- **WHEN** a sealed session ID token is copied, out of band, into an MFA enrolment's secret
- **THEN** reading that enrolment returns an error

#### Scenario: Emailed code copied into the secret column
- **WHEN** the sealed emailed code of user `alice` is copied, out of band, into `alice`'s secret column
- **THEN** reading `alice`'s enrolment returns an error

#### Scenario: Emailed code copied to another user's row
- **WHEN** the sealed emailed code of user `victim` is copied, out of band, into the emailed-code column of user `attacker`
- **THEN** reading `attacker`'s enrolment returns an error

#### Scenario: Emailed code carried into a new generation
- **WHEN** the sealed emailed code issued on generation G1 is copied, out of band, back onto the same user's enrolment after it moved to generation G2
- **THEN** reading the enrolment returns an error

#### Scenario: Replaced MFA secret restored
- **WHEN** `alice`'s sealed MFA secret from generation G1 is copied, out of band, back onto her enrolment after she re-enrolled as generation G2
- **THEN** reading the enrolment returns an error

#### Scenario: Tampered byte
- **WHEN** a byte in the ciphertext of a stored sealed value is changed
- **THEN** reading the record returns an error
