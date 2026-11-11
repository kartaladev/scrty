# Spec Delta

## ADDED Requirements

### Requirement: The password authenticator reports each verification
When given a telemetry observer, the username-and-password authenticator SHALL report each password verification as a `password.verify` operation under the context of the authentication call. The decoy verification it runs for an unknown or unusable account SHALL be reported the same way. Outcomes SHALL be unchanged, and the observer SHALL receive neither the password nor the stored hash.

#### Scenario: Wrong password
- **WHEN** a known user presents a wrong password to an authenticator given an observer
- **THEN** the observer sees one `password.verify` operation, under the call's context, ending refused, and the authentication fails as without an observer

#### Scenario: Unknown user reported like a known one
- **WHEN** an unknown username is presented
- **THEN** the observer sees one `password.verify` operation ending refused, the same as for a known user's wrong password

#### Scenario: Correct password
- **WHEN** a known user presents the right password
- **THEN** the `password.verify` operation ends in success, and nothing the observer receives contains the password or the hash
