# Spec Delta

## MODIFIED Requirements

### Requirement: A suspected clone at verification is not counted as a failed verification
When a method refuses a verification because the presented credential is suspected to be a clone, or is suspended, the verify endpoint SHALL return that refusal unchanged. It SHALL NOT count the refusal against the verification throttle, since it is not a wrong guess. The challenge SHALL stay pending and the handle unchanged, as for any failure, unless the refusal suspended the credential and ended the user's sessions, in which case the pending session SHALL no longer load. Every other refusal of the method SHALL still be counted.

#### Scenario: Clone at verification
- **WHEN** `u-1`'s pending session answers a passkey challenge with an assertion whose counter went backwards
- **THEN** the clone-suspected refusal is returned, no failed verification is recorded for `u-1`, and the pending session no longer loads

#### Scenario: Clone at verification with clone revocation off
- **WHEN** the passkey component keeps sessions on a clone and `u-1`'s pending session answers a passkey challenge with an assertion whose counter went backwards
- **THEN** the clone-suspected refusal is returned, no failed verification is recorded, and the challenge stays pending with the handle unchanged

#### Scenario: Wrong signature is still counted
- **WHEN** `u-1`'s pending session answers a passkey challenge with an assertion whose signature does not verify
- **THEN** the invalid second-factor code refusal is returned and a failed verification is recorded
