# Spec Delta

## ADDED Requirements

### Requirement: The reuse guard reports its password work
When given a telemetry observer, the reuse guard SHALL report each history check as a `password.verify` operation, and the hashing of an accepted new password as a `password.hash` operation, each under the context of the call. Its decisions and results SHALL be unchanged. The observer SHALL receive neither the candidate password nor any hash.

#### Scenario: Reused password
- **WHEN** a candidate matches the second stored hash in the history
- **THEN** the observer sees `password.verify` operations under the call's context, and the guard refuses the candidate exactly as without an observer

#### Scenario: Accepted change
- **WHEN** a candidate matches no stored hash and the change is written
- **THEN** the observer sees one `password.hash` operation end in success, and nothing it receives contains the candidate or a hash
