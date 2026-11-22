# Spec Delta

## ADDED Requirements

### Requirement: A consumer-supplied metadata fetch has a deadline
When the library calls a consumer-supplied attestation metadata fetch, it SHALL pass a context that keeps the caller's values, is not cancelled when one waiting caller gives up, and carries a deadline of the outbound client's default timeout (10 seconds) from the start of the fetch.

#### Scenario: Consumer fetch that never returns
- **WHEN** a registration requiring trusted attestation triggers the consumer's metadata fetch, and that fetch waits on its context
- **THEN** the fetch's context ends 10 seconds after the fetch started, and the registration is refused with the attestation-refused refusal and nothing is stored
