# Spec Delta

## MODIFIED Requirements

### Requirement: The cipher is replaceable
A consumer SHALL be able to supply their own cipher, such as one backed by a key management service, in place of the default. Stores SHALL use it for every seal and open, and the consumer's cipher errors SHALL propagate as store errors and fail closed.

Every seal and open SHALL carry the context of the store operation it serves, and the default cipher SHALL pass that context to its keyring. Neither the default cipher nor the default keyring performs input or output, and both SHALL answer whatever state the context is in. A cipher SHALL be able to mark a failure to reach its keys with the unavailable error. The adapter that lets a cipher seal sessions SHALL report that error as the session cipher-unavailable error, and SHALL pass context errors through unchanged.

#### Scenario: Consumer cipher used
- **WHEN** a durable session store is constructed with a consumer cipher, and a session with a provider ID token is saved and loaded
- **THEN** the consumer cipher is called once to seal and once to open, with additional data identifying that session

#### Scenario: Consumer cipher fails
- **WHEN** the consumer cipher returns an error while sealing an MFA secret
- **THEN** the enrolment returns an error wrapping it
- **AND** no enrolment is stored

#### Scenario: The cipher receives the store's context
- **WHEN** an MFA enrolment is stored and read through a consumer cipher that records its context, under a context carrying a value
- **THEN** the seal and the open each carry that value

#### Scenario: The default cipher answers under a cancelled context
- **WHEN** the default cipher seals a value and opens it again under a context that is already cancelled
- **THEN** both succeed, and the value opens to the original plaintext

#### Scenario: A marked outage reaches sessions as unavailable
- **WHEN** a session is loaded through the session adapter over a consumer cipher whose open fails with an error that wraps the unavailable error
- **THEN** the error matches the session cipher-unavailable error
- **AND** it does not match the session-unreadable error
