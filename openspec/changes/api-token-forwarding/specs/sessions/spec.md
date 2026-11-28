# Spec Delta

## ADDED Requirements

### Requirement: A session can carry a provider's tokens for forwarding
A session SHALL be able to record, in its creating write, a provider access token, an optional provider refresh token and the access token's expiry. These fields SHALL be owned by the library, kept apart from consumer data, and empty by default. Saving a session SHALL NOT change them.

#### Scenario: Recorded at creation
- **WHEN** a session is created with provider access token `at-1`, refresh token `rt-1` and access-token expiry 11:00:00, and is loaded
- **THEN** it carries `at-1`, `rt-1` and 11:00:00

#### Scenario: Consumer data cannot set them
- **WHEN** a consumer stores the entry `{"provider_access_token": "forged"}` in a session's consumer data
- **THEN** the session's provider access token is unchanged

#### Scenario: Save cannot change them
- **WHEN** a copy of a session holding `at-1`, its provider tokens cleared in memory, is saved
- **THEN** the stored session still carries `at-1`

### Requirement: Provider tokens are carried through every rotation
Every successor created by rotation, renewal or re-authentication SHALL carry the provider tokens its predecessor held at the time of rotation, already set on the successor handed to the caller's issuing step. A new sign-in SHALL carry only the tokens of its own sign-in.

#### Scenario: Privilege change rotates the session
- **WHEN** a session holding `at-1` and `rt-1` is rotated on a privilege change
- **THEN** the successor carries `at-1` and `rt-1`

### Requirement: Provider tokens are replaced only by a conditional write on the newest session
Replacing or clearing a session's provider tokens SHALL be a single write conditional on the session existing, not being superseded, and still holding the refresh token the caller names, or no refresh token when the caller names none. It SHALL report whether it changed the session, SHALL change nothing else, and SHALL report a superseded session distinctly from a missing one.

#### Scenario: Replace succeeds
- **WHEN** a caller replaces the tokens of a session holding `rt-1`, naming `rt-1`, with `at-2` and `rt-2`
- **THEN** the session holds `at-2` and `rt-2`, and its deadlines and other fields are unchanged

#### Scenario: Another writer won
- **WHEN** a caller names `rt-1` but the session already holds `rt-2`
- **THEN** nothing changes and the write reports that it did not apply

#### Scenario: Superseded session
- **WHEN** a caller replaces the tokens of a session that a rotation has superseded
- **THEN** nothing changes and the write reports the session as superseded

#### Scenario: Deleted session
- **WHEN** a caller replaces the tokens of a deleted session
- **THEN** the write fails with the session-not-found error and nothing is created

#### Scenario: Clearing
- **WHEN** a caller clears the tokens of a session holding `rt-1`, naming `rt-1`
- **THEN** the session holds no provider tokens and stays valid

### Requirement: A sealing store protects the provider forwarding tokens at rest
The sealing store SHALL seal a session's provider access token and provider refresh token with the configured cipher before they reach the inner store, and open them on load, under the same rules it applies to the provider ID token: bound to the session identifier, empty values unsealed, a value that cannot be opened failing the load as session-unreadable, and an outage failing it as a store failure.

#### Scenario: Sealed round trip
- **WHEN** a session holding `AT-SENTINEL` and `RT-SENTINEL` is saved through the sealing store and the inner store's record is read
- **THEN** the record contains neither sentinel, and loading through the sealing store returns both

#### Scenario: Copied to another session
- **WHEN** the sealed refresh token of session A is copied into session B's record and session B is loaded
- **THEN** the load fails with the session-unreadable error

#### Scenario: Conditional replace through the sealing store
- **WHEN** a caller replaces the tokens of a session through the sealing store, naming its current refresh token
- **THEN** the new tokens are stored sealed and the write applies

### Requirement: Provider forwarding tokens print redacted
A session's provider access token and refresh token SHALL print, format and log as a fixed redacted text under every verb, also when the session is a field of a consumer's struct.

#### Scenario: Session printed
- **WHEN** a session holding `AT-SENTINEL` is formatted with `%v`, `%+v` or `%#v` or logged as an attribute
- **THEN** the output does not contain `AT-SENTINEL`
