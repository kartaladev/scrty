## ADDED Requirements

### Requirement: A user's live sign-ins can be listed
The session manager SHALL list a user's live sign-ins, one entry per session family that has a live, non-superseded member, each with the family's identifier as its handle, when the sign-in happened, when it was last used, its first-factor kind, and its sign-in metadata when recorded. Expired and superseded members SHALL NOT be listed. The listing SHALL never contain a session identifier.

#### Scenario: Renewals are one sign-in
- **WHEN** a user signed in on two devices, and one device's session was renewed twice
- **THEN** the listing has two entries

#### Scenario: Expired sign-in
- **WHEN** one of a user's families has only expired members
- **THEN** it is not listed

### Requirement: Sign-in metadata is recorded only when the consumer opts in
By default a session SHALL record no client metadata. When the consumer opts in, a new session SHALL record the client address and the user agent the chain resolved at sign-in, truncated to a bounded length, and every successor in its family SHALL keep them. The metadata SHALL be returned unchanged by the listing, and SHALL never be written to a log by the library.

#### Scenario: Off by default
- **WHEN** metadata recording is off and a user signs in
- **THEN** the listing shows no address and no user agent for that sign-in

#### Scenario: Opted in
- **WHEN** metadata recording is on and a user signs in from 203.0.113.7 with user agent `Firefox/140`
- **THEN** the listing shows that address and user agent for the sign-in, also after it is renewed

### Requirement: A session carries its key binding through every rotation
A session SHALL be able to carry a key binding, either a DPoP key thumbprint or a certificate thumbprint, set when it is created. Every successor created by rotation, renewal or re-authentication SHALL carry the same binding. Saving a session SHALL NOT change its binding.

#### Scenario: Renewal keeps the binding
- **WHEN** a session bound to DPoP key thumbprint `K` is renewed
- **THEN** the successor is bound to `K`

#### Scenario: Save cannot unbind
- **WHEN** a copy of a bound session with its binding cleared is saved
- **THEN** the stored session is still bound

### Requirement: A user's sign-in is ended by its handle, only by its owner
Ending a sign-in by handle SHALL revoke every session of that family, and SHALL do nothing and report not found when the family does not belong to the named user. Ending every sign-in of a user except one SHALL revoke every other family of that user.

#### Scenario: Wrong owner
- **WHEN** user `u-1` asks to end the sign-in whose handle belongs to user `u-2`
- **THEN** nothing is revoked and the result is not found
