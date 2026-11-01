## ADDED Requirements

### Requirement: A user's live sign-ins can be listed
The session manager SHALL list a user's live sign-ins, one entry per session family that has a live, non-superseded member, each with the family's identifier as its handle, when the sign-in happened, when it was last used, its first-factor kind, whether it still owes a second factor or a recovery step, and its sign-in metadata when recorded. Expired and superseded members SHALL NOT be listed, judged by the manager's own clock. The listing SHALL never contain a session identifier or its digest. A store failure SHALL be returned as a dependency failure with fixed library text, and a failure caused by the caller's own context ending SHALL match that context's error.

#### Scenario: Renewals are one sign-in
- **WHEN** a user signed in on two devices, and one device's session was renewed twice
- **THEN** the listing has two entries

#### Scenario: Expired sign-in
- **WHEN** one of a user's families has only expired members
- **THEN** it is not listed

#### Scenario: Within the grace window
- **WHEN** a sign-in's session was renewed 5 seconds ago and its predecessor is still within its grace window
- **THEN** the sign-in is listed once, with the successor's last-use time

#### Scenario: Waiting for a second factor
- **WHEN** a user's password was entered on a new device and the second factor is still owed
- **THEN** that sign-in is listed and marked as owing a second factor

#### Scenario: Another user's sessions
- **WHEN** users `u-1` and `u-2` each have a live sign-in and `u-1`'s sign-ins are listed
- **THEN** the listing has one entry, `u-1`'s

### Requirement: Sign-in metadata is recorded only when the consumer opts in
By default a session SHALL record no client metadata. When the consumer opts in, a new session SHALL record the client address and the user agent the chain resolved at sign-in, the user agent truncated to 512 bytes at a UTF-8 character boundary, and every successor in its family SHALL keep them. An unattributable client address SHALL be recorded as absent. The metadata SHALL be returned unchanged by the listing, and SHALL never be written to a log by the library.

#### Scenario: Off by default
- **WHEN** metadata recording is off and a user signs in
- **THEN** the listing shows no address and no user agent for that sign-in

#### Scenario: Opted in
- **WHEN** metadata recording is on and a user signs in from 203.0.113.7 with user agent `Firefox/140`
- **THEN** the listing shows that address and user agent for the sign-in, also after it is renewed

#### Scenario: Long user agent
- **WHEN** metadata recording is on and a user agent of 2,000 bytes whose 512th byte falls inside a multi-byte character is recorded
- **THEN** the stored user agent is at most 512 bytes and is valid UTF-8

### Requirement: A session carries its key binding through every rotation
A session SHALL be able to carry a key binding, either a DPoP key thumbprint or a certificate thumbprint, never both, set when it is built. Every successor created by rotation, renewal or re-authentication SHALL carry the same binding, already set on the successor handed to the caller's issuing step. A re-authentication MAY set a binding on the successor of an unbound session, and SHALL NOT change or remove an existing one. Saving a session SHALL NOT change its binding or its sign-in metadata. A built session whose binding or metadata changed between building and storing SHALL NOT be stored, as for its other identity fields.

#### Scenario: Renewal keeps the binding
- **WHEN** a session bound to DPoP key thumbprint `K` is renewed
- **THEN** the successor is bound to `K`

#### Scenario: The issuing step sees the binding
- **WHEN** a session bound to `K` is rotated with a caller's issuing step
- **THEN** the successor handed to the step is already bound to `K`

#### Scenario: Save cannot unbind
- **WHEN** a copy of a bound session with its binding cleared is saved
- **THEN** the stored session is still bound

#### Scenario: Binding changed after building
- **WHEN** a caller builds a session bound to `K`, changes its binding to `K2`, and stores it
- **THEN** storing fails with a configuration error and nothing is stored

#### Scenario: Re-authentication cannot rebind
- **WHEN** a session bound to `K` is rotated by a re-authentication that asks for binding `K2`
- **THEN** the rotation fails with a configuration error and nothing is stored

### Requirement: A user's sign-in is ended by its handle, only by its owner
Ending a sign-in by handle SHALL revoke every session of that family, and SHALL do nothing and report not found when the handle is malformed, names no family, or names a family that does not belong to the named user. Ending every sign-in of a user except the current one SHALL revoke every other family of that user and keep the current family's live members, including a successor a racing renewal inserted. Ending the current sign-in by its own handle SHALL revoke it as a logout does.

#### Scenario: Wrong owner
- **WHEN** user `u-1` asks to end the sign-in whose handle belongs to user `u-2`
- **THEN** nothing is revoked and the result is not found

#### Scenario: Malformed handle
- **WHEN** user `u-1` asks to end the sign-in with handle `not-a-family`
- **THEN** nothing is revoked and the result is not found

#### Scenario: Others ended during a renewal
- **WHEN** user `u-1` ends every sign-in except the current one while the current sign-in is being renewed
- **THEN** the current sign-in's successor survives and every other family is revoked

#### Scenario: Ending the current sign-in
- **WHEN** user `u-1` ends the sign-in whose handle is the current request's family
- **THEN** that family is revoked, and the current session no longer loads
