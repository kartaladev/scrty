# Spec Delta

## ADDED Requirements

### Requirement: Ended sign-ins are reported to an optional observer
The manager SHALL accept an optional observer of ended sign-ins. With no observer it SHALL report nothing. Once a write that ends sessions has succeeded, it SHALL report the reason (`logout`, `ended`, `reuse`, `all_ended` or `provider_logout`), the user when the end names one, and either the ended family or, for a bulk end, no family plus any family kept. It SHALL carry no session identifier, and an end that names neither a user nor a family is not reported.

#### Scenario: No observer
- **WHEN** no observer is configured and a session is deleted
- **THEN** the deletion succeeds and nothing is reported

#### Scenario: Logout
- **WHEN** an observer is configured and a session of user `u-1` is deleted at logout
- **THEN** the observer receives `u-1`, the session's family and the reason `logout`, and no session identifier

#### Scenario: One sign-in ended
- **WHEN** an observer is configured and user `u-1` ends one of their sign-ins from another device
- **THEN** the observer receives `u-1`, that sign-in's family and the reason `ended`

#### Scenario: Sessions from one provider ended
- **WHEN** an observer is configured and user `u-1`'s sessions from one identity provider are ended
- **THEN** the observer receives one report naming `u-1`, no family, and the reason `provider_logout`

#### Scenario: Back-channel logout names no user
- **WHEN** an observer is configured and sessions are ended by a provider's session identifier alone
- **THEN** the observer receives nothing

#### Scenario: Family revoked on reuse
- **WHEN** an observer is configured and reuse of a superseded identifier revokes its family
- **THEN** the observer receives the user, the family and the reason `reuse`, after the revocation is stored

#### Scenario: All the user's sessions ended
- **WHEN** an observer is configured and every session of a user is deleted
- **THEN** the observer receives one report naming the user, no family, and the reason `all_ended`

#### Scenario: Every other sign-in ended
- **WHEN** an observer is configured and every session of a user but one family is deleted
- **THEN** the observer receives one report naming the user, the family kept, and the reason `all_ended`

#### Scenario: Every session but one ended
- **WHEN** an observer is configured and every session of a user but one named session is deleted
- **THEN** the observer receives one report naming the user, the kept session's family, the reason `all_ended`, and no session identifier

### Requirement: A kept session is reported by its family
Where an end spares one session, the report SHALL name that session's family as kept, never the session.

#### Scenario: Kept session named by family
- **WHEN** an observer is configured and every session of a user but one named session is deleted
- **THEN** the report names the kept session's family, and no session identifier

### Requirement: An observer cannot change an end's outcome
The ended-sign-in observer SHALL be called only after the write succeeded, and a failing or panicking observer SHALL NOT change the outcome of the call that ended the sessions.

#### Scenario: Observer panics
- **WHEN** the observer panics while a session is deleted
- **THEN** the deletion still succeeds

#### Scenario: Failed write
- **WHEN** deleting a session fails in the store
- **THEN** nothing is reported

### Requirement: Observers keep the caller's values and can be combined
The ended-sign-in observer SHALL be called with the caller's context values but not its cancellation. The consumer SHALL be able to combine several observers into one, each called in turn, and a panic in one SHALL NOT keep the next from being called.

#### Scenario: Caller hangs up
- **WHEN** an observer is configured and the caller's context is cancelled just as a session is deleted
- **THEN** the observer is still called once the deletion succeeds

#### Scenario: One of two combined observers panics
- **WHEN** two observers are combined, the first panics, and a session is deleted
- **THEN** the deletion succeeds and the second observer is still called

### Requirement: Expiry and sweeping are not reported as endings
A session that passes its idle or absolute deadline, and the sweeping of expired sessions, SHALL NOT be reported to the ended-sign-in observer. A deadline is known ahead of time, and is not an event.

#### Scenario: Sweep
- **WHEN** an observer is configured and the sweeper deletes expired sessions
- **THEN** the observer receives nothing
