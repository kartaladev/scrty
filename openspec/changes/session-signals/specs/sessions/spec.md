# Spec Delta

## ADDED Requirements

### Requirement: Ended sign-ins are reported to an optional observer
The manager SHALL accept an optional observer of ended sign-ins. With no observer it SHALL report nothing. Once a write that ends sessions has succeeded, it SHALL report the reason (`logout`, `ended`, `reuse`, `all_ended` or `provider_logout`), the user when the end names one, and either the ended family or, for a bulk end, no family plus any family kept. It SHALL carry no session identifier. An end that names neither a user nor a family is not reported.

#### Scenario: No observer
- **WHEN** no observer is configured and a session is deleted
- **THEN** the deletion succeeds and nothing is reported

#### Scenario: Family revoked on reuse
- **WHEN** an observer is configured and reuse of a superseded identifier revokes its family
- **THEN** the observer receives the user, the family and the reason `reuse`, after the revocation is stored

#### Scenario: All the user's sessions ended
- **WHEN** an observer is configured and every session of a user is deleted
- **THEN** the observer receives one report naming the user, no family, and the reason `all_ended`

#### Scenario: Every other sign-in ended
- **WHEN** an observer is configured and every session of a user but one family is deleted
- **THEN** the observer receives one report naming the user, the family kept, and the reason `all_ended`

### Requirement: An observer cannot change an end's outcome
The ended-sign-in observer SHALL be called only after the write succeeded, and a failing or panicking observer SHALL NOT change the outcome of the call that ended the sessions.

#### Scenario: Observer panics
- **WHEN** the observer panics while a session is deleted
- **THEN** the deletion still succeeds

#### Scenario: Failed write
- **WHEN** deleting a session fails in the store
- **THEN** nothing is reported

### Requirement: Expiry and sweeping are not reported as endings
A session that passes its idle or absolute deadline, and the sweeping of expired sessions, SHALL NOT be reported to the ended-sign-in observer. A deadline is known ahead of time, and is not an event.

#### Scenario: Sweep
- **WHEN** an observer is configured and the sweeper deletes expired sessions
- **THEN** the observer receives nothing
