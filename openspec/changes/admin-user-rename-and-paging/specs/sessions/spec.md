# Spec Delta

## MODIFIED Requirements

### Requirement: A sign-in's state can be read without presenting anything
The manager SHALL answer, for a user and a family, the deadlines and authentication time of that family's current session, or that it has no live one. The read SHALL record no presentation, SHALL NOT judge or revoke anything, and SHALL read no sealed field. It SHALL follow the family across renewal and rotation. Every session store SHALL read one family on its own, so the read never depends on decoding the user's other sign-ins.

#### Scenario: After a renewal
- **WHEN** a family's session has been renewed and the grace window has passed
- **THEN** the read answers the successor's deadlines, and the family stays live

#### Scenario: After a strict rotation
- **WHEN** a family's session has been rotated strictly
- **THEN** the read answers the new session's authentication time

#### Scenario: Never presented
- **WHEN** the read finds a session never yet presented
- **THEN** no presentation is recorded

#### Scenario: Ended
- **WHEN** the family has been ended, or its current session has passed a deadline
- **THEN** the read answers not found

#### Scenario: Another user's family
- **WHEN** the read names a family that belongs to another user
- **THEN** the read answers not found

#### Scenario: A store that can read one family
- **WHEN** another sign-in of the same user holds a row the store cannot decode
- **THEN** the read answers for the family it was asked about

#### Scenario: A store that can only list
- **WHEN** a consumer's session store is supplied
- **THEN** the read is answered by that store's read of the one family, never from the user's listing
