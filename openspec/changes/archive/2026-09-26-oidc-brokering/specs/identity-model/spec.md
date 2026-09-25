## MODIFIED Requirements

### Requirement: User loader contract
A user loader SHALL load user details by username and by user reference. The library SHALL pass the username, and the user reference, exactly as presented. A flow that recorded a user reference SHALL load by that reference, never by a username, because a username is a reusable handle. When no user matches, the loader SHALL return a "user not found" error that callers can identify. Any other failure SHALL be returned as an error that is not identifiable as "user not found". Details loaded by user reference SHALL carry exactly the reference asked for.

#### Scenario: Username passed unchanged
- **WHEN** a login presents the username ` Alice@Example.COM`
- **THEN** the loader receives exactly ` Alice@Example.COM`

#### Scenario: Unknown user
- **WHEN** a conforming loader is asked for a username that does not exist
- **THEN** it returns an error identifiable as "user not found"

#### Scenario: Loading by user reference
- **WHEN** a conforming loader is asked for user reference `U-1 ` of an existing user
- **THEN** it returns that user's details, whose user reference is exactly `U-1 `

#### Scenario: Unknown user reference
- **WHEN** a conforming loader is asked for a user reference that does not exist
- **THEN** it returns an error identifiable as "user not found"

#### Scenario: Reference is not case-folded
- **WHEN** a conforming loader holds user reference `u-1` and is asked for `U-1`
- **THEN** it returns an error identifiable as "user not found"
