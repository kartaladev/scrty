## ADDED Requirements

### Requirement: Removing a passkey notifies the user, by default
When a user removes one of their passkeys, the library SHALL send them a notice through the sending port, after the removal is committed, naming the passkey's label and the time, and never a credential identifier or user handle. The consumer SHALL be able to turn the notice off with an option whose name says so. A failure to send SHALL be reported as passkey binding notices are, and SHALL NOT undo the removal.

#### Scenario: Removal notice
- **WHEN** a user removes the passkey labelled `Work laptop`
- **THEN** the user receives a notice naming `Work laptop` and the time of removal

#### Scenario: Notice turned off
- **WHEN** the consumer turns the removal notice off and a user removes a passkey
- **THEN** no notice is sent and the removal succeeds
