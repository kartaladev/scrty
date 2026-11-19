## MODIFIED Requirements

### Requirement: The policy fails closed and keeps no credential
A history read or retire failure SHALL refuse the change with the history-unavailable error and SHALL NOT call the consumer's write.
- An error from the consumer's write SHALL be returned unchanged when its chain can be walked.
- When the chain cannot be walked, the library's fixed error SHALL be returned in its place, as the http-error-propagation capability requires.

The policy SHALL write no log record that contains the candidate, a hash or a context word, and SHALL NOT keep the candidate after the call returns.

#### Scenario: Retire failure
- **WHEN** the history port reads successfully but fails to retire the current hash
- **THEN** the change is refused with the history-unavailable error and the consumer's write is not called

#### Scenario: Unwalkable write error
- **WHEN** the consumer's write returns an error whose chain contains itself
- **THEN** the change returns the library's fixed error without hanging, and no log record contains the candidate or a hash
