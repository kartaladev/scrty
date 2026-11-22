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

### Requirement: The breach check is opt-in and its failure mode is the consumer's choice
When the consumer enables the breach check, the policy SHALL refuse a candidate found in the breach corpus. It SHALL send only the first five hexadecimal characters of the candidate's SHA-1 hash, with response padding requested, through the confined outbound client, and SHALL match the rest locally, ignoring entries whose count is zero, which are padding. Enabling the check SHALL require the consumer to choose whether a failed lookup refuses or accepts the candidate; construction SHALL fail without that choice. A failed lookup SHALL include a timeout, a non-success status, and a body that does not parse. The lookup source SHALL be replaceable, so an offline copy of the corpus can be used. When the request's own context ends during the lookup, the check SHALL fail with an error matching the context's error, whichever failure mode was chosen. A lookup failure the policy accepts SHALL be logged at error level, with fixed text and the failure's type, never the candidate, its hash, its prefix or the failure's text, so a screen that has stopped screening is visible; the record SHALL go to the consumer's logger when one is configured, else to the logger of the chain handling the request, else to the process default logger as it stands when the record is written, and a nil logger SHALL fail construction. A hang-up SHALL log nothing at error level. The local match SHALL compare hash suffixes without regard to case, so a source that lists them in lower case is still matched.

#### Scenario: Breached password
- **WHEN** the breach check is enabled and the corpus lists the candidate's hash with a count of 3
- **THEN** the candidate is refused as breached

#### Scenario: Padding entry
- **WHEN** the breach check is enabled and the range response lists the candidate's hash suffix only with a count of 0
- **THEN** the candidate is not refused as breached

#### Scenario: Lookup outage, refuse
- **WHEN** the breach check is enabled with failures refusing and the lookup times out
- **THEN** the check fails with the lookup-unavailable error, which is not a password refusal

#### Scenario: Lookup outage, accept
- **WHEN** the breach check is enabled with failures accepting and the lookup answers 429
- **THEN** the breach rule accepts the candidate, the next rule runs, and one error-level record names the failed breach lookup without the candidate, its hash or its prefix

#### Scenario: Chain logger
- **WHEN** the breach check accepts on failure, no logger is configured for the policy, and the lookup fails during a request handled by a chain configured with the consumer's logger
- **THEN** the record goes to the chain's logger and not to the default one

#### Scenario: Consumer logger
- **WHEN** the breach check accepts on failure, the consumer supplies its own logger, and the lookup fails
- **THEN** the record goes to the consumer's logger and not to the default one

#### Scenario: Lower-case source
- **WHEN** the breach check uses a consumer source that lists the candidate's hash suffix in lower case with a count of 3
- **THEN** the candidate is refused as breached

#### Scenario: Malformed response
- **WHEN** the breach check is enabled with failures refusing and the range response is not lines of suffix and count
- **THEN** the check fails with the lookup-unavailable error

#### Scenario: Failure mode not chosen
- **WHEN** the breach check is enabled without a failure mode
- **THEN** construction fails with a configuration error naming the breach check

#### Scenario: Only the prefix leaves the process
- **WHEN** the breach check looks up a candidate
- **THEN** the outbound request carries only the five-character prefix and `Add-Padding: true`, and neither the candidate nor its full hash
