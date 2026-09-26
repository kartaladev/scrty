## MODIFIED Requirements

### Requirement: Authentication refusal logs are bounded and never carry the password
The password provider SHALL write its refusal log records through the log sampler: one record per refusal reason per window, with a reporter so every suppressed record is counted. Log records SHALL NOT contain the submitted password, and SHALL NOT contain the submitted username unless the consumer opts in by an option whose documentation states that users type email addresses, and sometimes passwords, into that field. A user loader failure SHALL be recorded as the diagnostic-redaction capability requires, without its text. The default window SHALL be one minute, configurable by an option that governs only the password provider's logs. A window of zero or less SHALL log every refusal.

#### Scenario: Default sampling
- **WHEN** 50 unknown-username attempts arrive within one minute
- **THEN** one refusal record is written for that minute
- **AND** the 49 suppressed attempts are reported when the key ages out or the provider's logs are flushed

#### Scenario: Consumer disables sampling
- **WHEN** the provider is configured with a log interval of zero and 50 unknown-username attempts arrive
- **THEN** 50 refusal records are written

#### Scenario: Username withheld by default
- **WHEN** an unknown username `alice@example.com` is refused
- **THEN** the refusal record names the reason and does not contain `alice@example.com`

#### Scenario: Consumer opts in
- **WHEN** the provider is configured to include usernames and an unknown username `alice` is refused
- **THEN** the refusal record contains `alice`
