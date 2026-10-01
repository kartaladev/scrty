# Spec Delta

## ADDED Requirements

### Requirement: Unauthenticated ceremony begins are throttled per source
A flow that writes state for a caller who has not yet authenticated, such as the passwordless passkey begin, SHALL be guarded by a source guard that checks before the write and records every begin, not only failures. Its default limit SHALL be stated by the flow. A source over the limit SHALL be refused as throttled without anything being written, and an unattributable source SHALL be refused as for every guarded flow. The flow's limiter SHALL be its own unless the consumer shares one on purpose.

#### Scenario: Every begin is recorded
- **WHEN** a source makes 30 passwordless begins within 15 minutes, each issuing a challenge, and then begins again
- **THEN** the 31st begin is refused as throttled and no challenge is written

#### Scenario: Other flows unaffected
- **WHEN** a source has exhausted the passwordless begin guard and then requests a magic link, whose guard has its own limiter
- **THEN** the magic-link request is not throttled
