## ADDED Requirements

### Requirement: A consumer can refuse revoking what cannot be revoked
A consumer MAY choose that revoking a valid JWT access token issued to the calling client is answered 400 with `unsupported_token_type`, instead of 200 with nothing revoked. It is off by default. An unknown, expired or opaque token SHALL be answered as without the choice.

#### Scenario: Default answer
- **WHEN** a client revokes its own valid JWT access token and the consumer made no choice
- **THEN** the response is 200 and the token stays valid until it expires

#### Scenario: Consumer chooses the refusal
- **WHEN** the consumer chose the refusal, and a client revokes its own valid JWT access token
- **THEN** the response is 400 with `{"error":"unsupported_token_type"}`

#### Scenario: Unknown value with the choice
- **WHEN** the consumer chose the refusal, and a client revokes a value that is no token
- **THEN** the response is 200
