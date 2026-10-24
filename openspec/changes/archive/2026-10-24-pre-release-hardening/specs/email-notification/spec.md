# Spec Delta

## MODIFIED Requirements

### Requirement: Message content is encoded faithfully
The SMTP sender SHALL send the plain-text body as UTF-8 with CRLF line endings. A bare carriage return, a bare line feed and a CRLF in the body SHALL each become one CRLF, so no bare carriage return reaches the transfer. It SHALL encode a subject containing non-ASCII characters so that it arrives unchanged. It SHALL add no header naming scrty or any product.

#### Scenario: Non-ASCII subject
- **WHEN** a message with subject `Masuk ke akun Anda — tautan` is delivered to a test SMTP server
- **THEN** the received message's decoded subject is exactly `Masuk ke akun Anda — tautan`

#### Scenario: Bare line feeds normalised
- **WHEN** a message whose body contains `line one\nline two` is delivered
- **THEN** the received body separates the lines with CRLF

#### Scenario: Bare carriage returns normalised
- **WHEN** a message whose body contains `hello\r.\r\nMAIL FROM` is delivered
- **THEN** the transfer carries no bare carriage return, and the body's lines are separated by CRLF with the leading dot escaped

#### Scenario: No product header
- **WHEN** any message is delivered through the SMTP sender
- **THEN** no received header value contains `scrty`
