## RENAMED Requirements

- FROM: `### Requirement: Send logs carry no message body`
- TO: `### Requirement: Send logs carry no message body and no recipient`

## MODIFIED Requirements

### Requirement: Send logs carry no message body and no recipient
Logs written by the built-in senders SHALL NOT contain the message body, the recipient address, or the text of a delivery failure, which a mail server's reply routinely quotes the recipient in. A failure record SHALL name the stage that failed and the error's type, as the diagnostic-redaction capability requires.

#### Scenario: Failed delivery of a sign-in link
- **WHEN** delivery of a message whose body contains a sign-in link fails
- **THEN** no written log record contains the link

#### Scenario: Recipient rejected
- **WHEN** an SMTP server rejects the recipient with `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** no written log record contains `alice@example.com`
