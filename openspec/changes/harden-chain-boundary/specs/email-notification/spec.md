# Spec Delta

## ADDED Requirements

### Requirement: A send the caller ended reports the caller's context error
When an SMTP send fails after the caller's context has ended, the send's error SHALL match that context's error (`context.Canceled` or `context.DeadlineExceeded`) and SHALL keep the underlying network error. Such a send SHALL NOT be logged as a failed send at error level. A caller's deadline SHALL count as passed once the clock has reached it, even before the context reports it. A send that fails on the sender's own deadline while the caller's context is live SHALL keep reporting a timeout.

#### Scenario: Cancelled while waiting for the greeting
- **WHEN** the caller's context is cancelled while the server is waiting to greet
- **THEN** the send's error matches `context.Canceled`, and no error-level record is written

#### Scenario: Sender's own deadline
- **WHEN** the sender's deadline passes while the caller's context is live
- **THEN** the send fails with a timeout that does not match the context errors
