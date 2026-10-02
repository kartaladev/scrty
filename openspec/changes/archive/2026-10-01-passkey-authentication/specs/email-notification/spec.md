# Spec Delta

## ADDED Requirements

### Requirement: Passkey notices are sent through the sending port
The passkey component SHALL send every notice it owes through the library's sending port, never through a channel of its own: the binding notice, the removal notice, the suspected-clone notice and the emailed confirmation code. It SHALL require a sender that declares itself non-blocking, such as the queued sender, unless the consumer explicitly accepts synchronous delivery. A notice the sender refuses to queue SHALL be logged without its body or recipient. Only the emailed confirmation code SHALL fail its request when it cannot be queued, because the user cannot complete the step without it. Every other notice's failure SHALL leave the operation that caused it standing.

#### Scenario: Queued notice
- **WHEN** a passkey is suspended as a suspected clone, with a queued sender wrapping a slow SMTP sender
- **THEN** the login refusal returns without waiting for delivery, and the notice is delivered

#### Scenario: Refused notice is logged without its content
- **WHEN** the queue is full when a binding notice is sent to `ana@example.com`
- **THEN** an error record is written that contains neither the notice's body nor `ana@example.com`
- **AND** the passkey stays active
