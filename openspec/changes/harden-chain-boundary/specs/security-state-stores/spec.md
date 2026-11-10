# Spec Delta

## ADDED Requirements

### Requirement: Store work detached from the caller has a deadline
Every call the library makes on a request path to a store or an outbound service under a context detached from the caller's cancellation SHALL carry a deadline. Where the call has no bound of its own, the deadline SHALL be 10 seconds for a revocation of a session, a session family or a credential, and 5 seconds otherwise. A call that reaches its deadline SHALL be handled as that call's store error is handled.

#### Scenario: Hung store on a detached TOTP refund
- **WHEN** a TOTP verification's attempt is refunded after the client has hung up, and the store never answers
- **THEN** the refund's call is given a deadline no more than 5 seconds away, and the request returns once it passes

#### Scenario: Reuse-triggered revocation
- **WHEN** a reused session triggers the revocation of its family under a detached context
- **THEN** the revocation's call is given a deadline no more than 10 seconds away

#### Scenario: Detached write past its deadline
- **WHEN** a detached store write reaches its deadline
- **THEN** the outcome is the one the same write gives on a store error

### Requirement: Some detached work is bounded by its owner, not the library
The library SHALL NOT add a deadline to detached calls to the rate-limiter port, whose contract makes the limiter bound itself, or to consumer callbacks (session end observers, the event sink). The rollback or close of a transaction the same call opened, and the long-lived context of a background loop or queue, SHALL keep their existing bounds.

#### Scenario: Limiter record not cut short
- **WHEN** a failed second factor is recorded against a rate limiter that takes 7 seconds to answer
- **THEN** the library does not cut the record short, and the guess is charged
