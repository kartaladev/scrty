# Spec Delta

## ADDED Requirements

### Requirement: Limiters charge and refund atomically
Every limiter scrty ships SHALL offer a charge and a refund. A charge SHALL, in one indivisible step, either report the key at its limit and change nothing, or record one failure and report the key below its limit, so concurrent charges never hold more failures in the window than the limit. A refund SHALL remove the one failure its charge recorded while that failure is in the window. A charge that cannot be decided SHALL return an error, which a caller treats as a refusal.

#### Scenario: Concurrent charges stop at the limit
- **WHEN** 64 goroutines charge one key concurrently against a limit of 5
- **THEN** exactly five charges report the key below its limit, and the key holds five failures in the window

#### Scenario: A refund returns the allowance
- **WHEN** a key holds four failures under a limit of 5, a fifth charge succeeds, and that charge is refunded
- **THEN** the next charge for the key reports it below its limit

#### Scenario: A refund after the window removes nothing
- **WHEN** a charge's failure has left the window and the charge is then refunded
- **THEN** no other failure held for the key is removed

#### Scenario: Suite covers charging
- **WHEN** the conformance suite runs against the in-memory limiter and each shared limiter
- **THEN** the concurrent-charge and refund scenarios pass; the concurrent-charge scenario fails against a limiter whose charge checks and records in two separate steps, and each refund scenario fails against a limiter whose refund removes the wrong failures

### Requirement: A flow that must hold its limit under concurrency charges first
A flow whose limit must hold under concurrent attempts SHALL charge its limiter before the guarded work and refund the charge when the attempt succeeds. The source guards SHALL keep their separate check and record, and their documented burst bound.

#### Scenario: Saved-code presentation charges first
- **WHEN** a saved recovery code is presented for `u-1`
- **THEN** the limiter is charged for `u-1` before the code is looked up, and the charge is refunded when the code is valid

#### Scenario: Source guards keep their burst bound
- **WHEN** a source guard checks a source and later records its failure
- **THEN** it uses the limiter's separate check and record, as before
