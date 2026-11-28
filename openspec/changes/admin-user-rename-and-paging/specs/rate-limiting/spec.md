# Spec Delta

## MODIFIED Requirements

### Requirement: Built-in limiters report their limit and window
Every limiter, the in-memory limiter, every shared limiter scrty ships and a consumer's own limiter alike, SHALL report the limit and window it enforces, so that a component can derive a policy from a limiter it did not build. A shared limiter SHALL report them while its backend is unavailable.

#### Scenario: In-memory limiter
- **WHEN** an in-memory limiter built with a limit of 20 and a window of one minute is asked for its policy
- **THEN** it reports 20 and one minute

#### Scenario: Shared limiter
- **WHEN** a shared limiter built with a limit of 10 and a window of 15 minutes is asked for its policy
- **THEN** it reports 10 and 15 minutes

#### Scenario: Shared limiter with its backend down
- **WHEN** a shared limiter built with a limit of 10 and a window of 15 minutes is asked for its policy while its backend is unavailable
- **THEN** it reports 10 and 15 minutes
