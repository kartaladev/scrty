# Spec Delta

## ADDED Requirements

### Requirement: The outage hold stays bounded and keeps sweeping
The in-memory hold that keeps a source throttled after a failure could not be recorded SHALL hold at most as many keys as the in-memory limiter's default key cap, SHALL hold long keys by a digest. When the hold is full, a check for a key it does not hold SHALL be answered exceeded for the rest of the window, so a full hold fails closed.

#### Scenario: Key spray during an outage
- **WHEN** a shared limiter in its default refuse mode has lost its backend and failures are recorded for 300,000 distinct 1 KB keys
- **THEN** the hold holds no more keys than the in-memory limiter's key cap, and checks for keys it does not hold are answered exceeded

### Requirement: The outage hold survives a backwards clock step
The outage hold SHALL release holds it has seen end even after the clock steps backwards. A hold that ended unobserved before a backwards step SHALL be released no later than the size of that step after its end.

#### Scenario: Clock steps backwards
- **WHEN** 1,000 holds have been seen to end and the clock then steps back by an hour
- **THEN** the next call releases them, and none answers exceeded again

#### Scenario: A hold taken after the clock steps back
- **WHEN** the clock steps back and a hold is then taken
- **THEN** that hold is released one refusal window later by the stepped clock

### Requirement: Flow names cannot collide with sources
Building a source guard SHALL fail with a configuration error when its flow name is empty or contains `:`, so that no flow and source pair can produce the same limiter key as another pair.

#### Scenario: Flow name with a colon
- **WHEN** a source guard is built with the flow name `login:2001`
- **THEN** construction fails with a configuration error
