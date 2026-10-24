# Spec Delta

## MODIFIED Requirements

### Requirement: Memory stays bounded
The sampler SHALL retain counts only for keys seen in the current window and the window immediately before it, whatever the size of the key space. Within one window it SHALL hold at most 100,000 keys by default, replaceable by an option. An event for a new key when the window is full SHALL be counted under one overflow key, written at most once per window, and reported like any other suppressed count, so no event goes unaccounted.

#### Scenario: Unbounded key space
- **WHEN** one million distinct keys each send one event, and then after more than two windows one further event arrives
- **THEN** the sampler retains counts for at most that one further key

#### Scenario: Key spray within one window
- **WHEN** one million distinct keys each send one event within a single window
- **THEN** the sampler holds at most 100,000 keys plus the overflow key, and the overflow key's count accounts for every event it absorbed

#### Scenario: Consumer capacity
- **WHEN** the consumer sets the per-window capacity to 10,000
- **THEN** the sampler holds at most 10,000 keys plus the overflow key within a window
