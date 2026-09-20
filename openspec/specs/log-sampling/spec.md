# log-sampling Specification

## Purpose

Keeps a flood of repeated events, such as refusals driven by an attacker or an outage, from flooding a log sink, by writing at most one record per key per window while still accounting for every event it suppressed.

## Requirements

### Requirement: One written record per key per window
For each key, the first event in a window SHALL be marked for writing, and every later event for the same key in the same window SHALL be marked as suppressed. Different keys SHALL NOT affect each other. Windows SHALL have a fixed length, starting at the first event the sampler sees.

#### Scenario: Repeated events for one key
- **WHEN** five events for key `a` arrive within one window
- **THEN** the first is marked for writing
- **AND** the other four are marked as suppressed

#### Scenario: Independent keys
- **WHEN** an event for key `a` and then an event for key `b` arrive within one window
- **THEN** both are marked for writing

### Requirement: A written record carries the count suppressed before it
When an event is marked for writing, the sampler SHALL report how many events for the same key were suppressed since that key's previous written record and were not already reported by an eviction report. Suppressed events SHALL report a count of zero.

#### Scenario: Count carried into the next window
- **WHEN** four events for key `a` are suppressed in one window and the next event for `a` arrives in the following window
- **THEN** that event is marked for writing with a suppressed count of 4

#### Scenario: Nothing suppressed
- **WHEN** an event for key `a` arrives in a window after a window in which only one event for `a` arrived
- **THEN** it is marked for writing with a suppressed count of 0

### Requirement: Every suppressed event is accounted for exactly once when a reporter is configured
When an eviction reporter is configured, every suppressed event SHALL be counted exactly once, either in a later written record's suppressed count or in an eviction report. A key whose suppressed count would otherwise be discarded, because the key did not recur before its counts aged out, SHALL be passed to the reporter with that count. Keys with nothing suppressed SHALL NOT be reported.

#### Scenario: Key goes quiet
- **WHEN** three events for key `a` are suppressed in one window, no event for `a` arrives in the next window, and an event for any key arrives after that
- **THEN** the reporter receives key `a` with count 3
- **AND** a later event for `a` is marked for writing with a suppressed count of 0

#### Scenario: Long silence drops both windows
- **WHEN** events for keys `a` and `b` are suppressed, and the next event of any kind arrives more than two windows later
- **THEN** the reporter receives each of `a` and `b` once with its suppressed count

#### Scenario: Totals balance
- **WHEN** a random sequence of events across many keys and window boundaries is sampled and then flushed
- **THEN** the sum of all suppressed counts on written records plus all counts passed to the reporter equals the number of events marked as suppressed

### Requirement: Flushing reports everything pending
The sampler SHALL provide a flush operation. Flushing SHALL pass every pending, unreported suppressed count to the reporter and then forget all keys, so the next event for any key is marked for writing with a suppressed count of 0.

#### Scenario: Flush at shutdown
- **WHEN** two events for key `a` are suppressed and the sampler is flushed before the window ends
- **THEN** the reporter receives key `a` with count 2
- **AND** the next event for `a` is marked for writing with a suppressed count of 0

#### Scenario: Flush without a reporter
- **WHEN** a sampler with no reporter is flushed
- **THEN** all keys are forgotten and no error or panic occurs

### Requirement: Without a reporter, aged-out counts are a documented lower bound
When no reporter is configured, a suppressed count that ages out before its key recurs SHALL be discarded, and the suppressed count on written records SHALL therefore be a lower bound. This is the default, and SHALL be documented as such.

#### Scenario: Count discarded without a reporter
- **WHEN** a sampler with no reporter suppresses three events for key `a`, and the next event for `a` arrives more than two windows later
- **THEN** that event is marked for writing with a suppressed count of 0

### Requirement: Memory stays bounded
The sampler SHALL retain counts only for keys seen in the current window and the window immediately before it, whatever the size of the key space.

#### Scenario: Unbounded key space
- **WHEN** one million distinct keys each send one event, and then after more than two windows one further event arrives
- **THEN** the sampler retains counts for at most that one further key

### Requirement: Sampling can be disabled
A sampler configured with a window of zero or less, and an absent (nil) sampler, SHALL mark every event for writing with a suppressed count of 0, and SHALL never call a reporter.

#### Scenario: Zero window
- **WHEN** a sampler with a zero window receives five events for key `a`
- **THEN** all five are marked for writing with a suppressed count of 0

#### Scenario: Absent sampler
- **WHEN** an event is sampled through a nil sampler
- **THEN** it is marked for writing with a suppressed count of 0

### Requirement: A clock moving backwards cannot extend suppression
When an event's timestamp is earlier than the start of the current window, the sampler SHALL move the window start back to that timestamp without starting a new window, so the current window ends no later than one window length after the backwards timestamp.

#### Scenario: Backwards step
- **WHEN** with a one-minute window, an event for key `a` arrives at 12:00:30, the clock steps back and an event for `a` arrives at 12:00:00, and a third event for `a` arrives at 12:01:00
- **THEN** the second event is suppressed
- **AND** the third event is marked for writing

### Requirement: Safe for concurrent use and re-entrant reporters
The sampler SHALL be safe for concurrent use from multiple goroutines. The reporter SHALL be called synchronously on the goroutine whose sampling or flush call triggered the report, and SHALL NOT be called while the sampler holds internal state, so a reporter may itself sample or flush without deadlocking.

#### Scenario: Concurrent sampling
- **WHEN** 64 goroutines sample events for overlapping keys at the same time under the race detector
- **THEN** no data race is reported and the totals-balance property holds

#### Scenario: Reporter samples an event
- **WHEN** the reporter, while handling a report, samples an event for key `summary`
- **THEN** the call returns normally without deadlock
