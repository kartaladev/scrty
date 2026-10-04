## MODIFIED Requirements

### Requirement: The in-memory limiter bounds its own memory without disarming limits
The in-memory limiter SHALL:
- keep at most the limit's number of newest failures per key;
- remove keys whose newest failure has left the window, at most once per window in each independently locked part of its keys, from within its own check and record operations, without a background goroutine;
- provide an explicit prune that follows the same rule.

Neither pruning path SHALL accept a window or cutoff from its caller, and neither SHALL remove a key whose newest failure is still inside the window.

#### Scenario: Oldest expired, newest live
- **WHEN** a key has failures at 12:00:00 and 12:00:50 with a 1-minute window, and the limiter prunes at 12:01:10
- **THEN** the key is kept and still counts one failure

#### Scenario: Inline pruning under traffic
- **WHEN** 10,000 distinct keys each record one failure and, more than one window later, each of them is checked
- **THEN** the expired keys are no longer held

#### Scenario: Clock stepped backwards
- **WHEN** a limiter with a 1-minute window prunes at 12:00:00, its clock is then stepped back to 11:00:00, failures are recorded for 1,000 distinct keys at 11:00:00, and each of them is checked at 11:02:00
- **THEN** the 1,000 expired keys are no longer held

### Requirement: A limiter factory builds every built-in flow's limiter
Every built-in throttled flow SHALL build its default limiter from a limiter factory, with its own limit, window and a fixed namespace. A flow's own limiter option SHALL take precedence over a configured factory, and a configured factory over the in-memory default. With no factory configured, each flow SHALL build an in-memory limiter of its own, logging through the component's configured logger. A flow guarded by source with an IPv6 aggregate SHALL build its aggregate limiter from the same factory, under a namespace of its own.

#### Scenario: Default unchanged
- **WHEN** a chain is built with no factory and no per-flow limiter
- **THEN** each throttled flow uses its own in-memory limiter with its documented limit and window

#### Scenario: Consumer factory reaches every flow
- **WHEN** a chain is built with a consumer's factory and the API-key, magic-link, recovery, passwordless and second-factor flows enabled
- **THEN** the factory is asked once for each of those flows' limiters, each with that flow's namespace, limit and window
- **AND** once more for the aggregate limiter of each of those flows that is guarded by source, each with its own namespace

#### Scenario: Flow option wins over the factory
- **WHEN** a chain is built with a consumer's factory and an explicit API-key limiter
- **THEN** the API-key flow uses the explicit limiter and the factory is not asked for the API-key flow's own limiter

#### Scenario: Default limiter logs through the component's logger
- **WHEN** the second-factor verification throttle is built with a configured logger and no limiter
- **THEN** the in-memory limiter's per-replica warning is written through that logger

## ADDED Requirements

### Requirement: The in-memory limiter caps the keys it holds
The in-memory limiter SHALL hold at most a maximum number of keys, counting every held key until pruning removes it. The default maximum SHALL be 250,000 keys per limiter, and a consumer SHALL be able to set another. A maximum of zero or less SHALL be a configuration error.

#### Scenario: Default cap
- **WHEN** an in-memory limiter is constructed with no maximum configured
- **THEN** it holds at most 250,000 keys

#### Scenario: Consumer cap
- **WHEN** an in-memory limiter configured with a maximum of 3 keys records failures for keys `a`, `b`, `c` and then `d`
- **THEN** it holds `a`, `b` and `c` and does not hold `d`

#### Scenario: Zero cap
- **WHEN** an in-memory limiter is constructed with a maximum of 0 keys
- **THEN** construction fails with a configuration error

### Requirement: A full in-memory limiter refuses new keys and keeps counting held ones
When the in-memory limiter holds its maximum number of keys, a check of a key it does not hold SHALL report the key as exceeded with an error identifying a full limiter. Recording a failure for a key it does not hold SHALL record nothing and return that error. Checks and records of held keys SHALL behave as below the maximum. A key removed by pruning SHALL free its place. The limiter SHALL NOT remove a held key to make room.

#### Scenario: New source at the cap
- **WHEN** an in-memory limiter with a maximum of 2 keys holds `a` and `b`, and key `c` is checked
- **THEN** `c` is reported as exceeded with a full-limiter error

#### Scenario: Held source at the cap
- **WHEN** an in-memory limiter with a limit of 3 and a maximum of 2 keys holds `a` with one failure and `b`, and `a` records two more failures
- **THEN** `a` is reported as exceeded without an error

#### Scenario: Room after pruning
- **WHEN** an in-memory limiter with a maximum of 2 keys and a 1-minute window holds `a` and `b`, both failed at 12:00:00, and key `c` records a failure at 12:02:30
- **THEN** `c` is held and `a` and `b` are not

#### Scenario: Live keys are never evicted
- **WHEN** an in-memory limiter with a maximum of 2 keys holds `a` and `b` with failures inside the window, and 1,000 other keys are checked and recorded
- **THEN** `a` and `b` are still held with their failures

### Requirement: A full in-memory limiter says so
The in-memory limiter SHALL write a warning when it first finds itself holding its maximum number of keys, and at most one such warning per window after that. The warning SHALL name the maximum and state that new sources are being refused.

#### Scenario: Flood at the cap
- **WHEN** an in-memory limiter with a 1-minute window and a maximum of 10 keys is full and 500 new keys are checked within one minute
- **THEN** exactly one full-limiter warning is written in that minute

### Requirement: Guards report a full limiter as its own refusal
A source guard SHALL refuse an attempt whose check fails because the limiter is full as throttled, without making the guarded call. Its refusal record SHALL name a full limiter as the reason, apart from other limiter failures, and SHALL be sampled per flow.

#### Scenario: Full limiter behind a guard
- **WHEN** a guard's in-memory limiter is full and an attempt arrives from a source it does not hold
- **THEN** the attempt is refused as throttled
- **AND** the refusal record names a full limiter as the reason

### Requirement: Inline pruning never stalls the whole limiter
The in-memory limiter SHALL divide its keys into at least 64 independently locked parts and prune each part separately. A check or record SHALL wait only for pruning of the part holding its own key. With 1,000,000 expired keys held, the worst check or record that triggers inline pruning SHALL take at most one-thirtieth as long as pruning every key under one lock, as measured by the limiter's benchmark.

#### Scenario: One million expired keys
- **WHEN** the limiter's benchmark holds 1,000,000 expired keys and eight concurrent callers check other keys while inline pruning runs
- **THEN** no check takes more than one-thirtieth of the single-lock pruning time measured on the same machine

#### Scenario: Memory is returned after a flood
- **WHEN** 1,000,000 keys each record one failure and, more than two windows later, keys across every part are checked and the heap is collected
- **THEN** the limiter's heap use is under one-tenth of what it was at its peak

### Requirement: IPv6 sources can also be counted by an aggregate prefix
A source guard SHALL accept an optional aggregate: a prefix length and a limiter of its own. An IPv6 source SHALL then also be counted under its enclosing aggregate prefix. A check SHALL refuse as throttled when either the source or its aggregate is exceeded. A recorded failure SHALL count against both. IPv4 sources SHALL be unaffected. An aggregate prefix not wider than the source prefix, or outside 1 to 127, SHALL be a configuration error.

#### Scenario: Rotating /64s inside one aggregate
- **WHEN** a guard keyed by /64 with an aggregate of /56 whose limit is 4 records failures from `2001:db8:1:1::1`, `2001:db8:1:2::1`, `2001:db8:1:3::1` and `2001:db8:1:4::1`, and an attempt arrives from `2001:db8:1:5::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Another aggregate is unaffected
- **WHEN** the aggregate `2001:db8:1::/56` is exceeded and an attempt arrives from `2001:db8:1:100::1`, in `2001:db8:1:100::/56`
- **THEN** the attempt is not throttled

#### Scenario: IPv4 unaffected
- **WHEN** a guard with an aggregate configured checks `203.0.113.7`
- **THEN** only the source's own key is consulted

#### Scenario: Aggregate no wider than the source
- **WHEN** a guard keyed by /56 is constructed with an aggregate of /56
- **THEN** construction fails with a configuration error

### Requirement: Aggregate refusals are logged per aggregate
A refusal because an aggregate is exceeded SHALL be logged naming the aggregate prefix, and SHALL be sampled per flow and aggregate prefix, so that sources rotating inside one aggregate produce one record per sampling window.

#### Scenario: Rotation inside a throttled aggregate
- **WHEN** 50 attempts from 50 different /64s inside one exceeded /56 are refused within one minute
- **THEN** one aggregate refusal record is written for that /56 in that minute
