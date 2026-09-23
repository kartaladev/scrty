## Purpose

Bounds how many failed attempts a request source may make against a guessable credential. Failures are counted per canonical source rather than per presented credential, so rotating guesses or addresses within one allocation buys nothing, and the limiter fails closed whenever it cannot decide.

## ADDED Requirements

### Requirement: Limits count failures, not requests
A limiter SHALL report a key as exceeded once the key has accumulated the limit's number of recorded failures within the window. Only recorded failures SHALL count. An attempt that succeeds SHALL spend nothing. A key with exactly limit minus one failures SHALL NOT be exceeded.

#### Scenario: Reaching the limit
- **WHEN** a limiter with a limit of 3 records three failures for key `k`
- **THEN** `k` is reported as exceeded

#### Scenario: Successes never spend
- **WHEN** a source makes 100 successful attempts and then 2 failed ones through a guard with a limit of 3
- **THEN** the source is not exceeded

### Requirement: The window slides
The in-memory limiter SHALL count a failure while its timestamp is strictly later than now minus the window. Failures on either side of any fixed boundary SHALL count together while both are inside the window.

#### Scenario: Exactly one window old
- **WHEN** a limiter with a 1-minute window has a failure recorded at 12:00:00 and is checked at 12:01:00
- **THEN** that failure no longer counts

#### Scenario: Straddling a boundary
- **WHEN** a limiter with a limit of 2 and a 1-minute window records failures at 12:00:50 and 12:01:10 and is checked at 12:01:20
- **THEN** the key is exceeded

### Requirement: A limiter that cannot trip or always trips is refused at construction
Constructing the in-memory limiter with a limit or window of zero or less SHALL fail with a configuration error.

#### Scenario: Zero window
- **WHEN** an in-memory limiter is constructed with a limit of 10 and a zero window
- **THEN** construction fails with a configuration error

#### Scenario: Negative limit
- **WHEN** an in-memory limiter is constructed with a limit of -1
- **THEN** construction fails with a configuration error

### Requirement: Limiter errors fail closed
When a limiter cannot decide whether a key is exceeded, including because the request's context has ended, it SHALL return an error. A source guard SHALL treat that error as exceeded and refuse the attempt without making the guarded call.

#### Scenario: Cancelled context
- **WHEN** the in-memory limiter is checked with an already-cancelled context
- **THEN** it returns an error

#### Scenario: Consumer limiter outage
- **WHEN** a guard is configured with a consumer's shared limiter that returns a network error
- **THEN** the guard refuses the attempt as throttled

### Requirement: Sources are canonicalised before they become keys
A source keyer SHALL turn a client address into a limiter key as follows:
- an IPv4 address keys as itself;
- an IPv4-mapped IPv6 address keys as its IPv4 form;
- any other IPv6 address keys as its enclosing prefix, with any zone dropped.

The default IPv6 prefix length SHALL be 64 bits, and a consumer SHALL be able to choose another. Constructing a keyer with a prefix length outside 1 to 128 SHALL fail with a configuration error.

#### Scenario: IPv6 addresses in one /64
- **WHEN** `2001:db8:1:2::1` and `2001:db8:1:2:ffff:ffff:ffff:9` are keyed with default options
- **THEN** both key as `2001:db8:1:2::/64`

#### Scenario: Mapped IPv4
- **WHEN** `::ffff:203.0.113.7` is keyed
- **THEN** it keys as `203.0.113.7`

#### Scenario: Zone dropped
- **WHEN** `fe80::1%eth0` is keyed with default options
- **THEN** it keys as `fe80::/64`

#### Scenario: Consumer prefix
- **WHEN** a keyer configured with a 56-bit prefix keys `2001:db8:1:299::1`
- **THEN** it keys as `2001:db8:1:200::/56`, the prefix cutting within the fourth group rather than on its boundary

#### Scenario: Zero prefix
- **WHEN** a keyer is constructed with a prefix length of 0
- **THEN** construction fails with a configuration error

### Requirement: Unattributable sources are refused, not pooled
A source guard SHALL refuse, without consulting the limiter:
- an empty client address;
- a value that is not a single IP address (a port, a list or text);
- an unspecified address (`0.0.0.0`, `::`, or `::ffff:0.0.0.0` once unmapped).

Each of the three SHALL be logged as a distinct reason.

#### Scenario: Unspecified address
- **WHEN** an attempt arrives with client address `0.0.0.0`
- **THEN** the guard refuses it as unattributable without consulting the limiter
- **AND** the logged reason names an unspecified address

#### Scenario: Forwarding list passed through verbatim
- **WHEN** an attempt arrives with client address `198.51.100.1, 203.0.113.9`
- **THEN** the guard refuses it as unattributable
- **AND** the logged reason names a value that is not a single IP

#### Scenario: Empty address
- **WHEN** an attempt arrives with an empty client address
- **THEN** the guard refuses it as unattributable
- **AND** the logged reason names a missing client address

### Requirement: Guards check before and record after, on the same key
A source guard SHALL provide a check step that canonicalises the client address and consults the limiter, and a record step that counts one failure for the source the check step produced. The record step SHALL accept only a source produced by a check, so the checked key and the recorded key cannot differ. The record step SHALL count the failure even when the request's context has been cancelled. A recording error SHALL be logged and not returned.

#### Scenario: Distinct credentials from one source
- **WHEN** a guard with a limit of 3 checks and records failures for three different presented credentials from `203.0.113.7`, and a fourth attempt arrives from `203.0.113.7`
- **THEN** the fourth attempt is refused as throttled

#### Scenario: Client disconnects after its guess
- **WHEN** a guarded attempt fails and the request's context is cancelled before the failure is recorded
- **THEN** the failure is still counted

#### Scenario: Recording error
- **WHEN** the limiter fails to record a failure
- **THEN** the error is logged
- **AND** the record step returns nothing to the caller

### Requirement: Any failed guarded attempt can be recorded
The record step SHALL be available for any outcome the calling flow classifies as a failure, including a refused redemption of a credential that was itself valid. Whether such an outcome counts SHALL be decided by the calling flow, not by the guard.

#### Scenario: Refused redemption counts when the flow records it
- **WHEN** a redemption flow checks a source, finds a valid credential, refuses the redemption for a policy reason and records a failure for that source
- **THEN** the failure counts against the source like a wrong credential

### Requirement: The in-memory limiter bounds its own memory without disarming limits
The in-memory limiter SHALL:
- keep at most the limit's number of newest failures per key;
- remove keys whose newest failure has left the window, at most once per window, from within its own check and record operations, without a background goroutine;
- provide an explicit prune that follows the same rule.

Neither pruning path SHALL accept a window or cutoff from its caller, and neither SHALL remove a key whose newest failure is still inside the window.

#### Scenario: Oldest expired, newest live
- **WHEN** a key has failures at 12:00:00 and 12:00:50 with a 1-minute window, and the limiter prunes at 12:01:10
- **THEN** the key is kept and still counts one failure

#### Scenario: Inline pruning under traffic
- **WHEN** 10,000 distinct keys each record one failure and, more than one window later, any key is checked
- **THEN** the expired keys are no longer held

### Requirement: The in-memory limiter is per replica and says so
The in-memory limiter SHALL count only the failures seen by its own process, so that behind N replicas each limit is effectively multiplied by N. This SHALL be documented as a limit of the default, and the limiter SHALL write one warning saying so on first use. Any implementation of the limiter contract SHALL be usable in its place.

#### Scenario: Warned once
- **WHEN** an in-memory limiter is checked 100 times
- **THEN** exactly one per-replica warning is written

#### Scenario: Consumer shared limiter
- **WHEN** a guard is configured with a consumer's limiter
- **THEN** every check and record goes to that limiter and no per-replica warning is written

### Requirement: Guards refuse missing limiters and keep flows separate unless shared on purpose
Constructing a source guard without a limiter, including an interface holding a nil value, or without a flow name, SHALL fail with a configuration error. Guards built with separate limiters SHALL NOT share buckets. Guards given the same limiter instance SHALL share buckets, and this SHALL be documented.

#### Scenario: Typed nil limiter
- **WHEN** a guard is constructed with a limiter interface holding a nil pointer
- **THEN** construction fails with a configuration error

#### Scenario: Separate limiters
- **WHEN** a source exhausts the guard for flow `api-key` and then attempts flow `magic-link`, whose guard has its own limiter
- **THEN** the `magic-link` attempt is not throttled

### Requirement: Throttle refusal logs are sampled
A source guard SHALL write refusal records through its own log sampler with a reporter. Throttled sources SHALL be sampled per flow and source, limiter failures per flow, and unattributable sources per flow and reason. The window SHALL default to one minute and be configurable by an option that governs only that guard. A window of zero or less SHALL log every refusal. A check refused because the request's context had ended SHALL be logged at debug level without sampling.

#### Scenario: Attacker at the limit
- **WHEN** one throttled source makes 500 attempts within one minute
- **THEN** one throttle warning is written for that source in that minute
- **AND** the suppressed 499 are reported when the key ages out or the guard is flushed

#### Scenario: Consumer disables sampling
- **WHEN** a guard configured with a log interval of zero refuses 5 throttled attempts
- **THEN** 5 warnings are written

### Requirement: Limiters are safe for concurrent use
The in-memory limiter and source guard SHALL be safe for concurrent use. Checking and recording are separate steps, so a concurrent burst from one source can exceed the limit by up to the burst's concurrency. That bound SHALL be documented as a limit.

#### Scenario: Concurrent failures
- **WHEN** 64 goroutines check and record failures for overlapping keys under the race detector
- **THEN** no data race is reported
