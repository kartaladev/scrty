# rate-limiting Specification

## Purpose

Bounds how many failed attempts a request source may make against a guessable credential. Failures are counted per canonical source rather than per presented credential, so rotating guesses or addresses within one allocation buys nothing, and the limiter fails closed whenever it cannot decide.

## Requirements

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
When a limiter cannot decide whether a key is exceeded, including because the request's context has ended, it SHALL return an error. A source guard SHALL treat that error as exceeded and refuse the attempt without making the guarded call. A shared limiter that a consumer has explicitly configured to fall back to a local count or to allow during a backend outage SHALL answer from that mode instead of returning an error, as its own requirements state.

#### Scenario: Cancelled context
- **WHEN** the in-memory limiter is checked with an already-cancelled context
- **THEN** it returns an error

#### Scenario: Consumer limiter outage
- **WHEN** a guard is configured with a consumer's shared limiter that returns a network error
- **THEN** the guard refuses the attempt as throttled

#### Scenario: Consumer chose to allow
- **WHEN** a guard is configured with a shared limiter set to allow during an outage, and its backend is unavailable
- **THEN** the guard admits the attempt and the limiter logs the outage

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

### Requirement: Unauthenticated ceremony begins are throttled per source
A flow that writes state for a caller who has not yet authenticated, such as the passwordless passkey begin, SHALL be guarded by a source guard that checks before the write and records every begin, not only failures. Its default limit SHALL be stated by the flow. A source over the limit SHALL be refused as throttled without anything being written, and an unattributable source SHALL be refused as for every guarded flow. The flow's limiter SHALL be its own unless the consumer shares one on purpose.

#### Scenario: Every begin is recorded
- **WHEN** a source makes 30 passwordless begins within 15 minutes, each issuing a challenge, and then begins again
- **THEN** the 31st begin is refused as throttled and no challenge is written

#### Scenario: Other flows unaffected
- **WHEN** a source has exhausted the passwordless begin guard and then requests a magic link, whose guard has its own limiter
- **THEN** the magic-link request is not throttled

### Requirement: A limiter factory builds every built-in flow's limiter
Every built-in throttled flow SHALL build its default limiter from a limiter factory, with its own limit, window and a fixed namespace. A flow's own limiter option SHALL take precedence over a configured factory, and a configured factory over the in-memory default. With no factory configured, each flow SHALL build an in-memory limiter of its own, logging through the component's configured logger.

#### Scenario: Default unchanged
- **WHEN** a chain is built with no factory and no per-flow limiter
- **THEN** each throttled flow uses its own in-memory limiter with its documented limit and window

#### Scenario: Consumer factory reaches every flow
- **WHEN** a chain is built with a consumer's factory and the API-key, magic-link, recovery, passwordless and second-factor flows enabled
- **THEN** the factory is asked once for each of those flows' limiters, each with that flow's namespace, limit and window

#### Scenario: Flow option wins over the factory
- **WHEN** a chain is built with a consumer's factory and an explicit API-key limiter
- **THEN** the API-key flow uses the explicit limiter and the factory is not asked for an API-key limiter

#### Scenario: Default limiter logs through the component's logger
- **WHEN** the second-factor verification throttle is built with a configured logger and no limiter
- **THEN** the in-memory limiter's per-replica warning is written through that logger

### Requirement: A shared limiter counts across instances
A shared limiter SHALL keep its counts in a backend that every instance reads, with the same window, cap and threshold semantics as the in-memory limiter. Failures recorded through one instance SHALL count when the same namespace and key are checked through any other instance.

#### Scenario: Two replicas, one limit
- **WHEN** two shared limiters over one backend and namespace, with a limit of 3, record two failures for key `k` through the first and one through the second
- **THEN** `k` is reported as exceeded through either instance

#### Scenario: Window semantics preserved
- **WHEN** a shared limiter with a 1-minute window has a failure recorded at 12:00:00 and is checked at 12:01:00
- **THEN** that failure no longer counts

### Requirement: Shared limiter namespaces keep flows apart
A shared limiter SHALL require a non-empty namespace and SHALL keep each namespace's buckets apart. Within one process, asking a factory for a namespace it has already built SHALL return a limiter over the same buckets when the limit and window match, and SHALL fail with a configuration error when they differ.

#### Scenario: Separate namespaces
- **WHEN** a source exhausts the shared limiter for namespace `api-key`
- **THEN** the same key is not exceeded in namespace `magic-link-redeem`

#### Scenario: Conflicting policy for one namespace
- **WHEN** a factory is asked for namespace `api-key` with 20 per minute and again with 5 per minute
- **THEN** the second request fails with a configuration error

#### Scenario: Empty namespace
- **WHEN** a shared limiter is constructed with an empty namespace
- **THEN** construction fails with a configuration error

### Requirement: Shared limiters fail closed and fast when the backend is unavailable
By default, when the backend errors or times out while the caller's context is live, a check SHALL report the key as exceeded with an error, and a record SHALL return an error. After such an error, checks SHALL be refused without contacting the backend until a probe interval has passed, after which one call SHALL probe the backend. Each backend call SHALL be bounded by an operation timeout.

#### Scenario: Backend down
- **WHEN** the backend is stopped and a guard checks a source through a shared limiter in its default mode
- **THEN** the attempt is refused as throttled

#### Scenario: Refusal does not wait during an outage
- **WHEN** the backend has failed once and further checks arrive within the probe interval
- **THEN** each is refused without waiting for the operation timeout

#### Scenario: Recovery after the outage
- **WHEN** the backend becomes reachable again and the probe interval has passed
- **THEN** the next check reaches the backend and its answer is used

### Requirement: A failed record never leaves a source unthrottled
When recording a failure for a key fails, a shared limiter in its default mode SHALL report that key as exceeded on this instance for one window, even if later checks reach the backend successfully. Memory held for such keys SHALL be bounded and released when their window ends.

#### Scenario: Writes fail while reads succeed
- **WHEN** the backend rejects writes for lack of memory but still answers reads, and a source keeps failing
- **THEN** after its first unrecorded failure the source is refused on that instance for one window

### Requirement: Degrading during an outage is an explicit consumer choice
A consumer SHALL be able to choose, per shared limiter, one of two overrides of the fail-closed default:
- fall back to an in-memory count with the same limit and window while the backend is unavailable, counting a failed record locally;
- allow attempts and drop records while the backend is unavailable.

Each transition into and out of degraded operation SHALL be logged. While attempts are allowed, the error-level record SHALL be sampled per namespace, once a minute by default, at an interval the consumer can change. An unknown mode SHALL be a configuration error.

#### Scenario: Fall back to a local count
- **WHEN** a shared limiter configured to fall back, with a limit of 3, loses its backend and the same source then fails 3 times on this instance
- **THEN** the source is exceeded on this instance and an error-level record says the limiter fell back

#### Scenario: Allow during an outage
- **WHEN** a shared limiter configured to allow loses its backend
- **THEN** checks report not exceeded and an error-level record is written, sampled per namespace

### Requirement: Shared limiters take time from the backend by default
A shared limiter SHALL read the current time from the backend inside each operation, so that every instance orders stamps by one clock. A consumer SHALL be able to supply an application clock instead. A nil clock SHALL be a configuration error.

#### Scenario: Skewed replica
- **WHEN** one instance's host clock runs 30 seconds fast and it records a failure that another instance checks one window later
- **THEN** the failure no longer counts

#### Scenario: Consumer clock
- **WHEN** a shared limiter is configured with an application clock, records a failure, and the clock is advanced by one window
- **THEN** the failure no longer counts

### Requirement: Expiry and eviction never disarm a shared limit
A shared limiter SHALL keep each key at least until its newest stamp leaves the longest window any instance recorded it with. A check SHALL NOT extend or shorten that lifetime. Verifying a shared limiter SHALL fail with a configuration error when the backend may evict live keys under memory pressure, and SHALL log a warning when that setting cannot be read, unless the consumer disables the check.

#### Scenario: Shorter-window instance
- **WHEN** an instance with a 15-minute window records a failure for key `k`, and an instance with a 1-minute window records another for `k` 30 seconds later
- **THEN** 10 minutes later the 15-minute instance still counts both failures

#### Scenario: Late shorter-window record
- **WHEN** an instance with a 15-minute window records a failure for key `k`, and an instance with a 1-minute window records another for `k` 14 minutes 30 seconds later
- **THEN** 10 minutes after the second failure the 15-minute instance still counts it

#### Scenario: Evicting backend
- **WHEN** a shared limiter is verified against a backend configured to evict keys under memory pressure
- **THEN** verification fails with a configuration error naming the eviction setting

#### Scenario: Consumer disables the eviction check
- **WHEN** the consumer disables the eviction check and verifies against a backend whose setting cannot be read
- **THEN** verification succeeds and no warning is written

### Requirement: Shared limiters are verified before traffic, not at construction
Constructing a shared limiter or factory SHALL perform no I/O. Verification SHALL be a separate operation that fails with a configuration error when the backend is older than the supported minimum, may evict live keys, or cannot load the limiter's operations. Constructing one with an absent backend client, including a nil value behind an interface, or with a non-positive timeout or probe interval, SHALL fail with a configuration error.

#### Scenario: Unsupported server
- **WHEN** a shared limiter is verified against a server older than the supported minimum
- **THEN** verification fails with a configuration error naming the minimum version

#### Scenario: Typed nil client
- **WHEN** a shared limiter factory is constructed with a client interface holding a nil pointer
- **THEN** construction fails with a configuration error

### Requirement: Every limiter passes the conformance suite
The in-memory limiter and every shared limiter scrty ships SHALL pass one conformance suite covering the threshold, key separation, the window boundary, boundary straddling, the newest-stamp cap, ended contexts, namespaces and concurrent use. Shared limiters SHALL also pass its cross-instance scenarios. Every scenario SHALL be seen to fail against a deliberately broken limiter.

#### Scenario: Suite against the in-memory limiter
- **WHEN** the conformance suite runs against the in-memory limiter
- **THEN** every scenario passes

#### Scenario: Suite rejects a fixed window
- **WHEN** the conformance suite runs against a fixed-window counter
- **THEN** the boundary-straddling scenario fails
