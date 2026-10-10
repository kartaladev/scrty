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
- **WHEN** an in-memory limiter with a maximum of 2 keys and a 1-minute window holds `a` and `b`, both failed at 12:00:00, the limiter prunes at 12:02:00, and key `c` records a failure at 12:02:30
- **THEN** `c` is held and `a` and `b` are not

#### Scenario: Live keys are never evicted
- **WHEN** an in-memory limiter with a maximum of 2 keys holds `a` and `b` with failures inside the window, and 1,000 other keys are checked and recorded
- **THEN** `a` and `b` are still held with their failures

### Requirement: A full in-memory limiter says so
The in-memory limiter SHALL write a warning when it first refuses a key because it holds its maximum number of keys, and at most one such warning per window after that. The warning SHALL name the maximum and state that new sources are being refused.

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

### Requirement: Built-in limiters report their limit and window
The in-memory limiter and every shared limiter scrty ships SHALL report the limit and window they were built with, through an optional contract a consumer's limiter MAY also implement, so that a component can derive a policy from a limiter it did not build.

#### Scenario: In-memory limiter
- **WHEN** an in-memory limiter built with a limit of 20 and a window of one minute is asked for its policy
- **THEN** it reports 20 and one minute

#### Scenario: Shared limiter
- **WHEN** a shared limiter built with a limit of 10 and a window of 15 minutes is asked for its policy
- **THEN** it reports 10 and 15 minutes

### Requirement: A PostgreSQL limiter shares counts through the security-state database
scrty SHALL provide a shared limiter, and a limiter factory, on the `database/sql` and pgx backends; a gorm consumer SHALL use the `database/sql` one over its connection's underlying handle. It SHALL keep its counts in a table of the security-state migration set, with the window, cap, threshold, namespace, unavailable-mode, clock and policy-reporting behaviour required of every shared limiter. It SHALL pass the conformance suite, cross-instance scenarios included, on both backends and every supported PostgreSQL version.

#### Scenario: Two replicas over one database
- **WHEN** two PostgreSQL limiters over one database and namespace, with a limit of 3, record two failures for key `k` through the first and one through the second
- **THEN** `k` is reported as exceeded through either instance

#### Scenario: Backends share one table
- **WHEN** a failure for key `k` is recorded through the limiter of one supported backend, and `k` is checked through the limiter of another supported backend over the same database and namespace
- **THEN** the failure counts

#### Scenario: gorm consumer
- **WHEN** a consumer using the gorm backend builds the `database/sql` limiter factory over the gorm connection's underlying handle
- **THEN** its limiters count across instances like any other PostgreSQL limiter

#### Scenario: Database time by default
- **WHEN** one instance's host clock runs 30 seconds fast and it records a failure that another instance checks one window later
- **THEN** the failure no longer counts

### Requirement: A PostgreSQL limiter refuses a policy too large for one row
Constructing a PostgreSQL limiter, or asking a PostgreSQL factory for a limiter, with a limit above 128, or a namespace longer than 64 bytes, SHALL fail with a configuration error naming the maximum. Both maximums SHALL be documented. A key longer than 512 bytes SHALL be stored as a fixed-length digest, as for every shared limiter.

#### Scenario: Limit above the maximum
- **WHEN** a PostgreSQL limiter is constructed with a limit of 129
- **THEN** construction fails with a configuration error naming 128

#### Scenario: Namespace above the maximum
- **WHEN** a PostgreSQL factory is asked for a limiter with a 65-byte namespace
- **THEN** the request fails with a configuration error naming 64

#### Scenario: Limit at the maximum
- **WHEN** a PostgreSQL limiter is constructed with a limit of 128 and records 128 failures for key `k`
- **THEN** `k` is reported as exceeded

### Requirement: A PostgreSQL limiter ignores the caller's transaction
A PostgreSQL limiter SHALL perform every check and record on the database handle it was constructed with, and SHALL NOT join a transaction the caller attached or a configured transaction resolver would supply. A failure recorded while the caller's transaction is open SHALL count whether that transaction commits or rolls back.

#### Scenario: Failure survives the request's rollback
- **WHEN** a caller attaches its own transaction, a guarded attempt fails and records a failure through a PostgreSQL limiter, and the caller rolls back
- **THEN** the failure still counts

### Requirement: A PostgreSQL limiter reads and writes only the primary
A PostgreSQL limiter's verification SHALL fail with a configuration error when its connection is to a server in recovery, when the server is older than the oldest supported PostgreSQL major, when the limiter's table does not exist or is not logged, or when the limiter's own check, record and prune statements cannot run there. Its godoc SHALL require a handle that reaches the primary.

#### Scenario: Standby
- **WHEN** a PostgreSQL limiter is verified against a server in recovery
- **THEN** verification fails with a configuration error naming the standby

#### Scenario: Missing table
- **WHEN** a PostgreSQL limiter is verified against a database where the security-state migration set has not been applied
- **THEN** verification fails with a configuration error naming the migration set

#### Scenario: Missing privilege
- **WHEN** a PostgreSQL limiter is verified through a role that may read the limiter's table but not write it
- **THEN** verification fails with a configuration error naming the refused operation

#### Scenario: Unlogged table
- **WHEN** an operator has altered the limiter's table to unlogged and the limiter is verified
- **THEN** verification fails with a configuration error naming the unlogged table

### Requirement: A PostgreSQL record does not wait on a held row past its timeout
A record through a PostgreSQL limiter SHALL give up waiting for a row lock held by another session within its operation timeout, and the server SHALL stop waiting too, so that a held row cannot queue records behind it. Such a give-up SHALL be treated as the backend being unavailable.

#### Scenario: Row held by another session
- **WHEN** another session holds the row of key `k` locked, and a record for `k` is made with an operation timeout of 250 milliseconds
- **THEN** the record returns an error within about 250 milliseconds
- **AND** the server no longer has a session waiting for that row

### Requirement: The PostgreSQL limiter prunes idle keys through an expiry task
A PostgreSQL limiter factory SHALL provide a prune that deletes, across every namespace in its table, only keys whose newest failure is older than the longest window any instance recorded the key with, as measured by the limiter's time source. It SHALL skip rows another session holds rather than wait for them, and SHALL report how many keys it removed. The prune SHALL accept no window or cutoff from its caller.

#### Scenario: Longest recorded window protects a key
- **WHEN** an instance with a 15-minute window records a failure for key `k`, an instance with a 1-minute window records another 30 seconds later, and the prune runs 10 minutes after that
- **THEN** `k` is kept and the 15-minute instance still counts both failures

#### Scenario: Idle key removed
- **WHEN** an instance with a 1-minute window recorded the only failure for key `k` at 12:00:00, and the prune runs at 12:01:30
- **THEN** `k` is removed and the prune reports one key removed

#### Scenario: Locked row skipped
- **WHEN** another session holds the row of an idle key locked while the prune runs
- **THEN** the prune completes without waiting and keeps that key
