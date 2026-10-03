## ADDED Requirements

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

## MODIFIED Requirements

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
