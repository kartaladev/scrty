## ADDED Requirements

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
