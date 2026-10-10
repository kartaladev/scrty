## MODIFIED Requirements

### Requirement: A PostgreSQL limiter refuses a policy too large for one row
Constructing a PostgreSQL limiter, or asking a PostgreSQL factory for a limiter, with a limit above 400, or a namespace longer than 64 bytes, SHALL fail with a configuration error naming the maximum. Both maximums SHALL be documented. A key longer than 512 bytes SHALL be stored as a fixed-length digest, as for every shared limiter.

#### Scenario: Limit above the maximum
- **WHEN** a PostgreSQL limiter is constructed with a limit of 401
- **THEN** construction fails with a configuration error naming 400

#### Scenario: Namespace above the maximum
- **WHEN** a PostgreSQL factory is asked for a limiter with a 65-byte namespace
- **THEN** the request fails with a configuration error naming 64

#### Scenario: Limit at the maximum
- **WHEN** a PostgreSQL limiter is constructed with a limit of 400 and records 400 failures for key `k`
- **THEN** `k` is reported as exceeded

#### Scenario: Default chain builds over a PostgreSQL factory
- **WHEN** the default HTTP security chain, with password login and the default IPv6 aggregate enabled, is built over the limiter factory of either PostgreSQL backend
- **THEN** construction succeeds
- **AND** the chain's IPv6 aggregate limiter counts to its full limit of 200

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

#### Scenario: Temporary table shadows the migration's
- **WHEN** the session's connection has a temporary table with the limiter's table name, which resolves before the migration's, and the limiter is verified
- **THEN** verification fails with a configuration error naming a temporary table
- **AND** the error does not advise making the table logged

## ADDED Requirements

### Requirement: A PostgreSQL limiter refuses a database that is not UTF-8
Verifying a PostgreSQL limiter, or its factory, SHALL fail with a configuration error naming the database's server encoding when that encoding is not UTF-8, SQL_ASCII included. There SHALL be no override. The godoc of both PostgreSQL factories SHALL state that the database must be UTF-8.

#### Scenario: Single-byte encoding
- **WHEN** a PostgreSQL limiter is verified against a database whose server encoding is LATIN1
- **THEN** verification fails with a configuration error naming LATIN1

#### Scenario: SQL_ASCII
- **WHEN** a PostgreSQL limiter factory is verified against a database whose server encoding is SQL_ASCII
- **THEN** verification fails with a configuration error naming SQL_ASCII

#### Scenario: Multi-byte encoding
- **WHEN** a PostgreSQL limiter is verified against a database whose server encoding is EUC_JP
- **THEN** verification fails with a configuration error naming EUC_JP

#### Scenario: UTF-8 database
- **WHEN** a PostgreSQL limiter is verified against a UTF-8 database where every other check passes
- **THEN** verification succeeds

### Requirement: A PostgreSQL prune holds a record for at most one batch
A PostgreSQL prune SHALL remove idle keys in batches, each committed on its own, so that a record on a key the prune is removing waits no longer than one batch. The default batch SHALL be 1,000 keys. A factory option SHALL set the batch size, and a size below 1 SHALL be a configuration error. A key recorded while the prune runs SHALL be kept.

#### Scenario: Record during a large prune
- **WHEN** the prune runs over at least 100,000 idle keys with the default batch size, while records with an operation timeout of 250 milliseconds are made on keys the prune is removing, with the records' connections already open
- **THEN** no record waits on a lock the prune holds for as long as its timeout
- **AND** every key so recorded is kept

#### Scenario: The bound's limit is documented
- **WHEN** a consumer reads the documentation of the prune and of the batch-size option
- **THEN** it states that on an overloaded server one batch can outlast the operation timeout, and that a record behind it then fails as unavailable

#### Scenario: Consumer sets the batch size
- **WHEN** a factory built with a prune batch size of 2 prunes 5 idle keys
- **THEN** all 5 keys are removed and the prune reports 5 keys removed

#### Scenario: Invalid batch size
- **WHEN** a PostgreSQL limiter factory is built with a prune batch size of 0
- **THEN** construction fails with a configuration error

### Requirement: A failed PostgreSQL prune reports a partial count and no server text
When a PostgreSQL prune fails or is cancelled part way, the batches it already committed SHALL stay removed, and it SHALL return the number of keys they removed together with the error. The error SHALL repeat none of the database server's message text, and a cancellation or deadline SHALL remain distinguishable from a failure.

#### Scenario: Failure after a committed batch
- **WHEN** a prune with a batch size of 2 over 5 idle keys commits its first batch and its second batch fails
- **THEN** the prune returns 2 keys removed with an error, and those 2 keys stay removed

#### Scenario: Server message withheld
- **WHEN** a prune fails with a database error whose message contains a distinctive value
- **THEN** the returned error's text does not contain that value

#### Scenario: Cancelled prune
- **WHEN** the prune's context is cancelled between batches
- **THEN** the returned error is recognised as a cancellation
