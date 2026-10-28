# Spec Delta

## ADDED Requirements

### Requirement: A call can stage an outage without a server of its own
A PostgreSQL or Redis helper call that asks for an outage-capable connection SHALL get one on the shared server, and SHALL start no container for it. Its connection SHALL support stop, hang and start. By default a call gets a direct connection, which has no hang.

#### Scenario: Many outage-capable calls, one server
- **WHEN** ten tests in one process each ask the PostgreSQL helper for an outage-capable connection with the default image
- **THEN** one PostgreSQL container is started for that process, and each test still gets a database of its own

#### Scenario: A broken-variant child stages an outage
- **WHEN** a child test process that inherits its parent's PostgreSQL server asks for an outage-capable connection
- **THEN** no container is started by the child

#### Scenario: A real outage is still available
- **WHEN** a call asks for a restartable server of its own instead
- **THEN** stopping it stops that server's container, as before

### Requirement: Stopping an outage-capable connection cuts off only that call
Stopping an outage-capable connection SHALL close every connection the call has open to its server and refuse new ones, until the call starts it again. Starting it SHALL make the server reachable again at the same address, with the call's data intact. Other calls on the same server SHALL be unaffected throughout.

#### Scenario: Stopped
- **WHEN** a test stops its outage-capable connection and then runs a query through it
- **THEN** the query fails with a connection error, and a query by another test on the same server succeeds

#### Scenario: Started again
- **WHEN** the test inserts a row, stops the connection, starts it again and reads the row through a new connection to the same address
- **THEN** the read returns the row

### Requirement: Hanging an outage-capable connection stops answers without closing connections
Hanging an outage-capable connection SHALL keep the call's connections open and accept new ones, while nothing the call sends is answered, until the call starts it again. Requests sent while hung SHALL then be answered. Other calls on the same server SHALL be unaffected throughout.

#### Scenario: A request while hung
- **WHEN** a test hangs its connection and sends a query with a 250 ms deadline
- **THEN** the query fails at its deadline rather than with a closed connection, and a query by another test on the same server succeeds

#### Scenario: Answers resume
- **WHEN** a test hangs its connection, sends a query with no deadline, and starts the connection again
- **THEN** the query completes with its result

### Requirement: An outage-capable call cleans up whatever state its test left it in
A call's teardown SHALL run as for any other call even when its test ends with the connection stopped or hung: the per-call teardown checks run and the call's database is removed. A connection left stopped or hung SHALL NOT by itself fail the test.

#### Scenario: Test ends with the connection stopped
- **WHEN** a test that applied a migration set ends with its outage-capable connection stopped
- **THEN** the set is rolled back, the database is removed, and the test passes

### Requirement: Contradictory outage requests fail at the call
A call SHALL fail its test before starting anything when it asks for an outage-capable connection together with a server of its own. Hanging a connection that is not outage-capable SHALL fail the test. Stopping, hanging or starting a server shared with other calls SHALL fail the test.

#### Scenario: Outage-capable and own server
- **WHEN** a call asks for an outage-capable connection and a server of its own
- **THEN** the test fails naming both options, and no container is started

#### Scenario: Hang without the proxy
- **WHEN** a test hangs a direct connection to the shared server
- **THEN** the test fails, and the shared server keeps answering other tests

### Requirement: Every Redis call gets a database of its own
Each call of the Redis test helper SHALL return a client on a logical database no other concurrent call holds. The database SHALL be empty when handed out and SHALL be emptied at the call's cleanup. When every database of a server is held, one more call SHALL fail its test rather than share one.

#### Scenario: Two parallel calls
- **WHEN** two parallel tests on the same server each set the same key to different values
- **THEN** each reads back its own value

#### Scenario: Every database in use
- **WHEN** a call arrives while every logical database of its server is held by another call
- **THEN** that call fails its test, naming the server

### Requirement: Redis calls in one process share a server per image and start-up flags
Redis helper calls in one test process with the same image and the same start-up flags, in the same order, SHALL share one server, started on the first such call. A call with another image or other flags SHALL get another server. A call that asks for a server of its own SHALL get one that no other call shares, removed when its test ends.

#### Scenario: Same flags, one server
- **WHEN** three tests in one process call the Redis helper with the default image and the flags `--maxmemory-policy allkeys-lru`
- **THEN** one Redis container with that policy is started for them, and each test gets a database of its own on it

#### Scenario: Other flags, other server
- **WHEN** one call passes `--maxmemory-policy allkeys-lru` and another `--maxmemory-policy noeviction`
- **THEN** each reads back its own policy from its server

#### Scenario: A call asks for a server of its own
- **WHEN** a call passes start-up flags and asks for a server of its own
- **THEN** it gets a server no other call shares, and that server is removed when the call's test ends
