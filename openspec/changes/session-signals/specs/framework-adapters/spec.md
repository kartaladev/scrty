# Spec Delta

## ADDED Requirements

### Requirement: Every adapter can stream a response
The framework-neutral response writer SHALL let an interceptor stream a response: each event it writes and flushes SHALL reach the client while the response stays open. The net/http, gin and fiber adapters SHALL each support it. A response writer of the consumer's own SHALL implement it, or report that it cannot stream, in which case the stream endpoint answers 501.

#### Scenario: Flushed event arrives before the response ends
- **WHEN** an interceptor writes one event, flushes, and keeps the response open, on any of the three adapters
- **THEN** the client receives the event while the response is still open

#### Scenario: Consumer adapter that cannot stream
- **WHEN** a consumer's own response writer reports that it cannot stream and a client requests the signal stream
- **THEN** the response is 501

### Requirement: A streamed response is not ended by the server's write deadline
While a response is streamed, each adapter SHALL keep a configured write deadline from ending it, by extending the deadline as each write is made. A response that is not streamed SHALL keep the deadline as configured.

#### Scenario: Stream outlives the write timeout
- **WHEN** a server on any of the three adapters has a 3-second write timeout and a stream sends a heartbeat every 5 seconds for 30 seconds
- **THEN** the stream stays open for the 30 seconds

#### Scenario: Ordinary response keeps the deadline
- **WHEN** the same server answers an ordinary request that takes longer than 3 seconds to write
- **THEN** the write deadline ends it as before

### Requirement: A streamed response learns when its client leaves
On every adapter, a streamed response SHALL learn promptly that its client has disconnected, and SHALL then stop writing and release what it holds.

#### Scenario: Client closes the tab
- **WHEN** a client with an open stream disconnects, on any of the three adapters
- **THEN** the stream stops within one heartbeat interval and its place under the stream caps is freed
