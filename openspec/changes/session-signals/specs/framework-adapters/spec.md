# Spec Delta

## ADDED Requirements

### Requirement: Every adapter can flush a response
The framework-neutral response writer SHALL let an interceptor flush what it has written, so that it reaches the client before the request ends. The net/http, gin and fiber adapters SHALL each support it. A response writer of the consumer's own SHALL implement it too.

#### Scenario: Flushed event arrives before the response ends
- **WHEN** an interceptor writes one event, flushes, and keeps the response open, on any of the three adapters
- **THEN** the client receives the event while the response is still open

### Requirement: A streamed response is not ended by the server's write deadline
While a response is streamed, each adapter SHALL keep a configured write deadline from ending it, by extending the deadline as each write is made. A response that is not streamed SHALL keep the deadline as configured.

#### Scenario: Stream outlives the write timeout
- **WHEN** a net/http server has a 5-second write timeout and a stream sends a heartbeat every 2 seconds for 30 seconds
- **THEN** the stream stays open for the 30 seconds

#### Scenario: Ordinary response keeps the deadline
- **WHEN** the same server answers an ordinary request that takes longer than 5 seconds to write
- **THEN** the write deadline ends it as before

### Requirement: A streamed response learns when its client leaves
On every adapter, a streamed response SHALL learn promptly that its client has disconnected, and SHALL then stop writing and release what it holds.

#### Scenario: Client closes the tab
- **WHEN** a client with an open stream disconnects, on any of the three adapters
- **THEN** the stream stops within one heartbeat interval and its place under the stream caps is freed
