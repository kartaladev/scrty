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

### Requirement: A writer that cannot flush is reported as unable to stream
A response writer that cannot flush, such as a consumer's wrapper hiding the underlying writer, or a server timeout handler, SHALL be reported as unable to stream, not treated as a client that left.

#### Scenario: A wrapper that hides the writer
- **WHEN** a consumer's middleware wraps the response writer with no way to reach the one beneath, and a client requests the signal stream
- **THEN** the response is 501, nothing else is written, and no reconnection loop follows

### Requirement: Starting a stream sends the response head once
Starting a stream SHALL send the status and every header set before it, on every adapter. Starting a stream after the response has begun, or a second time, SHALL fail and write nothing. Once a stream has started successfully, its body SHALL run exactly once, on an already-ended context if the chain then refused, so that what it holds is always released.

#### Scenario: Headers set before streaming are sent
- **WHEN** an interceptor sets `Cache-Control: no-store` and a CORS header, and then starts a stream, on any of the three adapters
- **THEN** the client receives both headers with the streamed response

#### Scenario: Refused after starting
- **WHEN** an interceptor refuses the request after a stream was started, on any of the three adapters
- **THEN** the client receives the refusal and no stream, and the body runs once on an already-ended context

#### Scenario: Stream after the response began
- **WHEN** an interceptor has already written a body and then starts a stream
- **THEN** starting the stream fails and nothing more is written

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

#### Scenario: Server shuts down on fiber
- **WHEN** a fiber server with an open stream shuts down
- **THEN** the stream stops, and the shutdown is not held open by it
