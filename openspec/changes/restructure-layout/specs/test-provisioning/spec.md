# Spec Delta

## ADDED Requirements

### Requirement: A test's HTTP client keeps its connections when another test's server closes
An HTTP client that a test-module helper builds SHALL send through a transport of its own, not `http.DefaultTransport`, so that another test's server shutting down cannot close its connections. The helper SHALL close that transport's idle connections when the test that built the client ends.

#### Scenario: Another server closes between two requests
- **WHEN** a helper's client has completed a request to one test server, and a second test server is then closed
- **THEN** the client's next request to the first server reuses its connection

#### Scenario: The test ends
- **WHEN** the test that built a helper's client ends
- **THEN** the client's idle connections are closed
