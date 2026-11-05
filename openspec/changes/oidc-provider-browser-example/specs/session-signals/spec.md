## ADDED Requirements

### Requirement: A cross-site page learns nothing from the stream's answers
A page on another site SHALL NOT be able to tell, from any outcome it can observe of a request to the stream, whether the browser holds a sign-in, whether that sign-in is throttled, or whether a dependency failed. The chain SHALL NOT answer such a request with a status or body a page can tell apart.

#### Scenario: Signed in or signed out
- **WHEN** a page on another site requests the stream by `<script>`, `<img>`, `fetch` and `EventSource`, for a signed-in and a signed-out browser, in Chromium, Firefox and WebKit
- **THEN** every outcome that page can observe is the same for the two

#### Scenario: Throttled or failing
- **WHEN** the same page requests the stream while the sign-in is throttled, its cap is reached, or a dependency has failed
- **THEN** every outcome that page can observe is the same as for a signed-out browser

#### Scenario: A body that parses as a script
- **WHEN** any answer on the stream's path carries an event-stream body
- **THEN** it also carries `X-Content-Type-Options: nosniff`
