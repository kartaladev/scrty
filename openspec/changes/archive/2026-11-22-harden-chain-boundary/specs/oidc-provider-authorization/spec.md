## MODIFIED Requirements

### Requirement: An ID token hint must name the user who signs in
When a request carries `id_token_hint`, the provider SHALL accept it only if it is an ID token this provider issued, judged by its type, signature and issuer, with its expiry ignored. The signature SHALL be judged under the algorithm its header names, which SHALL be present and equal to the algorithm recorded on the key. A hint that fails those checks under a key the provider still publishes SHALL be answered with `invalid_request`. When the user of the browser session or the resumed sign-in is not the hint's subject, the provider SHALL answer with a redirect carrying `error=login_required`.

#### Scenario: Another user signs in
- **WHEN** a request carries a valid hint for user `u-1`, and the resume presents a sign-in of user `u-2`
- **THEN** the browser is redirected with `error=login_required`

#### Scenario: Silent request with a matching hint
- **WHEN** a request carries `prompt=none` and a hint for the browser session's user, and consent is not needed
- **THEN** a code is issued, and the ID token carries the same `sub`

#### Scenario: Keys unavailable while judging a hint
- **WHEN** a request with a valid client and redirect URI carries a hint, and the verification keys cannot be read
- **THEN** the browser is redirected to the redirect URI with `error=server_error` and the request's `state`, and nothing is parked

#### Scenario: Access token offered as a hint
- **WHEN** a request carries an access token this provider issued as `id_token_hint`
- **THEN** it is answered with `invalid_request`

#### Scenario: Hint without an algorithm
- **WHEN** a request carries an ID token signed with a key the provider publishes, whose header carries the key's `kid` and `typ` but no `alg`, as `id_token_hint`
- **THEN** it is answered with `invalid_request`
