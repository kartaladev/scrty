## MODIFIED Requirements

### Requirement: The end-session endpoint ends the browser's sign-in without asking only on a matching hint
The end-session endpoint SHALL accept GET and form POST with `id_token_hint`, `logout_hint`, `client_id`, `post_logout_redirect_uri`, `state` and `ui_locales`. A valid hint SHALL be an ID token this provider issued, judged by its type, signature and issuer, expiry ignored, its signature judged under the algorithm its header names, which SHALL be present and equal to the algorithm recorded on the key, whose audience equals `client_id` when given. When a valid hint's `sid` names the sign-in of the browser's session, the provider SHALL end that sign-in as a logout does, without asking.

#### Scenario: Keys unavailable while judging a logout hint
- **WHEN** an end-session request carries a hint and a `post_logout_redirect_uri`, and the verification keys cannot be read
- **THEN** the failure is answered at the provider, nothing ends, and the browser is not redirected to the relying party

#### Scenario: Logout with a matching hint
- **WHEN** a relying party sends the browser to the end-session endpoint with a valid hint naming the browser session's sign-in
- **THEN** that sign-in ends, and the grants without `offline_access` from it are revoked

#### Scenario: Expired hint
- **WHEN** a matching hint is an expired ID token this provider issued
- **THEN** that sign-in ends

#### Scenario: Logout hint without an algorithm
- **WHEN** an end-session request carries, as `id_token_hint`, an ID token signed with a published key whose header carries the key's `kid` and `typ` but no `alg`
- **THEN** the hint is refused as one that fails its checks, and nothing ends without asking
