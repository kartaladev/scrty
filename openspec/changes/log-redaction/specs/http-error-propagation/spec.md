## MODIFIED Requirements

### Requirement: Refusal errors are a stable public contract
The library SHALL expose distinguishable public refusal errors for at least these cases:
- authentication required;
- malformed login;
- request too large.

A refusal a core already names SHALL be reported as that core's own error rather than restated under a second name. In particular, a policy that denies without giving a reason SHALL be reported as the security-policy capability's reasonless-deny error, because the policy engine already substitutes it: a second sentinel for the same condition would be unreachable, and a consumer matching one identity would miss the other. Where this capability's own refusal and a core's name the same condition, the chain SHALL wrap the core's with its own so that either identity matches.

It SHALL also expose one challenge error type, and SHALL map the refusal errors that the authentication, authorization, session, security-policy and second-factor cores define. A challenge error SHALL carry its challenge kind, the pending session when one exists, and the access token issued with it when one was issued. No refusal error's text SHALL contain an access token, a session handle or a submitted credential. A refusal caused by a consumer-supplied dependency SHALL carry fixed library text, with the dependency's error reachable by identity and type, as the diagnostic-redaction capability requires; this SHALL NOT change the status it maps to.

#### Scenario: Challenge error contents
- **WHEN** form login is challenged for a second factor
- **THEN** the challenge error carries the second-factor kind, the pending session and the token

#### Scenario: Challenge text carries no secret
- **WHEN** a challenge error carrying a token is converted to text
- **THEN** the text names the challenge kind and contains neither the token nor the session handle

#### Scenario: Challenge raised on a later request
- **WHEN** the password-change gate refuses a session
- **THEN** the challenge error carries the session and no token

#### Scenario: Dependency text stays out of the refusal
- **WHEN** a login is refused because the attempt store failed with an error quoting `alice@example.com`
- **THEN** the refusal's text does not contain `alice@example.com`, and it still maps to the status it mapped to before
