## MODIFIED Requirements

### Requirement: Hook refusals and failures are reported like the broker's own
A decision error that is the unlinked-identity or refused-provisioning outcome SHALL fail the login as that authentication failure. A decision error that is the UserInfo-failure outcome SHALL fail the login as that provider failure. Any other decision or apply error, and a decision naming no user, SHALL fail the login as a broker failure, and SHALL NOT be reported as any other library outcome it wraps. Each outcome passed through SHALL carry none of the hook's own error. Before an error reaches the caller or a log, the library SHALL scrub the identity's subject and email and the upstream access token from its text.

#### Scenario: Consumer refuses an inactive account
- **WHEN** the hook returns the unlinked-identity outcome because the consumer's account is inactive
- **THEN** the login fails as an unlinked identity and is reported as an authentication failure

#### Scenario: UserInfo outage inside the hook
- **WHEN** the hook reads the upstream UserInfo, the provider's UserInfo endpoint cannot be reached, and the hook returns that error
- **THEN** the login fails as a UserInfo failure, and the returned error carries none of the hook's text

#### Scenario: Hook failure
- **WHEN** the hook returns an error that is neither refusal outcome nor the UserInfo-failure outcome
- **THEN** the login fails as a broker failure and no link is inserted

#### Scenario: Apply step failure
- **WHEN** the decision is accepted and its apply step returns an error
- **THEN** the login fails as a broker failure, and the link to the decided user remains for later logins

#### Scenario: Wrapped library outcome
- **WHEN** the hook returns an error wrapping the provider-failure outcome
- **THEN** the login fails as a broker failure, not as a provider failure

#### Scenario: Secrets scrubbed from the error
- **WHEN** the hook returns an error whose text contains the identity's email and the upstream access token
- **THEN** neither the returned error's text nor any log record contains either
