# Spec Delta

## ADDED Requirements

### Requirement: An opt-in endpoint lists the methods a pending session can use
The chain SHALL offer an endpoint that lists the MFA methods the session's user can use. It SHALL be off by default, and SHALL exist only when the consumer enables it on the MFA slot. It SHALL answer GET requests to its path, `/mfa/methods` by default, and SHALL NOT read the URL query. It SHALL answer only a session whose MFA challenge is pending:
- a request with no session SHALL be refused as authentication required;
- a session that owes no MFA challenge, including a fully authenticated one, SHALL be refused as no MFA challenge pending;
- an enrolment-only session SHALL be refused by the enrolment gate like any other route.

The list SHALL come from the one function the security policies use to decide usability, so it can never disagree with the MFA challenge or the policies. A failed lookup SHALL be a refusal, never an empty list. By default the endpoint SHALL answer with a documented JSON body naming each method's name, channel and whether it has a begin step; a consumer SHALL be able to replace the response through a responder. The endpoint's path and responder SHALL be settable only inside the option that enables it, and an explicitly given empty path or absent responder SHALL be refused rather than read as the default. Chain assembly SHALL fail with a configuration error when the endpoint's path is empty or equals the logout path or a path under the MFA verify or begin prefixes.

#### Scenario: Off by default
- **WHEN** the MFA slot is enabled without the listing option and a pending session sends GET `/mfa/methods`
- **THEN** no listing is produced by the library

#### Scenario: Pending session lists its methods
- **WHEN** the listing is enabled, TOTP and `email-code` are configured, `u-1` is enrolled on TOTP only, and `u-1`'s pending session sends GET `/mfa/methods`
- **THEN** the response is the default JSON body listing `totp` only

#### Scenario: A full session is refused
- **WHEN** the listing is enabled and a session whose second factor is satisfied sends GET `/mfa/methods`
- **THEN** it is refused as no MFA challenge pending

#### Scenario: No session
- **WHEN** the listing is enabled and a request without a session sends GET `/mfa/methods`
- **THEN** it is refused as authentication required

#### Scenario: Lookup failure
- **WHEN** the listing is enabled and a method's enrolment lookup fails for a pending session
- **THEN** the request is refused with that failure and no list is written

#### Scenario: Consumer path and responder
- **WHEN** the listing is enabled with path `/account/mfa/methods` and a responder that writes its own document, and a pending session sends GET there
- **THEN** the consumer's responder writes the response with the same list

#### Scenario: Explicit empty path
- **WHEN** the listing is enabled with an explicitly empty path
- **THEN** construction fails with a configuration error

#### Scenario: Path collides with a verify path
- **WHEN** the listing path is set to `/mfa/verify/totp`
- **THEN** chain assembly fails with a configuration error
