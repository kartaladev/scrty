# Spec Delta

## MODIFIED Requirements

### Requirement: An enrolment-only session reaches only the enrolment endpoints and logout
A request whose session is in the enrolment-pending state SHALL be refused with an enrolment challenge error carrying that session, whatever its method or path, before any interceptor after the enrolment gate runs. These requests are exempt:
- a POST to a begin path, formed from the begin prefix, by default `/mfa/enrol/begin`, and an enrolling method's name;
- a POST to a confirm path, under the confirm prefix, by default `/mfa/enrol/confirm`;
- a POST to an emailed-code path, under the emailed-code prefix, by default `/mfa/enrol/confirm-email`, when email confirmation is on;
- a POST to the passkey registration begin, finish, saved-code confirm and emailed-code confirm paths, when passkey registration serves the enrolment path;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

Each enrolment prefix SHALL be replaceable by an option. There SHALL be no option that lets further routes through. The MFA verify and begin endpoints, the method-listing endpoint, the passkey listing, rename and remove endpoints and the password-change resolve endpoint SHALL be refused like any other route. A session in the enrolment-pending state SHALL always be able to log out, and logging out SHALL end it.

#### Scenario: Protected route
- **WHEN** an enrolment-only session requests `/invoices`
- **THEN** an enrolment challenge error carrying the session is returned
- **AND** the route's handler, the authorizer and any consumer interceptor after the gate do not run

#### Scenario: Verify endpoint is not reachable
- **WHEN** an enrolment-only session posts a code to `/mfa/verify/totp`
- **THEN** an enrolment challenge error is returned and no code is verified

#### Scenario: GET on an enrolment path
- **WHEN** an enrolment-only session sends a GET to `/mfa/enrol/begin/totp`
- **THEN** an enrolment challenge error is returned

#### Scenario: Passkey registration reachable
- **WHEN** passkey registration serves the enrolment path and an enrolment-only session posts to `/passkey/register/begin`
- **THEN** a registration challenge is issued

#### Scenario: Passkey listing is not reachable
- **WHEN** an enrolment-only session sends a GET to `/passkey/credentials`
- **THEN** an enrolment challenge error is returned

#### Scenario: Logout
- **WHEN** an enrolment-only session posts to the logout endpoint
- **THEN** no enrolment challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer path
- **WHEN** the begin prefix is configured as `/account/2fa/start` and an enrolment-only session posts to `/account/2fa/start/totp`
- **THEN** a pending enrolment is begun

## ADDED Requirements

### Requirement: Passkey registration serves the enrolment path when the passkey method is enrolled through it
When the enrolment path is enabled on the chain, passkey registration is enabled, and the passkey MFA method is among the path's enrolling methods, passkey registration SHALL serve the path. The passkey method is among them by default, and a consumer who names the path's methods SHALL name `passkey` to include it. An enrolment-only session SHALL then be able to register a passkey, under the path's email confirmation, confirmation limiter, notification and contact resolver, as the `passkey-authentication` capability defines. When the passkey becomes active, the session SHALL move to the MFA pending state, and the MFA verify endpoint SHALL complete the upgrade as for any enrolment through the path.

Chain assembly SHALL fail with a configuration error when the passkey method is among the path's enrolling methods but passkey registration is not enabled, because the policy would send users to a path that cannot enrol the method.

#### Scenario: Passkey through the path
- **WHEN** MFA is required for all users, the path is on with TOTP and the passkey method, and a user who has never enrolled logs in by password, registers a passkey, confirms the emailed code, and verifies the passkey at `/mfa/verify/passkey`
- **THEN** the session is a full session with a satisfied second factor

#### Scenario: Passkey method without registration
- **WHEN** the path is enabled with the passkey method among its enrolling methods and passkey registration is not enabled on the chain
- **THEN** chain assembly fails with a configuration error

#### Scenario: Consumer names TOTP only
- **WHEN** the path's enrolling methods are named as `totp` only and an enrolment-only session posts to `/passkey/register/begin`
- **THEN** an enrolment challenge error is returned

### Requirement: A suspected clone at verification is not counted as a failed verification
When a method refuses a verification because the presented credential is suspected to be a clone, or is suspended, the verify endpoint SHALL return that refusal unchanged. It SHALL NOT count the refusal against the verification throttle, since it is not a wrong guess. The challenge SHALL stay pending and the handle unchanged, as for any failure. Every other refusal of the method SHALL still be counted.

#### Scenario: Clone at verification
- **WHEN** `u-1`'s pending session answers a passkey challenge with an assertion whose counter went backwards
- **THEN** the clone-suspected refusal is returned and no failed verification is recorded for `u-1`

#### Scenario: Wrong signature is still counted
- **WHEN** `u-1`'s pending session answers a passkey challenge with an assertion whose signature does not verify
- **THEN** the invalid second-factor code refusal is returned and a failed verification is recorded
