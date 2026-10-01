# Spec Delta

## MODIFIED Requirements

### Requirement: A recovery-pending session reaches only the binding endpoints and logout
When recovery is enabled, a request whose session is in the recovery-pending state SHALL be refused with a challenge error of the account-recovery kind carrying that session. The refusal SHALL come before the password-change gate, the enrolment gate, the MFA challenge gate and any interceptor after them run, whatever the request's method or path. These requests are exempt:
- a POST under an MFA enrolment prefix, when the enrolment path is enabled;
- a POST to the passkey registration begin, finish, saved-code confirm and emailed-code confirm paths, when passkey registration is enabled;
- a POST to the password-change resolve endpoint, when one is registered;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

There SHALL be no option that lets further routes through. A capability that adds another way to bind an authenticator SHALL add its endpoint to this list in its own change. A recovery-pending session SHALL always be able to log out, and logging out SHALL end it.

The per-request policy phase SHALL still be evaluated for a recovery-pending session, and a deny SHALL refuse the request. A challenge it raises SHALL NOT be marked on the session: marking one would take the session out of the recovery-pending state without a binding.

#### Scenario: Protected route
- **WHEN** a recovery-pending session requests `/invoices`
- **THEN** it is refused with an account-recovery challenge error carrying the session, and the handler does not run

#### Scenario: Enrolment reachable
- **WHEN** the enrolment path is enabled and a recovery-pending session posts to `/mfa/enrol/begin/totp`
- **THEN** a pending enrolment is begun

#### Scenario: Passkey registration reachable
- **WHEN** passkey registration is enabled and a recovery-pending session posts to `/passkey/register/begin`
- **THEN** a registration challenge is issued

#### Scenario: Passkey listing not reachable
- **WHEN** a recovery-pending session sends a GET to `/passkey/credentials`
- **THEN** it is refused with an account-recovery challenge error

#### Scenario: Verify path is not reachable
- **WHEN** a recovery-pending session posts a code to `/mfa/verify/totp`
- **THEN** it is refused with an account-recovery challenge error and no code is verified

#### Scenario: Password change reachable
- **WHEN** the consumer registered `POST /account/password` as the resolve endpoint and a recovery-pending session posts there
- **THEN** the consumer's function runs

#### Scenario: Logout
- **WHEN** a recovery-pending session posts to the logout endpoint
- **THEN** the session is deleted, and its handle no longer loads

#### Scenario: Per-request challenge not marked
- **WHEN** a recovery-pending session of a user required to use MFA, whose enrolments were removed by the recovery, requests `/invoices`
- **THEN** the request is refused with an account-recovery challenge error
- **AND** the session is still in the recovery-pending state

## ADDED Requirements

### Requirement: The login completion step records a second factor met at the first factor
The login completion step SHALL accept, as an input, the library's proof that the login's second factor was met at its first factor, and SHALL hand it to the post-authentication policy phase. When the proof holds, the step SHALL create the session in the satisfied second-factor state with the met-by-first-factor marker, in the write that creates the session, as the `sessions` capability defines. A challenge the phase still raises, such as a password change, SHALL be marked and refused as for any login. When the proof does not hold, the step SHALL behave exactly as before. Only the library's passkey login SHALL supply a proof that holds.

#### Scenario: Satisfied at creation
- **WHEN** the passkey login hands the login completion step a user-verified login of a required user enrolled on nothing else
- **THEN** the session is created satisfied and marked as met by the first factor, and its token is returned without a challenge

#### Scenario: Other challenges still apply
- **WHEN** the same login is for a user whose password is older than the password-age policy allows
- **THEN** the login is refused with a password-change challenge carrying a session that is satisfied and owes the password change

### Requirement: Passkey endpoints plug into the chain
Enabling passkeys on the chain SHALL register the endpoints the `passkey-authentication` capability defines. The registration, saved-code confirm, emailed-code confirm, listing, rename and remove endpoints SHALL run after bearer authentication. The recovery gate, the enrolment gate and the MFA challenge gate SHALL decide, as their own requirements state, which sessions reach them. The passwordless begin and finish endpoints, when enabled, SHALL run as a first factor at a named slot of their own, after the one-time link slot and before Basic authentication. They SHALL complete the login through the login completion step, and their begin SHALL be guarded by the chain's source throttle step under the flow `passkey-login`. Flushing the chain's refusal logs SHALL flush the passkey samplers too. The passkey MFA method SHALL be served by the MFA slot like any other challenge method, with no endpoint of its own.

#### Scenario: Passwordless login reaches login completion
- **WHEN** a passwordless finish authenticates `u-1` and the policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Unattributable source at passwordless begin
- **WHEN** a passwordless begin is posted from client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error and no challenge is issued

#### Scenario: Registration needs bearer
- **WHEN** a request without a bearer credential posts to `/passkey/register/begin`
- **THEN** it is refused as authentication required
