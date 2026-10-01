# Spec Delta

## ADDED Requirements

### Requirement: A recovery-pending session reaches only the binding endpoints and logout
When recovery is enabled, a request whose session is in the recovery-pending state SHALL be refused with a challenge error of the account-recovery kind carrying that session. The refusal SHALL come before the password-change gate, the enrolment gate, the MFA challenge gate and any interceptor after them run, whatever the request's method or path. These requests are exempt:
- a POST under an MFA enrolment prefix, when the enrolment path is enabled;
- a POST to the password-change resolve endpoint, when one is registered;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

There SHALL be no option that lets further routes through. A capability that adds a way to bind an authenticator, such as passkey registration, SHALL add its endpoint to this list in its own change. A recovery-pending session SHALL always be able to log out, and logging out SHALL end it.

The per-request policy phase SHALL still be evaluated for a recovery-pending session, and a deny SHALL refuse the request. A challenge it raises SHALL NOT be marked on the session: marking one would take the session out of the recovery-pending state without a binding.

#### Scenario: Protected route
- **WHEN** a recovery-pending session requests `/invoices`
- **THEN** it is refused with an account-recovery challenge error carrying the session, and the handler does not run

#### Scenario: Enrolment reachable
- **WHEN** the enrolment path is enabled and a recovery-pending session posts to `/mfa/enrol/begin/totp`
- **THEN** a pending enrolment is begun

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

### Requirement: A password change resolved on a recovery-pending session completes the recovery
When the consumer's function at the password-change resolve endpoint succeeds for a recovery-pending session, the chain SHALL restore the session's deadlines as the `sessions` capability defines, set its second-factor state to none, clear any pending password-change marker, and save it. The consumer's function SHALL own the response, as for any resolution. The session SHALL NOT be rotated, because it was created by the recovery for this caller and has no earlier holder. The documentation SHALL state this. The security policies SHALL then decide on the next request what the session owes, such as an MFA challenge or an enrolment. A failure of the consumer's function SHALL leave the session recovery-pending.

#### Scenario: Password route
- **WHEN** a recovery-pending session resolves a password change successfully, and then requests `/invoices`
- **THEN** the request reaches the handler, provided no policy challenges it

#### Scenario: Password route for a required user
- **WHEN** the same happens for a user required to use MFA with no usable enrolment, and the enrolment path is on
- **THEN** the next request is refused with an enrolment challenge

#### Scenario: Function fails
- **WHEN** the consumer's function fails for a recovery-pending session
- **THEN** its error is the refusal and the session stays recovery-pending

### Requirement: Recovery endpoints plug into the chain
Enabling recovery on the chain SHALL register the endpoints the `account-recovery` capability defines, each answering POST on its own path, except the code listing, which also answers GET:
- start: `/recovery/start`, only when issued codes are enabled;
- complete: `/recovery/complete`;
- finish: `/recovery/finish` and cancel: `/recovery/cancel`, only when a hold is configured;
- saved codes: `/recovery/codes`, only when saved codes are enabled.

Each path SHALL be replaceable by an option. The start and complete endpoints SHALL be guarded by the chain's source throttle step, each under a flow of its own, using the chain's client address, refusal rules and sampled logs, so an unattributable address is refused as for every throttled flow. Flushing the chain's refusal logs SHALL flush the recovery endpoints' samplers too. When a hold is configured, the chain's login completion step SHALL cancel the user's held recovery after the first factor succeeds and before the session is created, and a failure to cancel SHALL refuse the login.

#### Scenario: Consumer path
- **WHEN** the complete path is set to `/account/recover` and two valid proofs are posted there
- **THEN** the recovery succeeds

#### Scenario: Unattributable source
- **WHEN** a recovery is posted from client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error and no proof is checked

#### Scenario: Magic-link login cancels a held recovery
- **WHEN** a recovery of `u-1` is held and `u-1` then signs in by magic link
- **THEN** the held recovery is cancelled

### Requirement: The cool-down guard runs after authentication
When the recovery cool-down is enabled, the chain SHALL register its guard after bearer authentication, so it sees the session's user. It SHALL act only on the requests the consumer marked, each marked by method and exact path. It SHALL let requests without a session through for later interceptors to decide.

#### Scenario: Unauthenticated marked request
- **WHEN** a request without a session posts to a marked route
- **THEN** the cool-down guard does not refuse it, and authorization decides
