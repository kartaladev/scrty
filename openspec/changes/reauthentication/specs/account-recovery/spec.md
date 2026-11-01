# Spec Delta

## MODIFIED Requirements

### Requirement: A held recovery is cancelled by the user
While a recovery is held, the user's existing authenticators and sessions SHALL stay valid. It SHALL be cancelled by:
- the cancel link, redeemed at the cancel endpoint, `/recovery/cancel` by default, with a POST;
- any login of the user that completes a first factor through the chain's login completion step;
- a password re-authentication of a session of the user, once its password is proved.

Cancellation and completion SHALL each be one conditional write on a pending record, so of a racing cancel and finish at most one SHALL succeed. A cancelled recovery SHALL NOT complete. When a held recovery has spent a saved code, the user's remaining saved set SHALL be voided when the hold starts, and the hold's notice SHALL say that it was, so a cancelled recovery leaves no code of that set usable whichever way it was cancelled. A login or password re-authentication that cannot record the cancellation SHALL be refused rather than let the recovery stand.

#### Scenario: Login cancels
- **WHEN** a recovery of `u-1` is held and `u-1` then logs in with their password
- **THEN** the finish is later refused as a recovery-refused error

#### Scenario: A password re-authentication cancels
- **WHEN** a recovery of `u-1` is held and a session of `u-1` re-authenticates with the password
- **THEN** the finish is later refused as a recovery-refused error

#### Scenario: Cancel link
- **WHEN** the cancel link is redeemed while the recovery is held
- **THEN** the finish is later refused, and `u-1`'s saved set is void if a saved code was spent

#### Scenario: A hold voids the saved set
- **WHEN** a recovery of `u-1` presenting a saved code is held
- **THEN** no code of `u-1`'s saved set is usable while the hold runs, and the hold's notice says the set was voided

#### Scenario: Racing cancel and finish
- **WHEN** a cancel and a finish of the same held recovery run at the same time after its hold
- **THEN** exactly one of them succeeds

#### Scenario: Cancellation store outage at login
- **WHEN** a recovery of `u-1` is held, and `u-1` logs in while the recovery store fails
- **THEN** the login is refused

#### Scenario: Cancellation store outage at re-authentication
- **WHEN** a recovery of `u-1` is held, and a session of `u-1` re-authenticates with the password while the recovery store fails
- **THEN** the re-authentication is refused and the session is unchanged

### Requirement: Regenerating codes needs a recent authentication and notifies the user
The endpoint that regenerates a user's set SHALL answer POST requests on its path, `/recovery/codes` by default, and SHALL be answered only for a full session: one with no pending challenge of any kind. It SHALL refuse with a reauthentication-required error unless the session's latest authentication is within the freshness window. The latest authentication is the session's authentication time, as the `sessions` capability records it: the sign-in, a satisfied second factor or a re-authentication, whichever is latest. The window SHALL be 15 minutes by default, replaceable by an option, and a window of zero or less SHALL fail construction. On success it SHALL return the new codes once, through a replaceable responder, and SHALL notify the user at their contact address. The notice SHALL name the time and SHALL contain no code. The notice SHALL NOT be sent through a sender that delivers synchronously, unless the consumer explicitly accepts synchronous delivery. A GET on the same path SHALL answer any full session with the remaining count and whether it is low, and SHALL NOT return a code.

#### Scenario: Fresh session regenerates
- **WHEN** a session created at 09:00 posts to `/recovery/codes` at 09:10
- **THEN** a new set is returned once, the previous set is void, and a notice is queued to the user

#### Scenario: Stale session
- **WHEN** a session created at 09:00, whose second factor was never satisfied since, posts to `/recovery/codes` at 09:20
- **THEN** it is refused with the reauthentication-required error and the set is unchanged

#### Scenario: Consumer window
- **WHEN** the freshness window is configured as 2 hours and a session created at 09:00 posts at 10:30
- **THEN** a new set is returned

#### Scenario: Count without codes
- **WHEN** a full session sends GET `/recovery/codes`
- **THEN** the response carries the remaining count and the low flag, and no code

#### Scenario: Pending session refused
- **WHEN** a session with an MFA challenge pending posts to `/recovery/codes`
- **THEN** it is refused by the gate enforcing that challenge, and no set is generated

#### Scenario: Fresh after a re-authentication
- **WHEN** a session created at 09:00 re-authenticates at 09:30 and posts to `/recovery/codes` at 09:40
- **THEN** a new set is returned
