# Spec Delta

## MODIFIED Requirements

### Requirement: Registration admits a session only at the account's assurance and only while fresh
The registration endpoints SHALL refuse a request with no session, or whose session carries no resolved caller, as authentication required. They SHALL serve:
- a **full session**, with no pending challenge and not confined. The session SHALL have satisfied its second factor when its user can use any configured MFA method, as decided by the one function the security policies use, or when its user holds an active passkey while a passkey route can meet the second factor: the passkey MFA method is configured, or passwordless login is enabled and meets the second factor at login. The user's own passkeys SHALL count whatever the session's first factor, since the account's assurance does not depend on how this session was established. Otherwise registration SHALL be refused with the reauthentication-required refusal. The session SHALL also be fresh: its authentication time, as the `sessions` capability records it (the sign-in, a satisfied second factor or a re-authentication, whichever is latest), SHALL be no more than 15 minutes old. Otherwise registration SHALL be refused with the reauthentication-required refusal. The freshness window SHALL be replaceable by an option, and a window of zero or less SHALL be a configuration error;
- a **recovery-pending session**, without the assurance and freshness checks, since the recovery is its authentication and its lifetime is short by construction;
- an **enrolment-only session**, without the assurance and freshness checks, since its user has no usable second factor and its lifetime is short by construction.

A session with a pending MFA or password-change challenge never reaches registration, because the gate of its challenge refuses it first.

#### Scenario: Fresh full session
- **WHEN** `u-1`, who has no MFA enrolment, logged in by password at 09:00 and begins a registration at 09:10
- **THEN** a challenge is issued

#### Scenario: Stale full session
- **WHEN** the same session begins a registration at 09:16
- **THEN** it is refused with the reauthentication-required refusal and no challenge is issued

#### Scenario: Freshness from the second factor
- **WHEN** `u-1` logged in by password at 09:00, satisfied TOTP at 09:20, and begins a registration at 09:30
- **THEN** a challenge is issued

#### Scenario: A usable second factor not yet satisfied
- **WHEN** `u-1` enrolled on TOTP from another session after this session was established without a second factor, and this session begins a registration
- **THEN** it is refused with the reauthentication-required refusal

#### Scenario: A passkey login without user verification
- **WHEN** user verification is relaxed to preferred, `u-1` holds an active passkey, signs in with it without user verification, and begins a registration
- **THEN** it is refused with the reauthentication-required refusal and no challenge is issued

#### Scenario: A password session of a passkey holder
- **WHEN** passwordless login is enabled, `u-1` holds an active passkey, signs in by password without a second factor, and begins a registration
- **THEN** it is refused with the reauthentication-required refusal and no challenge is issued

#### Scenario: Consumer freshness window
- **WHEN** the freshness window is set to 1 hour and a session created at 09:00 begins a registration at 09:50
- **THEN** a challenge is issued

#### Scenario: No session
- **WHEN** a request without a session posts to the registration begin path
- **THEN** it is refused as authentication required

#### Scenario: Freshness from a re-authentication
- **WHEN** `u-1`, who has no MFA enrolment, logged in by password at 09:00, re-authenticated with the password at 09:30, and begins a registration at 09:40
- **THEN** a challenge is issued
