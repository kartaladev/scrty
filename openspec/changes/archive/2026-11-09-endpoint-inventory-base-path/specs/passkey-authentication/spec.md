# Spec Delta

## MODIFIED Requirements

### Requirement: Binding a passkey on a confined session moves it to the MFA-pending state
When a credential becomes active for a session in the enrolment-pending or recovery-pending state, the library SHALL move that session to the MFA pending state. This happens at finish, or at the last confirmation that activates it. The session SHALL keep its confinement marker and any recovery time, and SHALL be saved. The user SHALL then prove the new passkey through the MFA begin and verify endpoints. The MFA verify endpoint SHALL resolve the challenge, restore the session's deadlines and rotate it, as it does for an enrolment confirmed through the path. A registration on a full session SHALL NOT change the session's second-factor state. A credential that is still pending SHALL leave the session's state unchanged.

#### Scenario: Recovery route through a passkey
- **WHEN** a recovery-pending session created at 09:00 registers a passkey, begins the passkey challenge at `/mfa/challenge/passkey` and posts a valid assertion to `/mfa/verify/passkey` at 09:05, with a 12-hour absolute timeout
- **THEN** the rotated session reports a satisfied second factor, an absolute deadline of 21:00 and a recovery time of 09:00

#### Scenario: Registration alone is not a second factor
- **WHEN** an enrolment-only session's passkey has just become active and the session requests `/invoices`
- **THEN** an MFA challenge error is returned, listing `passkey`

#### Scenario: Pending credential leaves the session confined
- **WHEN** an enrolment-only session finishes a registration awaiting its emailed code
- **THEN** the session is still in the enrolment-pending state

### Requirement: Passkeys serve as a challenge-capable MFA method
The library SHALL provide an MFA method named `passkey` that reports the `public-key` channel and declares a begin step and a JSON body response. A user SHALL be enrolled on it when they hold at least one active passkey. A failed lookup SHALL be an error, never "not enrolled". Its begin data SHALL be request options listing the user's active credentials as allowed credentials, including credentials that are not discoverable. The challenge SHALL be the one the MFA slot issued. Verification SHALL require the assertion to come from one of the session's user's active credentials, and SHALL verify it as at the passwordless finish, except that user presence without user verification SHALL be accepted when user verification is relaxed to `preferred`, since a second factor proves possession. The method's channel SHALL equal the `passkey` kind's channel, so a passkey never serves as the second factor of a passkey login. The method SHALL be able to remove all of a user's passkeys for the operator reset.

#### Scenario: Passkey after a password
- **WHEN** `u-1`, enrolled only on the passkey method, logs in by password, begins at `/mfa/challenge/passkey` and posts a valid assertion to `/mfa/verify/passkey`
- **THEN** the challenge is resolved and the session rotated

#### Scenario: Another user's credential
- **WHEN** `u-1`'s pending session answers its passkey challenge with an assertion from `u-2`'s credential
- **THEN** it is refused as an invalid second-factor code and the challenge stays pending

#### Scenario: No passkey after a passkey login
- **WHEN** `u-1` logs in with a passkey without user verification, under relaxed user verification, and is enrolled only on the passkey method
- **THEN** the passkey method is not among the usable methods for that session

#### Scenario: Operator reset
- **WHEN** an operator reset is run for `u-1` with the passkey method's remover
- **THEN** `u-1` holds no passkey afterwards

### Requirement: Passkey endpoints have documented default paths
When enabled, the passkey endpoints SHALL answer at these default paths, each replaceable by an option:
- registration begin `/passkeys/register/begin`, finish `/passkeys/register/finish`, saved-code confirm `/passkeys/register/confirm`, emailed-code confirm `/passkeys/register/confirm-email`, each POST;
- listing `/passkeys` (GET), rename `/passkeys/rename` (POST), remove `/passkeys/remove` (POST);
- passwordless begin `/sign-in/passkey/begin` and finish `/sign-in/passkey/finish`, each POST, only when passwordless login is enabled.

The passkey second factor SHALL answer at the MFA slot's paths for the method name `passkey`, by default `/mfa/challenge/passkey` and `/mfa/verify/passkey`. Any other HTTP method on a passkey path SHALL pass through without touching a challenge or a credential. Begin data, finish results and listings SHALL be written through replaceable responders, and the default responses SHALL be documented JSON bodies.

#### Scenario: GET on a finish path
- **WHEN** a GET request is sent to `/sign-in/passkey/finish`
- **THEN** it passes through and no challenge is spent

#### Scenario: Consumer paths
- **WHEN** the registration prefix paths are configured under `/account/passkeys` and a fresh session begins at `/account/passkeys/begin`
- **THEN** a challenge is issued

### Requirement: Passkey wiring mistakes fail at construction
Passkey endpoints SHALL NOT exist until the consumer enables passkeys on the chain. Construction SHALL fail with a configuration error when:
- passwordless login is enabled while saved recovery codes are not wired to registration, unless the optional mode is chosen;
- trusted attestation is required with no metadata source;
- the relying party is missing or malformed;
- no sender, or no repudiation contact, is configured;
- a synchronous sender is configured without accepting synchronous delivery;
- a challenge lifetime, freshness window, issuance limit or passkey limit is zero or less;
- no session manager is given to the passkey component while removal revocation or clone revocation is on;
- any endpoint path does not have the shape `http-security-chain` requires of endpoint paths, or collides with another passkey path or another endpoint the chain answers, as that capability's chain-wide collision requirement judges.

#### Scenario: Passwordless without recovery codes
- **WHEN** passwordless login is enabled, no saved recovery codes are wired, and the optional mode is not chosen
- **THEN** construction fails with a configuration error

#### Scenario: Optional mode accepted
- **WHEN** the same configuration chooses the optional mode
- **THEN** construction succeeds

#### Scenario: Path collision
- **WHEN** the passwordless finish path is set to the sign-out path
- **THEN** construction fails with a configuration error naming passkeys and logout

#### Scenario: No session manager for revocation
- **WHEN** the passkey component is built with no session manager and both revocations left on
- **THEN** construction fails with a configuration error

#### Scenario: Both revocations off
- **WHEN** the passkey component is built with no session manager and both revocations turned off
- **THEN** construction succeeds
