# Spec Delta

## MODIFIED Requirements

### Requirement: A recovery produces a confined session, never a full one
A completed recovery SHALL create a session for the user, recording the `recovery` first factor, in the recovery-pending state with the time it was recovered, and SHALL answer with a credential for it through a replaceable responder. The session SHALL live at most the recovery lifetime, 15 minutes by default, replaceable by an option. Construction SHALL fail when the lifetime is zero or less, or longer than the session manager's absolute timeout. The session SHALL become a full session only by binding a new authenticator, through one of:
- the MFA enrolment path, after which the MFA verify endpoint resolves the challenge;
- passkey registration, after which the MFA verify endpoint resolves the challenge with the new passkey;
- a successful password change at the password-change resolve endpoint.

Recovery SHALL fail construction when none is wired. No option SHALL let a recovery end in a full session on its own.

#### Scenario: Recovery session
- **WHEN** `u-1` completes a recovery at 09:00 with default options
- **THEN** the response carries a credential for a session in the recovery-pending state, recording the `recovery` first factor and a recovery time of 09:00
- **AND** that session is refused at 09:16 as expired, unless it has become full by then

#### Scenario: Passkey is the only binding route
- **WHEN** recovery is enabled on a chain with passkey registration and the passkey method on the MFA slot, and neither the MFA enrolment path nor a password-change resolve endpoint
- **THEN** construction succeeds

#### Scenario: Nothing to bind
- **WHEN** recovery is enabled on a chain with neither the MFA enrolment path, passkey registration nor a password-change resolve endpoint
- **THEN** construction fails with a configuration error

### Requirement: The library reports whether a user has another way back in
The library SHALL export a check that reports whether a user has a way back into the account other than saved codes they have yet to generate. It SHALL report yes when any of these holds:
- the user has a password or a usable authenticator, and issued codes are enabled, so it can pair with an issued code. An authenticator is usable when it can authenticate now: an enrolled MFA method, or an active passkey. A pending or suspended passkey is not usable;
- the user holds at least one unspent saved code;
- the user has a linked federated identity whose login would admit them without the second factor they might lose, as decided by the same MFA exemption decision the login itself makes.

Linked identities SHALL be read through a lookup the consumer supplies. With none supplied they SHALL NOT count, and the documentation SHALL say so. Kinds of authenticator added later SHALL feed the check through the authenticator-reset port. A kind that holds authenticators that cannot authenticate SHALL report only its usable ones to the check, while still listing every one it holds for the reset. A failed lookup SHALL return an error and SHALL NOT report no.

#### Scenario: Password with issued codes
- **WHEN** issued codes are enabled and `u-1` has a password and no saved codes
- **THEN** the check reports yes

#### Scenario: Password without issued codes
- **WHEN** issued codes are disabled and `u-1` has a password, no MFA enrolment and no saved codes
- **THEN** the check reports no

#### Scenario: Saved codes held
- **WHEN** `u-1` has no password and holds 3 unspent saved codes
- **THEN** the check reports yes

#### Scenario: Linked provider under the default exemption
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who has nothing else, and OIDC logins are exempt from MFA
- **THEN** the check reports yes

#### Scenario: Active passkey with issued codes
- **WHEN** issued codes are enabled and `u-1` has no password and one active passkey
- **THEN** the check reports yes

#### Scenario: Only a suspended passkey
- **WHEN** issued codes are enabled and `u-1` has no password and only a suspended passkey
- **THEN** the check reports no

#### Scenario: Lookup failure
- **WHEN** the enrolment lookup fails during the check
- **THEN** the check returns an error
