# Spec Delta

## MODIFIED Requirements

### Requirement: The library reports whether a user has another way back in
The library SHALL export a check that reports whether a user has a way back into the account other than saved codes they have yet to generate. It SHALL report yes when any of these holds:
- the user has a password or a usable authenticator, and issued codes are enabled, so it can pair with an issued code. An authenticator is usable when it can authenticate now: an enrolled MFA method, or an active passkey. A pending or suspended passkey is not usable;
- the user holds at least one unspent saved code;
- the user has a linked federated identity whose login would be admitted without a local second factor whatever the provider asserts, as decided by the MFA requirement policy the login itself is evaluated by: the policy is in the exempt federated-assurance mode, the exemption rule marks `oidc` exempt, or the user is not required to use MFA. Provider assurance SHALL NOT be assumed, because it is known only at a login.

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
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who has nothing else, and the MFA requirement policy is in the exempt federated-assurance mode
- **THEN** the check reports yes

#### Scenario: Linked provider, required user, default mode
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who is required to use MFA and has nothing else, and the policy is in the default mode
- **THEN** the check reports no

#### Scenario: Linked provider, user not required
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who is not required to use MFA and has nothing else
- **THEN** the check reports yes

#### Scenario: Requirement lookup failure
- **WHEN** a linked OIDC identity is reported for `u-1` and the requirement lookup fails during the check
- **THEN** the check returns an error

#### Scenario: Active passkey with issued codes
- **WHEN** issued codes are enabled and `u-1` has no password and one active passkey
- **THEN** the check reports yes

#### Scenario: Only a suspended passkey
- **WHEN** issued codes are enabled and `u-1` has no password and only a suspended passkey
- **THEN** the check reports no

#### Scenario: Lookup failure
- **WHEN** the enrolment lookup fails during the check
- **THEN** the check returns an error
