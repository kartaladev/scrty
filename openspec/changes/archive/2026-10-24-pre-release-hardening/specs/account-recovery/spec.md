# Spec Delta

## ADDED Requirements

### Requirement: The issued-code limit holds under concurrent starts
The per-user issuance limit for issued recovery codes SHALL be decided by one atomic count-and-issue, so that no number of concurrent starts for one user issues more codes within the window than the limit allows.

#### Scenario: Concurrent starts
- **WHEN** 20 recoveries for `u-1` start concurrently with the default limit of 5
- **THEN** at most 5 issued codes exist for `u-1` within the window, and at most 5 messages are sent

### Requirement: A cancel link may use plain http only on a loopback host
A held recovery's cancel link SHALL be refused at construction when it uses `http` on a host other than a loopback host. The comparison with `localhost` SHALL fold ASCII letter case only, so a host that matches `localhost` only under Unicode case folding is not a loopback host.

#### Scenario: Plain http on localhost
- **WHEN** the cancel link is configured as `http://LOCALHOST:8080/recovery/cancel`
- **THEN** construction succeeds

#### Scenario: Look-alike of localhost
- **WHEN** the cancel link is configured as `http://localhoſt/recovery/cancel`, with U+017F in place of `s`
- **THEN** construction fails with a configuration error

## MODIFIED Requirements

### Requirement: A recovery needs two proofs of different kinds
The completion endpoint SHALL match only POST requests to its path, `/recovery/complete` by default, and SHALL read the username and the proofs from form fields. It SHALL accept exactly two proofs, of different kinds, and at least one of them a recovery code:
- a saved code and an issued code;
- a saved code or an issued code, together with an authenticator the user holds: the user's password, or a code for an MFA method the user is enrolled on.

The two proofs SHALL NOT share a delivery channel. An issued code is delivered by email, so it SHALL NOT be paired with an MFA method whose code is delivered by email. This is a stated limit with no override, because accepting it would let one mailbox recover the account alone.

A request with one proof, with more than two, with two of the same kind, with two proofs sharing a delivery channel, or with no recovery code SHALL be refused as a malformed recovery before any proof is checked. Each proof kind SHALL be enabled separately by the consumer, and a proof of a kind that is not enabled SHALL be refused as a malformed recovery. Only an MFA method whose response is a single form field and which has no begin step SHALL serve as a proof. The documentation SHALL state that a challenge method cannot serve as a proof. A password proof SHALL be subject to the pre-authentication policy phase, which includes lockout, and SHALL be verified by the same password authenticator as form login, recording a failed attempt as login does. An unknown username, a disabled user, and any refused proof, including a password proof refused because the account is locked, SHALL all be refused with the same recovery-refused error, unless the consumer has chosen to disclose locks.

#### Scenario: Saved and issued codes
- **WHEN** `u-1` posts a valid saved code and a valid issued code
- **THEN** the recovery succeeds

#### Scenario: Saved code and password
- **WHEN** `u-1` posts a valid saved code and their correct password
- **THEN** the recovery succeeds

#### Scenario: Issued code and TOTP
- **WHEN** `u-1`, enrolled on TOTP, posts a valid issued code and a valid TOTP code naming the `totp` method
- **THEN** the recovery succeeds

#### Scenario: Issued code and an emailed MFA code
- **WHEN** `u-1`, enrolled on an MFA method whose codes are sent by email, posts a valid issued code and a valid code for that method
- **THEN** it is refused as a malformed recovery and nothing is checked or spent

#### Scenario: Saved code and an emailed MFA code
- **WHEN** `u-1`, enrolled on an MFA method whose codes are sent by email, posts a valid saved code and a valid code for that method
- **THEN** the recovery succeeds

#### Scenario: An emailed code alone
- **WHEN** `u-1` posts only a valid issued code
- **THEN** it is refused as a malformed recovery and nothing is checked or spent

#### Scenario: Password and TOTP without a recovery code
- **WHEN** `u-1` posts their password and a TOTP code
- **THEN** it is refused as a malformed recovery

#### Scenario: Locked account
- **WHEN** `u-1`'s account is locked and they post a valid saved code and their password
- **THEN** the recovery is refused with the recovery-refused error, identifiable as the account-locked refusal by the consumer's error handling, the account's password is not checked, and one decoy verification is spent

#### Scenario: Locked account with locks disclosed
- **WHEN** the chain is configured to disclose locks, `u-1`'s account is locked, and they post a valid saved code and their password
- **THEN** the recovery is refused with the account-locked refusal, answered 429, and no decoy verification is spent

#### Scenario: Unknown and wrong look alike
- **WHEN** one recovery names an unknown username and another names `u-1` with a wrong saved code
- **THEN** both are refused with the same recovery-refused error

### Requirement: The library reports whether a user has another way back in
The library SHALL export a check that reports whether a user has a way back into the account other than saved codes they have yet to generate. It SHALL report yes when any of these holds:
- the user has a password or a usable authenticator that does not share the issued code's delivery channel, and issued codes are enabled, so it can pair with an issued code. An authenticator is usable when it can authenticate now: an enrolled MFA method, or an active passkey. A pending or suspended passkey is not usable. An MFA method whose codes are delivered by email does not pair with an issued code;
- the user holds at least one unspent saved code;
- the user has a linked federated identity whose login would be admitted without a local second factor whatever the provider asserts, as decided by the MFA requirement policy the login itself is evaluated by: the policy is in the exempt federated-assurance mode, the exemption rule marks `oidc` exempt, or the user is not required to use MFA. Provider assurance SHALL NOT be assumed, because it is known only at a login.

Linked identities SHALL be read through a lookup the consumer supplies. With none supplied they SHALL NOT count, and the documentation SHALL say so. Kinds of authenticator added later SHALL feed the check through the authenticator-reset port. A kind that holds authenticators that cannot authenticate SHALL report only its usable ones to the check, while still listing every one it holds for the reset. A kind SHALL report each usable authenticator's delivery channel where it has one. A failed lookup SHALL return an error and SHALL NOT report no. A lookup that returns no user and no error SHALL be treated as a user with nothing, never dereferenced.

#### Scenario: Password with issued codes
- **WHEN** issued codes are enabled and `u-1` has a password and no saved codes
- **THEN** the check reports yes

#### Scenario: Password without issued codes
- **WHEN** issued codes are disabled and `u-1` has a password, no MFA enrolment and no saved codes
- **THEN** the check reports no

#### Scenario: Only an emailed MFA method with issued codes
- **WHEN** issued codes are enabled and `u-1` has no password, no saved codes, and only an MFA method whose codes are sent by email
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

#### Scenario: Loader returns no user
- **WHEN** the user loader returns no user and no error for `u-1`
- **THEN** the check reports from the remaining lookups and does not panic
