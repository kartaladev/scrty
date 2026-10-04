## MODIFIED Requirements

### Requirement: A recovery needs two proofs of different kinds
The completion endpoint SHALL match only POST requests to its path, `/recovery/complete` by default, and SHALL read the username and the proofs from form fields. It SHALL accept exactly two proofs, of different kinds, and at least one of them a recovery code:
- a saved code and an issued code;
- a saved code or an issued code, together with an authenticator the user holds: the user's password, or a code for an MFA method the user is enrolled on.

A request with one proof, with more than two, with two of the same kind, or with no recovery code SHALL be refused as a malformed recovery before any proof is checked. Each proof kind SHALL be enabled separately by the consumer, and a proof of a kind that is not enabled SHALL be refused as a malformed recovery. Only an MFA method whose response is a single form field and which has no begin step SHALL serve as a proof. The documentation SHALL state that a challenge method cannot serve as a proof. A password proof SHALL be subject to the pre-authentication policy phase, which includes lockout, and SHALL be verified by the same password authenticator as form login, recording a failed attempt as login does. An unknown username, a disabled user, and any refused proof, including a password proof refused because the account is locked, SHALL all be refused with the same recovery-refused error, unless the consumer has chosen to disclose locks.

#### Scenario: Saved and issued codes
- **WHEN** `u-1` posts a valid saved code and a valid issued code
- **THEN** the recovery succeeds

#### Scenario: Saved code and password
- **WHEN** `u-1` posts a valid saved code and their correct password
- **THEN** the recovery succeeds

#### Scenario: Issued code and TOTP
- **WHEN** `u-1`, enrolled on TOTP, posts a valid issued code and a valid TOTP code naming the `totp` method
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
