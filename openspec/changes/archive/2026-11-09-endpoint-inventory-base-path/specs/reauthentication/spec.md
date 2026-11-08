# Spec Delta

## MODIFIED Requirements

### Requirement: A user re-proves with the strongest factor they hold, by default
By default a user who holds a usable re-proof second factor SHALL re-prove with one and SHALL NOT re-prove with the password; a user who holds none SHALL re-prove with the password. A usable re-proof second factor is a configured MFA method the user is enrolled on, whatever its channel. A failed enrolment lookup SHALL refuse the request and SHALL NOT fall back to the password.

#### Scenario: A TOTP holder offers a password
- **WHEN** `u-1`, enrolled on TOTP, posts the correct password to `/reauth/password`
- **THEN** it is refused with the re-proof-method-not-usable error before the body is read, the password is not checked and no failure is recorded

#### Scenario: A user without a second factor
- **WHEN** `u-2`, enrolled on no method, posts the correct password to `/reauth/password`
- **THEN** `u-2`'s session is re-authenticated

#### Scenario: MFA not configured
- **WHEN** the chain has form login and no MFA slot, and `u-1` posts the correct password to `/reauth/password`
- **THEN** the session is re-authenticated

#### Scenario: Lookup failure does not downgrade
- **WHEN** the TOTP enrolment lookup fails for `u-1` and `u-1` posts the correct password to `/reauth/password`
- **THEN** the request is refused with the lookup failure and the password is not checked

#### Scenario: A passkey login re-proves with the passkey
- **WHEN** `u-3` signed in with a passkey, the passkey MFA method is configured, and `u-3` re-proves through `/reauth/challenge/passkey` and `/reauth/verify/passkey`
- **THEN** `u-3`'s session is re-authenticated, although the passkey shares the first factor's channel

### Requirement: Re-proof challenges are their own and bound to the session
Begin SHALL apply verify's refusals and throttle check, then issue a re-proof challenge: a one-time token of a purpose of its own per method, whose subject is the user and which is bound to the session, expiring after 5 minutes by default. A login challenge SHALL NOT answer a re-proof, nor the reverse. The lifetime, the issuance limit (10 per user and method within an hour by default) and the store SHALL be replaceable.

#### Scenario: Begin
- **WHEN** `u-3`, holding an active passkey, posts to `/reauth/challenge/passkey`
- **THEN** the response carries a challenge document and is marked not to be cached

#### Scenario: A login challenge is refused
- **WHEN** a challenge issued by `/mfa/challenge/passkey` is presented to `/reauth/verify/passkey`
- **THEN** it is refused with the invalid-code error and counted

#### Scenario: Another session's challenge
- **WHEN** a re-proof challenge issued to one session of `u-3` is presented by another session of `u-3`
- **THEN** it is refused with the invalid-code error and counted

#### Scenario: Expired challenge
- **WHEN** a re-proof challenge is answered six minutes after it was issued with the default lifetime
- **THEN** it is refused with the invalid-code error

#### Scenario: Issuance limit
- **WHEN** `u-3` begins a passkey re-proof ten times within an hour and begins again
- **THEN** the eleventh begin is refused with the throttled error and no challenge is issued

#### Scenario: Consumer lifetime
- **WHEN** the re-proof challenge lifetime is set to 2 minutes and a challenge is answered after 3 minutes
- **THEN** it is refused with the invalid-code error

#### Scenario: Zero lifetime
- **WHEN** the re-proof challenge lifetime is set to zero
- **THEN** construction fails with a configuration error

### Requirement: A second-factor re-proof judges only the session's own user
A second-factor re-proof SHALL refuse, as authentication required and before the post-authentication phase, a caller whose user is not the session's user, counting and verifying nothing.

#### Scenario: A substituted caller
- **WHEN** a consumer interceptor publishes a principal other than the session's user and that session posts a valid code to `/reauth/verify/totp`
- **THEN** it is refused as authentication required before the phase, and the session is unchanged

#### Scenario: A substituted caller at begin
- **WHEN** a consumer interceptor publishes a principal other than the session's user and that session posts to `/reauth/challenge/passkey`
- **THEN** it is refused as authentication required, no challenge is issued and nothing is counted

### Requirement: Re-authentication wiring mistakes fail at construction
Enabling re-authentication SHALL fail chain construction with a configuration error when:
- neither the MFA slot nor form login is enabled;
- second-factor-only re-proof is required without the MFA slot;
- the prefix is empty;
- a re-proof path collides with a path another enabled endpoint answers, as the chain-wide collision requirement of `http-security-chain` judges;
- it is enabled twice;
- no credential can be issued for the rotated session;
- the challenge stores are wired inconsistently, as the challenge-store requirement states.

#### Scenario: Nothing to re-prove with
- **WHEN** re-authentication is enabled on a chain without the MFA slot and without form login
- **THEN** construction fails with a configuration error

#### Scenario: Second factor only without MFA
- **WHEN** second-factor-only re-proof is required on a chain with form login and without the MFA slot
- **THEN** construction fails with a configuration error

#### Scenario: Empty prefix
- **WHEN** re-authentication is enabled with an explicitly empty prefix
- **THEN** construction fails with a configuration error

#### Scenario: Prefix collides with MFA verify
- **WHEN** the re-authentication prefix is set to `/mfa/verify`
- **THEN** construction fails with a configuration error

#### Scenario: Enabled twice
- **WHEN** re-authentication is enabled twice on one chain
- **THEN** construction fails with a configuration error

#### Scenario: No credential to issue
- **WHEN** re-authentication is enabled on a token-bearer chain without a token generator for it
- **THEN** construction fails with a configuration error

### Requirement: Re-proof paths are checked against every endpoint the chain answers
Re-proof paths SHALL be judged by the chain-wide collision requirement of `http-security-chain`, like every built-in endpoint: re-proof begin and verify match their path and everything beneath it, and the listing and the password path match exactly. A collision SHALL fail construction with a configuration error naming both options and both paths.

#### Scenario: Prefix collides with passkey registration
- **WHEN** passkeys are enabled and the passkey registration prefix is set to `/reauth/challenge`
- **THEN** construction fails with a configuration error naming re-authentication and the passkey registration path

#### Scenario: Another endpoint's exact path collides
- **WHEN** the session renewal path is set to `/reauth/password`
- **THEN** construction fails with a configuration error

#### Scenario: A prefix under an exact path is accepted
- **WHEN** password sign-in answers `/sign-in/password` and the re-authentication prefix is set to `/sign-in/password/reauth`
- **THEN** construction succeeds, `/sign-in/password` is answered by password sign-in and `/sign-in/password/reauth/methods` by re-authentication
