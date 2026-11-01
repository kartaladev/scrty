# Spec Delta

## MODIFIED Requirements

### Requirement: Redemption checks everything before it consumes
Redeeming a link SHALL proceed in this order:
1. check the token;
2. resolve the user;
3. evaluate the post-authentication policy phase, with the `magic-link` first factor and the user's password-change time;
4. run the consumer's refusal checks in order;
5. build the session and issue its credential, through the login completion step of the `http-security-chain` capability;
6. consume the token atomically, last, and only then store the session and hand out its credential.

A failure or refusal at any step before the last SHALL leave the link redeemable until it expires. The consume SHALL refuse a link whose expiry has passed by then, even if it was valid when it was checked, and SHALL leave it unspent. The link SHALL be spent only by a redemption that goes on to succeed. A failure to issue the credential is a dependency failure, not a refusal: it SHALL NOT be answered as an invalid link, and SHALL NOT be counted against the source. Of racing redemptions of one link, at most one SHALL succeed; a losing redemption's credential SHALL be discarded and its session never stored.

#### Scenario: Refused, then fixed, then redeemed
- **WHEN** a link is redeemed while a policy denies the user because they must enrol in MFA, the user then enrols, and the same link is redeemed again
- **THEN** the first redemption is refused with the enrolment-required reason
- **AND** the second redemption succeeds

#### Scenario: Transient user lookup failure
- **WHEN** the user loader fails with a connection error during redemption, and the same link is redeemed after the loader recovers
- **THEN** the first redemption fails
- **AND** the second succeeds

#### Scenario: Racing redemptions
- **WHEN** 16 requests redeem the same valid link at the same time
- **THEN** exactly one succeeds and establishes a session
- **AND** the store holds exactly one session for the user

#### Scenario: Credential cannot be issued
- **WHEN** a valid link is redeemed while the key source fails when the credential is issued, and the same link is redeemed after the key source recovers
- **THEN** the first redemption fails as a dependency failure, not as an invalid link, stores no session, and records nothing against the source
- **AND** the second redemption succeeds

#### Scenario: A link that expires while its credential is issued
- **WHEN** a link valid for 60 seconds is redeemed at 59 seconds, and issuing its credential takes 2 seconds
- **THEN** the redemption is refused as an invalid link, no session is stored, and the link is not spent
