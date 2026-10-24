# Spec Delta

## ADDED Requirements

### Requirement: A TOTP code counts only for the secret it was checked against
Confirming a TOTP enrolment and accepting a verified code SHALL each record their outcome only for the enrolment generation whose secret the code was checked against. When the enrolment was replaced, reset or re-enrolled between the check and the write, the confirmation or verification SHALL fail with the invalid-code error and SHALL NOT confirm or accept anything on the newer generation.

#### Scenario: Enrolment begun again during a confirmation
- **WHEN** a confirmation checks a valid code against pending secret A, and before its write a new enrolment replaces A with secret B
- **THEN** the confirmation fails with the invalid-code error and the enrolment reads as unconfirmed with secret B

#### Scenario: Re-enrolled during a verification
- **WHEN** a verification checks a code against the confirmed secret of generation G1, and before its write the enrolment is reset and re-enrolled and confirmed as G2
- **THEN** the verification fails with the invalid-code error

### Requirement: MFA configuration errors are identifiable as configuration errors
Every construction failure of an MFA method or verification throttle SHALL be identifiable as the MFA configuration error, whatever parameter caused it.

#### Scenario: Missing store
- **WHEN** a TOTP method is constructed without a store
- **THEN** the error is identifiable as the MFA configuration error

## MODIFIED Requirements

### Requirement: TOTP codes follow RFC 6238
The TOTP method SHALL verify codes as RFC 6238 specifies, with HMAC-SHA-1. It SHALL accept a code for the current time step or for one step on either side. The defaults SHALL be 6 digits and a 30-second step. A consumer SHALL be able to choose 8 digits and another step length of a whole number of seconds. Constructing the method with a digit count other than 6 or 8, or a step shorter than one second or not a whole number of seconds, SHALL fail with a configuration error. A wrong code SHALL fail with an invalid-code error. Codes SHALL be compared in constant time.

#### Scenario: RFC test vector
- **WHEN** a method configured with 8 digits verifies code `94287082` against the RFC 6238 SHA-1 test secret at Unix time 59
- **THEN** verification succeeds

#### Scenario: Previous step accepted
- **WHEN** a code for the previous 30-second step is presented with default options
- **THEN** verification succeeds

#### Scenario: Two steps old rejected
- **WHEN** a code for two steps ago is presented with default options
- **THEN** verification fails with the invalid-code error

#### Scenario: Consumer digits
- **WHEN** the method is configured with 8 digits and a valid 8-digit code is presented
- **THEN** verification succeeds

#### Scenario: Invalid digit count
- **WHEN** a TOTP method is constructed with 7 digits
- **THEN** construction fails with a configuration error

#### Scenario: Sub-second step
- **WHEN** a TOTP method is constructed with a 500-millisecond step
- **THEN** construction fails with a configuration error

#### Scenario: Fractional step
- **WHEN** a TOTP method is constructed with a 45.5-second step
- **THEN** construction fails with a configuration error

### Requirement: A challenge method verifies only against a challenge the library issued
A method MAY declare a begin step. For such a method the library SHALL provide a begin endpoint that matches POST requests to one path per method under a begin prefix, `/mfa/begin` by default and replaceable by an option. Begin SHALL apply the same session, method and usability refusals as verification, SHALL be refused while the user's verification is throttled, and SHALL then issue a pending challenge: a one-time token of a purpose of the method's own, whose subject is the session's user and which is bound to the session's handle, expiring after 5 minutes by default, replaceable by an option. The token string SHALL be the challenge the method builds its begin data around, and the begin data SHALL be written through a replaceable responder. The pending-challenge store SHALL default to the in-memory one-time store and be replaceable by an option, and the documentation SHALL state that the in-memory store serves a single process.

At verification of a challenge method, after the response is read, the library SHALL take from the response the challenge the client answered, check it against the pending challenges it issued for that session, and spend it, before the method verifies the response. A challenge SHALL be spent by any verification attempt that presents it on the session it was issued to, whether that attempt is accepted or refused. A challenge presented on another session SHALL be refused without being spent, since it matches no challenge issued to that session. A challenge that is absent, unknown, expired, already spent, or bound to another session SHALL be refused as an invalid second-factor code and counted as a failed verification. A challenge SHALL only ever be compared with one the library issued, never accepted from the request alone.

A begin path naming a method that has no begin step SHALL be refused as an unknown MFA method.

Begin SHALL be refused as throttled, issuing nothing, once the user has been issued as many challenges for that method within the pending-challenge store's issuance window as the challenge limit allows: 10 within one hour by default, the limit replaceable by an option, and a limit of zero or less a configuration error. The count and the issue SHALL be one atomic bounded issue, so begins that race SHALL NOT together exceed the limit. The library SHALL remove a method's expired challenges from the store at most once per issuance window, as part of a begin, so the default store does not grow without bound, and SHALL keep doing so after the clock steps backwards; a failed removal SHALL NOT refuse the begin.

#### Scenario: Begin then verify
- **WHEN** a pending session begins a challenge method, and posts a response answering the issued challenge
- **THEN** the method verifies the response and the challenge is resolved

#### Scenario: One try per challenge
- **WHEN** a pending session posts a response answering an issued challenge and the method refuses it, and then posts a second response answering the same challenge
- **THEN** the second attempt is refused as an invalid second-factor code without the method being asked to verify

#### Scenario: Challenge from another session
- **WHEN** session A begins a challenge method, and session B, for the same user, posts a response answering A's challenge
- **THEN** it is refused as an invalid second-factor code

#### Scenario: Expired challenge
- **WHEN** a challenge issued at 12:00 with the default lifetime is answered at 12:06
- **THEN** it is refused as an invalid second-factor code and a failure is counted

#### Scenario: Consumer challenge lifetime
- **WHEN** the challenge lifetime is set to 2 minutes and a challenge issued at 12:00 is answered at 12:03
- **THEN** it is refused as an invalid second-factor code

#### Scenario: Too many challenges
- **WHEN** a pending session of `u-1` begins the same challenge method 10 times within an hour, then begins it once more
- **THEN** the eleventh begin is refused as throttled and no challenge is issued

#### Scenario: Consumer challenge limit
- **WHEN** the challenge limit is set to 3 and `u-1` begins the same method 4 times within an hour
- **THEN** the fourth begin is refused as throttled

#### Scenario: Concurrent begins
- **WHEN** the challenge limit is set to 3 and 12 begins of the same method for `u-1` run concurrently
- **THEN** at most 3 challenges are issued

#### Scenario: Expired challenges are removed
- **WHEN** with the challenge limit raised to 1000, 200 challenges are issued and left unanswered, more than an hour passes, and another begin is made
- **THEN** the expired challenges are no longer held by the store

#### Scenario: Removal after the clock steps backwards
- **WHEN** the clock steps back by an hour after a removal, and challenges then expire and more than an issuance window passes before another begin
- **THEN** the expired challenges are removed at that begin

#### Scenario: Begin for a method without a begin step
- **WHEN** a pending session posts to the begin path of the TOTP method
- **THEN** it is refused as an unknown MFA method
