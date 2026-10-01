# Spec Delta

## Purpose

Lets users register passkeys and use them to sign in without a password, or as a second factor after
another first factor. Each ceremony runs over a one-time challenge the library issued. User
verification is required by default, a user-verified passkey login counts as both factors, and a
suspected cloned credential is refused and suspended.

## ADDED Requirements

### Requirement: The relying party is required configuration
Constructing the passkey component SHALL fail with a configuration error when any of the following is missing or malformed:
- the relying-party ID;
- the relying-party display name;
- the set of allowed origins.

The library SHALL NOT supply a default for any of them. The relying-party ID SHALL be a host name with no scheme, port, path or trailing dot. Each allowed origin SHALL be an absolute `https` origin, or an `http` origin on a loopback host. Its host SHALL equal the relying-party ID or end with `.` followed by it. An empty origin set SHALL be a configuration error. The documentation SHALL state that changing the relying-party ID orphans every registered passkey, because authenticators scope their credentials to it.

#### Scenario: Missing relying-party ID
- **WHEN** the passkey component is constructed without a relying-party ID
- **THEN** construction fails with a configuration error naming the relying-party ID

#### Scenario: Origin outside the relying party
- **WHEN** the relying-party ID is `example.com` and an allowed origin is `https://example.org`
- **THEN** construction fails with a configuration error

#### Scenario: Subdomain origin
- **WHEN** the relying-party ID is `example.com` and the allowed origin is `https://login.example.com`
- **THEN** construction succeeds

#### Scenario: Plain http outside loopback
- **WHEN** an allowed origin is `http://example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Loopback development origin
- **WHEN** the relying-party ID is `localhost` and the allowed origin is `http://localhost:8080`
- **THEN** construction succeeds

### Requirement: Each user has one random user handle, never the user reference
The library SHALL give each user one WebAuthn user handle: 64 bytes from the operating system's cryptographically secure random source. It SHALL be created the first time the user begins a registration, and reused for every later registration. Two registrations that begin at the same time for a user with no handle SHALL end with the user holding one handle. The user reference, username and any other user detail SHALL NOT be sent to an authenticator as the user handle. The handle SHALL be kept by a store that maps it to the user reference in both directions. Removing passkeys, including the user's last one, SHALL NOT change the handle, so an authenticator holding an old credential for the user replaces it rather than keeping a second entry.

#### Scenario: Handle is reused
- **WHEN** `u-1` begins two registrations a day apart
- **THEN** both creation options carry the same 64-byte user handle

#### Scenario: The handle is not the user reference
- **WHEN** `u-1`, whose username is `ana@example.com`, begins a registration
- **THEN** the creation options' user handle contains neither `u-1` nor `ana@example.com`

#### Scenario: Concurrent first registrations
- **WHEN** 8 registrations begin at the same time for a user who has no handle
- **THEN** all 8 creation options carry the same handle

### Requirement: Registration is a begin and finish ceremony over a challenge bound to the session
Registration SHALL take two requests from a session:
- **Begin** SHALL issue a pending challenge. The challenge SHALL be a one-time token of the purpose `passkey-registration`, its subject the session's user, bound to the session's handle, and expiring after 5 minutes by default. The token string SHALL be the challenge. Begin SHALL answer with creation options. These SHALL carry:
  - the relying party;
  - the user handle, and a user name and display name from a name resolver over the user's loaded details, by default the username;
  - the challenge;
  - the timeout equal to the challenge lifetime;
  - user verification `required`;
  - resident key `required`;
  - attestation conveyance `none`;
  - every credential the user already holds, as credentials to exclude.
- **Finish** SHALL read the authenticator's response, take from it the challenge the client answered, and check and spend it against the challenges issued to that session for that user. It SHALL then verify the response.

A challenge that is absent, unknown, expired, already spent or bound to another session SHALL refuse the finish with the authentication-failed refusal, and nothing SHALL be stored. Begin SHALL be refused as throttled, issuing nothing, once the user has been issued 10 registration challenges within one hour. That limit SHALL be replaceable by an option, and a limit of zero or less SHALL be a configuration error. The challenge lifetime, the name resolver, the resident-key requirement (`required` or `preferred`) and the challenge store SHALL each be replaceable by an option. The documentation SHALL state that a `preferred` resident key allows credentials that cannot sign in without a username, which serve only as a second factor.

#### Scenario: Begin then finish
- **WHEN** a full session of `u-1` begins a registration and finishes it with a valid response answering the issued challenge
- **THEN** `u-1` holds one more passkey

#### Scenario: Challenge from another session
- **WHEN** session A of `u-1` begins a registration and session B of `u-1` finishes with a response answering A's challenge
- **THEN** the finish is refused with the authentication-failed refusal and nothing is stored

#### Scenario: Expired challenge
- **WHEN** a registration challenge issued at 12:00 with default options is answered at 12:06
- **THEN** the finish is refused and nothing is stored

#### Scenario: Existing credentials are excluded
- **WHEN** `u-1` holds two passkeys and begins a registration
- **THEN** the creation options list both credential IDs as credentials to exclude

#### Scenario: Consumer name resolver
- **WHEN** the consumer configures a name resolver returning the user's display email
- **THEN** the creation options' user name is that email

#### Scenario: Too many begins
- **WHEN** `u-1` begins a registration 10 times within an hour and then begins once more
- **THEN** the eleventh begin is refused as throttled and no challenge is issued

### Requirement: Registration admits a session only at the account's assurance and only while fresh
The registration endpoints SHALL refuse a request with no session, or whose session carries no resolved caller, as authentication required. They SHALL serve:
- a **full session**, with no pending challenge and not confined. When the session's user can use any configured MFA method, as decided by the one function the security policies use, the session SHALL have satisfied its second factor. Otherwise registration SHALL be refused with the reauthentication-required refusal. The session SHALL also be fresh: its latest authentication, the later of its creation time and its second-factor-satisfied time, SHALL be no more than 15 minutes old. Otherwise registration SHALL be refused with the reauthentication-required refusal. The freshness window SHALL be replaceable by an option, and a window of zero or less SHALL be a configuration error;
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

#### Scenario: Consumer freshness window
- **WHEN** the freshness window is set to 1 hour and a session created at 09:00 begins a registration at 09:50
- **THEN** a challenge is issued

#### Scenario: No session
- **WHEN** a request without a session posts to the registration begin path
- **THEN** it is refused as authentication required

### Requirement: Registration verifies the response and stores the credential once
Finish SHALL verify the authenticator's response against the relying-party ID, the allowed origins and the issued challenge. It SHALL require user presence. It SHALL require user verification unless the consumer relaxed it. A response that fails verification SHALL be refused with the authentication-failed refusal, and nothing SHALL be stored. On success the library SHALL store a credential record for the session's user, holding:
- the credential ID and public key;
- the signature counter;
- the backup-eligible and backup-state flags;
- the transports the response reported;
- the authenticator model identifier (AAGUID), when the response carries one;
- a name;
- the creation time;
- a state of active or pending.

The name SHALL be taken from the response's optional `name` member when it is present. It SHALL be trimmed, at most 64 characters, and free of control characters. Otherwise the name SHALL be a default naming the creation date. A credential ID already registered, to this or any other user, SHALL refuse the finish with the authentication-failed refusal and SHALL leave the existing record unchanged. This SHALL be decided by the write, so of two finishes storing the same credential ID at most one succeeds. A user SHALL hold at most 25 passkeys by default, counting every state, and a finish beyond that SHALL be refused with the passkey-limit refusal. The limit SHALL be replaceable by an option, and a limit below 1 SHALL be a configuration error.

#### Scenario: Stored record
- **WHEN** `u-1` finishes a registration whose response reports backup-eligible and backed-up, transports `internal` and `hybrid`, and a counter of 0
- **THEN** the stored record carries those flags, transports and counter, and a creation time

#### Scenario: Wrong origin
- **WHEN** a registration response's client data names origin `https://evil.example`
- **THEN** the finish is refused with the authentication-failed refusal and nothing is stored

#### Scenario: Credential ID already registered
- **WHEN** a registration response carries a credential ID already registered to `u-2`
- **THEN** the finish is refused and `u-2`'s record is unchanged

#### Scenario: Concurrent finishes of one credential ID
- **WHEN** two finishes storing the same credential ID run at the same time
- **THEN** at most one stores a record

#### Scenario: Name from the response
- **WHEN** the response carries the name `Work laptop`
- **THEN** the stored record is named `Work laptop`

#### Scenario: Passkey limit
- **WHEN** `u-1` holds 25 passkeys and finishes another registration
- **THEN** it is refused with the passkey-limit refusal and nothing is stored

### Requirement: Attestation is not requested by default
By default, registration SHALL request attestation conveyance `none` and SHALL accept any authenticator. A consumer SHALL be able to choose either of these instead:
- **record without enforcing:** request direct attestation, store the attestation format and statement with the credential, and accept every authenticator. The documentation SHALL state that this collects data that can identify the authenticator model or batch;
- **require trusted attestation:** request direct attestation, and refuse registration with the attestation-refused refusal unless the statement verifies against a trusted, non-revoked entry of a metadata source. The registration can optionally be limited to an allowlist of authenticator models. The documentation SHALL state that this excludes synced passkeys, which carry no attestation.

Metadata SHALL come only from a source the consumer supplies, or through the library's confined outbound HTTP client. It SHALL never be fetched by the verification library's own HTTP client. Requiring attestation without a metadata source SHALL fail construction with a configuration error.

A consumer SHALL be able to supply a registration check. It SHALL be given the user, the authenticator model identifier, the backup flags, the attestation format and whether the attestation verified as trusted. It SHALL run after verification and before anything is stored. An error it returns SHALL refuse the registration unchanged, and nothing SHALL be stored. A consumer can use it to apply a stricter policy to some users only.

#### Scenario: Default accepts a synced passkey
- **WHEN** a registration response carries no attestation statement, from a synced authenticator
- **THEN** the credential is stored

#### Scenario: Required attestation refuses an unattested authenticator
- **WHEN** trusted attestation is required and a registration response carries format `none`
- **THEN** the finish is refused with the attestation-refused refusal and nothing is stored

#### Scenario: Required attestation without metadata
- **WHEN** the component is constructed requiring trusted attestation and no metadata source
- **THEN** construction fails with a configuration error

#### Scenario: Consumer check for administrators
- **WHEN** the consumer's registration check refuses credentials that are backup-eligible for users in its administrator group, and an administrator registers a synced passkey
- **THEN** the finish is refused with the consumer's error and nothing is stored

#### Scenario: Record without enforcing
- **WHEN** the record mode is chosen and a security key registers with a `packed` attestation
- **THEN** the credential is stored with format `packed` and its statement

### Requirement: A first passkey waits for saved recovery codes when the user has no other way back in
When saved recovery codes are wired to registration, finish SHALL ask the account-recovery capability's other-way-back-in check about the session's user before storing the credential. A failed check SHALL refuse the finish, and nothing SHALL be stored. When the check reports no way back:
- the credential SHALL be stored in the pending state, awaiting saved codes;
- a new set of saved codes SHALL be generated for the user, replacing any set they held;
- the codes SHALL be returned in the finish response, once, with `Cache-Control: no-store`.

The credential SHALL become active only when the user posts one of those codes to the registration confirm endpoint. That endpoint SHALL:
- read the code from the `code` form field;
- check the code with the saved-code check, which spends nothing and is throttled per user;
- clear the pending reason by one conditional write on the user's credential awaiting codes.

A wrong code SHALL leave the credential pending. The registration confirm endpoint SHALL accept only the session's own user's credential. A new registration finish for a user who holds a credential awaiting codes SHALL delete that credential before storing the new one. A user who already has another way back in SHALL register without this step.

A consumer SHALL be able to choose the optional mode instead. Finish then SHALL store the credential active at once, and SHALL report in its response that recovery is not set up, for the consumer's interface to prompt. The documentation SHALL state that the optional mode allows accounts that only the operator can recover.

#### Scenario: Passwordless user's first passkey
- **WHEN** `u-1` has no password, no MFA enrolment, no saved codes and no counted linked identity, and finishes a registration
- **THEN** the response carries ten saved codes and the credential is pending
- **AND** `u-1` cannot log in with that passkey

#### Scenario: Confirming with a saved code
- **WHEN** `u-1` then posts one of those codes to the registration confirm endpoint
- **THEN** the credential is active and `u-1` can log in with it
- **AND** that code is still unspent

#### Scenario: Wrong code
- **WHEN** `u-1` posts a code that is not in the set
- **THEN** the credential stays pending

#### Scenario: Abandoned registration is replaced
- **WHEN** `u-1` holds a credential awaiting codes and finishes a new registration
- **THEN** the earlier credential no longer exists, and the new one is pending with a new set of codes

#### Scenario: User with a way back
- **WHEN** `u-1` holds three unspent saved codes and finishes a registration
- **THEN** the credential is active at once and no codes are returned

#### Scenario: Consumer chooses the optional mode
- **WHEN** the optional mode is chosen and `u-1`, with no other way back in, finishes a registration
- **THEN** the credential is active at once and the response reports that recovery is not set up

#### Scenario: Check failure
- **WHEN** the way-back check fails because the saved-code store is unavailable
- **THEN** the finish is refused and nothing is stored

### Requirement: A passkey bound from an enrolment-only session proves the mailbox first, by default
When the MFA enrolment path's email confirmation is on, its default, a registration finished on an enrolment-only session SHALL store the credential in the pending state, awaiting the emailed code. It SHALL generate a 6-digit code from the cryptographically secure random source. The code SHALL be kept on the credential, sealed, with an expiry 10 minutes later, and sent to the user's contact address. The registration emailed-code endpoint SHALL read the code from the `code` form field and SHALL, in order:
1. charge one attempt on the credential, as one conditional write that succeeds only while the credential belongs to the session's user, awaits its emailed code, the code has not expired, and fewer than five attempts have been charged;
2. compare the presented code in constant time;
3. clear the pending reason last, as one conditional write.

Every presented code SHALL be charged before it is compared, so the fifth wrong code voids it. Failed confirmations SHALL count against the enrolment path's per-user confirmation limiter. If the sender refuses to queue the code, the finish SHALL fail and nothing SHALL be stored. There SHALL be no resend: a lost or expired code is replaced by registering again, which deletes the credential awaiting it. When email confirmation is off on the enrolment path, it SHALL be off for passkeys too, and the documentation of that option SHALL say so. A credential awaiting both its emailed code and saved codes SHALL become active only when both are confirmed, in either order.

#### Scenario: Emailed code activates the passkey
- **WHEN** an enrolment-only session of `u-1` finishes a registration and posts the emailed code within 10 minutes
- **THEN** the credential is active

#### Scenario: Expired emailed code
- **WHEN** the emailed code is posted 11 minutes after the finish
- **THEN** it is refused and the credential stays pending

#### Scenario: Fifth wrong code
- **WHEN** five wrong codes are posted, followed by the correct one
- **THEN** the correct one is refused and the credential stays pending

#### Scenario: Concurrent guesses are bounded
- **WHEN** twenty wrong codes for the same credential are posted at the same moment, followed by the correct one
- **THEN** no more than five are compared and the credential stays pending

#### Scenario: Sender refuses to queue
- **WHEN** the sender's queue is full when an enrolment-only session finishes a registration
- **THEN** the finish fails and nothing is stored

#### Scenario: Consumer turns email confirmation off
- **WHEN** email confirmation is off on the enrolment path and an enrolment-only session finishes a registration
- **THEN** the credential is active at once

#### Scenario: Full sessions are not asked for an emailed code
- **WHEN** a fresh full session finishes a registration
- **THEN** no emailed code is sent

### Requirement: A pending or suspended passkey is not usable
A credential in the pending or suspended state SHALL NOT complete a passwordless login, and SHALL NOT verify as a second factor. It SHALL NOT count toward the user being enrolled on the passkey MFA method, so the usable-methods function never offers the passkey method to a user whose only passkeys are pending or suspended. A passwordless login presenting a pending credential SHALL be refused with the pending-passkey refusal. A login or verification presenting a suspended credential SHALL be refused with the passkey-suspended refusal. Neither SHALL update the credential's counter.

#### Scenario: Pending credential at login
- **WHEN** `u-1` presents a valid assertion from a pending credential at the passwordless finish
- **THEN** it is refused with the pending-passkey refusal and no session is created

#### Scenario: Only pending passkeys
- **WHEN** `u-1`'s only passkey is pending and `u-1` logs in by password
- **THEN** the usable methods offered do not include `passkey`

#### Scenario: Suspended credential as a second factor
- **WHEN** `u-1` answers a passkey challenge with a suspended credential
- **THEN** it is refused with the passkey-suspended refusal and the challenge stays pending

### Requirement: Binding a passkey on a confined session moves it to the MFA-pending state
When a credential becomes active for a session in the enrolment-pending or recovery-pending state, the library SHALL move that session to the MFA pending state. This happens at finish, or at the last confirmation that activates it. The session SHALL keep its confinement marker and any recovery time, and SHALL be saved. The user SHALL then prove the new passkey through the MFA begin and verify endpoints. The MFA verify endpoint SHALL resolve the challenge, restore the session's deadlines and rotate it, as it does for an enrolment confirmed through the path. A registration on a full session SHALL NOT change the session's second-factor state. A credential that is still pending SHALL leave the session's state unchanged.

#### Scenario: Recovery route through a passkey
- **WHEN** a recovery-pending session created at 09:00 registers a passkey, begins the passkey challenge at `/mfa/begin/passkey` and posts a valid assertion to `/mfa/verify/passkey` at 09:05, with a 12-hour absolute timeout
- **THEN** the rotated session reports a satisfied second factor, an absolute deadline of 21:00 and a recovery time of 09:00

#### Scenario: Registration alone is not a second factor
- **WHEN** an enrolment-only session's passkey has just become active and the session requests `/invoices`
- **THEN** an MFA challenge error is returned, listing `passkey`

#### Scenario: Pending credential leaves the session confined
- **WHEN** an enrolment-only session finishes a registration awaiting its emailed code
- **THEN** the session is still in the enrolment-pending state

### Requirement: Binding a passkey notifies the user
When a credential becomes active, the library SHALL send the user a plain-text notice naming the passkey's name and the time. The notice SHALL say how to repudiate a registration the user did not make, with contact details the consumer configures. It SHALL contain no challenge, code, credential ID or public key. The contact address SHALL come from a contact resolver, by default the username, replaceable by the consumer. Delivery SHALL be non-blocking: a sender that delivers synchronously SHALL be refused at construction unless the consumer explicitly accepts synchronous delivery. A notice the sender refuses to queue SHALL be logged and SHALL NOT undo the registration. A missing sender, or missing repudiation contact details, SHALL fail construction. A consumer SHALL be able to replace every passkey notice's subject and body through a message builder, while the library still sets the recipient.

The finish response SHALL report whether the new credential is backup-eligible. When every active passkey the user holds is device-bound (not backup-eligible), the response SHALL also report that the user has no synced passkey, so the consumer's interface can advise registering a second one.

#### Scenario: Notice on binding
- **WHEN** `u-1`, whose username is `ana@example.com`, registers a passkey named `Phone` that becomes active
- **THEN** a notice is queued to `ana@example.com` naming `Phone`, the time and the repudiation contact details
- **AND** it contains no challenge, code or credential ID

#### Scenario: Pending credential notifies later
- **WHEN** a credential awaiting saved codes is confirmed
- **THEN** the notice is queued at confirmation, not at finish

#### Scenario: Only device-bound passkey
- **WHEN** `u-1`'s first passkey is a security key that is not backup-eligible
- **THEN** the finish response reports that `u-1` has no synced passkey

#### Scenario: Synchronous sender
- **WHEN** passkeys are enabled with a synchronous sender and synchronous delivery is not accepted
- **THEN** construction fails with a configuration error

### Requirement: Users list, name and remove their own passkeys
A full session SHALL be able to:
- **list** its user's passkeys with a GET request, each with its identifier, name, state, creation and last-use times, backup flags, transports and authenticator model identifier. The list SHALL include no public key;
- **rename** one, with a POST naming its identifier and a new name, under the same name rules as registration;
- **remove** one, with a POST naming its identifier. A removal SHALL require the same assurance and freshness as registration, and SHALL notify the user as a binding does, naming the removed passkey. A suspended passkey SHALL be removable.

An identifier that names no passkey of the session's user SHALL be refused with the passkey-not-found refusal, whether it names another user's passkey or none, and SHALL change nothing. Confined sessions and sessions with a pending challenge SHALL NOT reach these endpoints. Every response SHALL be written through a replaceable responder. The documentation SHALL state that removing a user's last active passkey leaves a passwordless-only user to account recovery.

#### Scenario: List
- **WHEN** `u-1` holds an active and a suspended passkey and lists them
- **THEN** both are listed with their states, and no public key appears in the response

#### Scenario: Another user's passkey
- **WHEN** `u-1` asks to remove a passkey identifier belonging to `u-2`
- **THEN** it is refused with the passkey-not-found refusal and `u-2`'s passkey still exists

#### Scenario: Stale removal
- **WHEN** a session whose latest authentication is 20 minutes old removes a passkey with default options
- **THEN** it is refused with the reauthentication-required refusal and the passkey still exists

#### Scenario: Rename
- **WHEN** `u-1` renames a passkey to `Old phone`
- **THEN** listing reports the name `Old phone`

### Requirement: Passwordless login is a begin and finish ceremony bound to a ceremony cookie
Passwordless login SHALL be off unless the consumer enables it. Its begin endpoint SHALL answer POST requests without a session. It SHALL:
- issue a pending challenge: a one-time token of the purpose `passkey-login`, expiring after 5 minutes by default, bound to a fresh random value of 32 bytes from the cryptographically secure random source;
- set that value in a ceremony cookie;
- answer with request options carrying the relying-party ID, the challenge, the timeout equal to the challenge lifetime, user verification `required`, and no allowed credentials, so the client offers the user's discoverable passkeys.

The ceremony cookie SHALL:
- be HttpOnly and Secure, with SameSite Strict;
- be scoped to the passwordless finish path;
- have a lifetime equal to the challenge lifetime.

Its name SHALL be replaceable by an option. Every finish response, whether accepted or refused, SHALL clear the cookie with an expired cookie of the same name and path. A finish SHALL be refused with the authentication-failed refusal when it has no ceremony cookie, or when the cookie's value does not match the challenge's binding. Begin SHALL write before anyone is authenticated, so it SHALL be guarded by the chain's source throttle step under a flow of its own. It SHALL record every begin, by default 30 per source per 15 minutes, with the limiter replaceable by an option. A source over the limit SHALL be refused as throttled, and an unattributable source SHALL be refused as for every throttled flow. The library SHALL remove expired login challenges from the store at most once per challenge lifetime, as part of a begin. A failed removal SHALL NOT refuse the begin.

#### Scenario: Usernameless begin
- **WHEN** a client without a session posts to the passwordless begin path
- **THEN** the response carries request options with a challenge and no allowed credentials
- **AND** a ceremony cookie that is HttpOnly, Secure, SameSite Strict, scoped to the finish path, with a 5-minute lifetime

#### Scenario: Another browser
- **WHEN** a finish answers a challenge issued to a browser whose ceremony cookie it does not carry
- **THEN** it is refused with the authentication-failed refusal

#### Scenario: Begin throttled per source
- **WHEN** one source begins 30 passwordless logins within 15 minutes and then begins again
- **THEN** the 31st begin is refused as throttled and no challenge is issued

#### Scenario: Cookie cleared on refusal
- **WHEN** a finish is refused for a wrong signature
- **THEN** the response clears the ceremony cookie

#### Scenario: Off by default
- **WHEN** passkeys are enabled without passwordless login and a POST is sent to the passwordless begin path
- **THEN** no challenge is issued by the library

### Requirement: A passwordless finish verifies the assertion and completes the login
The passwordless finish endpoint SHALL answer POST requests, and SHALL, in order:
1. read the assertion as a JSON body;
2. take from it the challenge the client answered, then check and spend the challenge against the ceremony cookie's binding;
3. find the credential by its ID, refusing an unknown one with the authentication-failed refusal;
4. refuse a pending or suspended credential, as defined for those states;
5. require the response's user handle, and require it to equal the handle mapped to the credential's user, refusing a mismatch with the authentication-failed refusal;
6. verify the assertion against the stored public key, the relying-party ID, the allowed origins and the challenge, requiring user presence, and user verification unless relaxed;
7. run the consumer's login check;
8. record the counter and flags, applying the clone rule;
9. load the user by the credential's user reference, refusing an unknown or disabled user with the authentication-failed refusal;
10. complete the login through the chain's login completion step, recording the `passkey` first factor.

Every refusal SHALL leave no session. A refused finish SHALL NOT reveal whether the credential exists to a client that does not hold its private key: an unknown credential, a handle mismatch and a bad signature SHALL be the same refusal.

#### Scenario: Passwordless login
- **WHEN** `u-1` answers a passwordless challenge with a valid, user-verified assertion from an active passkey
- **THEN** a session recording the `passkey` first factor is created and a credential for it is returned

#### Scenario: Unknown credential
- **WHEN** an assertion names a credential ID no user holds
- **THEN** it is refused with the authentication-failed refusal

#### Scenario: Handle of another user
- **WHEN** an assertion from `u-1`'s credential carries `u-2`'s user handle
- **THEN** it is refused with the authentication-failed refusal and no session is created

#### Scenario: Disabled user
- **WHEN** `u-1` is disabled and presents a valid assertion
- **THEN** it is refused with the authentication-failed refusal

#### Scenario: Password change still challenged
- **WHEN** `u-1`, whose password is older than the password-age policy allows, logs in with a user-verified passkey
- **THEN** the login is refused with a password-change challenge carrying a session, exactly as form login would refuse it

### Requirement: Every ceremony challenge is spent by any attempt and never taken from the client
For registration, passwordless login and the passkey second factor alike, a challenge SHALL be spent by any finish or verification that presents it on the session or ceremony cookie it was bound to, whether the attempt is then accepted or refused. Of concurrent attempts presenting one challenge, at most one SHALL proceed to verification. A challenge SHALL only ever be compared with one the library issued, never accepted from the request alone. The rest of the ceremony's expectations (relying party, origins, user verification, allowed credentials) SHALL be rebuilt at finish from configuration and the credential store, never read from the request. The challenge SHALL be the one-time token string, whose secret is 32 random bytes.

#### Scenario: One try per challenge
- **WHEN** a passwordless finish presenting an issued challenge is refused for a bad signature, and a second finish presents the same challenge with a valid assertion
- **THEN** the second is refused with the authentication-failed refusal

#### Scenario: Racing finishes
- **WHEN** 8 registration finishes presenting the same issued challenge run at the same time
- **THEN** at most one proceeds to verify the response

#### Scenario: Challenge invented by the client
- **WHEN** a finish carries an assertion signed over a challenge the library never issued
- **THEN** it is refused with the authentication-failed refusal

### Requirement: WebAuthn responses are read by the library as bounded JSON bodies
The registration finish, the passwordless finish and the passkey second factor SHALL each read the authenticator's response through the library's JSON body reader. They SHALL read the request body only, never the URL query. They SHALL require a JSON content type, and SHALL bound the body by default at 64 KiB for a registration and 16 KiB for an assertion. A body over the limit SHALL be refused as too large. A body that is empty, of another content type or does not parse SHALL be refused as missing credentials. Neither refusal SHALL be counted against any throttle. No passkey code SHALL read the request itself. The passkey MFA method SHALL declare the JSON body format to the MFA slot.

#### Scenario: Form body
- **WHEN** a passwordless finish is posted as a URL-encoded form
- **THEN** it is refused as missing credentials

#### Scenario: Oversized registration
- **WHEN** a registration finish body is 70 KiB
- **THEN** it is refused as too large and the challenge is not spent

#### Scenario: Assertion in the query string
- **WHEN** a passwordless finish carries its assertion in the query string and an empty body
- **THEN** it is refused as missing credentials

### Requirement: User verification is required by default
Every ceremony SHALL ask for user verification `required`, and an assertion or attestation without the user-verified flag SHALL be refused with the authentication-failed refusal. A consumer SHALL be able to relax this to `preferred`, for security keys without a PIN. An assertion without user verification then proves possession only: a passwordless login made with one SHALL be single-factor, and SHALL NOT record a second factor. The documentation of the option SHALL say so.

#### Scenario: Assertion without user verification
- **WHEN** user verification is required and a passwordless assertion arrives without the user-verified flag
- **THEN** it is refused with the authentication-failed refusal

#### Scenario: Consumer relaxes user verification
- **WHEN** user verification is `preferred` and `u-1`, who is not required to use MFA and is enrolled on no other method, logs in with an assertion without the user-verified flag
- **THEN** the login completes on the first factor alone, and the session records no satisfied second factor

### Requirement: A user-verified passkey login satisfies the second factor
A passwordless login whose assertion carried the user-verified flag SHALL hand the login completion step a proof that its second factor was met at the first factor. Only the library's own passkey verification SHALL be able to produce that proof. Its type SHALL have no public constructor, and its zero value SHALL prove nothing. The login completion step SHALL create the session with its second factor satisfied, recording the satisfied time and that the passkey login met it, in the write that creates the session. The MFA challenge SHALL therefore never be raised for that login. The proof is not an MFA exemption: the `passkey` kind stays non-exempt, and a login without the proof is judged like any other non-exempt login. A consumer SHALL be able to require a separate second factor even after a user-verified passkey login, by an option on passwordless login that stops the proof from being produced. The user must then complete a second factor on a channel other than the passkey's.

#### Scenario: Required user signs in with a passkey alone
- **WHEN** `u-1` is required to use MFA, is enrolled on no other method, and logs in with a user-verified passkey
- **THEN** a full session is created, reporting a satisfied second factor met by the passkey login

#### Scenario: Consumer requires a separate second factor
- **WHEN** the option requiring a separate second factor is set, and `u-1`, required to use MFA and enrolled on TOTP, logs in with a user-verified passkey
- **THEN** the login is refused with an MFA challenge listing `totp` only

#### Scenario: Separate factor with nothing else enrolled
- **WHEN** the same option is set, the enrolment path is off, and `u-1`, required to use MFA and holding only passkeys, logs in with a user-verified passkey
- **THEN** the login is refused with the enrolment-required reason

### Requirement: Passkeys serve as a challenge-capable MFA method
The library SHALL provide an MFA method named `passkey` that reports the `public-key` channel and declares a begin step and a JSON body response. A user SHALL be enrolled on it when they hold at least one active passkey. A failed lookup SHALL be an error, never "not enrolled". Its begin data SHALL be request options listing the user's active credentials as allowed credentials, including credentials that are not discoverable. The challenge SHALL be the one the MFA slot issued. Verification SHALL require the assertion to come from one of the session's user's active credentials, and SHALL verify it as at the passwordless finish, except that user presence without user verification SHALL be accepted when user verification is relaxed to `preferred`, since a second factor proves possession. The method's channel SHALL equal the `passkey` kind's channel, so a passkey never serves as the second factor of a passkey login. The method SHALL be able to remove all of a user's passkeys for the operator reset.

#### Scenario: Passkey after a password
- **WHEN** `u-1`, enrolled only on the passkey method, logs in by password, begins at `/mfa/begin/passkey` and posts a valid assertion to `/mfa/verify/passkey`
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

### Requirement: A suspected clone is refused and its credential suspended
When an accepted assertion's signature counter and the stored counter are not both zero, and the new counter is not greater than the stored one, the library SHALL treat the credential as cloned. This SHALL be decided by the write that records the counter: the counter SHALL be recorded only where the stored value is lower, or where both are zero. By default the library SHALL:
- refuse the login or verification with the clone-suspected refusal, which SHALL NOT count as a failed verification or a wrong guess;
- set the credential's state to suspended;
- notify the user, naming the passkey and the time, with instructions to remove it and register a new one, and the repudiation contact details.

A suspended credential SHALL never be reinstated by the library. It is cleared by removing it from a full session established another way, or by an account recovery's reset. A consumer SHALL be able to choose instead:
- **signal only:** allow the login, keep the stored counter, and write a sampled warning naming the credential's identifier;
- **a consumer function:** given the user, the credential's identifier, both counters and the backup flags, it returns allow, refuse, or refuse and suspend.

Credentials whose authenticator always reports a counter of zero, as synced passkeys do, SHALL never be affected.

#### Scenario: Counter goes backwards
- **WHEN** `u-1`'s security key credential has a stored counter of 42 and an assertion arrives with a counter of 41
- **THEN** the login is refused with the clone-suspected refusal, the credential is suspended, and a notice is queued

#### Scenario: Equal non-zero counter
- **WHEN** the stored counter is 42 and an assertion arrives with a counter of 42
- **THEN** the login is refused with the clone-suspected refusal

#### Scenario: Synced passkey
- **WHEN** a credential's stored counter is 0 and an assertion arrives with a counter of 0
- **THEN** the login proceeds

#### Scenario: Concurrent assertions with one counter
- **WHEN** two assertions from different challenges, both carrying counter 43 over a stored 42, are recorded at the same time
- **THEN** exactly one is accepted and the other is treated as a suspected clone

#### Scenario: Consumer chooses signal only
- **WHEN** the signal-only mode is chosen and an assertion arrives with a counter lower than the stored one
- **THEN** the login proceeds, the credential stays active, and a warning is written through the sampler

#### Scenario: Consumer function for administrators
- **WHEN** the consumer's function refuses and suspends only for users in its administrator group, and a non-administrator's counter goes backwards
- **THEN** the login proceeds as the function returned allow

### Requirement: Counters, flags and last use are recorded on every accepted assertion
On every accepted assertion, whether at a passwordless login or as a second factor, the library SHALL record on the credential:
- the new signature counter, under the clone rule;
- the backup-state flag;
- the time of last use.

This SHALL happen after the consumer's login check and before the login or verification completes. The library SHALL refuse with the authentication-failed refusal an assertion whose backup-eligible flag differs from the one stored at registration. A consumer SHALL be able to supply a login check, given the user, the credential's identifier, its authenticator model identifier, its backup flags and whether the assertion was user-verified. It SHALL run after verification and before anything is written, and an error it returns SHALL refuse the login unchanged.

#### Scenario: Backup state recorded
- **WHEN** a credential registered as not backed up is used in an assertion reporting backed up
- **THEN** the stored backup-state flag reads backed up

#### Scenario: Backup eligibility changed
- **WHEN** a credential registered as not backup-eligible is used in an assertion reporting backup-eligible
- **THEN** it is refused with the authentication-failed refusal

#### Scenario: Consumer login check
- **WHEN** the consumer's login check refuses device-bound credentials for a user, and that user presents one
- **THEN** the login is refused with the consumer's error and the credential's counter is unchanged

### Requirement: Passkeys take part in the recovery reset and the way-back check
The library SHALL provide an authenticator kind `passkey` for the account-recovery reset port. It SHALL list as held every passkey the user holds, in any state, each referenced by its identifier. It SHALL remove the passkeys it is told to. A failed listing SHALL be an error, never an empty list. For the other-way-back-in check, only active passkeys SHALL count, so a pending or suspended passkey never counts as a way back in. A passkey SHALL never be presented as a recovery proof. The default reset therefore removes every passkey the user holds.

#### Scenario: Default reset removes passkeys
- **WHEN** `u-1` holds two active passkeys and a TOTP enrolment, and recovers with a saved code and an issued code
- **THEN** `u-1` holds no passkey and no TOTP enrolment afterwards

#### Scenario: Reported loss of one passkey
- **WHEN** the reported-loss mode is chosen and `u-1` recovers reporting only their security key lost
- **THEN** that passkey is removed and `u-1`'s synced passkey stays

#### Scenario: Pending passkey is no way back
- **WHEN** `u-1`'s only authenticator is a pending passkey and issued codes are enabled
- **THEN** the way-back check does not count it

### Requirement: Passkey wiring mistakes fail at construction
Passkey endpoints SHALL NOT exist until the consumer enables passkeys on the chain. Construction SHALL fail with a configuration error when:
- passwordless login is enabled while saved recovery codes are not wired to registration, unless the optional mode is chosen;
- trusted attestation is required with no metadata source;
- the relying party is missing or malformed;
- no sender, or no repudiation contact, is configured;
- a synchronous sender is configured without accepting synchronous delivery;
- a challenge lifetime, freshness window, issuance limit or passkey limit is zero or less;
- any endpoint path is empty, lacks a leading `/`, or equals another passkey path, the login path, the logout path, or a path under the MFA verify or begin prefixes.

#### Scenario: Passwordless without recovery codes
- **WHEN** passwordless login is enabled, no saved recovery codes are wired, and the optional mode is not chosen
- **THEN** construction fails with a configuration error

#### Scenario: Optional mode accepted
- **WHEN** the same configuration chooses the optional mode
- **THEN** construction succeeds

#### Scenario: Path collision
- **WHEN** the passwordless finish path is set to the logout path
- **THEN** construction fails with a configuration error

### Requirement: Passkey endpoints have documented default paths
When enabled, the passkey endpoints SHALL answer at these default paths, each replaceable by an option:
- registration begin `/passkey/register/begin`, finish `/passkey/register/finish`, saved-code confirm `/passkey/register/confirm`, emailed-code confirm `/passkey/register/confirm-email`, each POST;
- listing `/passkey/credentials` (GET), rename `/passkey/credentials/rename` (POST), remove `/passkey/credentials/remove` (POST);
- passwordless begin `/passkey/login/begin` and finish `/passkey/login/finish`, each POST, only when passwordless login is enabled.

The passkey second factor SHALL answer at the MFA slot's paths for the method name `passkey`, by default `/mfa/begin/passkey` and `/mfa/verify/passkey`. Any other HTTP method on a passkey path SHALL pass through without touching a challenge or a credential. Begin data, finish results and listings SHALL be written through replaceable responders, and the default responses SHALL be documented JSON bodies.

#### Scenario: GET on a finish path
- **WHEN** a GET request is sent to `/passkey/login/finish`
- **THEN** it passes through and no challenge is spent

#### Scenario: Consumer paths
- **WHEN** the registration prefix paths are configured under `/account/passkeys` and a fresh session begins at `/account/passkeys/begin`
- **THEN** a challenge is issued

### Requirement: Passkey logs carry no secrets
Records written by the passkey component SHALL contain no challenge, emailed code, saved code, user handle, public key, attestation statement or contact address. A credential SHALL be named in logs only by its library identifier. Refusals at the passwordless endpoints, clone signals and notice failures SHALL be written through log samplers with reporters, keyed by refusal reason. Each sampler's window SHALL default to one minute and be configurable by an option governing only passkey logs.

#### Scenario: No challenge in logs
- **WHEN** a passwordless finish is refused for a bad signature
- **THEN** no written log record contains the challenge or the credential's public key

#### Scenario: Sampled refusals
- **WHEN** 200 passwordless finishes are refused within one minute for an unknown credential
- **THEN** one refusal record is written for that minute, and the reporter receives the suppressed count
