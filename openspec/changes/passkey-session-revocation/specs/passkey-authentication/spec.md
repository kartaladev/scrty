# Spec Delta

## ADDED Requirements

### Requirement: Removing a passkey ends the user's other sessions
By default, a removal SHALL delete every session of the user except the session that made the removal, before the passkey is deleted. The removing session SHALL stay valid. The removal notice SHALL say whether other sessions were ended. A consumer SHALL be able to make keeping the other sessions the default.

#### Scenario: Other sessions end on removal
- **WHEN** `u-1` has sessions on a laptop, a phone and a tablet, and removes a passkey from the laptop session
- **THEN** the passkey is removed, the phone and tablet sessions no longer load, the laptop session still loads, and the removal notice says other sessions were ended

#### Scenario: Consumer keeps sessions by default
- **WHEN** the consumer turns removal revocation off and `u-1` removes a passkey
- **THEN** the passkey is removed, every session of `u-1` still loads, and the removal notice does not say sessions were ended

### Requirement: A removal request chooses whether other sessions end
A removal request SHALL accept an optional field `other_sessions`. `keep` SHALL keep the user's other sessions for that request, and `end` SHALL end them, whatever the default. Any other value SHALL be refused as a malformed request that changes nothing.

#### Scenario: The user keeps other sessions
- **WHEN** with default options, a removal posts `other_sessions=keep`
- **THEN** the passkey is removed and every session of `u-1` still loads

#### Scenario: The user ends other sessions against a keep default
- **WHEN** the consumer turned removal revocation off and a removal posts `other_sessions=end`
- **THEN** the passkey is removed and only the removing session of `u-1` still loads

#### Scenario: Unknown choice
- **WHEN** a removal posts `other_sessions=maybe`
- **THEN** it is refused as a malformed request, the passkey still exists, and every session still loads

### Requirement: A removal whose sessions cannot be ended changes nothing
When ending the user's other sessions fails, the removal SHALL be refused, the passkey SHALL stay in place, and no removal notice SHALL be queued, so the user can retry.

#### Scenario: Sessions cannot be ended
- **WHEN** ending `u-1`'s other sessions fails during a removal
- **THEN** the removal is refused, the passkey still exists, and no removal notice is queued

### Requirement: Suspending a suspected clone ends the user's sessions
By default, when a suspected clone suspends a credential, the library SHALL delete every session of the credential's user, including a session that presented the clone at second-factor verification. The refusal SHALL stay the clone-suspected refusal, and the suspension notice SHALL say whether the sessions were ended. A consumer SHALL be able to turn this revocation off.

#### Scenario: Clone at passwordless login
- **WHEN** `u-1` has two sessions and a passwordless login presents `u-1`'s security key with a counter lower than the stored one
- **THEN** the login is refused with the clone-suspected refusal, the credential is suspended, neither session loads, and the suspension notice says the sessions were ended

#### Scenario: Clone as a second factor
- **WHEN** a session pending its second factor for `u-1` answers a passkey challenge with a counter lower than the stored one, while `u-1` has one other session
- **THEN** the clone-suspected refusal is returned and neither the pending session nor the other session loads

#### Scenario: Consumer keeps sessions on a clone
- **WHEN** the consumer turns clone revocation off and a clone suspends `u-1`'s credential
- **THEN** the clone-suspected refusal is returned, the credential is suspended, and `u-1`'s existing sessions still load

### Requirement: Clone revocation never weakens the refusal
Sessions SHALL be ended only when a credential is suspended: signal-only mode, and a consumer function that allows or only refuses, SHALL end no session. Ending the sessions SHALL NOT depend on the requesting client staying connected. A failure to end them SHALL be logged and SHALL NOT turn the refusal into an acceptance.

#### Scenario: Signal only ends nothing
- **WHEN** signal-only mode is chosen and an assertion arrives with a counter lower than the stored one
- **THEN** the login proceeds and every existing session of the user still loads

#### Scenario: Revocation fails
- **WHEN** a clone suspends a credential and deleting the user's sessions fails
- **THEN** the clone-suspected refusal is still returned, the credential is suspended, and an error is logged

#### Scenario: Client disconnects
- **WHEN** a clone suspends a credential and the requesting client's context is cancelled before the sessions are deleted
- **THEN** the user's sessions are still deleted

## MODIFIED Requirements

### Requirement: Passkey wiring mistakes fail at construction
Passkey endpoints SHALL NOT exist until the consumer enables passkeys on the chain. Construction SHALL fail with a configuration error when:
- passwordless login is enabled while saved recovery codes are not wired to registration, unless the optional mode is chosen;
- trusted attestation is required with no metadata source;
- the relying party is missing or malformed;
- no sender, or no repudiation contact, is configured;
- a synchronous sender is configured without accepting synchronous delivery;
- a challenge lifetime, freshness window, issuance limit or passkey limit is zero or less;
- no session manager is given to the passkey component while removal revocation or clone revocation is on;
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

#### Scenario: No session manager for revocation
- **WHEN** the passkey component is built with no session manager and both revocations left on
- **THEN** construction fails with a configuration error

#### Scenario: Both revocations off
- **WHEN** the passkey component is built with no session manager and both revocations turned off
- **THEN** construction succeeds
