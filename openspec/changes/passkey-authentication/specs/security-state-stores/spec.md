# Spec Delta

## MODIFIED Requirements

### Requirement: Durable stores exist for every security-state record on every supported backend
scrty SHALL provide a durable store for each security-state record type (sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes, recovery records, passkey credentials and passkey user handles) on each supported database access backend. Each durable store SHALL satisfy the same store contract as the in-memory default for that record type. A record written through one store instance SHALL be visible to every other store instance, on any supported backend, connected to the same database.

#### Scenario: State survives a process restart
- **WHEN** a session is saved through a durable store, the process exits, and a new store instance is created against the same database
- **THEN** loading the session through the new instance returns the saved session

#### Scenario: Another replica sees a consumption
- **WHEN** a one-time token is consumed through a store instance in one process
- **AND** a second process tries to consume the same token through its own store instance
- **THEN** the second consumption is refused

#### Scenario: Handoff subject round trip
- **WHEN** a handoff is inserted with user reference `Alice@Example.com`, provider, issuer, external session id and next location, and is found by its token id
- **THEN** every one of those values is returned exactly as inserted

#### Scenario: Backends share one schema
- **WHEN** an API key is inserted through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, finds that API key with every attribute equal

#### Scenario: Passkey seen by another backend
- **WHEN** a passkey credential is inserted through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, finds it by its credential ID with every attribute equal

## ADDED Requirements

### Requirement: Passkey credentials are unique, and their state changes are decided by the write
A passkey credential store SHALL keep, per credential, a library identifier and the user reference. It SHALL also keep:
- the credential ID and public key, as bytes;
- the signature counter;
- the backup-eligible and backup-state flags;
- the transports;
- the authenticator model identifier;
- the attestation format and statement, when recorded;
- the name;
- the creation and last-use times;
- the state: active, pending or suspended;
- the pending reasons;
- for a credential awaiting its emailed code, the sealed code, its expiry and the attempts charged.

It SHALL:
- **insert** a credential, refusing one whose credential ID is already stored, whatever its user, with a duplicate outcome decided by the write;
- **find** a credential by credential ID, and by library identifier within a user;
- **list** a user's credentials, and **count** them;
- **record an assertion** by one conditional write that sets the counter, the backup-state flag and the last-use time only where the credential is active and the stored counter is lower than the new one, or both are zero. It SHALL report whether this call recorded it;
- **suspend** a credential, and **clear one pending reason**, each by one conditional write on its current state, reporting whether this call changed it. Clearing the last pending reason SHALL make the credential active;
- **charge an emailed-code attempt** by one conditional write that succeeds only while the code is outstanding, unexpired and has fewer than five attempts charged;
- **rename** and **delete** a credential within a user, and **delete every credential of a user** awaiting saved codes;
- **delete every credential of a user**, returning how many were removed.

A refused write SHALL change nothing. The emailed code SHALL be sealed at rest with the store's cipher, which durable stores SHALL require at construction. A read that cannot open a sealed code SHALL be an error, never a missing code. The in-memory store SHALL be the default, SHALL hold its own copies of byte values, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Duplicate credential ID
- **WHEN** a credential with ID C is stored for `u-1`, and another with ID C is inserted for `u-2`
- **THEN** the second insert is refused as a duplicate and `u-1`'s credential is unchanged

#### Scenario: Concurrent counter recordings
- **WHEN** 8 callers record counter 43 on the same credential whose stored counter is 42, at the same time
- **THEN** exactly one recording succeeds

#### Scenario: Counter going backwards is not recorded
- **WHEN** a recording of counter 41 is made on a credential whose stored counter is 42
- **THEN** it is refused and the stored counter is still 42

#### Scenario: Zero counters are recorded
- **WHEN** a recording of counter 0 is made on a credential whose stored counter is 0
- **THEN** it succeeds and the last-use time is updated

#### Scenario: Suspended credential is not recorded
- **WHEN** a recording is made on a suspended credential
- **THEN** it is refused and nothing changes

#### Scenario: Attempts bounded under concurrency
- **WHEN** 20 attempts are charged at the same time on a credential awaiting its emailed code
- **THEN** exactly five are charged

#### Scenario: Last reason cleared activates
- **WHEN** a credential pending on both its emailed code and saved codes has the emailed-code reason cleared and then the saved-code reason cleared
- **THEN** it is pending after the first clearing and active after the second

### Requirement: Passkey user handles are assigned once per user
A passkey user-handle store SHALL map each user reference to one handle, and each handle to one user reference. Assigning a handle SHALL be one write that stores the offered handle only when the user has none, and SHALL return the handle the user holds afterwards, whether newly stored or already present. Of concurrent assignments for one user, every caller SHALL receive the same handle. Looking a handle up SHALL return its user reference, or report that no user holds it. The in-memory store SHALL be the default.

#### Scenario: Concurrent assignment
- **WHEN** 8 callers assign different offered handles to `u-1`, who has none, at the same time
- **THEN** all 8 receive the same handle, and exactly one handle is stored for `u-1`

#### Scenario: Reverse lookup
- **WHEN** `u-1` holds handle H and H is looked up
- **THEN** the lookup returns `u-1`

### Requirement: A second factor met at the first factor survives a durable store
Durable session stores SHALL store and return unchanged a session's met-by-first-factor marker. A session stored without it SHALL read back with it unset.

#### Scenario: Marker round trip across backends
- **WHEN** a session created satisfied by a user-verified passkey login is saved through the store of one supported backend and loaded through another
- **THEN** it loads in the satisfied state with the marker set and the same satisfied time

#### Scenario: Unmarked session
- **WHEN** a password session that satisfied TOTP is saved and loaded
- **THEN** it loads with the marker unset
