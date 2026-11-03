## ADDED Requirements

### Requirement: Durable session stores list a user's live sign-ins
Every durable session store SHALL list a user's live sign-ins as the `sessions` capability defines, answering from the existing index on the user reference so the cost does not grow with other users' sessions, and SHALL exclude expired and superseded members by the time the caller passes, not the database's clock. The user reference SHALL be matched exactly as the consumer supplied it.

#### Scenario: Listing across replicas
- **WHEN** a user signs in through two replicas sharing one PostgreSQL store
- **THEN** listing that user's sign-ins on either replica returns both

#### Scenario: Reference matched exactly
- **WHEN** users `Alice` and `alice` each have a live sign-in and `alice`'s sign-ins are listed
- **THEN** only `alice`'s sign-in is returned

### Requirement: Sign-in metadata and key binding survive a durable store
A durable session store SHALL persist a session's sign-in metadata and key binding, return them unchanged on load and in the listing, and SHALL NOT change either on save. The metadata SHALL be stored as plain text, since it is not a secret; the key binding SHALL be stored as its kind and thumbprint only. A supersession SHALL insert the successor with its binding and metadata.

#### Scenario: Bound session reloaded
- **WHEN** a session bound to DPoP key thumbprint `K`, with recorded metadata, is created in a durable store and loaded
- **THEN** the loaded session is bound to `K` and carries the same metadata

#### Scenario: Save leaves the binding
- **WHEN** a bound session is loaded, its binding cleared in memory, and saved
- **THEN** a fresh load is still bound

### Requirement: A session's CSRF token is stored sealed and bound to its session
A durable session store SHALL store a session's CSRF token sealed, as it stores the retained provider ID token, bound to the session's identifier, and SHALL return it unchanged on load. A supersession SHALL store the successor's copy sealed for the successor's identifier. Saving a session SHALL NOT change its token. A token copied to another session's row SHALL NOT open.

#### Scenario: Token reloaded
- **WHEN** a session carrying CSRF token `T` is created in a durable store and loaded
- **THEN** the loaded session carries `T`, and the stored column neither equals nor contains `T`

#### Scenario: Token survives supersession
- **WHEN** a session carrying `T` is renewed in a durable store and the successor is loaded
- **THEN** the successor carries `T`

#### Scenario: Copied token does not open
- **WHEN** the sealed token of one session is copied, out of band, into another session's row and that session is loaded
- **THEN** the load fails as an unreadable session, and the token is not returned
