# Spec Delta

## ADDED Requirements

### Requirement: A session's provider forwarding tokens are stored sealed and bound to its session
A durable session store SHALL store a session's provider access token and refresh token sealed, as it stores the retained provider ID token, bound to the session's identifier, together with the access token's expiry, and SHALL return them unchanged on load. A supersession SHALL store the successor's copies sealed for the successor's identifier. Saving a session SHALL NOT change them.

#### Scenario: Tokens reloaded
- **WHEN** a session holding `at-1`, `rt-1` and expiry 11:00:00 is created in a durable store and loaded
- **THEN** the loaded session holds `at-1`, `rt-1` and 11:00:00, and neither token column equals or contains its token

#### Scenario: Tokens survive supersession
- **WHEN** a session holding `at-1` and `rt-1` is renewed in a durable store and the successor is loaded
- **THEN** the successor holds `at-1` and `rt-1`

#### Scenario: Copied token does not open
- **WHEN** the sealed refresh token of one session is copied, out of band, into another session's row and that session is loaded
- **THEN** the load fails as an unreadable session, and the token is not returned

#### Scenario: Existing rows
- **WHEN** a session stored before the provider-token columns existed is loaded after the migration
- **THEN** it loads with no provider tokens

### Requirement: Durable stores replace provider tokens with one conditional write
Every session store, in memory and durable, SHALL implement the conditional replacement of provider tokens as a single write whose conditions are all checked by that write: the session exists, is not superseded, and holds the refresh token the caller names. Concurrent replacements naming the same refresh token SHALL result in exactly one success.

#### Scenario: Racing replacements
- **WHEN** two callers concurrently replace the tokens of one session, each naming `rt-1`, one with `rt-2` and one with `rt-3`
- **THEN** exactly one write applies, the session holds that writer's tokens, and the other write reports that it did not apply

#### Scenario: Conformance on every backend
- **WHEN** the store conformance suite runs against the in-memory, `database/sql`, pgx and GORM session stores
- **THEN** each passes the conditional replacement cases, including the superseded and deleted session cases
