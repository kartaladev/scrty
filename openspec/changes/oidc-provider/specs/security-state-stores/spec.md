# Spec Delta

## ADDED Requirements

### Requirement: Durable stores exist for every provider record on every supported backend
Each SQL adapter (`database/sql`, `pgx` and GORM) SHALL provide a durable store for each provider record: clients, pending requests, authorization codes, consents, grants, refresh-token lineages, opaque access tokens, and seen client-assertion identifiers. Each SHALL behave as the in-memory default does.

#### Scenario: Each backend
- **WHEN** the provider is wired with the stores of any one SQL adapter
- **THEN** an authorization, a code exchange, a refresh and a revocation all succeed against that database

### Requirement: Codes, handles and assertion identifiers are consumed by the write
Spending an authorization code, spending a pending-request handle for a stage, and recording a client-assertion identifier SHALL each be decided by one conditional write. Under concurrent attempts exactly one SHALL succeed.

#### Scenario: Concurrent code exchanges
- **WHEN** two requests spend one code at once against a durable store
- **THEN** exactly one succeeds

#### Scenario: Concurrent assertion replay
- **WHEN** two requests record the same assertion identifier for one client at once
- **THEN** exactly one is recorded as new

### Requirement: A revoked grant stays revoked
Revoking a grant SHALL be one write that marks it revoked. No later write SHALL clear the mark, including a code exchange that commits after the code's replay revoked the grant. A grant created by an exchange SHALL be written so that a revocation recorded first for the same grant survives.

#### Scenario: Revocation before the grant is stored
- **WHEN** a code's replay revokes grant `g-1`, and the first exchange then stores `g-1`
- **THEN** `g-1` is stored revoked

### Requirement: Refresh-token lineages are kept apart from sign-ins
Refresh-token lineages SHALL be stored in a table of their own, never in the table that holds sign-in sessions. No sign-in lookup SHALL read the lineage table.

#### Scenario: Lineage identifier looked up as a session
- **WHEN** an identifier stored in the lineage table is loaded through the session store
- **THEN** it is not found

### Requirement: Provider stores hold no credential in clear
Stores SHALL keep codes, handles, refresh tokens, opaque access tokens and client secrets only as digests. They SHALL keep the consumer's client metadata and user references unchanged.

#### Scenario: Database read by an attacker
- **WHEN** the provider's tables are read directly after a code, a refresh token and a client secret were issued
- **THEN** none of the three appears in any column

### Requirement: A user's grants are revoked by one operation
A grant store SHALL revoke every grant of a user, and every grant of a user and client, each in one operation, in a bounded number of passes, whether or not the grants hold `offline_access`. It SHALL also revoke the grants without `offline_access` created from one sign-in.

#### Scenario: Revoke by sign-in
- **WHEN** user `u-1` holds an online and an offline grant from sign-in `s-1`, and the store revokes the online grants of `s-1`
- **THEN** the online grant is revoked and the offline grant is not

### Requirement: Expired provider records are swept
Expired pending requests, codes, opaque access tokens, assertion identifiers, and grants past their deadlines or revoked SHALL be removable by the expiry sweep. A revoked grant SHALL be kept until every code that could still name it has expired.

#### Scenario: Sweep
- **WHEN** the sweep runs after pending requests and codes expired
- **THEN** they are deleted, and unexpired ones are kept
