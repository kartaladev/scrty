# Spec Delta

## MODIFIED Requirements

### Requirement: The security-state set creates only security-state tables
The security-state migration set SHALL create the tables for sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes and recovery records. It SHALL create no identity tables, SHALL declare no foreign key to any table outside the set, SHALL store every library-owned primary key in a native uuid column, and SHALL store every user reference in a text column. The set SHALL be embedded in the library as plain SQL, so applying it needs no files on disk.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** the eleven security-state tables and the set's version table exist
- **AND** no users, roles, organizations, groups or privileges table exists

#### Scenario: Column types
- **WHEN** the set has been applied
- **THEN** every security-state table's primary key column has type uuid
- **AND** every column holding a user reference has type text

#### Scenario: Single-use guards stay nullable
- **WHEN** the set has been applied
- **THEN** the consumption time columns of one-time tokens and handoffs, the completion time column of flows, the spending time column of saved recovery codes, and the completion and cancellation time columns of recovery records, are nullable and have no default

#### Scenario: Login attempt indexes
- **WHEN** the set has been applied
- **THEN** login attempts are indexed by login name and attempt time together
- **AND** separately by attempt time alone

#### Scenario: Saved codes are unique per user and hash
- **WHEN** the set has been applied
- **THEN** saved recovery codes are unique by user reference and hash together
- **AND** recovery records are indexed by user reference

