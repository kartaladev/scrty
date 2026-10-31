## Purpose

Decides whether a new password may be set: long enough, not common, not tied to the account or service, optionally not found in a known breach, and not a reuse of the user's own recent passwords; and runs the change that stores it.

## ADDED Requirements

### Requirement: One policy holds every rule for a new password
The library SHALL provide one password policy that checks a candidate password for a user and, on a change, stores it. With no options, the policy SHALL apply a minimum length of 15 characters and a list of common passwords, and nothing else. Each option SHALL replace or add only the rule it names, so setting one rule never removes another default; removing a default rule SHALL need an option whose name says so. Rules SHALL run cheapest first: length, then the common-password and context-word lists, then the breach check, then reuse. The first refusal SHALL end the check.

#### Scenario: Defaults
- **WHEN** a policy built with no options checks `correcthorsebatterystaple` for a user
- **THEN** the candidate is accepted
- **AND** a 16-character entry of the common-password list is refused as common, and `short` is refused as too short

#### Scenario: One option keeps the other defaults
- **WHEN** a policy is built with a minimum length of 8 and checks `password1`
- **THEN** it is refused as a common password

#### Scenario: Removing a default explicitly
- **WHEN** a policy is built with the common-password list removed and checks a 16-character entry of that list
- **THEN** the candidate is accepted

### Requirement: Length is counted in characters and long passwords are accepted
Length SHALL be counted in Unicode code points. The policy SHALL accept passwords of at least 64 characters, SHALL NOT truncate a password, and SHALL NOT impose composition rules such as a required digit, case or symbol. The minimum SHALL be replaceable; a minimum below 8 SHALL fail construction. The maximum the policy accepts SHALL be replaceable but no lower than 64. The bcrypt encoder's 72-byte limit SHALL remain its own refusal.

#### Scenario: Multi-byte characters
- **WHEN** a policy with a minimum of 15 checks a 15-character password whose characters each take 3 bytes
- **THEN** it passes the length rule

#### Scenario: Minimum too low
- **WHEN** a policy is built with a minimum length of 6
- **THEN** construction fails with a configuration error naming the minimum length

### Requirement: Common and context-specific passwords are refused
The policy SHALL refuse a candidate that equals, compared case-insensitively, an entry of the common-password list, which SHALL hold at least the 3,000 most common passwords. The consumer SHALL be able to supply context words, derived from the user and the service, that the candidate may not equal. The list SHALL be replaceable.

#### Scenario: Username as password
- **WHEN** context words include the username `alice.smith2026` and the candidate is `Alice.Smith2026`
- **THEN** the candidate is refused as a context word

### Requirement: The breach check is opt-in and its failure mode is the consumer's choice
When the consumer enables the breach check, the policy SHALL refuse a candidate found in the breach corpus. It SHALL send only the first five hexadecimal characters of the candidate's SHA-1 hash, with response padding requested, through the confined outbound client, and SHALL match the rest locally. Enabling the check SHALL require the consumer to choose whether a failed lookup refuses or accepts the candidate; construction SHALL fail without that choice. The lookup source SHALL be replaceable, so an offline copy of the corpus can be used.

#### Scenario: Breached password
- **WHEN** the breach check is enabled and the corpus lists the candidate's hash
- **THEN** the candidate is refused as breached

#### Scenario: Lookup outage, refuse
- **WHEN** the breach check is enabled with failures refusing and the lookup times out
- **THEN** the candidate is refused with the policy-unavailable error

#### Scenario: Failure mode not chosen
- **WHEN** the breach check is enabled without a failure mode
- **THEN** construction fails with a configuration error naming the breach check

### Requirement: Every refusal says which rule refused
A refusal SHALL be identifiable as a password-rejected error and SHALL name the rule that refused it: too short, too long, common, context word, breached or reused. The reused refusal SHALL also be the password-reused error. No refusal's text SHALL contain the candidate, a stored hash or the user reference.

#### Scenario: Reason for the user
- **WHEN** a candidate is refused as breached
- **THEN** the error is a password-rejected error whose rule is "breached", and its text contains neither the candidate nor the user reference

### Requirement: Reuse checking is a rule the consumer enables with a history and a depth
The policy SHALL NOT check or record password history unless the consumer adds the reuse rule with a password-history port and a depth N, which SHALL have no default. With it, a candidate matching the user's current hash or one of their N−1 most recent retired hashes SHALL be refused as reused; matching SHALL verify the candidate against each stored hash with the library's Argon2id, bcrypt and scrypt matchers and the policy's own encoder, never by re-encoding, and the extra matchers SHALL be replaceable. An absent current hash SHALL match nothing. No other library component SHALL check or record history on its own.

#### Scenario: Depth 3
- **WHEN** the reuse rule has depth 3, and a user whose provisioned password was `p1` changes it through the policy to `p2`, then `p3`, then `p4`
- **THEN** changing to `p4`, `p3` or `p2` is refused as reused, and changing to `p1` succeeds

#### Scenario: Retired algorithm still matches
- **WHEN** the policy's encoder is Argon2id and the user's history holds a bcrypt hash of `p1`
- **THEN** changing to `p1` is refused as reused

#### Scenario: New account
- **WHEN** a policy with the reuse rule checks a candidate for a user with no stored password and no history
- **THEN** the reuse rule accepts it

### Requirement: A change through the policy checks, retires, encodes and writes in order
A change SHALL run, stopping at the first failure: every rule's check; with the reuse rule, retiring the current hash and keeping only the newest N−1 retired hashes; encoding the candidate; and handing the user record, the new hash and the change time, read from the policy's replaceable clock, to the consumer's write. Retiring a hash identical to the newest retired hash SHALL add nothing. The library SHALL provide a ready-made write over any user provisioner that records the hash and the change time together.

#### Scenario: Retry after a failed write does not double-count
- **WHEN** a reuse rule of depth 3 is used, a user with current password `p2` and history `p1` changes to `p3`, the consumer's write fails, and the change is retried and succeeds
- **THEN** the history holds exactly `p2` and `p1`

#### Scenario: Consumer write receives the time
- **WHEN** the policy's clock returns `T` and a change succeeds
- **THEN** the write receives the user record, the new hash and `T`

### Requirement: The policy fails closed and keeps no credential
A history read or retire failure SHALL refuse the change with the history-unavailable error and SHALL NOT call the consumer's write. An error from the consumer's write SHALL be returned unchanged. The policy SHALL write no log record that contains the candidate or a hash, and SHALL NOT keep the candidate after the call returns.

#### Scenario: Retire failure
- **WHEN** the history port reads successfully but fails to retire the current hash
- **THEN** the change is refused with the history-unavailable error and the consumer's write is not called

### Requirement: Policy wiring mistakes fail at construction
Building a policy SHALL fail with a configuration error naming the mistake when given: a reuse rule without a history port (including a typed-nil one), or with a depth below one; no encoder for a change; an absent matcher or clock; a breach check without a lookup source or a failure mode; a minimum length below 8. A check or change given no user record, or a change given no write, SHALL fail with a configuration error and SHALL read and write nothing.

#### Scenario: Reuse depth zero
- **WHEN** a policy is built with the reuse rule at depth 0
- **THEN** construction fails with a configuration error naming the reuse depth
