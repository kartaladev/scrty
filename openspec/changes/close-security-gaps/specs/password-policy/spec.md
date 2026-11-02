## Purpose

Decides whether a new password may be set: long enough, not common, not tied to the account or service, optionally not found in a known breach, and not a reuse of the user's own recent passwords; and runs the change that stores it.

## ADDED Requirements

### Requirement: One policy holds every rule for a new password
The library SHALL provide one password policy that checks a candidate password for a user and, on a change, stores it. With no options, the policy SHALL apply a minimum length of 15 characters, a maximum of 128 characters, and a list of common passwords, and nothing else. Each option SHALL replace or add only the rule it names, so setting one rule never removes another default; removing a default rule SHALL need an option whose name says so. Rules SHALL run cheapest first: length, then the common-password and context-word lists, then the breach check, then reuse. The first refusal SHALL end the check, and no later rule SHALL run.

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

#### Scenario: A cheap refusal skips the breach lookup
- **WHEN** the breach check is enabled and a candidate is refused as too short
- **THEN** no lookup is made

### Requirement: Length is counted in characters and long passwords are accepted
Length SHALL be counted in Unicode code points of the candidate as given: the policy SHALL NOT trim, normalise or truncate it, and SHALL NOT impose composition rules such as a required digit, case or symbol. An empty candidate SHALL be refused as too short. The minimum SHALL be replaceable, and a minimum below 8 SHALL fail construction. The maximum SHALL be replaceable but no lower than 64, and no lower than the minimum. When the policy's encoder has a byte limit, as bcrypt's 72 bytes, a candidate over it SHALL be refused as too long by the check, so a check and a change agree. A consumer's encoder states its limit through an optional method; a change that its encoder still refuses as too long SHALL be refused as too long, never answered as a failure.

#### Scenario: Multi-byte characters
- **WHEN** a policy with a minimum of 15 checks a 15-character password whose characters each take 3 bytes
- **THEN** it passes the length rule

#### Scenario: Spaces count
- **WHEN** a policy with a minimum of 15 checks a candidate of 13 letters with a leading and a trailing space
- **THEN** it passes the length rule, and the spaces are kept in the stored hash

#### Scenario: Too long
- **WHEN** a policy with the default maximum checks a 129-character candidate
- **THEN** it is refused as too long

#### Scenario: Minimum too low
- **WHEN** a policy is built with a minimum length of 6
- **THEN** construction fails with a configuration error naming the minimum length

#### Scenario: Maximum too low
- **WHEN** a policy is built with a maximum length of 32
- **THEN** construction fails with a configuration error naming the maximum length

#### Scenario: bcrypt's byte limit
- **WHEN** a policy whose encoder is bcrypt checks a 30-character candidate whose characters each take 3 bytes
- **THEN** it is refused as too long by the check, before any change is attempted

### Requirement: Common and context-specific passwords are refused
The policy SHALL refuse a candidate that equals, compared case-insensitively, an entry of the common-password list, which SHALL hold at least the 3,000 most common passwords. The consumer SHALL be able to supply context words, derived from the user and the service. A candidate SHALL be refused as a context word when it equals one, or contains one of at least 4 characters, compared case-insensitively; shorter words SHALL be refused only on equality. The list SHALL be replaceable. A context-word function that fails SHALL fail the check with its error, which is a dependency failure, not a refusal.

#### Scenario: Username as password
- **WHEN** context words include the username `alice.smith2026` and the candidate is `Alice.Smith2026`
- **THEN** the candidate is refused as a context word

#### Scenario: Username inside the password
- **WHEN** context words include `alice.smith2026` and the candidate is `my-alice.smith2026-pass`
- **THEN** the candidate is refused as a context word

#### Scenario: Short word only on equality
- **WHEN** context words include the service name `abc` and the candidate is `abcdefghijklmnopq`
- **THEN** the context-word rule accepts it

### Requirement: The breach check is opt-in and its failure mode is the consumer's choice
When the consumer enables the breach check, the policy SHALL refuse a candidate found in the breach corpus. It SHALL send only the first five hexadecimal characters of the candidate's SHA-1 hash, with response padding requested, through the confined outbound client, and SHALL match the rest locally, ignoring entries whose count is zero, which are padding. Enabling the check SHALL require the consumer to choose whether a failed lookup refuses or accepts the candidate; construction SHALL fail without that choice. A failed lookup SHALL include a timeout, a non-success status, and a body that does not parse. The lookup source SHALL be replaceable, so an offline copy of the corpus can be used. When the request's own context ends during the lookup, the check SHALL fail with an error matching the context's error, whichever failure mode was chosen.

#### Scenario: Breached password
- **WHEN** the breach check is enabled and the corpus lists the candidate's hash with a count of 3
- **THEN** the candidate is refused as breached

#### Scenario: Padding entry
- **WHEN** the breach check is enabled and the range response lists the candidate's hash suffix only with a count of 0
- **THEN** the candidate is not refused as breached

#### Scenario: Lookup outage, refuse
- **WHEN** the breach check is enabled with failures refusing and the lookup times out
- **THEN** the check fails with the lookup-unavailable error, which is not a password refusal

#### Scenario: Lookup outage, accept
- **WHEN** the breach check is enabled with failures accepting and the lookup answers 429
- **THEN** the breach rule accepts the candidate and the next rule runs

#### Scenario: Malformed response
- **WHEN** the breach check is enabled with failures refusing and the range response is not lines of suffix and count
- **THEN** the check fails with the lookup-unavailable error

#### Scenario: Failure mode not chosen
- **WHEN** the breach check is enabled without a failure mode
- **THEN** construction fails with a configuration error naming the breach check

#### Scenario: Only the prefix leaves the process
- **WHEN** the breach check looks up a candidate
- **THEN** the outbound request carries only the five-character prefix and `Add-Padding: true`, and neither the candidate nor its full hash

### Requirement: Every refusal says which rule refused
A refusal SHALL be identifiable as a password-rejected error and SHALL name the rule that refused it: too short, too long, common, context word, breached or reused. The reused refusal SHALL also be the password-reused error. No refusal's text SHALL contain the candidate, a stored hash, a context word or the user reference.

#### Scenario: Reason for the user
- **WHEN** a candidate is refused as breached
- **THEN** the error is a password-rejected error whose rule is "breached", and its text contains neither the candidate nor the user reference

### Requirement: Reuse checking is a rule the consumer enables with a history and a depth
The policy SHALL NOT check or record password history unless the consumer adds the reuse rule with a password-history port and a depth N, which SHALL have no default. With it, a candidate matching the user's current hash or one of their N−1 most recent retired hashes SHALL be refused as reused; matching SHALL verify the candidate against each stored hash with the library's Argon2id, bcrypt and scrypt matchers and the policy's own encoder, never by re-encoding, and the extra matchers SHALL be replaceable. An absent current hash SHALL match nothing, and a stored hash no matcher recognises SHALL match nothing. No other library component SHALL check or record history on its own.

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

#### Scenario: A refused change writes nothing
- **WHEN** a change is refused as common
- **THEN** no hash is retired and the consumer's write is not called

### Requirement: The policy fails closed and keeps no credential
A history read or retire failure SHALL refuse the change with the history-unavailable error and SHALL NOT call the consumer's write. An error from the consumer's write SHALL be returned unchanged. The policy SHALL write no log record that contains the candidate, a hash or a context word, and SHALL NOT keep the candidate after the call returns.

#### Scenario: Retire failure
- **WHEN** the history port reads successfully but fails to retire the current hash
- **THEN** the change is refused with the history-unavailable error and the consumer's write is not called

### Requirement: Policy wiring mistakes fail at construction
Building a policy SHALL fail with a configuration error naming the mistake when given: a reuse rule without a history port (including a typed-nil one), or with a depth below one; a nil encoder (including a typed-nil one); an absent matcher or clock; a breach check without a lookup source or a failure mode; a minimum length below 8; a maximum below 64 or below the minimum; a replaced common-password list that is empty. A check or change given no user record, or a change given no write, SHALL fail with a configuration error and SHALL read and write nothing.

#### Scenario: Reuse depth zero
- **WHEN** a policy is built with the reuse rule at depth 0
- **THEN** construction fails with a configuration error naming the reuse depth

#### Scenario: No encoder named
- **WHEN** a policy is built without naming an encoder and changes a password
- **THEN** the new hash is an Argon2id hash at the built-in encoder's defaults

#### Scenario: Nil encoder
- **WHEN** a policy is built with a nil encoder
- **THEN** construction fails with a configuration error naming the encoder

#### Scenario: Empty replacement list
- **WHEN** a policy is built with the common-password list replaced by an empty list
- **THEN** construction fails with a configuration error naming the common-password list
