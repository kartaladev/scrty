## ADDED Requirements

### Requirement: The consumer can add rules of its own
The policy SHALL accept rules the consumer owns, each with a unique name and a check given the candidate and the user record. A rule that refuses SHALL end the check with a refusal naming it. A rule that fails SHALL fail the check and the change, fail closed, with the rule's error reachable and not identifiable as a password-rejected error. The library SHALL ship no composition rule of its own and add none by default.

#### Scenario: Letters and digits
- **WHEN** a policy with a minimum of 10 and a consumer rule requiring a letter and a digit checks `abcdefghijkl`
- **THEN** it is refused by the consumer's rule
- **AND** `abcdefghij12` is accepted

#### Scenario: Weak and reused stay distinct
- **WHEN** the same policy also enables reuse at depth 1, and a user changes to their current password, which satisfies the consumer's rule
- **THEN** the refusal is the password-reused error, and a candidate the consumer's rule refuses is not

#### Scenario: Rule failure
- **WHEN** a consumer rule returns an error rather than a verdict during a change
- **THEN** the change fails with that error reachable, it is not a password-rejected error, and the consumer's write is not called

#### Scenario: No rule by default
- **WHEN** a policy built with no options checks `abcdefghijklmnop`
- **THEN** it is accepted, as no composition rule applies

## MODIFIED Requirements

### Requirement: One policy holds every rule for a new password
The library SHALL provide one password policy that checks a candidate password for a user and, on a change, stores it. With no options, the policy SHALL apply a minimum length of 15 characters, a maximum of 128 characters, and a list of common passwords, and nothing else. Each option SHALL replace or add only the rule it names, so setting one rule never removes another default; removing a default rule SHALL need an option whose name says so. Rules SHALL run cheapest first: length, then the common-password and context-word lists, then the consumer's own rules in the order given, then the breach check, then reuse. The first refusal SHALL end the check, and no later rule SHALL run.

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

#### Scenario: A consumer rule runs before the breach lookup
- **WHEN** the breach check is enabled, a consumer rule is added, and the consumer rule refuses a candidate
- **THEN** no breach lookup is made

### Requirement: Every refusal says which rule refused
A refusal SHALL be identifiable as a password-rejected error and SHALL name the rule that refused it: too short, too long, common, context word, breached or reused, or the name of the consumer's own rule that refused it. The reused refusal SHALL also be the password-reused error. No refusal's text SHALL contain the candidate, a stored hash, a context word or the user reference.

#### Scenario: Reason for the user
- **WHEN** a candidate is refused as breached
- **THEN** the error is a password-rejected error whose rule is "breached", and its text contains neither the candidate nor the user reference

#### Scenario: Consumer rule named
- **WHEN** a consumer rule named `letters-and-digits` refuses `abcdefghijkl`
- **THEN** the error is a password-rejected error whose rule is `letters-and-digits`, it is not the password-reused error, and its text does not contain the candidate

### Requirement: Policy wiring mistakes fail at construction
Building a policy SHALL fail with a configuration error naming the mistake when given: a reuse rule without a history port (including a typed-nil one), or with a depth below one; a nil encoder (including a typed-nil one); an absent matcher or clock; a breach check without a lookup source or a failure mode; a minimum length below 8; a maximum below 64 or below the minimum; a replaced common-password list that is empty; a consumer rule with no check (including a typed-nil one), or with an empty name, the name of a built-in rule, or a name another consumer rule already has. A check or change given no user record, or a change given no write, SHALL fail with a configuration error and SHALL read and write nothing.

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

#### Scenario: Consumer rule named like a built-in
- **WHEN** a policy is built with a consumer rule named `reused`
- **THEN** construction fails with a configuration error naming the rule
