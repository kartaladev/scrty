# Spec Delta

## MODIFIED Requirements

### Requirement: Privilege checks match granted privileges of the active role
The privilege authorizer SHALL load the privileges of the subject's active role and find the entry whose group and resource match the attributes.
- In any-of mode, access SHALL be allowed when at least one required privilege is present and granted.
- In all-of mode, access SHALL be allowed only when every required privilege is present and granted.
- A privilege present but not granted SHALL NOT count.
- No matching group and resource SHALL deny.

By default, group, resource and privilege names SHALL be compared ignoring surrounding ASCII whitespace and ASCII letter case only, so a character that matches an ASCII letter only under Unicode case folding, or Unicode whitespace around a name, never makes two names equal. A consumer SHALL be able to replace the comparison.

#### Scenario: Any-of
- **WHEN** the active role grants `read` on `billing/invoice` and the attributes require any of `read` or `write`
- **THEN** access is allowed

#### Scenario: All-of
- **WHEN** the active role grants `read` but not `write` on `billing/invoice` and the attributes require all of `read` and `write`
- **THEN** access is denied

#### Scenario: Present but not granted
- **WHEN** the active role lists `write` on `billing/invoice` as not granted and the attributes require `write`
- **THEN** access is denied

#### Scenario: Default comparison ignores case
- **WHEN** the active role grants `READ` on `Billing/Invoice` and the attributes require `read` on `billing/invoice`
- **THEN** access is allowed

#### Scenario: Unicode look-alike names
- **WHEN** the active role grants `ſign` on `Keys/Vault`, with U+017F in place of `s`, and the attributes require `sign` on `keys/vault`
- **THEN** access is denied

#### Scenario: Unicode whitespace around a name
- **WHEN** the active role grants `read` followed by a no-break space on `billing/invoice`, and the attributes require `read`
- **THEN** access is denied

#### Scenario: Consumer exact comparison
- **WHEN** the authorizer is configured with an exact name comparison, and the same request is made
- **THEN** access is denied
