# Spec Delta

## MODIFIED Requirements

### Requirement: Privilege checks match granted privileges of the active role
The privilege authorizer SHALL load the privileges of the subject's active role and find the entry whose group and resource match the attributes.
- In any-of mode, access SHALL be allowed when at least one required privilege is present and granted with a scope the attributes accept.
- In all-of mode, access SHALL be allowed only when every required privilege is present and granted with a scope the attributes accept.
- A privilege present but not granted SHALL NOT count.
- No matching group and resource SHALL deny.
- Attributes that name no scope requirement SHALL accept only the `all` scope. A privilege stored without a scope SHALL be read as `all`.

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

#### Scenario: Consumer exact comparison
- **WHEN** the authorizer is configured with an exact name comparison, and the same request is made
- **THEN** access is denied

#### Scenario: Unicode look-alike names
- **WHEN** the active role grants `ſign` on `Keys/Vault`, with U+017F in place of `s`, and the attributes require `sign` on `keys/vault`
- **THEN** access is denied

#### Scenario: Unicode whitespace around a name
- **WHEN** the active role grants `read` followed by a no-break space on `billing/invoice`, and the attributes require `read`
- **THEN** access is denied

#### Scenario: Own-only grant fails a plain check
- **WHEN** the active role grants `update` on `crm/lead` only with scope `own`, and attributes that name no scope requirement require `update`
- **THEN** access is denied with the wrong-scope reason

#### Scenario: Grant stored without a scope
- **WHEN** the role loader returns `read` on `billing/invoice` with no scope, and the attributes require `read`
- **THEN** access is allowed

### Requirement: Requirements distinguish anonymous callers from forbidden ones
The library SHALL provide requirements that permit all, deny all, require an authenticated principal, require any of a set of roles, require any of a set of scopes, require all of a set of scopes, require any of a set of requirements, require all of a set of requirements, and require a privilege.
- A requirement that needs a principal and finds none SHALL fail with an authentication-required error.
- A known principal that does not meet a requirement SHALL be denied.
- Requiring all of an empty set of scopes, any of an empty set of requirements, or all of an empty set of requirements, SHALL deny.
- Requiring any of a set of requirements SHALL return the authentication-required error only when every member returned it, and SHALL otherwise deny.
- Requiring all of a set of requirements SHALL evaluate the members in order and return the first failure unchanged, and an absent member SHALL deny.
- Scopes SHALL be matched exactly, and a principal with no scopes SHALL NOT meet a scope requirement.
- The privilege requirement SHALL delegate the decision to the authorizer available in the request context, and SHALL deny when none is available.

#### Scenario: Anonymous caller
- **WHEN** a request with no principal meets a requirement for role `admin`
- **THEN** the authentication-required error is returned

#### Scenario: Known caller without the role
- **WHEN** a principal holding only role `viewer` meets a requirement for role `admin`
- **THEN** access is denied

#### Scenario: Empty all-of scopes
- **WHEN** an authenticated service principal meets a requirement for all of no scopes
- **THEN** access is denied

#### Scenario: Any-of mixes anonymous and forbidden outcomes
- **WHEN** a principal with no scopes and no `admin` role meets "any of: role `admin`, scope `orders:read`"
- **THEN** access is denied rather than authentication being required

#### Scenario: Privilege requirement delegates
- **WHEN** a privilege requirement for `read` on `billing/invoice` is evaluated with an authorizer in the request context
- **THEN** the authorizer's decision for those privilege attributes is returned

#### Scenario: All-of across resources
- **WHEN** a principal granted `read` on `crm/lead` but nothing on `crm/deal` meets "all of: `read` on `crm/lead`, `read` on `crm/deal`"
- **THEN** access is denied with the denial from the second member

#### Scenario: Empty all-of requirements
- **WHEN** any principal meets a requirement for all of no requirements
- **THEN** access is denied

#### Scenario: All-of with an absent member
- **WHEN** a requirement for all of `Authenticated` and an absent member is evaluated for an authenticated principal
- **THEN** access is denied

## ADDED Requirements

### Requirement: A grant carries a scope
Each granted privilege SHALL carry a scope. The defined scopes SHALL be `all` and `own`. `all` SHALL cover every record and `own` only records the subject owns. A scope the authorizer does not define SHALL cover nothing, so a privilege granted with it never allows.

#### Scenario: Undefined scope
- **WHEN** the role loader returns `read` on `crm/lead` granted with scope `team`, which the authorizer does not define, and a check accepts any scope
- **THEN** access is denied

### Requirement: A check can accept any scope and report the one held
The library SHALL provide a privilege check that accepts a privilege granted with any defined scope and, when it allows, makes the strongest scope held available to the caller, `all` before `own`. It SHALL NOT be the default reading of a privilege requirement.

#### Scenario: Own scope reported
- **WHEN** the active role grants `view` on `crm/lead` with `own`, and a request is checked with the any-scope check for `view`
- **THEN** access is allowed and the scope reported is `own`

#### Scenario: Strongest scope wins
- **WHEN** the active role is a super role and the any-scope check for `view` is made
- **THEN** access is allowed and the scope reported is `all`

### Requirement: A check for one record combines scope and ownership
The library SHALL provide a privilege check for one record that allows when the privilege is granted with `all`, or when it is granted with `own` and the consumer's ownership check reports that the subject owns the record. With `own`, it SHALL deny with the not-the-owner reason when the subject does not own the record, and SHALL return an ownership-check error wrapped, not as a denial.

#### Scenario: All scope needs no ownership check
- **WHEN** the active role grants `update` on `crm/lead` with `all` and the record check is made for lead `L-1`
- **THEN** access is allowed and the ownership check is not called

#### Scenario: Own scope and owner
- **WHEN** the active role grants `update` with `own`, and the ownership check reports that the caller's organization owns `L-1`
- **THEN** access is allowed

#### Scenario: Own scope and not the owner
- **WHEN** the active role grants `update` with `own`, and the ownership check reports that the caller does not own `L-1`
- **THEN** access is denied with the not-the-owner reason

### Requirement: Denials say why
Every denial from the privilege authorizer and the requirements SHALL still match the access-denied error, and SHALL also be identifiable as exactly one of: no subject, no active role, not granted, wrong scope, not the owner.

#### Scenario: No active role
- **WHEN** a subject with no active role requests a privilege
- **THEN** the error matches the access-denied error and the no-active-role reason, and no other reason

#### Scenario: Wrong scope
- **WHEN** an own-only grant fails a plain privilege check
- **THEN** the error matches the access-denied error and the wrong-scope reason

### Requirement: One call reports which of several privileges are held
The library SHALL provide a bulk check that takes a group, a resource and a list of privilege names, loads the active role's privileges once, and returns for each name whether it is held and its scope. A super role SHALL hold every name with `all`. An empty list SHALL be refused as invalid attributes.

#### Scenario: Allowed actions
- **WHEN** the active role grants `view` (all) and `update` (own) on `crm/lead`, and the bulk check asks for `view`, `update`, `delete`
- **THEN** it reports `view` held with `all`, `update` held with `own`, and `delete` not held
- **AND** the role loader is called once

#### Scenario: Bulk check without an active role
- **WHEN** a subject with no active role asks for any privileges
- **THEN** every name is reported not held, the role loader is not called, and no error is returned

#### Scenario: Loader outage
- **WHEN** the role loader fails with a connection error during a bulk check
- **THEN** the error matches the connection error and no privilege is reported held

### Requirement: A role's privileges are loaded at most once per request
When the request context carries a privilege memo, the privilege authorizer and the bulk check SHALL load each role's privileges at most once for that context, including when checks run concurrently. A load failure SHALL NOT be remembered. Without a memo, every check SHALL load. A memo SHALL NOT be shared between requests.

#### Scenario: Ten checks, one load
- **WHEN** a request with a memo checks a route privilege and then nine privileges on one resource
- **THEN** the role loader is called once

#### Scenario: Concurrent checks
- **WHEN** eight goroutines check privileges of the same role at once under one memo
- **THEN** the role loader is called once and every check sees the same privileges

#### Scenario: Next request sees a change
- **WHEN** a role's grants are replaced between two requests
- **THEN** the second request's checks use the new grants

#### Scenario: Failure is not remembered
- **WHEN** the first load under a memo fails with a connection error, and a second check follows in the same request
- **THEN** the second check calls the loader again

### Requirement: A consumer can install a memo outside the chain
The library SHALL let a consumer attach a new privilege memo to a context, for authorization checks made outside the chain, such as in a background job.

#### Scenario: Job checks with a memo
- **WHEN** a job attaches a memo to its context and makes five checks for one role
- **THEN** the role loader is called once
