## Purpose

Decides whether an authenticated principal may perform an action, through centralized ordered rules, per-resource privilege checks and ownership checks. Anything it cannot decide positively is denied, and it never panics on a missing subject or role.

## ADDED Requirements

### Requirement: Authorization is delegated to ordered authorizers
The authorization manager SHALL offer each request to its authorizers in configured order. An authorizer that does not handle the request's kind of attributes SHALL be skipped. The first authorizer that handles them SHALL decide: allow, deny, invalid attributes, or an error. When every authorizer skips, the manager SHALL deny.

#### Scenario: First handling authorizer decides
- **WHEN** a manager holds an ownership authorizer and then a privilege authorizer, and privilege attributes are presented
- **THEN** the ownership authorizer is skipped and the privilege authorizer's decision is returned

#### Scenario: Nobody handles the attributes
- **WHEN** attributes of a kind no configured authorizer handles are presented
- **THEN** access is denied

#### Scenario: Consumer-supplied authorizer
- **WHEN** a consumer configures an authorizer of their own for a custom attribute kind
- **THEN** its decision is returned unchanged for those attributes

### Requirement: Construction refuses absent authorizers
Constructing an authorization manager with no authorizers, or with any absent authorizer (including an interface holding a nil value), SHALL fail with a configuration error. Constructing a privilege authorizer without a role loader SHALL fail with a configuration error.

#### Scenario: Absent authorizer
- **WHEN** a manager is constructed with a privilege authorizer and an absent one
- **THEN** construction fails with a configuration error

#### Scenario: Missing role loader
- **WHEN** a privilege authorizer is constructed without a role loader
- **THEN** construction fails with a configuration error

### Requirement: Invalid attributes are refused distinctly
The following SHALL be refused with an invalid-attributes error, distinct from an access denial:
- privilege attributes with a blank group, a blank resource or no required privileges;
- ownership attributes with a blank group, a blank resource, no identifier resolver or no ownership check.

#### Scenario: No privileges required
- **WHEN** privilege attributes for group `billing`, resource `invoice` require no privileges
- **THEN** the invalid-attributes error is returned, not an access denial

### Requirement: A subject without an active role is denied, never a panic
The privilege authorizer SHALL deny access when there is no subject, or when the subject has no active role. It SHALL do so without dereferencing the absent value and without consulting the role loader.

#### Scenario: No active role
- **WHEN** a subject with no active role requests privilege `read` on `billing/invoice`
- **THEN** access is denied
- **AND** the role loader is not called

#### Scenario: No subject
- **WHEN** privilege attributes are authorized with no subject
- **THEN** access is denied without a panic

### Requirement: Privilege checks match granted privileges of the active role
The privilege authorizer SHALL load the privileges of the subject's active role and find the entry whose group and resource match the attributes.
- In any-of mode, access SHALL be allowed when at least one required privilege is present and granted.
- In all-of mode, access SHALL be allowed only when every required privilege is present and granted.
- A privilege present but not granted SHALL NOT count.
- No matching group and resource SHALL deny.

By default, group, resource and privilege names SHALL be compared ignoring surrounding whitespace and letter case. A consumer SHALL be able to replace the comparison.

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

### Requirement: A super role bypasses privilege checks
When the subject's active role is marked as a super role, the privilege authorizer SHALL allow access without loading privileges.

#### Scenario: Super role
- **WHEN** a subject whose active role is a super role requests any valid privilege attributes
- **THEN** access is allowed and the role loader is not called

### Requirement: Loader failures are wrapped, not collapsed
When the role loader reports that the role has no privileges, the privilege authorizer SHALL deny access. Any other loader error SHALL be returned wrapped, so it still matches the original cause, and SHALL NOT be reported as an access denial.

#### Scenario: No privileges recorded
- **WHEN** the role loader reports that role `auditor` has no privileges
- **THEN** access is denied

#### Scenario: Loader outage
- **WHEN** the role loader returns a connection error
- **THEN** the returned error matches the connection error
- **AND** it does not match the access-denied error

### Requirement: Ownership checks consult consumer-supplied functions
The ownership authorizer SHALL resolve the target resource identifier with the attributes' resolver, then ask the attributes' ownership check whether the subject owns it.
- It SHALL allow when the check reports ownership, and deny when it does not.
- A resolver or check error SHALL be returned wrapped, still matching the original cause, and not as a denial.
- The identifier SHALL be passed through without interpretation.

#### Scenario: Owner
- **WHEN** the resolver returns order `o-9` and the check reports that the subject owns `o-9`
- **THEN** access is allowed

#### Scenario: Not the owner
- **WHEN** the check reports that the subject does not own the resource
- **THEN** access is denied

#### Scenario: Resolver failure
- **WHEN** the resolver fails with a parse error
- **THEN** the returned error matches the parse error and is not an access denial

### Requirement: Centralized rules decide first-match and deny what no rule matches
A centralized rule set SHALL evaluate its rules in order. The first rule whose matcher accepts the request SHALL decide by evaluating its requirement, and later rules SHALL NOT be consulted. When the rule set has at least one rule, a request no rule matches SHALL be denied. A rule set with no rules SHALL apply no centralized decision, and SHALL leave authorization to per-endpoint checks. Constructing a rule with a missing matcher or requirement SHALL fail with a configuration error.

#### Scenario: First match wins
- **WHEN** the rules are "`/admin/**` requires role `admin`" then "any request is permitted", and a principal without `admin` requests `/admin/users`
- **THEN** access is denied by the first rule

#### Scenario: Unmatched request is denied
- **WHEN** the only rule matches `/api/**` and a request for `/health` arrives
- **THEN** access is denied

#### Scenario: Consumer opts into a default-allow remainder
- **WHEN** a consumer appends a final rule that matches any request and permits all, and a request for `/health` arrives
- **THEN** access is allowed

#### Scenario: No rules configured
- **WHEN** a rule set with no rules evaluates any request
- **THEN** no centralized decision is made and the request proceeds to per-endpoint checks

### Requirement: Requirements distinguish anonymous callers from forbidden ones
The library SHALL provide requirements that permit all, deny all, require an authenticated principal, require any of a set of roles, require any of a set of scopes, require all of a set of scopes, require any of a set of requirements, and require a privilege.
- A requirement that needs a principal and finds none SHALL fail with an authentication-required error.
- A known principal that does not meet a requirement SHALL be denied.
- Requiring all of an empty set of scopes, or any of an empty set of requirements, SHALL deny.
- Requiring any of a set of requirements SHALL return the authentication-required error only when every member returned it, and SHALL otherwise deny.
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
