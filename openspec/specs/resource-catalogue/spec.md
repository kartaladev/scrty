# resource-catalogue Specification

## Purpose

Declares, in code and at start-up, the resources an application protects, the privileges each one
has and the scopes each privilege may be granted with, so grants can be checked against it and an
application can draw a grant matrix from it.

## Requirements

### Requirement: The catalogue is declared at construction and does not change
A catalogue SHALL be built once from a list of resources, each with a group, a name, a display name and its privileges, each privilege with a name, a display name and the scopes it may be granted with. After construction it SHALL NOT change, and SHALL be safe for concurrent reads.

#### Scenario: Declared resource
- **WHEN** a catalogue is built with resource `crm/lead` and privileges `view`, `create`, `update`, `delete`, `print` and `assign`
- **THEN** reading the catalogue returns that resource with those six privileges in the declared order

#### Scenario: Caller's slice changed afterwards
- **WHEN** the slice the catalogue was built from is changed after construction
- **THEN** the catalogue still returns what it was built with

### Requirement: A contradictory catalogue fails at construction
Building a catalogue SHALL fail with a configuration error when a group, resource or privilege name is blank, a resource or a privilege within one resource is declared twice under the default name comparison, or a privilege allows an undefined scope.

#### Scenario: Duplicate privilege
- **WHEN** resource `crm/lead` declares `view` and `VIEW`
- **THEN** construction fails with a configuration error

#### Scenario: Undefined scope
- **WHEN** privilege `view` on `crm/lead` allows the scope `team`
- **THEN** construction fails with a configuration error

### Requirement: A privilege allows both scopes unless it says otherwise
A privilege declared without scopes SHALL allow `all` and `own`. A privilege MAY restrict itself to a subset.

#### Scenario: Default scopes
- **WHEN** privilege `view` is declared without scopes
- **THEN** the catalogue reports that it allows `all` and `own`

#### Scenario: Restricted scope
- **WHEN** privilege `create` is declared with only `all`
- **THEN** the catalogue reports that it allows only `all`

### Requirement: The catalogue answers whether a grant is allowed
The catalogue SHALL report whether a group, resource, privilege and scope form an allowed grant, comparing names as the privilege authorizer does by default.

#### Scenario: Allowed grant
- **WHEN** the catalogue is asked about `view` with `own` on `CRM/Lead`, declared as `crm/lead`
- **THEN** it reports the grant allowed

#### Scenario: Unknown resource
- **WHEN** the catalogue is asked about any privilege on `crm/ghost`
- **THEN** it reports the grant not allowed
