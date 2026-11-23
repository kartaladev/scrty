# Spec Delta

## ADDED Requirements

### Requirement: Adapter guards accept any requirement
The gin and fiber guards SHALL offer a guard that takes any requirement, including any-of and all-of compositions across resources, and SHALL refuse, render and log its outcome exactly as the net/http guard does for the same requirement. An absent requirement SHALL fail when the guard is built.

#### Scenario: Composed requirement
- **WHEN** a gin route and a fiber route are guarded by "any of: `read` on `crm/lead`, `read` on `crm/deal`" and a principal granted only `read` on `crm/deal` calls them
- **THEN** both handlers run

#### Scenario: Same refusal everywhere
- **WHEN** an anonymous request reaches a route guarded by any requirement that needs a principal, in net/http, gin and fiber
- **THEN** each refuses with the authentication-required error and the same status

#### Scenario: Absent requirement
- **WHEN** a fiber guard is built from an absent requirement
- **THEN** building the guard fails, before any request
