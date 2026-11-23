# Spec Delta

## ADDED Requirements

### Requirement: The net/http guard accepts any requirement
The chain's guards SHALL offer a guard that takes any requirement, including any-of and all-of compositions across resources, refusing with the requirement's own error: authentication-required, access-denied or a dependency failure. An absent requirement SHALL fail when the guard is built.

#### Scenario: All-of across resources
- **WHEN** a route is guarded by "all of: `read` on `crm/lead`, `read` on `crm/deal`" and a principal granted only `read` on `crm/lead` calls it
- **THEN** the request is refused with the access-denied error and the handler does not run

#### Scenario: Outage is not a denial
- **WHEN** the role loader fails with a connection error while such a guard is evaluated
- **THEN** the request fails as a dependency failure, not as access denied

### Requirement: Every request carries its own privilege memo by default
The chain SHALL attach a new privilege memo to every request it authenticates, before any guard or handler runs, and SHALL NOT carry it to another request. A consumer SHALL be able to turn this off, so every check loads.

#### Scenario: Default
- **WHEN** a request passes a route privilege guard and its handler makes nine more checks on one resource
- **THEN** the role loader is called once for the request

#### Scenario: Consumer turns the memo off
- **WHEN** the chain is built with the memo turned off and the same request is made
- **THEN** the role loader is called ten times

### Requirement: The principal holds only the role grants valid at the request's time
When the chain builds a principal from a reloaded user, it SHALL keep only the role grants valid at the chain clock's current time, as the identity model's point-in-time mapping states. A user whose every grant is outside its dates SHALL be authenticated with no active role.

#### Scenario: Expired grant
- **WHEN** `ada`'s only grant `sales` ended an hour ago and she makes a request with a live session
- **THEN** the request is authenticated, and a guard requiring a privilege of `sales` refuses it with the no-active-role reason

### Requirement: Switching the active role is opt-in
The chain SHALL offer switching the active role only when the consumer turns it on. Switching SHALL take the authenticated request's context and a role name, and SHALL succeed only when the reloaded user holds a grant of that name valid at the chain clock's time. It SHALL then record the choice on the request's session and emit an event. With switching off, a call SHALL fail with a not-enabled error.

#### Scenario: Switch
- **WHEN** switching is on and `ada`, holding `sales` (primary) and `audit`, switches to `audit`
- **THEN** the call succeeds and her next request's principal has `audit` as its active role

#### Scenario: Role not held
- **WHEN** `ada` switches to `admin`, which she does not hold
- **THEN** the call fails with the no-role error and her session is unchanged

#### Scenario: Off by default
- **WHEN** switching was not turned on and any switch is attempted
- **THEN** the call fails with the not-enabled error

### Requirement: A selected role applies only while it is still held
On every request, when the session records a selected role, the chain SHALL make it the active role only when the reloaded user still holds a grant of that name valid at the chain clock's time, and SHALL otherwise use the primary grant, as if nothing were selected. A selection SHALL never add a role the user does not hold.

#### Scenario: Selected role removed
- **WHEN** `ada` selected `audit` and an administrator then removes her `audit` grant
- **THEN** her next request's active role is her primary grant

#### Scenario: Selection with switching turned off later
- **WHEN** a session records a selected role and the chain is rebuilt with switching off
- **THEN** the selection is ignored and the primary grant is active
