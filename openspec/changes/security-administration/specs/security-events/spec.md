# Spec Delta

## ADDED Requirements

### Requirement: Administration changes are reported under OWASP names
Administration services SHALL report each committed change to the event sink, using the OWASP Logging Vocabulary where it has a name: `user_created`, `user_updated`, `user_archived` for deactivation, `user_deleted`, `authn_password_change` for an administrator's password reset, `privilege_permissions_changed` for a grant change, `authz_change` for an assignment change, and `authz_admin` for a role's creation, update or deletion. Reactivation and import SHALL use names under the `scrty_` prefix.

#### Scenario: Deactivation
- **WHEN** an administrator deactivates `ada`
- **THEN** the sink receives one `user_archived` event naming `ada`'s identifier

#### Scenario: Import that changed nothing
- **WHEN** an import of `ada` with equal values completes
- **THEN** the sink receives no event

### Requirement: An administration event names its actor, target and changed fields
An administration event SHALL carry the actor's reference, or the system actor's name, the target user's reference or the role name, and the names of the changed fields. It SHALL NOT carry a field's value. Events of other components SHALL leave these empty.

#### Scenario: Grant change
- **WHEN** an administrator replaces role `sales`'s grants on `crm/lead`
- **THEN** the `privilege_permissions_changed` event names the administrator as actor, `sales` as target, and `crm/lead` as the changed field

### Requirement: Role switches and identifier conflicts are reported
A successful active-role switch SHALL be reported under a `scrty_`-prefixed name with the user and the role switched to. An email login refused because the identifier names two users SHALL be reported under a `scrty_`-prefixed name with no user and no identifier.

#### Scenario: Switch
- **WHEN** `ada` switches her active role to `audit`
- **THEN** the sink receives one role-switch event naming `ada` and `audit`

#### Scenario: Conflict
- **WHEN** an email login is refused because the identifier names two users
- **THEN** the sink receives one identifier-conflict event that names no user and does not contain the identifier
