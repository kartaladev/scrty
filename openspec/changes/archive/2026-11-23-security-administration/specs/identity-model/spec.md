# Spec Delta

## MODIFIED Requirements

### Requirement: Roles, privileges and organizations are carried as data
An assigned role SHALL carry an identifier, a name, whether it is primary, whether it is a super role, a start date and a valid-until date. A resource privilege entry SHALL carry a group, a resource and named privileges, each granted or not and each with a scope. An organization SHALL carry an identifier, a name and an optional group, which carries an identifier, a name and whether it is internal. The identity model SHALL carry these values unchanged and SHALL NOT decide access from them. The library SHALL NOT supply any default organization.

#### Scenario: Role attributes preserved
- **WHEN** a loader returns a role `ops` that is a super role, valid from 2030-01-01 until 2030-06-01, and the details are mapped to a principal
- **THEN** the principal's role `ops` reports super role, start 2030-01-01 and valid-until 2030-06-01

#### Scenario: No default organization
- **WHEN** user details with no organization are mapped to a principal
- **THEN** the principal has no organization

#### Scenario: Scope preserved
- **WHEN** a role loader returns `update` on `crm/lead` granted with scope `own`
- **THEN** the privilege entry carries scope `own` unchanged

## ADDED Requirements

### Requirement: User details carry an email and when it was verified
User details SHALL carry an email address and the time it was verified, each empty when unknown. A loader that does not store an email SHALL return them empty. The model SHALL NOT treat an email as verified unless the time is set.

#### Scenario: Unverified email
- **WHEN** a loader returns details with email `ada@example.com` and no verification time
- **THEN** the details report the email as not verified

### Requirement: Email loader contract
An optional email loader SHALL load user details by email, matching it ignoring case, only among users that are not deleted and whose email is verified. A miss SHALL return the user-not-found error, and input the store cannot represent SHALL be reported as not found. Any other failure SHALL NOT be identifiable as not found.

#### Scenario: Case-insensitive match
- **WHEN** user `ada` has verified email `Ada@Example.com` and the loader is asked for `ada@example.COM`
- **THEN** it returns `ada`'s details

#### Scenario: Unverified email
- **WHEN** user `ada` has email `ada@example.com` with no verification time and the loader is asked for it
- **THEN** it returns the user-not-found error

### Requirement: A deleted user is not found
A user loader SHALL report a soft-deleted user as not found, by username and by user reference alike.

#### Scenario: Deleted user by reference
- **WHEN** a conforming loader is asked for the reference of a deleted user
- **THEN** it returns an error identifiable as "user not found"

### Requirement: A principal can be built for a point in time
Mapping user details to a principal for a given time SHALL keep only the role grants whose start date, when set, is not after that time and whose valid-until date, when set, is after it. The active role SHALL be the first kept primary grant, or none. The existing mapping without a time SHALL be unchanged.

#### Scenario: Expired primary grant
- **WHEN** `ada`'s primary grant `sales` ended yesterday, she also holds `audit`, and her details are mapped for now
- **THEN** her principal holds only `audit` and has no active role

#### Scenario: Grant not yet started
- **WHEN** `ada`'s primary grant `sales` starts tomorrow and her details are mapped for now
- **THEN** her principal does not hold `sales`

#### Scenario: Primary grant without dates
- **WHEN** `ada`'s primary grant `sales` has no start date and no end date, and her details are mapped for any time
- **THEN** her principal holds `sales` as its active role

#### Scenario: Boundary
- **WHEN** a grant's valid-until date is exactly the mapping time
- **THEN** the grant is not kept
