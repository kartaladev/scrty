# Spec Delta

## MODIFIED Requirements

### Requirement: The clock is injectable
The key manager SHALL read time from a configurable time source, defaulting to the system clock, for key creation times, rotation, reload and housekeeping. The same source SHALL pace the rotation, reload and housekeeping background work, so a controlled source drives them without real waiting. The key manager SHALL only accept a time source that can wait as well as read the time. Each background task SHALL next run one interval after its previous run finishes, and an interval stated elsewhere in this capability is measured that way.

#### Scenario: Controlled time
- **WHEN** a key manager's time source advances by 25 hours
- **THEN** rotation and housekeeping behave as if 25 hours had passed without real waiting

#### Scenario: Controlled reload
- **WHEN** replicas A and B share a store and a controlled time source, replica A rotates in key `k2`, and the source advances by one reload interval
- **THEN** replica B publishes `k2` with no real waiting

#### Scenario: Interval measured from the end of a run
- **WHEN** a reload that started at 12:00:00 with a 1-minute reload interval finishes at 12:00:03
- **THEN** the next reload starts at 12:01:03
