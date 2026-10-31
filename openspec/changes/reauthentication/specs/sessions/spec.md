# Spec Delta

## MODIFIED Requirements

### Requirement: A session records when the user last authenticated
Every session SHALL record the time the user last authenticated: the sign-in time at creation, refreshed when a second factor is satisfied and when the user re-authenticates the session. A renewal SHALL carry it over unchanged, because a renewal is not an authentication. A session's creation time SHALL be when that record was written.

#### Scenario: Renewal keeps the authentication time
- **WHEN** a session created at 09:00 is renewed at 15:00
- **THEN** the successor reports 09:00 as its authentication time and 15:00 as its creation time

#### Scenario: A second factor refreshes the authentication time
- **WHEN** a session signed in at 09:00 satisfies a second factor at 09:20
- **THEN** it reports 09:20 as its authentication time

#### Scenario: A re-authentication refreshes the authentication time
- **WHEN** a session signed in at 09:00 re-authenticates with its password at 11:00
- **THEN** its successor reports 11:00 as its authentication time

#### Scenario: Saving cannot refresh it
- **WHEN** a consumer changes a loaded session's authentication time and saves the session
- **THEN** the stored authentication time is unchanged

## ADDED Requirements

### Requirement: One check decides whether a session authenticated within a window
The library SHALL offer one check of whether a session authenticated within a window at a given time: true when no more than the window has elapsed since its authentication time, inclusive. A time later than the given time SHALL count as no time elapsed. A session with no recorded authentication time SHALL never be within any window. Every freshness check the library makes SHALL use this check.

#### Scenario: Inside the window
- **WHEN** a session authenticated at 09:00 is checked against a 15-minute window at 09:10
- **THEN** it is within the window

#### Scenario: At the window's end
- **WHEN** it is checked at exactly 09:15
- **THEN** it is within the window

#### Scenario: Past the window
- **WHEN** it is checked at 09:15:01
- **THEN** it is not within the window

#### Scenario: Authentication time ahead of the clock
- **WHEN** a session whose authentication time is 09:00:05 is checked at 09:00:00, as when replicas' clocks disagree
- **THEN** it is within the window

#### Scenario: No recorded authentication time
- **WHEN** a session with a zero authentication time is checked against a 24-hour window
- **THEN** it is not within the window
