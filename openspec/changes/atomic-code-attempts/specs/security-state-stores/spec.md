## ADDED Requirements

### Requirement: TOTP verification attempts are charged and given back by the write
Every MFA enrolment store SHALL keep, per enrolment, a verification attempt count and the end of its window. Charging an attempt SHALL be one conditional write, only on a confirmed enrolment: an ended window SHALL be replaced by one ending a window later, counting one; otherwise the count SHALL rise by one while below the given limit. A charge SHALL report its window's end. A give-back SHALL be one conditional write that lowers a positive count only while the enrolment's window end equals the one named.

A window has ended from its end instant onward. A refused charge or give-back SHALL change nothing. Storing a pending enrolment SHALL clear the count and the window. Of any number of concurrent charges against one enrolment within one window, at most the limit SHALL succeed. A sealing store SHALL pass both operations through unchanged.

#### Scenario: Concurrent charges against one enrolment
- **WHEN** 20 callers charge an attempt against the same confirmed enrolment at the same time, with a limit of 5
- **THEN** exactly five succeed
- **AND** the enrolment reads with five charged attempts

#### Scenario: The window ends at its end instant
- **WHEN** an enrolment holds five charged attempts in a window ending at 12:15, and an attempt is charged at exactly 12:15
- **THEN** the charge succeeds in a new window ending at 12:30, counting one

#### Scenario: Pending enrolment is not charged
- **WHEN** an attempt is charged against an enrolment that is not confirmed
- **THEN** the charge is refused and the enrolment is unchanged

#### Scenario: Give-back in the window it was charged in
- **WHEN** an attempt is charged in the window ending at 12:15 and given back naming 12:15
- **THEN** the give-back succeeds and the count falls by one

#### Scenario: Give-back after the window was replaced
- **WHEN** an attempt is charged in the window ending at 12:15, a later charge opens the window ending at 12:30, and the first attempt is given back naming 12:15
- **THEN** the give-back is refused and the count is unchanged

#### Scenario: Give-back at zero
- **WHEN** a give-back names the current window and the count is zero
- **THEN** it is refused and the count stays zero

#### Scenario: A new begin clears the count
- **WHEN** a confirmed enrolment holding three charged attempts is deleted, and a pending enrolment is then stored for the same user
- **THEN** the pending enrolment reads with no charged attempts and no window
