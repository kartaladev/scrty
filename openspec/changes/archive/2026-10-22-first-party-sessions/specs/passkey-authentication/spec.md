## MODIFIED Requirements

### Requirement: Removing a passkey ends the user's other sessions
By default, a removal SHALL delete every session of the user except the session that made the removal, before the passkey is deleted. The removing session SHALL stay valid. When the removing session was renewed and is still inside its renewal window, its successor SHALL stay valid too, and every other superseded session of its sign-in SHALL be deleted. The removal notice SHALL say whether other sessions were ended. A consumer SHALL be able to make keeping the other sessions the default.

#### Scenario: Other sessions end on removal
- **WHEN** `u-1` has sessions on a laptop, a phone and a tablet, and removes a passkey from the laptop session
- **THEN** the passkey is removed, the phone and tablet sessions no longer load, the laptop session still loads, and the removal notice says other sessions were ended

#### Scenario: Removal made with a renewed session inside its window
- **WHEN** `u-1`'s laptop session O was renewed into S1 with a 30-second grace, `u-1` also has a phone session, and a request bearing O removes a passkey inside the window
- **THEN** the passkey is removed, O and S1 still load, and the phone session does not

#### Scenario: Removal made with the successor
- **WHEN** `u-1`'s laptop session O was renewed into S1 with a 30-second grace, and a request bearing S1 removes a passkey inside the window
- **THEN** S1 still loads, and O does not

#### Scenario: Consumer keeps sessions by default
- **WHEN** the consumer turns removal revocation off and `u-1` removes a passkey
- **THEN** the passkey is removed, every session of `u-1` still loads, and the removal notice does not say sessions were ended
