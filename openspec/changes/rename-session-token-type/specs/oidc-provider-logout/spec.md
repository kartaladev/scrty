## MODIFIED Requirements

### Requirement: A failed logout can be retried and finishes
An end through the end-session endpoint or its confirmation SHALL end grants first, the sign-in's sessions next, and the browser session last, so that a failure answers an error, leaves the browser able to retry, and a retry from it finishes the end. It SHALL NOT answer success while a grant or session of that sign-in lives on.

#### Scenario: A grant store failure, then a retry
- **WHEN** a logout confirmation fails because the grant store is down, and the browser retries once it is back
- **THEN** the first attempt answers an error, and after the retry the sign-in's grants and sessions have ended

#### Scenario: A session store failure, then a retry
- **WHEN** a logout confirmation ends the grants, but deleting the sign-in's sessions fails, and the browser retries
- **THEN** the first attempt answers an error and clears no cookie, and after the retry the sign-in's sessions have ended
