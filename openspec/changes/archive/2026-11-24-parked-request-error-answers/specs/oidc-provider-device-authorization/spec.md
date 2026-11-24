## ADDED Requirements

### Requirement: A consumer can send a refused user-code entry back to the code-entry page
A consumer MAY choose that the chain's code-entry endpoint answers an invalid user code with a 303 to the code-entry page carrying `result=invalid`, and a throttled entry with `result=throttled`, instead of an error. It is off by default. The redirect SHALL carry nothing else from the entry, and SHALL tell the codes that do not exist from the ones that do no more than the error does.

#### Scenario: Default answer
- **WHEN** a browser submits an unknown user code and the consumer made no choice
- **THEN** the entry is refused with the invalid-code error, as without this change

#### Scenario: Invalid code sent back
- **WHEN** the consumer chose the redirect, and a browser submits an unknown or expired user code
- **THEN** the browser is redirected with 303 to the code-entry page with `result=invalid` and nothing else

#### Scenario: Throttled entry sent back
- **WHEN** the consumer chose the redirect, and a throttled source submits a user code
- **THEN** the browser is redirected with 303 to the code-entry page with `result=throttled`, and the code is not looked up
