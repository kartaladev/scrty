# Spec Delta

## ADDED Requirements

### Requirement: A challenge method may describe its begin data
The library SHALL accept from a second-factor method that issues a challenge an optional description of the shape of the data its begin step returns. A method that gives none SHALL keep working exactly as before. A description SHALL NOT change what the method returns or how it is verified.

#### Scenario: Method describes its data
- **WHEN** a challenge method describes its begin data as an object with a required `challenge` string
- **THEN** the description is available to whatever documents the begin endpoint, and the method's begin and verify behave as before

#### Scenario: Method describes nothing
- **WHEN** a challenge method gives no description
- **THEN** begin and verify behave exactly as they do today, and its begin data is documented as unknown
