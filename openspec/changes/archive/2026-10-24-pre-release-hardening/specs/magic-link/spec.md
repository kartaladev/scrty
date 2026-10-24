# Spec Delta

## MODIFIED Requirements

### Requirement: Link issuance is limited per user
The library SHALL NOT issue a link for a user who already has the issuance limit's number of links issued within the one-time-token issuance window. The default limit SHALL be 5, replaceable by an option. A limit below 1 SHALL fail construction with a configuration error. The count and the issue SHALL be one atomic bounded issue, so that requests for one user that race SHALL NOT together issue more links, or send more messages, than the limit allows.

#### Scenario: Default limit
- **WHEN** five links were issued for `u-1` in the last hour and a sixth is requested
- **THEN** no sixth link is issued

#### Scenario: Consumer limit
- **WHEN** the limit is configured as 2, two links were issued for `u-1` in the last hour, and a third is requested
- **THEN** no third link is issued

#### Scenario: Concurrent requests
- **WHEN** 20 link requests for `u-1` run concurrently with the default limit and no links were issued before
- **THEN** at most 5 links are issued and at most 5 messages are sent
