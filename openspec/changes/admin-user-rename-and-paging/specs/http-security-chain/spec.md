# Spec Delta

## MODIFIED Requirements

### Requirement: Chain source guards count an IPv6 aggregate by default
Every source guard the chain builds SHALL also count IPv6 sources by an aggregate prefix of /56, with a limit four times the flow's limit, over the flow's window, in a limiter of its own. A consumer SHALL be able to set the aggregate prefix and multiplier, or turn the aggregate off. When the source prefix is already /56 or wider and the aggregate was not set explicitly, the default aggregate SHALL be skipped. For a flow given its own limiter, the aggregate SHALL use that limiter's reported limit and window; every limiter SHALL report them.

#### Scenario: Default aggregate
- **WHEN** a chain with default settings records 80 failed API-key attempts, 20 from each of `2001:db8:1:1::1`, `2001:db8:1:2::1`, `2001:db8:1:3::1` and `2001:db8:1:4::1`, and an attempt arrives from `2001:db8:1:5::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Consumer aggregate
- **WHEN** a chain configured with a /48 aggregate and a multiplier of 2 records 40 failed API-key attempts, 20 from each of `2001:db8:1:1::1` and `2001:db8:1:200::1`, and an attempt arrives from `2001:db8:1:300::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Aggregate turned off
- **WHEN** a chain with the aggregate turned off records 80 failed API-key attempts from four /64s in one /56, and an attempt arrives from a fifth /64 in it
- **THEN** the attempt is not throttled

#### Scenario: Wide source prefix skips the default aggregate
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and no aggregate setting
- **THEN** construction succeeds and its guards count no aggregate

#### Scenario: Aggregate follows a consumer limiter
- **WHEN** a chain with default settings gives the API-key flow its own limiter allowing 200 failures per minute, and 200 failed API-key attempts arrive from one /64
- **THEN** none of them is throttled by the aggregate, whose limit is 800 per minute

#### Scenario: Consumer limiter that reports no policy
- **WHEN** a chain with default settings gives the API-key flow its own consumer limiter
- **THEN** the aggregate is built from the limit and window that limiter reports, and no flow is left without an aggregate with only a warning

### Requirement: Contradictory aggregate settings fail at construction
Building a chain SHALL fail with a configuration error, naming the aggregate option for a contradictory setting and the flow for a flow limiter's policy, when an explicitly set aggregate prefix is not wider than the chain's source prefix, is outside 1 to 127, or has a multiplier below 1, when the aggregate is both set and turned off, when a flow's own limiter reports a limit below 1 or a window of zero or less, and when an aggregate's limit, the multiplier times the flow's limit, does not fit in an int.

#### Scenario: Aggregate no wider than the source
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and an explicit /56 aggregate
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Zero multiplier
- **WHEN** a chain is configured with an aggregate multiplier of 0
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Explicit aggregate over a limiter that reports no policy
- **WHEN** a chain configured with an explicit /48 aggregate gives the API-key flow its own consumer limiter reporting 50 failures per minute
- **THEN** construction succeeds and the API-key aggregate allows 100 failures per minute

#### Scenario: Consumer limiter reports an unusable policy
- **WHEN** a chain with default settings gives the API-key flow its own limiter that reports a limit of 0 and a window of 0
- **THEN** construction fails with an error naming the API-key flow, without asking the factory for an aggregate limiter

#### Scenario: Consumer limit too large for the default aggregate
- **WHEN** a chain with default settings gives the API-key flow its own limiter whose limit times 4 does not fit in an int
- **THEN** construction fails with an error naming the API-key flow and pointing to the options that turn the aggregate off or set it
