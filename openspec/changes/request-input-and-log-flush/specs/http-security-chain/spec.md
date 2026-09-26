## MODIFIED Requirements

### Requirement: Chain refusal logs are sampled and summarised
The chain's own refusal log records SHALL be sampled per key per window, one minute by default. These are the throttled-source warning, the limiter failure and the unattributable-address errors. The keys SHALL be:
- the flow and source for the throttled-source warning;
- the flow alone for a limiter failure;
- the flow and reason for an unattributable address.

A written record SHALL carry the count suppressed before it when that count is non-zero. The sampler SHALL always have a reporter. By default the reporter writes one summary record naming the key and the suppressed count. The consumer SHALL be able to:
- change the interval, with zero or less disabling sampling;
- replace the reporter;
- flush pending counts, for example at shutdown.

Flushing the chain's refusal logs SHALL report the pending counts of every log sampler the chain holds, not only its own:
- the samplers of the interceptors it built, including the second-factor verification throttle, the enrolment path and every per-flow source guard, whether the chain built the guard or was given it;
- the samplers of every component it was given that can flush its refusal logs: the policies registered on its policy engine, the authenticators of form login and basic authentication, and the OIDC manager and handoff manager.

A component the consumer holds but never gave the chain is not reached, and the chain's documentation SHALL say so and name the components that flush otherwise.

The interval SHALL govern only the chain's own records. It SHALL NOT change which requests are refused, or how any other component samples its logs. A request that ended before the rate-limit check SHALL be logged at DEBUG, unsampled.

#### Scenario: Flood from one source
- **WHEN** one source is throttled 50 times within a minute
- **THEN** one warning is written for that source in that window

#### Scenario: Sources do not suppress each other
- **WHEN** two sources are throttled in the same window
- **THEN** a warning is written for each

#### Scenario: Summary for a key that goes quiet
- **WHEN** a source is throttled 5 times in one window and not again
- **THEN** once its count ages out, the default reporter writes a summary record naming that source's key with a count of 4

#### Scenario: Consumer reporter and flush
- **WHEN** the consumer supplies a reporter that increments a metric, 3 records are suppressed, and the chain's refusal logs are flushed
- **THEN** the consumer's reporter receives the pending count of 3

#### Scenario: Sampling disabled
- **WHEN** the interval is set to zero and a source is throttled 5 times
- **THEN** five warnings are written

#### Scenario: One flush reaches the components
- **WHEN** a chain with form login, the second-factor verify endpoint, a magic-link source guard and OIDC login holds suppressed counts in the password authenticator, the verification throttle, the guard and the OIDC manager, and the chain's refusal logs are flushed
- **THEN** each of those components' reporters receives its pending count

#### Scenario: Registered policy flushed
- **WHEN** a lockout policy registered on the chain's engine has suppressed refusals and the chain's refusal logs are flushed
- **THEN** the policy's reporter receives its pending count
