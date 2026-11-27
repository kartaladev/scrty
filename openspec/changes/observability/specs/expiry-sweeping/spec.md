# Spec Delta

## ADDED Requirements

### Requirement: The runner reports each task run to a telemetry observer
When given a telemetry observer, the runner SHALL report each task run, manual or scheduled, as an `expiry.run` operation with the task name as its method, ending in success, or in an error naming the error's Go type. The existing result observer SHALL keep receiving every result unchanged.

#### Scenario: Run reported to both
- **WHEN** a runner has a result observer and a telemetry observer, and the session task removes 3 records
- **THEN** the result observer receives the result as before, and the telemetry observer sees an `expiry.run` operation for `sessions` end in success

#### Scenario: Failed run
- **WHEN** a task's purge fails
- **THEN** its `expiry.run` operation ends with an error outcome naming the error's type, and the other tasks' operations are unaffected
