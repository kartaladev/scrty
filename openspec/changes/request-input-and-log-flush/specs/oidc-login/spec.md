## ADDED Requirements

### Requirement: OIDC components flush their refusal logs
The OIDC login manager, the handoff manager and the identity broker SHALL each expose a flush that reports every pending suppressed count of their refusal-log samplers to the configured reporter. Flushing the login manager SHALL also flush the broker it was given, when that broker can flush. A flush SHALL write nothing else and SHALL leave the component usable.

#### Scenario: Handoff redemption flood flushed at shutdown
- **WHEN** the handoff manager has suppressed 30 refusal records in the current window and is flushed
- **THEN** its reporter receives the pending count of 30

#### Scenario: Manager flushes its broker
- **WHEN** a login manager built with a broker that has suppressed provisioning refusals is flushed
- **THEN** the broker's reporter receives its pending count
