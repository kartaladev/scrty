## ADDED Requirements

### Requirement: Session signal buses are integrations under httpsec
The Redis and PostgreSQL signal buses SHALL be nested modules under `httpsec`, each package named after its path's last element, and the core module SHALL gain neither driver.

#### Scenario: Module paths
- **WHEN** a consumer imports a signal bus
- **THEN** it is `github.com/kartaladev/scrty/httpsec/redisbus` or `github.com/kartaladev/scrty/httpsec/pgxbus`, in package `redisbus` or `pgxbus`

#### Scenario: The core's dependencies
- **WHEN** the core module's dependencies are listed
- **THEN** they hold neither go-redis nor pgx because of a bus, and `httpsec/signalwire` imports neither
