# Spec Delta

## MODIFIED Requirements

### Requirement: Modules are released in lockstep with directory-prefixed tags
Every release SHALL give all published modules the same semantic version. The root module SHALL be tagged `vX.Y.Z`, and each nested module SHALL be tagged with its directory path as prefix, `<dir>/vX.Y.Z`, at the same commit. The published modules SHALL be the root, `httpsec/fibersec`, `httpsec/ginsec`, `httpsec/prblmsec`, `store/gormstore`, `authenticate/passkey/webauthn`, `store/pgxstore`, `ratelimit/redisstore`, `expiry/sweep` and `test`. The `tools` module SHALL never be tagged.

#### Scenario: First release
- **WHEN** version `v0.1.0` is released
- **THEN** the tags `v0.1.0`, `httpsec/fibersec/v0.1.0`, `httpsec/ginsec/v0.1.0`, `store/gormstore/v0.1.0`, `authenticate/passkey/webauthn/v0.1.0`, `store/pgxstore/v0.1.0`, `ratelimit/redisstore/v0.1.0`, `expiry/sweep/v0.1.0` and `test/v0.1.0` exist and name one commit
- **AND** no tag carries the `tools/` prefix

#### Scenario: A module without changes
- **WHEN** a release changes only the root module
- **THEN** every published module is still tagged at the new version

#### Scenario: First release that includes the problem-details module
- **WHEN** the first version after `httpsec/prblmsec` is added, `vX.Y.Z`, is released
- **THEN** `httpsec/prblmsec/vX.Y.Z` exists and names the same commit as `vX.Y.Z` and every other published module's tag
