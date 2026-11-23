## ADDED Requirements

### Requirement: Device authorizations are kept in a store with an in-memory default
The provider SHALL keep device authorizations in a device authorization store, in memory by default. A consumer MAY supply their own. Each SQL adapter (`database/sql`, `pgx` and GORM) SHALL provide a durable one that behaves as the in-memory default does. No store error SHALL carry a digest.

#### Scenario: Each backend
- **WHEN** the provider is wired with any one SQL adapter's device authorization store
- **THEN** issuing, claiming, approving, polling and exchanging a device authorization all succeed against that database

#### Scenario: A consumer's store
- **WHEN** the consumer supplies their own device authorization store
- **THEN** the provider keeps device authorizations there, and not in memory

### Requirement: No store holds a usable device or user code in clear
No store SHALL hold a device code, or a user code not yet claimed, in clear. A claimed user code MAY be kept in clear on the pending request it was claimed for, so that the consumer's consent page can show it back, because a claimed code is bound to one browser and yields no token.

#### Scenario: Issued, not yet claimed
- **WHEN** a device authorization is issued and no browser has entered its code
- **THEN** every store holds only digests of its device code and user code

#### Scenario: Claimed
- **WHEN** a browser claims a user code
- **THEN** the pending request parked for it holds the code's display form, and the device authorization store still holds only digests

### Requirement: Every device authorization transition is one conditional write
Claiming a user code, approving or denying, recording a poll, and spending a device code SHALL each be decided by one conditional write on the record's current state. Under concurrent attempts at one transition, exactly one SHALL succeed, and a transition from a state that no longer holds SHALL write nothing.

#### Scenario: Concurrent claims
- **WHEN** two claims of one user code reach a durable store at once
- **THEN** exactly one succeeds

#### Scenario: Approval racing denial
- **WHEN** an approval and a denial of one device authorization reach the store at once
- **THEN** exactly one is recorded, and the other writes nothing

#### Scenario: A spend racing a spend
- **WHEN** two exchanges of one approved device code reach the store at once
- **THEN** exactly one spends it

### Requirement: A user code is looked up only among unexpired authorizations
Looking up a device authorization by its user code's digest SHALL return only an unexpired one, judged by the time the provider passes, never the store's clock. An expired record holding the same digest SHALL NOT block a new authorization from using that user code.

#### Scenario: An expired record with the same user code
- **WHEN** an expired, unswept device authorization holds a user code, and a new authorization is issued the same user code
- **THEN** the new one is stored, and a lookup by that code returns the new one

### Requirement: Expired device authorizations are swept
Expired device authorizations SHALL be removable by the expiry sweep, judged by the time the sweep passes. A spent device authorization SHALL be kept until the replay detection window of its device code has passed, so that a replay still reaches the grant it created.

#### Scenario: Sweep
- **WHEN** the sweep runs after some device authorizations expired and others did not
- **THEN** the expired ones are deleted, and the unexpired ones are kept

#### Scenario: A spent code within its replay window
- **WHEN** the sweep runs while a spent device authorization's replay window is still open
- **THEN** the record is kept
