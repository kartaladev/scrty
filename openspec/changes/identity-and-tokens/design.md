## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** `project-foundation` provides:
  - the core module and its dependency guard;
  - `pkg/id`;
  - `pkg/logsample`.

  No security package exists yet.
- **Settled decisions this design builds on:**
  - the user reference `identity.UserID` is an opaque, consumer-owned string;
  - every default is replaceable through options, ports, hooks or plain data;
  - wiring mistakes fail at construction;
  - shared test helpers live in the `test` module;
  - the core module takes no framework, driver, scheduler or DI dependency;
  - JOSE work uses `github.com/lestrrat-go/jwx/v4` as the single stack.
- **Project rules:** library-design, golang-tdd, the `table-test`, `use-mockgen` and `use-testcontainers` skills.
- **Failure classes this design rules out, each pinned by a test:**
  - an issuer check whose condition is inverted, so a configured issuer is never enforced;
  - the expiry requirement registered twice;
  - a key manager that loads nothing from its store, so every restart invalidates every token;
  - a loop whose `break` leaves the `select` but not the `for`, so goroutines outlive shutdown;
  - a housekeeping step called while rotation already holds the key-ring lock;
  - a `Start`/`Stop` race that leaves goroutines unjoined;
  - a password encoder that is an unimplemented stub;
  - a login that answers faster for an unknown user than for a wrong password.

## Goals / Non-Goals

**Goals:**
- One identity vocabulary and a small set of ports that any consumer's user table can implement.
- Password encoders with a safe default algorithm, replaceable parameters and a stated floor.
- A JWT issuer and verifier whose algorithm, key, expiry, issuer and audience checks are each a tested requirement.
- A signing-key manager that survives restarts, rotates, and starts and stops without leaking goroutines.

**Non-Goals:**
- Deciding a login, an MFA requirement for a request, or a permission. `authentication`, `security-policy` and `authorization` consume these types.
- Revoking tokens before expiry, which is `sessions`.
- Durable key stores and sealing private keys (`security-state-stores`, `secrets-at-rest`).
- Serving the JWKS over HTTP (`http-security-chain`).
- Verifying external identity providers' tokens, and refetching their key sets on an unknown `kid` (`oidc-login`). Keys scrty signs with are held in process, so its own verifier has nothing to refetch.

## Decisions

### 1. Packages

| Package | Role | Imports |
|---|---|---|
| `identity` | Principal, details, roles, privileges, organizations, credentials, the identity ports, principal context helpers | standard library only |
| `factor` | First-factor kinds and channels, as a leaf package so `sessions`, `security-policy`, `multi-factor-auth` and `http-security` share them without an import cycle | none |
| `password` | Argon2id, bcrypt and scrypt encoders | `golang.org/x/crypto` |
| `signingkey` | Key manager, key store port, in-memory store, key source ports | jwx |
| `token` | JWT generator and verifier | `identity`, `signingkey`, jwx |

`password` is not named `crypto`: sealing secrets at rest is the separate `secrets-at-rest` capability.

### 2. Identity model

```go
type UserID string          // opaque; never parsed
type Kind uint8             // KindUser (zero value), KindService

type Principal struct {
    ID           UserID
    Name         string
    Username     string
    Roles        []*AssignedRole
    ActiveRole   *AssignedRole        // the primary role when present
    Organization *Organization
    Kind         Kind
    Scopes       []string             // service principals only
}
func (p Principal) IsService() bool

type Details struct {                  // internal: carries the password hash
    ID                UserID
    Name              string
    Username          string
    Password          []byte
    Active            bool             // zero value: inactive
    Roles             []*AssignedRole
    Role              string           // primary role name
    Organization      *Organization
    PasswordChangedAt time.Time
}
func PrincipalFromDetails(d *Details) *Principal   // drops Password; nil in, nil out

type AssignedRole struct {
    ID                    string
    Name                  string
    Primary, SuperRole    bool
    StartDate, ValidUntil time.Time
}
type Privilege struct { Name string; Granted bool }
type ResourcePrivileges struct { Group, Resource string; Privileges []Privilege }

type Organization struct { ID string; Name string; Group *Group }
type Group struct { ID string; Name string; Internal bool }

type CredentialsType string
type Credentials interface { Type() CredentialsType; Cleanup() error }

func WithPrincipal(ctx context.Context, p *Principal) context.Context
func PrincipalFromContext(ctx context.Context) (*Principal, bool)
func MustPrincipalFromContext(ctx context.Context) *Principal   // panics with ErrNoPrincipal
```

- **Principal:** the identity exposed outward. It never carries the password hash.
- **Role data is carried, not decided.** `SuperRole`, `StartDate` and `ValidUntil` are data; what they mean for access is decided by `authorization`.
- **Credential types:** the named values `username-password` and `jwt` ship here. Later methods add their own.
- **`MustPrincipalFromContext`:** for handlers behind an authentication interceptor. It panics with a sentinel, so a `recover` can identify the panic with `errors.Is`.
- **Default / override:** plain data. The consumer fills it from any source.

### 3. First-factor kinds

```go
type Kind string      // Password "password", MagicLink "magic-link", OIDC "oidc", Basic "basic", APIKey "api-key"
type Channel string   // Knowledge, Email, AuthenticatorApp, Federated, Machine
func (k Kind) Channel() Channel     // Password, Basic -> Knowledge; MagicLink -> Email; OIDC -> Federated; APIKey -> Machine; else ""
func (k Kind) MFAExempt() bool      // true only for OIDC and APIKey
```

- **Sole owner of the vocabulary:** `factor` (capability `identity-model`) defines every first-factor kind and every channel scrty uses:
  - `AuthenticatorApp` is the channel of TOTP and other authenticator-app second factors;
  - `Email` is also the channel of email-delivered second factors.

  `multi-factor-auth`, `security-policy` and every other capability import these values and define none of their own.
- **Fails closed:** the empty kind and unknown kinds are not exempt and report no channel. A caller that forgets to set the kind is therefore enforced, and never matches an enrolled method's channel.
- **Default:** the table above.
- **Override:** a consumer's own kind flows through as enforced with no channel. Whether an exempt login is accepted for a required user is `security-policy`'s decision, with its own options; `oidc-mfa-assurance` revisits the OIDC exemption.

### 4. Identity ports

```go
var (
    ErrUserNotFound       = errors.New("identity: user not found")
    ErrUserExists         = errors.New("identity: user already exists")
    ErrPrivilegesNotFound = errors.New("identity: role privileges not found")
    ErrNoPrincipal        = errors.New("identity: no principal in context")
)

type UserLoader interface {
    LoadByUsername(ctx context.Context, username string) (*Details, error)
}
type RoleLoader interface {
    LoadPrivileges(ctx context.Context, role string) ([]*ResourcePrivileges, error)
}
type UserProvisioner interface {
    Provision(ctx context.Context, username string, opts ...UserOption) (*Details, error)
    Update(ctx context.Context, username string, opts ...UserOption) (*Details, error)
}
type MFARequirementLookup interface {
    Required(ctx context.Context, userID UserID) (bool, error)
}

// UserOption values: WithUserName, WithUserEmail, WithUserRoles, WithUserOrganization,
// WithUserPassword. Each records that it was applied; NewUser.IsSet(Field) exposes that.
```

**User loader:**
- The username is passed exactly as presented.
- A miss returns `ErrUserNotFound`.

**Role loader:**
- A role with no privileges returns `ErrPrivilegesNotFound`.

**Provisioning (`Provision`) is create-only:**
- A taken username is refused with `ErrUserExists`, and the existing account is never adopted. Adopting it would be the same takeover path as matching identities by email.
- The collision is decided by the write, for example `INSERT ... ON CONFLICT (username) DO NOTHING` with zero rows meaning a collision. A pre-flight `SELECT` is not a check, because two overlapping transactions both pass it.
- The username is required.
- The password hash is stored verbatim, never hashed again.
- Email is passed through and is never a lookup key.
- Each role name creates a grant, and the first name is primary. A repeated name creates one grant per occurrence.
- The new user is active.

**Amending (`Update`) is a separate verb:**
- It never creates. An unknown username returns `ErrUserNotFound`.
- It writes only fields whose option was applied, decided by `IsSet`, never by a field's value, so an unnamed field is never wiped.
- **Roles change only when at least one non-empty name is given.** An empty list, or only empty names, leaves the stored grants untouched: nothing can remove every role through `Update`.
  - Names are deduplicated by first occurrence, and the first surviving name is primary.
  - A name matching an existing grant keeps that grant's identifier, super-role flag and validity window.
  - If the stored grants hold a duplicate name, the first stored grant is the one reused.
- `PasswordChangedAt` is never modified by either verb.
- It returns the complete stored record, not only the amended columns.
- Concurrent updates of one user are serialized, with a lock on the user's own row, so a stale role rebuild cannot undo another writer's change.

The two verbs are not merged into an upsert, because an upsert would let a caller overwrite an existing account on its first call.

**MFA requirement lookup:**
- A lookup by user reference, not a field on `Details`, kept as the prior art has it. No settled decision or demonstrated defect calls for folding it into the loader.
- The requirement lives with the user, not with the enrolment, so losing an enrolment row cannot clear it.
- Callers fail closed on a lookup error.

**No silent defaults:**
- No in-memory implementation of any identity port is wired by default.
- A component that needs a port and is given none returns a configuration error.
- The in-memory provisioner (which is also a user loader) ships in the `test` module for tests and local development (see departure D3).

Overrides: every port is the override point. The conformance suite in the `test` module states each contract above as cases, including a concurrent duplicate `Provision` and concurrent role rebuilds, which `default-identity-store` and consumers run.

### 5. Password encoders

```go
type Encoder interface {
    Encode(input string) ([]byte, error)
    Match(input string, encoded []byte) bool     // malformed or foreign hash: false
}
func NewArgon2idEncoder(opts ...Argon2idOption) (Encoder, error)
func NewBcryptEncoder(opts ...BcryptOption) (Encoder, error)
func NewScryptEncoder(opts ...ScryptOption) (Encoder, error)
var ErrPasswordTooLong, ErrWeakParameters error
```

| Algorithm | Default | Encoded form | Floor (below: `ErrWeakParameters` at construction) |
|---|---|---|---|
| Argon2id (the default encoder) | memory 64 MiB, 1 iteration, 4 threads, 16-byte salt, 32-byte key | `argon2id$<memory KiB>$<iterations>$<threads>$<salt>$<key>` | memory ≥ 46 MiB with 1 iteration, or memory ≥ 19 MiB with ≥ 2 iterations; threads ≥ 1; salt ≥ 16 B; key ≥ 32 B |
| bcrypt | cost 10 | the standard `$2a$`/`$2b$` form | cost ≥ 10 |
| scrypt | N = 32768, r = 8, p = 1, 16-byte salt, 32-byte key | `scrypt$<N>$<r>$<p>$<salt>$<key>` | N ≥ 32768, r ≥ 8, p ≥ 1 |

Salt and key use unpadded standard base64.

- **Default:** Argon2id with the parameters above.
- **Override:** each parameter has an option naming its default; the consumer picks bcrypt or scrypt instead, or supplies their own `Encoder`. The floors are the OWASP password storage minimums, placed so every default above sits at or above them.
- **Match:**
  - reads parameters from the encoded hash, so hashes made with older parameters keep verifying;
  - compares derived keys in constant time;
  - returns false for a hash of another format or a malformed one.
- **bcrypt:** `Encode` rejects inputs over 72 bytes with `ErrPasswordTooLong`, and `Match` returns false for them (departure D5).
- **Constant work for unknown users:**
  - a mismatch costs the same derivation as a match;
  - the `authentication` capability computes a decoy hash with the configured encoder when it is constructed, and matches the presented password against that decoy whenever the user lookup misses or the user is inactive;
  - so the decoy follows whatever algorithm and parameters the consumer configured.
- **Salt read failure:** returned from `Encode`.
- **Input:** used byte-for-byte, with no normalization.

### 6. JOSE library: `github.com/lestrrat-go/jwx/v4`

All JWT issuance, verification and JWK work uses jwx v4, the single JOSE stack for scrty. `oidc-login` reuses it for ID token verification.

- **Go 1.27 is the floor, and jwx v4 sets it.** v4 handles JSON through `encoding/json/v2`, which ships in the standard library from Go 1.27. On Go 1.26 it builds only under `GOEXPERIMENT=jsonv2`, a build-environment flag every consumer would inherit — which `library-design` forbids leaving unstated, and which no option can remove. Raising the floor is the alternative, and it is free before the first tag. The CI matrix follows.
- **API shape this design relies on** (v4 differs from v3 here):
  - `jwk.Import` is generic: `jwk.Import[jwk.Key](signer.Public())`;
  - field access is `jwt.Get[T](tok, name)` / `jwk.Get[T](key, name)` or `Field(name)`, not `Get(name, &dst)`;
  - a key set iterates with `for _, key := range set.All()`;
  - `jws.WithKeySet` requires a `kid` by default (`requireKid` is true), which is the behaviour the verifier wants, so it is not configured;
  - validation errors are struct types: `errors.Is(err, jwt.TokenExpiredError{})`.
- **Migration aid:** `github.com/jwx-go/jwxmigrate/v4` applies the mechanical v3→v4 rewrites and reports what needs judgement. It is a tool, not a dependency.

- **Algorithm pinned by the key.** Keys in the verification set carry their `alg`, and verification with the key set selects the key by `kid` and uses that key's algorithm. A header naming a different algorithm, or `none`, does not verify.
- **`kid` bound to the header.** The generator imports the signer as a JWK carrying the manager's `kid`, so the `kid` is written into the JWS protected header. The verifier requires a `kid` and looks the key up by it.
- **One place for claim checks.** Expiry is registered as a required claim exactly once; issuer and audience checks are added only when configured; the clock is passed through.
- **Alternatives rejected:**
  - `github.com/golang-jwt/jwt/v5`: no JWK or JWKS support, so keys would need a second library, with two algorithm guards that can disagree;
  - `github.com/go-jose/go-jose/v4`: a smaller dependency graph, but scrty would still hand-write key-set selection by `kid` and claim validation that jwx provides;
  - `github.com/coreos/go-oidc`: brings go-jose as a second JOSE stack into the OIDC path.
- **Trade-off:** jwx is a larger dependency graph than a minimal JOSE library, and a future jwx incompatibility affects every token and key path at once — as the v3→v4 move itself shows. The public surface is `crypto.Signer`, `signingkey.PublicKey`, the public JWK bytes each key record carries, and scrty's own claim accessors. **No exported signature in either package names a jwx type** (decision 10): `token`'s is enforced by a guard over its exported surface, and `KeySource` describes a verification key as `signingkey.PublicKey`, a struct of standard-library types. jwx stays inside both packages — `signingkey` uses it to render a key's public JWK and its RFC 7638 thumbprint, `token` to parse and verify — so a major-version bump is scrty's problem and reaches no consumer, least of all one who wrote their own key source. v4 trims the core's own dependencies and drops `net/http`, which narrows the graph rather than widening it.

### 7. Token generator and verifier

```go
var ErrTokenInvalid = errors.New("token: invalid")

type Claims struct{ /* verified token */ }
func (c *Claims) Subject() string
func (c *Claims) ID() string

type Verifier interface { Verify(ctx context.Context, token string) (*Claims, error) }
type Generator interface {
    Generate(ctx context.Context, id string, p *identity.Principal) (string, error)
    Verifier
}
func NewGenerator(keys signingkey.KeySource, opts ...GenerateOption) (Generator, error)
func NewVerifier(opts ...VerifyOption) (Verifier, error)   // VerifyWithKeySource required
```

**Issued token:**
- **Header:** `alg`, and the `kid` of the key currently signing for that algorithm.
- **Claims:**
  - `jti`: the caller's identifier, the session identifier on the session path;
  - `iss`: the configured issuer;
  - `sub`: the principal's username;
  - `aud`: when configured (departure D6);
  - `iat`: the time of issue;
  - `exp`: `iat` plus the lifetime.

| Generator option | Default |
|---|---|
| `WithIssuer` | none |
| `WithAudience` | none |
| `WithLifetime` | 15 min; ≤ 0 is a construction error |
| `WithSigningAlg` | `RS256` |
| `WithClock` | system clock |

- **No key for the algorithm:** issuing returns an error, never an unsigned token.
- **The generator is also a verifier,** with the generator's issuer and audience, so a service that issues can verify without a second construction.
- **Lifetime cap:** when the key source reports its key lifetime and rotation interval, a token lifetime longer than lifetime minus rotation interval is a construction error (departure D7).

**Verification:**
1. The token must be a compact JWS signed by a key in the key source's current set, with the key selected by `kid`. `token` builds that set itself from the `[]signingkey.PublicKey` the source returns, so no jwx type crosses the port (decision 10). A missing `kid`, an unknown `kid`, `alg: none` and a header algorithm differing from the key's are all rejected.
2. `exp` is required, and the token is rejected at or after `exp`.
3. `nbf` and `iat`, when present, must not be in the future.
4. No clock skew is tolerated by default.
5. **Issuer:** enforced only when configured. `iss` must then be present and equal it. Enforcement depends on whether the option was given, never on its emptiness in the other direction.
6. **Audience:** enforced only when configured. `aud` must then contain it, and a token without `aud` is rejected. With no audience configured, `aud` is not checked.
7. **Errors:** every rejection returns `ErrTokenInvalid` wrapping the cause. A failure to obtain the key set is returned as that error and does not match `ErrTokenInvalid`.

| Verifier option | Default |
|---|---|
| `VerifyWithKeySource` | none; required, construction error when absent |
| `VerifyWithIssuer` | none |
| `VerifyWithAudience` | none |
| `VerifyWithClock` | system clock |

- **Override:** every option above, or the consumer's own `Verifier` or `Generator` wherever later changes accept one.

### 8. Signing keys

```go
type Alg = string   // RS256 (default), ES256, EdDSA

type Record struct {
    Kid       string
    Alg       Alg
    Private   []byte     // PKCS #8 DER; opaque to the store
    PublicJWK []byte     // public JWK JSON
    CreatedAt time.Time
}
type KeyStore interface {
    Store(ctx context.Context, rec Record) error        // insert, or replace the record with that kid
    LoadAll(ctx context.Context) ([]Record, error)      // oldest first by CreatedAt
}
func NewInMemoryKeyStore() KeyStore

// One verification key, described in standard-library types so a consumer's
// own source needs no JOSE library (decision 10).
type PublicKey struct {
    Kid string
    Alg Alg              // this package's own string alias
    Key crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
}

type KeySource interface {                                // implemented by *KeyManager
    GetSigner(alg Alg) (kid string, signer crypto.Signer, ok bool)
    VerificationKeys() ([]PublicKey, error)
}

// Optional, reported by a source that knows its own rotation schedule, so the
// generator can refuse a token lifetime the keys cannot outlive (D7).
type LifetimeReporter interface {
    KeyLifetime() time.Duration
    RotateInterval() time.Duration
}

type Clock interface{ Now() time.Time }                   // WithClock

// Optional. A clock that also paces the loops, so an injected time source
// drives rotation, reload and housekeeping rather than only stamping keys.
// Without it the loops run on time.NewTicker and no advance of the clock can
// fire one, which leaves every configured-interval guarantee unobservable.
type TickerClock interface {
    Clock
    NewTicker(d time.Duration) Ticker
}
type Ticker interface {
    C() <-chan time.Time
    Stop()
}

func NewKeyManager(ctx context.Context, opts ...Option) (*KeyManager, error)   // decision 9
func (km *KeyManager) Start(ctx context.Context) error
func (km *KeyManager) Stop() error
func (km *KeyManager) SupportedAlgs() []Alg
```

| Option | Default |
|---|---|
| `WithAlgs` | `RS256` |
| `WithLifetime` | 24 h |
| `WithRotateInterval` | 1 h |
| `WithHousekeepingInterval` | 1 h |
| `WithReloadInterval` | 1 min; must be shorter than the rotation interval (D10) |
| `WithKeyStore` | in-memory store |
| `WithClock` | system clock |
| `WithLogger` | `slog.Default()`; rotation and reload failures, sampled with `pkg/logsample` and a reporter (D11) |
| `WithErrorHook` | none; called with every rotation and reload failure (D11) |
| `WithLogSampleWindow` | 5 min; the window `pkg/logsample` suppresses repeated failure records over, each record stating how many it stood for |

**Construction:**
- **The caller's context reaches the store** for the load and for any initial write, and nothing else in construction inspects it (decision 9).
- **Construction errors:**
  - an unsupported algorithm;
  - a non-positive duration;
  - a lifetime not longer than the rotation interval (departure D7);
  - a reload interval not shorter than the rotation interval (departure D10);
  - no algorithms at all, which would otherwise construct a manager holding no keys;
  - a nil key store, clock or logger. The logger is dereferenced from a
    background goroutine, so a nil one panics the consumer's process at the
    first store failure rather than at wiring time.
- **Loading:**
  - it loads every record from the store;
  - a record that cannot be decoded is a construction error and is never skipped, since skipping it would mint a fresh key and orphan every token the unreadable key signed;
  - the current key per algorithm is the record with the latest `CreatedAt`, not the record in the last position, since a store or a sealing decorator may return records in any order; an exact tie goes to the later record.
- **Initial keys:**
  - for each configured algorithm without a current key, it mints one, stores it, and only then uses it;
  - a store error is a construction error;
  - RSA keys are 2048 bits;
  - the `kid` is the RFC 7638 SHA-256 thumbprint;
  - the public JWK carries `alg` and `use: sig`.

**Lifecycle:**
- `Start` launches two goroutines:
  - **rotation:** every rotation interval, mints and stores a new key per algorithm, which becomes current at once;
  - **housekeeping:** every housekeeping interval, removes from the manager's set every key older than the lifetime (measured from creation), except the current key per algorithm.
- **Reload:** every reload interval, the manager loads the store and adds keys it does not hold. It skips non-current keys older than the lifetime, then re-picks the current key per algorithm by latest `CreatedAt`. A failed reload keeps the held keys.
- A failed rotation leaves the previous key current and is retried on the next tick.
- Rotation and reload failures go to the logger and the error hook.
- Housekeeping takes its own lock, and is never called while rotation holds one.
- Housekeeping removes keys from the in-memory set, so they stop being published; the store is not pruned.
- Each loop returns on its context's cancellation or on `Stop`.
- `Start` is idempotent.
- `Stop`:
  - cancels both loops, then waits for them to return, including an in-flight key generation and store write, so no write lands after `Stop` returns;
  - is idempotent;
  - returns at once on a manager that was never started, and a later `Start` then launches nothing.
- `Start` and `Stop` coordinate so a concurrent pair cannot leave a goroutine unjoined.

**Published keys:** `VerificationKeys()` returns the public half of every key the manager holds — identifier, algorithm and public key — as copies the caller owns (decision 10). Nothing private leaves, and no jwx type does either. A consumer serving a JWKS endpoint serves what `JWKS()` returns (decision 11), or builds their own set from those keys where they need one this library does not produce.

**Store:**
- Private bytes are opaque to the store: `secrets-at-rest` wraps a `KeyStore` to seal them.
- **Default:** in-memory, lasting only as long as the process.
- **Override:** any `KeyStore`, such as the durable stores from `security-state-stores`.

- **Overrides:** every option above; any `KeyStore`; and any `KeySource` in place of the manager, such as a KMS-backed signer (departure D4).

### 9. Construction takes the caller's context

```go
func NewKeyManager(ctx context.Context, opts ...Option) (*KeyManager, error)
```

Construction is not pure: it reads every record from the key store, and for each configured algorithm with no stored key it writes the key it mints. Both are I/O against something the consumer owns — a PostgreSQL table, a KMS, a network. The context the caller passes is the context those calls receive.

- **Default:** the caller's context is propagated to `KeyStore.LoadAll` and to `KeyStore.Store` unchanged. A context already cancelled, or whose deadline has passed, fails construction with the store's error; no manager is returned, no key is held, and nothing is started.
- **The manager does not itself inspect the context.** It adds no deadline of its own and checks no cancellation between steps. What a consumer observes is what their store does with the context, which keeps the contract one sentence long and puts the decision where the I/O is.
- **Override:** the parameter itself is the override point. `context.Background()` asks for an unbounded construction, `context.WithTimeout` for a startup budget, a request or tracing context for a startup span. There is no option and none is needed.
- **Stated limit:** the default in-memory store performs no I/O, so nothing it does can be cancelled, and construction over it succeeds with an already-cancelled context. The limit belongs to that store, not to the contract; it is documented rather than hidden, per `library-design` rule 4.
- **Why it changed:** construction previously did its store I/O on `context.Background()` — a context that can never be cancelled and carries no deadline. A durable store that hung at startup therefore hung construction for ever, with no way for the caller to give up: under an orchestrator's startup probe, an init that cannot be killed cleanly. Tracing and request-scoped values were dropped at the one point a consumer would want a startup span.
- **Alternatives rejected:**
  - a `WithConstructionContext` option — it stores a context in a struct, which is the anti-pattern the `context` guidance exists to warn against;
  - leaving it documented — that records a limitation with no upside, when the fix costs one parameter.
- **Taken now:** nothing is tagged, and `NewKeyManager` had no production caller outside its own doc comment, so the break costs nothing today and gets more expensive after the first tag.
- **Pinned by** `TestNewKeyManagerConstructionContext`: a cancelled context on the load, an expired deadline on the load, a cancelled context on the initial write, and a live context constructing normally.

### 10. The key source names no JOSE type

```go
type PublicKey struct {
    Kid string
    Alg Alg              // a string alias; jwx-free
    Key crypto.PublicKey // standard library
}

type KeySource interface {
    GetSigner(alg Alg) (kid string, signer crypto.Signer, ok bool)
    VerificationKeys() ([]PublicKey, error)
}
```

`KeySource` is the port a consumer implements to supply keys from an HSM or an external key service, with no key manager constructed at all (D4). Its previous `JWKS() (jwk.Set, error)` obliged every such implementation to import jwx by path and major version for a reason of scrty's and none of its own, so a jwx v5 bump would break all of them. The port is now standard library plus `signingkey.Alg`, which is a string.

- **Default:** `*KeyManager` implements the port, and `token` builds the jwx key set it verifies against from the returned slice. A consumer who wires the manager sees no difference.
- **Override:** any `KeySource`. What a consumer's source returns is used as given: the library neither interprets it nor rewrites it (`library-design` rule 5), and a source that cannot supply keys is an outage, not a verdict on the token.
- **The keys are copies.** `crypto.PublicKey` shares structure with the manager's own key — `*rsa.PublicKey` shares `N *big.Int`, `*ecdsa.PublicKey` shares its coordinates, `ed25519.PublicKey` is a slice — so returning live handles would let a consumer reach through a published key and rewrite the material the manager signs under. Each returned key is therefore deep-copied, the same boundary every other key the manager hands out keeps.
  - An ECDSA key is copied through `PublicKey.Bytes` and `ecdsa.ParseUncompressedPublicKey`, not by building a key from its coordinates. Go deprecated `X` and `Y` in 1.26 because a key assembled from raw coordinates can be off its curve, which is the very thing this copy exists to prevent; the sanctioned round trip validates the point instead of asserting it, so it is the stronger answer and not merely the quieter one. It reports an error, which is why copying a key can fail at all: such a failure is an outage — the key set could not be produced — and never a verdict on a token, exactly as the port already documents for a source that cannot answer.
- **The name changed deliberately.** The method returns neither JSON nor a set, so `JWKS` named an encoding it does not produce. "Verification keys" is the term the codebase already uses: `token.ErrNoVerificationKeys`, `VerifyWithKeySource`'s godoc, and the signing-keys requirement "Signing and verification keys can be supplied without the key manager".
- **Alternatives rejected:**
  - keeping `jwk.Set` with the coupling recorded as a stated exception — which is what this design said before this decision; it makes every consumer's compatibility hostage to scrty's dependency choice, at the one place the library invites consumers to write code;
  - returning the serialized RFC 7517 set, `JWKS() ([]byte, error)` — `token` would then re-parse JSON and reconstruct keys on every verification, far more work than either other option.

**The cost, measured.** An earlier version of this design asserted that a jwx-free port would cost roughly zero. It does not, and the numbers replace that claim. Apple M4 Pro, 3 runs of 2000 iterations with the first discarded as warm-up — indicative, not benchstat-grade:

| Step | 1 key | 3 algorithms |
|---|---|---|
| A full RS256 `Verify` — the denominator | ~25,600 ns / 7,886 B / 119 allocs | — |
| Obtaining the key set before: `JWKS()` with its per-key clone | ~165 ns / 632 B / 9 allocs (0.6% of a verification) | ~290 ns / 1,288 B / 24 allocs |
| Obtaining it after: deep copy, then rebuilding the jwx set in `token` | ~440 ns / 1,376 B / 18 allocs (1.7%) | ~1,400 ns / 3,659 B / 64 allocs (~5%) |
| The deep copy on its own | ~46 ns / 336 B / 3 allocs (0.18%) | — |

The dominant new cost is `jwk.Import` inside `token`, which is paid whether or not the keys are copied. **The trade accepted:** a jwx-free port for about +270 ns and +9 allocations per verification in the default single-key configuration, on a ~25.6 µs operation whose asymmetric cryptography dominates everything around it.

- **Pinned by** `TestVerificationKeysDoNotShareKeyMaterialWithTheManager` for the copies, a consumer key source written with the standard library alone for the port, and `TestNoExportedSymbolExposesAJOSEType`, a guard over `signingkey`'s exported surface that refuses a jwx type reappearing on it — the counterpart of the guard `token` already had.

**What it enables, left open.** An immutable `[]PublicKey` is safe for `token` to cache and rebuild only when the key identifiers change, which would land *below* today's cost; a mutable `jwk.Set` is not safely cacheable, which is why the question could not be asked before. That caching is not part of this change — it needs a lock or an atomic to be correct under concurrent verifications — and is recorded in Open Questions.

### 11. Publishing the key set

```go
func (km *KeyManager) JWKS() ([]byte, error) // on the manager, not on the port
```

Decision 10 took `jwk.Set` off the port, which is right for the port and left a gap behind it. A
service that issues scrty tokens usually has to publish its public keys so other services can
verify them — a `/.well-known/jwks.json` endpoint. With nothing returning a document, a consumer
had to serialize RFC 7517 themselves from `VerificationKeys()`, which means importing a JOSE
library to redo work this package already does, and reintroduces at the endpoint exactly the
coupling decision 10 removed from the port. Under the default in-memory store it was not merely
inconvenient but impossible: the `PublicJWK` bytes each record carries are reachable only through a
store the consumer supplied and can read.

- **Default:** every key the manager currently holds, in the order `VerificationKeys()` reports
  them, each carrying its `kid`, its `alg` and `use: "sig"`, and none carrying private material. A
  key held for an algorithm this manager was not configured with is published too, for the reason
  it is published anywhere: a replica sharing the store wrote it, and publishing it is what
  verifies the tokens it signed.
- **Override:** `VerificationKeys()`, which returns plain data. A consumer who needs a document
  this method does not produce — extra JWK parameters such as `x5c`, a filtered subset of the keys,
  a different order, or a wrapper their infrastructure expects — renders their own from that slice
  and never has to fork or copy this one. That is the `library-design` rule 2 override point, and
  it is named in the godoc so it is discoverable from the method a consumer finds first.
- **Bytes, deliberately.** Returning `[]byte` rather than a JOSE type is what lets the endpoint be
  `w.Write(...)` with no JOSE dependency, and it is what keeps this package's exported surface free
  of jwx, which `TestNoExportedSymbolExposesAJOSEType` enforces. The package still uses jwx
  internally to build the document; the guard forbids it on the surface, not in the implementation.
- **Not the rejected alternative.** Decision 10 rejected `JWKS() ([]byte, error)` *on the port*,
  because `token` would then re-parse JSON and reconstruct keys on every verification. This is the
  same signature in a different place and for a different purpose: on the concrete manager, for
  publication, on a path no verification takes. The port keeps `VerificationKeys()`, and a consumer
  implementing `KeySource` is never asked to serialize anything.
- **Stated limit:** the document is built on each call and not cached, so a handler serving it on
  every request pays for it on every request. A consumer who serves it at volume caches the bytes
  and rebuilds them no more often than the rotation interval.

### 12. Departures

Each departure below is justified by (a) a settled decision, or (b) a demonstrable defect in the prior art scrty learned from.

| # | scrty does differently | Why |
|---|---|---|
| D1 | User, role, organization and group identifiers are opaque strings, not sortable numeric or UUID identifiers. The MFA requirement lookup and later session records key on `UserID`. | (a) The user reference is opaque and consumer-owned, and identity-store data belongs to the consumer. |
| D2 | The MFA requirement lookup is an identity port in `identity`, not a policy-package interface. | (a) The settled identity ports list the MFA requirement lookup beside the loaders and provisioner. |
| D3 | The in-memory user provisioner and loader live in the `test` module, not the `identity` package. | (a) Shared test helpers live in the `test` module. |
| D4 | The generator and verifier take a `KeySource` port rather than the concrete key manager. | (a) Every default is replaceable through a port without forking. |
| D5 | bcrypt `Match` returns false for inputs over 72 bytes. | (b) The bcrypt comparison hashes only the first 72 bytes and applies no length check, so an input sharing a stored password's first 72 bytes matched, although `Encode` already refused such inputs. |
| D6 | The generator can set `aud`. | (b) Without it, a verifier configured with an audience rejected every token the generator issued, a limitation recorded in the prior art's own tests. |
| D7 | Password parameters are options with a floor, the key lifetime must exceed the rotation interval, and a token lifetime longer than key lifetime minus rotation interval is a construction error. | (a) Every default is replaceable; wiring mistakes fail at construction; the floor is part of this change's assignment. The prior art used fixed constants and accepted configurations that would unpublish a key while tokens it signed were still valid. |
| D8 | A provisioning collision error does not include the username. | (b) The prior art's own comment on the collision write names the harm of an error message embedding the username, which is an email address on just-in-time provisioning, yet its collision error still embedded it. |
| D9 | JOSE library is jwx v4, and the module's Go floor rises to 1.27 to carry it. | (a) settled: jwx is the single JOSE stack, on its current major. The floor follows from v4's use of `encoding/json/v2`; the alternative imposes `GOEXPERIMENT=jsonv2` on every consumer on Go 1.26. Free before the first tag. |
| D10 | The key manager reloads the store periodically: default every minute, `WithReloadInterval` to override, and an interval not shorter than the rotation interval is a construction error. | (b) Keys were loaded only at construction, so replicas sharing a store never saw each other's rotated keys, and a token minted on one replica was rejected by the others until restart. |
| D11 | Rotation and reload failures are logged (sampled) and passed to an optional error hook. | (b) Rotation errors were discarded, so a store that kept rejecting writes left one key signing indefinitely with no signal. |

Behaviours kept exactly as in the prior art, though a fresh design might question them. They are recorded so a later change decides deliberately:
- `sub` is the username;
- rotated keys are current at once, with no pre-publication;
- keys are removed by age since creation;
- the store is never pruned;
- RS256 is the default algorithm;
- `aud` is not checked when no audience is configured.

### 13. Test-first

- **`identity` and `factor`:**
  - table tests over the kind/channel/exemption matrix, including empty and unknown kinds;
  - the principal mapping;
  - the context helpers.
- **Conformance suite** (`test` module) for loader, role loader, provisioner and MFA lookup, run here against the in-memory implementations:
  - `Provision` collision;
  - the `Update` field and role rules;
  - `PasswordChangedAt` preservation;
  - full-record returns.
- **`password`:**
  - round trips;
  - floors;
  - the 72-byte boundary, including a 73-byte input sharing a prefix;
  - malformed hashes;
  - a benchmark showing match and mismatch cost the same.
- **`token`:**
  - hand-built tokens for `alg: none`, algorithm mismatch, missing and unknown `kid`, a token signed by another key manager;
  - expiry;
  - issuer and audience configured and not;
  - clock injection.
- **`signingkey`:**
  - two managers over one store: reload at construction, and a key rotated in by one verifying on the other within one reload interval;
  - reload-interval validation;
  - rotation and reload failures reaching the logger and error hook;
  - failing stores;
  - out-of-order stores;
  - housekeeping under a controlled clock;
  - `goleak` for `Stop`, double `Start`, concurrent `Start`/`Stop`, and `Stop` during an in-flight rotation;
  - construction under a cancelled context and under an expired deadline, on the load and on the initial write, and normally under a live one (decision 9);
  - a verification key handed out, mutated by the caller, and the manager's own published keys and signatures unchanged (decision 10).

## Risks / Trade-offs

- [A token minted by one replica with a freshly rotated key reaches another replica before that replica's next reload] → Rejected for at most one reload interval (default 1 minute). Documented. A consumer lowers the interval to narrow the window.
- [Replicas each rotate independently, so the store gains one key per replica per rotation] → Harmless: all are published, and replicas converge on the newest key after reload.
- [`sub` is the username, so renaming a user invalidates their live tokens and the per-request reload targets the new name] → Documented; renames also end sessions. Raised as an open question.
- [Rotated keys sign immediately, so an external verifier that caches the JWKS rejects new tokens until its cache refreshes] → Internal verification reads the in-process set and is unaffected. Documented for external resource servers.
- [The key store grows by one record per algorithm per rotation and is loaded in full at start] → `expiry-sweeping` is the natural owner of pruning; raised as an open question.
- [A store that keeps failing leaves one key signing] → The previous key stays current. Every failure reaches the logger and error hook (D11). Logs are sampled with a reporter, so a persistent outage writes a bounded number of records with exact suppressed counts.
- [jwx enlarges the core module's dependency graph] → Accepted as settled. The dependency guard still passes, since jwx is no framework, driver, scheduler or DI container. v4 narrows the graph rather than widening it: its core drops `net/http` and `httprc`, moving HTTP JWKS retrieval to the `jwkfetch` companion, which this change does not need.
- [jwx v4 forces the module's Go floor to 1.27] → Accepted, and free before the first tag. A consumer on Go 1.26 cannot embed scrty; the alternative was to make every such consumer set `GOEXPERIMENT=jsonv2`, which `library-design` forbids leaving as a silent inherited constraint.
- [Argon2id at 64 MiB per verification under concurrency] → Sizing guidance in godoc; the login rate limit bounds concurrency per source.
- [Construction over the default in-memory store cannot be cancelled, because that store performs no I/O] → Stated rather than hidden (decision 9). A consumer who needs a bounded startup has a durable store, which is where the I/O and therefore the cancellation live.
- [`token` rebuilds the jwx key set on every verification from the slice the key source returns] → Measured at ~1.7% of an RS256 verification with one key and ~5% with three (decision 10), against asymmetric cryptography that dominates the operation. Caching the set is the open follow-up the shape now makes possible.

## Migration Plan

Not applicable: a new library with no consumers and no tags.

## Open Questions

- **Token subject:** should `sub` stay the username, or become the user reference, with a user loader by reference?
- **Store pruning:** kept as the prior art has it, with no pruning. Whether `expiry-sweeping` should delete keys past their lifetime is for that change to decide.
- **Caching the verification key set:** `token` rebuilds the jwx set on every verification from the `[]PublicKey` the source returns. That slice is immutable, so the set can be built once and rebuilt only when the key identifiers change, which lands below the cost of the shape that preceded decision 10 — the mutable `jwk.Set` could not be cached safely at all. It needs a lock or an atomic to be correct under concurrent verifications, so it is not part of this change.
