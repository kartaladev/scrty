# Signal Bus Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every task to a subagent and reviews it (`.claude/rules/subagent-delegation.md`).

**Goal:** Consumers on several replicas carry session signals through Redis or PostgreSQL, with one encoding and authenticated messages by default.

**Architecture:** A core package, `httpsec/signalwire`, holds the encoding and the MAC. Two nested modules, `httpsec/redisbus` and `httpsec/pgxbus`, implement `httpsec.SignalBus` on one channel each and return every failure to the chain's backoff. An optional `SignalBusChecker` lets a bus refuse an envelope when it is raised.

**Tech Stack:** Go 1.27; go-redis v9.23.0; pgx v5.12.0; testify, uber-go/mock, the `test` module's `RunTestRedis`, `RunTestPostgres` and `RunTestPostgresStandby`.

**Spec:** `openspec/changes/signal-bus-backends/` (`proposal.md`, `design.md` D1 to D9, `specs/`, `tasks.md`).

## Global Constraints

- Test-first: a red run failing on an assertion (`.claude/rules/golang-tdd.md`). Tables follow the `table-test` skill. Mocks come from `use-mockgen`, and real brokers from `use-testcontainers`, never a fake.
- Defaults: Redis channel `scrty:signals`; PostgreSQL channel `scrty_signals`; health interval 5 s; replay window 5 minutes, 0 turning it off; keys at least 32 bytes.
- A wiring mistake is `httpsec.ErrConfig` from `New`. Every option names its default in godoc.
- Never use `PubSub.Channel()`: `Subscribe` loops on `ReceiveTimeout` and `Ping`, and returns every failure.
- A message that fails to decode or verify is dropped and counted, and never ends `Subscribe`.
- The chain logs only an error's type, so errors are typed and hold no broker text.
- The core gains neither driver. Nothing imports `test` but `test`.
- A bus never ends a stream: an envelope only wakes it, and the store decides.
- `New` closes nothing it was handed.
- Never read or cite `.claude/.legacy`. Never edit `openspec/` from an implementer. Run conformance at `-parallel 4`, one module at a time. Run `golangci-lint run ./...` in every module changed, because `make lint` stops at the first failure.

## Review Focus

1. A forged or malformed message flooding a bus. Expected: dropped and counted, the subscription stays up, and it never ends `Subscribe`. Tasks 2.2 and 3.2.
2. A broker that stops answering during a logout. Expected: the logout completes, within `BusTimeout`. Task 4.1.
3. A dead listening connection the operating system has not reported. Expected: `Subscribe` returns within its health interval. Tasks 2.2 and 3.2.
4. A mistaken `WithoutAuthentication` on one replica of a signed group. Expected: each drops the other's messages visibly, by count, and the heartbeat still ends streams. Task 4.1.
5. `Data` at exactly the PostgreSQL limit, multi-byte included. Expected: delivered unchanged, and one byte more is refused. Task 3.3.

---

## Dispatch map (main session)

| Wave | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 | F1 | 1.1, 1.2 | `httpsec/signals*.go` for the port, `httpsec/signalwire` | Opus: signature verification written for the first time, and a port other lanes compile against |
| 2 (parallel) | F2 | 2.1–2.3 | `httpsec/redisbus`, its `test` rows, the `integrationTable` row and `go.work` line | Opus: a reconnect loop whose mistakes pass the tests |
| 2 (parallel) | F3 | 3.1–3.4 | `httpsec/pgxbus`, its `test` rows, the `integrationTable` row and `go.work` line | Opus: as F2 |
| 3 | F4 | 4.1 | `test` module's bus suite | Sonnet: a conformance suite over a stated contract |
| 4 | F5 | 4.2 | `README.md`; the main session updates `release-readiness` | Sonnet: documentation |
| 5 | main, one reviewer | 4.3, then 4.4 | | Opus reviewer |

F2 and F3 share `go.work` and `layout_guard_test.go`, so each gets its own worktree, and the main session integrates. Each dispatch gets a fresh reviewer that edits nothing, Opus for F1 to F3 and Sonnet for F4 and F5. CodeQL does not run on a draft, so mark the pull request ready before 4.4's CI watch.

---

### Tasks 1.1–1.2: The port and the encoding (F1)

**Files:** Modify: `httpsec/signals.go`, `httpsec/signals_bus.go`. Create: `httpsec/signalwire/{doc,wire,signer}.go` and tests.

**Interfaces produced:**
```go
// httpsec
type SignalBusChecker interface { CheckEnvelope(e SignalEnvelope) error }
// httpsec/signalwire
type Key struct { ID string; Secret []byte }
func NewSigner(channel string, keys []Key, opts ...SignerOption) (*Signer, error) // refuses no keys, under 32 bytes, duplicate IDs
func NewUnsigned(channel string) *Signer
func WithReplayWindow(d time.Duration) SignerOption // default 5 * time.Minute; 0 turns it off
func Encode(e httpsec.SignalEnvelope, s *Signer, now time.Time) ([]byte, error)
func Decode(raw []byte, s *Signer, now time.Time) (httpsec.SignalEnvelope, error)
func Overhead(e httpsec.SignalEnvelope, s *Signer) int // what Encode adds, for a backend's limit
var ErrMalformed, ErrBadMAC, ErrUnknownKey, ErrStale error
```

**Decisions the implementer cannot make alone:**
- The MAC covers the exact bytes of a versioned, fixed-order encoding, including the channel name and timestamp. Verify with `hmac.Equal` before decoding what the MAC covers.
- `Decode` on a `NewUnsigned` signer refuses a signed message as malformed, and a signed signer refuses an unsigned one.
- `raise` consults the check after the closed check and before queueing, and only on a consumer's bus. An end report ignores its error, as it ignores `ErrSignalsBusy`.

- [ ] **1.1 Red:** `TestSessionSignals_Bus_Check`: a refusal returns to `PublishSignal`, with nothing queued and `BusDropped` unchanged; an end report still ends its sign-in; a bus with no check queues as before. Expect `PublishSignal` returning nil. **Green** in `raise`.
- [ ] **1.2 Red:** `TestSignalwire_RoundTrip` and `TestSignalwire_Refuses`: every row of `tasks.md` 1.2, and `FuzzDecode`. **Green** per the interfaces. Verify with each task's command.

### Tasks 2.1–2.3: Redis (F2)

**Files:** Create: `httpsec/redisbus/{go.mod,doc,bus,options,errors}.go` and unit tests. Modify: `go.work`, `layout_guard_test.go`. Tests needing a broker: `test/redisbus/`.

**Interfaces produced:**
```go
func New(client redis.UniversalClient, opts ...Option) (*Bus, error)
func WithKeys(keys ...signalwire.Key) Option
func WithoutAuthentication() Option
func WithChannel(name string) Option         // default "scrty:signals"
func WithHealthInterval(d time.Duration) Option // default 5 * time.Second
func WithSharded() Option                    // default off
func WithReplayWindow(d time.Duration) Option // default 5 * time.Minute
func (b *Bus) Publish(ctx context.Context, e httpsec.SignalEnvelope) error
func (b *Bus) Subscribe(ctx context.Context, deliver func(httpsec.SignalEnvelope)) error
func (b *Bus) Verify(ctx context.Context) error
func (b *Bus) Dropped() uint64
var ErrUnauthorized error
```

**Decisions:** copy `redisstore`'s client check. A context end returns nil from `Subscribe`, and every other failure returns an error. Map `NOAUTH`, `WRONGPASS` and `NOPERM` to `ErrUnauthorized`, without their text.

- [ ] **2.1 Red:** `TestNew_Refuses`, by `tasks.md` 2.1. **Green.** Run the layout guards.
- [ ] **2.2 Red:** `TestBus_Redis`, by `tasks.md` 2.2, stopping the container for the outage row, and asserting no goroutine is left. **Green** over `ReceiveTimeout` and `Ping`.
- [ ] **2.3 Red:** `TestBus_Redis_Options` and `TestBus_Redis_Verify`, by `tasks.md` 2.3. First run `go doc github.com/redis/go-redis/v9.UniversalClient`, and state in the report whether it has `SSubscribe`. **Green.**

### Tasks 3.1–3.4: PostgreSQL (F3)

**Files:** Create: `httpsec/pgxbus/{go.mod,doc,bus,options,errors}.go` and unit tests. Modify: `go.work`, `layout_guard_test.go`. Tests needing a database: `test/pgxbus/`.

**Interfaces produced:**
```go
func New(pool *pgxpool.Pool, opts ...Option) (*Bus, error)
// WithKeys, WithoutAuthentication, WithChannel (default "scrty_signals", at most 63 bytes),
// WithHealthInterval, WithReplayWindow, Publish, Subscribe, Verify, Dropped: as redisbus
func WithListenConfig(c *pgx.ConnConfig) Option // default pool.Config().ConnConfig
func (b *Bus) CheckEnvelope(e httpsec.SignalEnvelope) error
var ErrUnauthorized, ErrStandby, ErrEnvelopeTooLarge error
```

**Decisions:** quote the channel with `pgx.Identifier{ch}.Sanitize()` for `LISTEN`. Publish as one statement, `SELECT pg_notify($1, $2)`. Each wait uses a context with a deadline of the health interval, and a deadline expiry is the cue to `Ping`, not a failure. The limit is `NOTIFY`'s under 8000 bytes, of the encoded message, through `signalwire.Overhead`.

- [ ] **3.1 Red:** `TestNew_Refuses`, by `tasks.md` 3.1. **Green.** Run the layout guards.
- [ ] **3.2 Red:** `TestBus_Postgres`, by `tasks.md` 3.2, using `pg_terminate_backend` for the outage row. **Green.**
- [ ] **3.3 Red:** `TestBus_Postgres_Size`, by `tasks.md` 3.3, with multi-byte data at the limit and one byte over. **Green.** State the measured limit in godoc and in the report.
- [ ] **3.4 Red:** `TestBus_Postgres_Options` and `TestBus_Postgres_Verify`, by `tasks.md` 3.4. **Green.**

### Tasks 4.1–4.4: Conformance and integration (F4, F5, main)

- [ ] **4.1 Red:** in `test/signalbustest`, `RunSignalBus(t, newBus func(t *testing.T, channel string) httpsec.SignalBus)`, and `TestSuitesCatchBrokenBuses` over seeded buses that hide a dead connection and that end on bad input. Add the rows from Review Focus 2 and 4, and two real chains sharing a bus. **Green** on both backends, at `-parallel 4`.
- [ ] **4.2:** the README section by `tasks.md` 4.2. The main session adds both modules to `release-readiness`'s tag list and `GOWORK=off` gate, and its `plans.md`.
- [ ] **4.3:** an Opus reviewer, by `tasks.md` 4.3.
- [ ] **4.4:** the gate, by `tasks.md` 4.4, marking the pull request ready so that CI and CodeQL run.
