# Shared Rate Limiting on PostgreSQL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The OpenSpec `tasks.md` beside this file is the checklist of record: only the main session ticks it.

**Goal:** A shared `ratelimit.Limiter` and `ratelimit.LimiterFactory` over PostgreSQL, in `sqlstore` and `pgx`, that passes the shared-limiter conformance suite, stays HOT and out of TOAST, and is pruned by one expiry task.

**Architecture:** The table `rate_limit_buckets` is keyed by `(namespace, key)`. Each row holds at most `limit` newest stamps, the newest stamp ever recorded, and the longest window any instance recorded with. All SQL lives in `internal/pgschema`, and both backends wrap a thin backend in `internal/unavailable.Wrap`, as the Redis limiter does. The factory doubles as the `ratelimit.Pruner` that `ratelimit.ExpiryTask` now accepts.

**Tech Stack:** Go 1.27, `database/sql`, pgx v5 (`pgxpool`), goose-format embedded SQL, testcontainers-go (PostgreSQL 15 and 18), testify, clockwork, `test/ratelimittest`.

**Spec:** `openspec/changes/shared-rate-limiting-postgres/` (`proposal.md`, `design.md`, `specs/**`, `tasks.md`). Read the design decision a task names before starting it.

## Global Constraints

- The core module gains **no** dependency; `sqlstore` reads SQLSTATE through the existing `sqlStater` interface (`sqlstore/identity_errors.go:67`), never by importing pgx.
- Test helpers, conformance runs, fault tests and benchmarks live in the `github.com/kartaladev/scrty/test` module only; no other module imports it.
- Every Go change is test-first: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, re-run, then refactor (consider `/simplify`).
- Table-driven tests use the project `table-test` skill: `assert` closures, `t.Context()`.
- Construction errors wrap `ratelimit.ErrConfig`, as the Redis limiter's do. Constructors perform no I/O.
- Limits: `limit` 1–128, namespace 1–64 bytes and free of `:`, window ≥ 1µs, keys over 512 bytes (or beginning `sha256:`) stored as `sha256:<hex>`.
- Time: `clock_timestamp()` read once per statement by default; `WithLimiterClock` passes `$now`.
- Each limiter on the `database/sql` backend takes a `*sql.DB`, and each pgx one a `*pgxpool.Pool`. Neither ever joins an ambient transaction.
- PostgreSQL supported: 15 and 18 (`SCRTY_TEST_POSTGRES_IMAGE`); `Verify` floor `server_version_num >= 150000`.
- Never cite the predecessor; never copy from `.claude/.legacy`.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.

## Review Focus

These five inputs are the most likely to bite and are not obvious from the task list. Each is pinned by a test in the task named:

1. **A key of exactly 512 bytes, and one of 513.** The first is stored raw and the second as a digest; the two must not collide (Task 4, step 1 of 4.2).
2. **Application clock behind the newest stamp.** A record whose `now` sorts below the stored newest must keep `newest_at` and keep the stamps ascending (Task 2, 2.2 cases).
3. **A namespace of exactly 64 bytes containing multi-byte UTF-8.** It is counted in bytes, not runes (Task 4, 4.1 table).
4. **Prune racing a record on the same idle key.** The record wins or inserts fresh. A live count is never lost (Task 6, 6.5).
5. **`Verify` against a database where the table exists in another schema only.** `to_regclass` resolves through `search_path`, so it must report missing (Task 4, 4.3 `Verify` table).

---

## Delegation: lanes, order and models

The main session dispatches, verifies and reviews. It writes no code (`subagent-delegation.md`).

| Wave | Lane | tasks.md | Owns (writes) | Must not touch | Model, and why |
|---|---|---|---|---|---|
| 1 | A: pruner | 1.1, 1.2 | `ratelimit/expiry.go`, `ratelimit/memory.go` (`Prune`), `ratelimit/expiry_test.go`, every other caller of `MemoryLimiter.Prune` found by gopls references, including in `test/expirytasks_test.go` | `internal/`, `sqlstore/`, `pgx/`, `migrate/` | Sonnet: a signature change whose callers gopls lists and whose tests exist |
| 1 | B: schema | 2.1, 2.2 | `migrate/securitystate/20260926000000_security_state.sql`, `internal/pgschema/ratelimit.go`, `test/migrate_securitystate_test.go`, `test/pgschema_ratelimit_test.go` | `ratelimit/`, `test/testutils*.go` | Sonnet: SQL whose shape the design gives, pinned by direct tests |
| 1 | C: helpers | 3.1, 3.2 | `test/testutils.go` (`PostgresConn` Stop/Start), `test/testutils_pgstandby.go`, `test/testutils_postgres_test.go` | `test/migrate_securitystate_test.go`, `test/expirytasks_test.go` | Sonnet: mirrors `RedisConn.Stop/Start`, plus a container recipe |
| 2 | D: sqlstore | 4.1–4.4 | `sqlstore/limiter.go`, `sqlstore/limiter_factory.go`, `sqlstore/limiter_options.go`, `sqlstore/limiter_verify.go`, `sqlstore/limiter_test.go`, `sqlstore/example_limiter_test.go`, `gorm/doc.go`, `test/pg_ratelimit_test.go` | `pgx/` | **Opus**: verification and refusal logic written for the first time, and lock-timeout ordering, where a mistake can pass the tests and still be wrong |
| 3 | E: pgx | 5.1–5.4 | `pgx/limiter*.go`, `pgx/example_limiter_test.go`, and an extension of `test/pg_ratelimit_test.go` | `sqlstore/` | Sonnet: mirrors lane D's reviewed code over `pgxpool` |
| 4 | F: faults | 6.1–6.5 | `test/pg_ratelimit_fault_test.go`, `test/storetest/doc.go` (exclusion note) | everything else | **Opus**: held locks, the breaker under outage, and races between prune and record |
| 5 | G: benchmark | 7.1 | `test/pg_ratelimit_bench_test.go` | everything else | Sonnet: a measurement harness the design specifies |
| 5 | main | 7.2, 8.1 | the migration's storage values, `design.md`, and the factories' godoc (a few lines, said so when done) | | |
| 6 | review | 8.2 | nothing (reports only) | | **Opus** reviewer |

**Why the waves are ordered this way:**
- Wave 1's lanes touch disjoint files.
- D needs B's statements and C's standby helper.
- E mirrors D, after D's review.
- F needs A (6.5 runs `ratelimit.ExpiryTask(factory)`), D, E and C (`Stop`/`Start`).
- G needs both backends.
- Every dispatch is followed by the main session's verification and a fresh reviewer: Opus for D and F, Sonnet for the rest.

---

### Task 1 (tasks 1.1, 1.2): `ratelimit.Pruner` and the widened expiry task

**Files:**
- Modify: `ratelimit/expiry.go`, `ratelimit/memory.go` (`Prune`), `ratelimit/expiry_test.go`
- Modify: every caller of `(*MemoryLimiter).Prune`, found with `"$(go env GOPATH)/bin/gopls" references ratelimit/memory.go:<line>:<col>`

**Interfaces:**
- Produces:
  - `type Pruner interface { Prune(ctx context.Context) (removed int, err error) }`
  - `func ExpiryTask(p Pruner) expiry.Task`
  - `func (l *MemoryLimiter) Prune(ctx context.Context) (int, error)`

- [ ] **Step 1: Write the failing test** in `ratelimit/expiry_test.go`:

```go
type fakePruner struct {
	removed int
	err     error
}

func (f fakePruner) Prune(context.Context) (int, error) { return f.removed, f.err }

func TestExpiryTask_ReportsPruner(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	type testCase struct {
		name   string
		p      ratelimit.Pruner
		assert func(t *testing.T, removed int, err error)
	}
	cases := []testCase{
		{name: "count reaches the result", p: fakePruner{removed: 7},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 7, removed)
			}},
		{name: "error reaches the result", p: fakePruner{err: boom},
			assert: func(t *testing.T, _ int, err error) { assert.ErrorIs(t, err, boom) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			task := ratelimit.ExpiryTask(tc.p)
			assert.Equal(t, "ratelimit", task.Name)
			assert.Zero(t, task.Interval)
			removed, err := task.Run(t.Context())
			tc.assert(t, removed, err)
		})
	}
}
```

Update `TestMemoryLimiter_Prune` to call `l.Prune(t.Context())` and `require.NoError`.

- [ ] **Step 2: Run it and see it fail**

Run: `go test -count=1 -run 'TestExpiryTask_ReportsPruner|TestMemoryLimiter_Prune' ./ratelimit/`

Expected: a compile failure first (`cannot use fakePruner … as *MemoryLimiter`), which is **not** the red step. Make the red step real:
1. add the `Pruner` interface;
2. change `ExpiryTask`'s parameter to `Pruner`, with a body that still returns `0, nil`;
3. change `Prune`'s signature.

Re-run. Expected: FAIL, `expected: 7 actual: 0` and `boom` not in the chain.

- [ ] **Step 3: Implement**

```go
// Pruner removes the keys a limiter no longer counts, by the limiter's own
// rule. It accepts no cutoff, so a sweep can never shorten a limit. The
// in-memory limiter and the PostgreSQL limiter factories implement it.
type Pruner interface {
	Prune(ctx context.Context) (removed int, err error)
}

func ExpiryTask(p Pruner) expiry.Task {
	return expiry.Task{Name: "ratelimit", Run: p.Prune}
}
```

`MemoryLimiter.Prune(ctx context.Context) (int, error)` keeps its body, ignores `ctx` and returns `n, nil`. Move every gopls-listed caller to the new form, including the inline-prune tests and `test/expirytasks_test.go`.

- [ ] **Step 4: Run it and see it pass**, then the wider suites:
  - `go test -count=1 ./ratelimit/... ./expiry/...`
  - `go vet ./...`
  - `(cd test && go test -count=1 -run 'Expiry' ./...)`

  All green.

- [ ] **Step 5: Godoc (1.2).** The godoc on `Pruner` and `ExpiryTask`:
  - names both built-in pruners;
  - says the name is `ratelimit` and the interval is unset;
  - says no cutoff is accepted;
  - shows `t := ratelimit.ExpiryTask(f); t.Name = "ratelimit:postgres"` for a deployment with two pruners.

  Check: `go doc ./ratelimit ExpiryTask`.

- [ ] **Step 6: Report.** List the files, the tests and the red output seen. The main session commits.

---

### Task 2 (tasks 2.1, 2.2): table and statements

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql`
- Create: `internal/pgschema/ratelimit.go`
- Modify: `test/migrate_securitystate_test.go`
- Create: `test/pgschema_ratelimit_test.go`

**Interfaces:**
- Produces (in `internal/pgschema`):
  - `LimiterCheck` (`$1` namespace, `$2` key, `$3` window µs `int64`, `$4` now `*time.Time` or nil): returns one `count`;
  - `LimiterRecord` (`$1` namespace, `$2` key, `$3` limit `int`, `$4` window µs `int64`, `$5` now or nil, `$6` lock timeout `text`, e.g. `"250ms"`);
  - `LimiterPrune` (`$1` now or nil): its rows affected are the count removed;
  - `LimiterDeleteKey` (`$1` namespace, `$2` key);
  - `LimiterServerFacts`: returns `in_recovery bool, version_num int, table_exists bool, logged bool`;
  - `LimiterTable = "rate_limit_buckets"`, `LimiterMaxLimit = 128`, `LimiterMaxNamespace = 64`, `LimiterMinServerVersion = 150000`;
  - `func LimiterKey(key string) string`: the 512-byte and `sha256:` digest rule.

- [ ] **Step 1: Failing migration test (2.1).**
  - In `test/migrate_securitystate_test.go`, add `"rate_limit_buckets"` to `securityStateTables`, and fix its comment to say fourteen.
  - Exempt it in the uuid primary-key case.
  - Add table cases, in the file's existing closure form, on catalogue queries:
    - `relpersistence = 'p'` for `rate_limit_buckets`;
    - `SELECT count(*) FROM pg_index WHERE indrelid = 'rate_limit_buckets'::regclass` is `1`, and that index is the primary key on `(namespace, key)`;
    - `reloptions` contains an entry starting `fillfactor=`;
    - the column types are `text`, `text`, `timestamp with time zone[]`, `timestamp with time zone` and `bigint`, all `NOT NULL`.

- [ ] **Step 2: Run it and see it fail.** Run: `(cd test && go test -count=1 -run 'SecurityState' ./...)`. Expected: FAIL, with `rate_limit_buckets` missing from the table list.

- [ ] **Step 3: Add the table** before `-- +goose Down`, and the `DROP TABLE IF EXISTS rate_limit_buckets;` first in the down section:

```sql
-- +goose StatementBegin
-- Shared rate-limit buckets: one row per namespace and key. No index on a
-- column that changes, so updates stay HOT; logged, so a failover keeps limits.
CREATE TABLE rate_limit_buckets (
    namespace         text          NOT NULL,
    key               text          NOT NULL,
    stamps            timestamptz[] NOT NULL,
    newest_at         timestamptz   NOT NULL,
    longest_window_us bigint        NOT NULL,
    PRIMARY KEY (namespace, key)
) WITH (fillfactor = 70);
-- +goose StatementEnd
```

  `fillfactor = 70` is provisional (design decision 11); Task 7.2 replaces it.

- [ ] **Step 4: Run it and see it pass**, on both majors:
  - `SCRTY_TEST_POSTGRES_IMAGE=postgres:15-alpine` and `postgres:18.6-alpine`, each with `(cd test && go test -count=1 -run 'SecurityState' ./...)`;
  - the leftover-table check passes after rollback.

- [ ] **Step 5: Failing key-mapping test (2.2)** in `internal/pgschema/ratelimit_test.go`. The `test` module cannot import an internal package, so the statements are proven through the public limiters: Task 4 Steps 5–12, Task 5 and Task 6.5, as `tasks.md` 2.2 states. This step pins the one pure function:

```go
func TestLimiterKey(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 513)
	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}
	cases := []testCase{
		{name: "short key stored as given", in: "203.0.113.7",
			assert: func(t *testing.T, got string) { assert.Equal(t, "203.0.113.7", got) }},
		{name: "512 bytes stored as given", in: strings.Repeat("a", 512),
			assert: func(t *testing.T, got string) { assert.Len(t, got, 512) }},
		{name: "513 bytes stored as digest", in: long,
			assert: func(t *testing.T, got string) {
				sum := sha256.Sum256([]byte(long))
				assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), got)
			}},
		{name: "digest-shaped key is hashed too", in: "sha256:abc",
			assert: func(t *testing.T, got string) { assert.NotEqual(t, "sha256:abc", got) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { t.Parallel(); tc.assert(t, pgschema.LimiterKey(tc.in)) })
	}
}
```

- [ ] **Step 6: Run it and see it fail.**
  1. Run: `go test -count=1 -run TestLimiterKey ./internal/pgschema/`. A missing `LimiterKey` is a compile error; add the stub `func LimiterKey(k string) string { return k }`.
  2. Run it again. Expected: FAIL on the 513-byte and `sha256:` cases.

- [ ] **Step 7: Implement `internal/pgschema/ratelimit.go`:**

```go
package pgschema

// The shared rate limiter's statements (design decisions 4–7). $now is NULL
// in database-clock mode; each statement reads the time once.
const (
	LimiterTable            = "rate_limit_buckets"
	LimiterMaxLimit         = 128
	LimiterMaxNamespace     = 64
	LimiterMinServerVersion = 150000
	limiterMaxRawKey        = 512
	limiterDigestPrefix     = "sha256:"
)

const LimiterCheck = `WITH t AS (SELECT coalesce($4::timestamptz, clock_timestamp()) AS now)
SELECT count(*) FROM rate_limit_buckets b CROSS JOIN t
CROSS JOIN LATERAL unnest(b.stamps) AS u(stamp)
WHERE b.namespace = $1 AND b.key = $2
  AND u.stamp > t.now - $3::bigint * interval '1 microsecond'`

// LimiterRecord sets lock_timeout in the row it inserts from, so the setting
// is in force before ON CONFLICT waits for a held row (design decision 6).
const LimiterRecord = `WITH t AS (SELECT coalesce($5::timestamptz, clock_timestamp()) AS now)
INSERT INTO rate_limit_buckets AS b (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, $2, ARRAY[t.now], t.now, $4::bigint
FROM t CROSS JOIN (SELECT set_config('lock_timeout', $6::text, true)) AS lt
ON CONFLICT (namespace, key) DO UPDATE SET
  stamps = (SELECT array_agg(n.s ORDER BY n.s) FROM
            (SELECT s FROM unnest(b.stamps || EXCLUDED.stamps) AS u(s) ORDER BY s DESC LIMIT $3::int) AS n),
  newest_at = GREATEST(b.newest_at, EXCLUDED.newest_at),
  longest_window_us = GREATEST(b.longest_window_us, EXCLUDED.longest_window_us)`

const LimiterPrune = `WITH t AS (SELECT coalesce($1::timestamptz, clock_timestamp()) AS now),
victims AS (
  SELECT b.namespace, b.key FROM rate_limit_buckets b CROSS JOIN t
  WHERE b.newest_at + b.longest_window_us * interval '1 microsecond' <= t.now
  FOR UPDATE OF b SKIP LOCKED)
DELETE FROM rate_limit_buckets d USING victims v
WHERE d.namespace = v.namespace AND d.key = v.key`

const LimiterDeleteKey = `DELETE FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`

const LimiterServerFacts = `SELECT pg_is_in_recovery(),
  current_setting('server_version_num')::int,
  to_regclass('rate_limit_buckets') IS NOT NULL,
  coalesce((SELECT c.relpersistence = 'p' FROM pg_class c
            WHERE c.oid = to_regclass('rate_limit_buckets')), false)`

// LimiterKey maps a caller's key to its stored form: as given, unless it is
// longer than 512 bytes or itself begins "sha256:", when it is "sha256:" and
// the hex SHA-256 digest of the key, the same on every replica.
func LimiterKey(key string) string {
	if len(key) <= limiterMaxRawKey && !strings.HasPrefix(key, limiterDigestPrefix) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return limiterDigestPrefix + hex.EncodeToString(sum[:])
}
```

- [ ] **Step 8: Run it and see it pass:**
  - `go test -count=1 ./internal/pgschema/`
  - `gofmt -l internal/pgschema`
  - `go vet ./internal/...`

  2.2 is ticked by the main session once Task 4's conformance run is green.

---

### Task 3 (tasks 3.1, 3.2): test helpers

**Files:**
- Modify: `test/testutils.go`, which holds `PostgresConn` and gains a container handle
- Create: `test/testutils_pgstandby.go`
- Modify: `test/testutils_postgres_test.go`

**Interfaces:**
- Produces:
  - `func (c PostgresConn) own() (*tcpostgres.PostgresContainer, error)`, an error naming `WithTestPostgresOwnServer` on a shared server
  - `func (c PostgresConn) Stop(t *testing.T)`
  - `func (c PostgresConn) Start(t *testing.T)`
  - `type PostgresStandby struct{ Primary, Standby PostgresConn }`
  - `func RunTestPostgresStandby(t *testing.T, opts ...TestOption) PostgresStandby`

  `Stop` and `Start` require `WithTestPostgresOwnServer`, and fail the test otherwise. The standby always runs its own primary, with the security-state migrations applied when `WithTestPostgresMigrations` is given.

- [ ] **Step 1: Failing tests (3.1)** in `test/testutils_postgres_test.go`:

```go
func TestRunTestPostgres_StopStart(t *testing.T) {
	t.Parallel()
	conn := RunTestPostgres(t, WithTestPostgresOwnServer())
	conn.Stop(t)
	require.Error(t, conn.DB.PingContext(t.Context()))
	conn.Start(t)
	require.NoError(t, conn.DB.PingContext(t.Context()))
}

func TestRunTestPostgres_Refusals(t *testing.T) {
	t.Parallel()
	// Stop and Start end the test with t.Fatal on a shared server, which a
	// test cannot observe on its own *testing.T, so the check behind them is
	// exercised directly, as TestRunTestRedis_Refusals does.
	_, err := PostgresConn{}.own()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithTestPostgresOwnServer")
}
```

- [ ] **Step 2: Run them and see them fail.** Add stub methods that do nothing, and an `own()` that returns `nil, nil`. Run: `(cd test && go test -count=1 -run 'TestRunTestPostgres_Stop' ./...)`. Expected: FAIL, because Ping after Stop succeeds.

- [ ] **Step 3: Implement**, mirroring `RedisConn.Stop` and `Start` (`test/testutils.go:1429`):
  - keep the own container on `PostgresConn` (an unexported field);
  - `Stop` calls `ctr.Stop` with a 2s timeout;
  - `Start` calls `ctr.Start`, waits for readiness, then re-resolves the mapped port;
  - `DB` must keep working after a restart moves the host port. Open it with a connector that resolves the address on every dial, as `RedisConn` does.

- [ ] **Step 4: Run them and see them pass.**

- [ ] **Step 5: Failing standby test (3.2):**

```go
func TestRunTestPostgresStandby(t *testing.T) {
	t.Parallel()
	s := RunTestPostgresStandby(t)
	var inRecovery bool
	require.NoError(t, s.Standby.DB.QueryRowContext(t.Context(), `SELECT pg_is_in_recovery()`).Scan(&inRecovery))
	assert.True(t, inRecovery)
	_, err := s.Primary.DB.ExecContext(t.Context(), `CREATE TABLE standby_probe (v int); INSERT INTO standby_probe VALUES (1)`)
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var v int
		assert.NoError(c, s.Standby.DB.QueryRowContext(t.Context(), `SELECT v FROM standby_probe`).Scan(&v))
	}, 30*time.Second, 200*time.Millisecond)
}
```

- [ ] **Step 6: Run it and see it fail.** A stub returns two separate own primaries, so `pg_is_in_recovery()` is false.

- [ ] **Step 7: Implement `RunTestPostgresStandby`:**
  1. Start a primary from the helper's image on a Docker network, with:
     - `-c wal_level=replica -c max_wal_senders=4 -c hot_standby=on`;
     - an `pg_hba.conf` line `host replication all all trust`, through the helper's init-script mechanism.
  2. Start a second container from the same image. Its entrypoint is overridden to run, as user `postgres`:
     - `pg_basebackup -h <primary alias> -U postgres -D "$PGDATA" -R -X stream`;
     - then `exec postgres`.
  3. Wait for `pg_is_in_recovery()` to be true.
  4. Return both connections and terminate both at cleanup.
  5. Apply migrations to the primary only.

- [ ] **Step 8: Run it and see it pass** on both majors.

---

### Task 4 (tasks 4.1–4.4): the `database/sql` limiter (`sqlstore`)

**Files:**
- Create:
  - `sqlstore/limiter_options.go`
  - `sqlstore/limiter.go`
  - `sqlstore/limiter_factory.go`
  - `sqlstore/limiter_verify.go`
  - `sqlstore/limiter_test.go`
  - `sqlstore/example_limiter_test.go`
  - `test/pg_ratelimit_test.go`
- Modify: `gorm/doc.go`

**Interfaces:**
- Consumes:
  - `pgschema.Limiter*` (Task 2);
  - `unavailable.Wrap`, `unavailable.DefaultConfig`;
  - `ratelimit.ErrConfig`, `ratelimit.Pruner`;
  - `PostgresConn.Stop` and `Start`, and `RunTestPostgresStandby` (Task 3).
- Produces:

```go
type LimiterOption func(*limiterConfig)
func WithLimiterClock(clk clock.Clock) LimiterOption
func WithLimiterOnUnavailable(m ratelimit.UnavailableMode) LimiterOption
func WithLimiterOperationTimeout(d time.Duration) LimiterOption   // default 250ms
func WithLimiterProbeInterval(d time.Duration) LimiterOption      // default 1s
func WithLimiterUnavailableLogInterval(d time.Duration) LimiterOption // default ratelimit.DefaultLogInterval
func WithLimiterLogger(l *slog.Logger) LimiterOption              // default slog.Default()

type Limiter struct{ /* unexported */ }
func NewLimiter(db *sql.DB, namespace string, limit int, window time.Duration, opts ...LimiterOption) (*Limiter, error)
func (l *Limiter) Exceeded(ctx context.Context, key string) (bool, error)
func (l *Limiter) RecordFailure(ctx context.Context, key string) error
func (l *Limiter) Policy() (int, time.Duration)
func (l *Limiter) Verify(ctx context.Context) error

type LimiterFactory struct{ /* unexported */ }
func NewLimiterFactory(db *sql.DB, opts ...LimiterOption) (*LimiterFactory, error)
func (f *LimiterFactory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error)
func (f *LimiterFactory) Prune(ctx context.Context) (int, error)
func (f *LimiterFactory) Verify(ctx context.Context) error
```

  In `test/pg_ratelimit_test.go`: `type pgLimiterBuilder func(t *testing.T, db *sql.DB, dsn, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter`, which Lane E extends with a pgx builder.

- [ ] **Step 1: Failing construction table (4.1)** in `sqlstore/limiter_test.go`, with a non-nil `*sql.DB` from `sql.OpenDB` over a connector that never dials:

```go
func TestNewLimiter(t *testing.T) {
	t.Parallel()
	db := neverDialDB(t) // existing sqlstore test helper for constructor tests, or sql.OpenDB(stubConnector{})
	var nilDB *sql.DB
	ok := func(t *testing.T, l *sqlstore.Limiter, err error) { require.NoError(t, err); require.NotNil(t, l) }
	refused := func(want string) func(t *testing.T, l *sqlstore.Limiter, err error) {
		return func(t *testing.T, l *sqlstore.Limiter, err error) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
			assert.Nil(t, l)
		}
	}
	type testCase struct {
		name      string
		db        *sql.DB
		namespace string
		limit     int
		window    time.Duration
		opts      []sqlstore.LimiterOption
		assert    func(t *testing.T, l *sqlstore.Limiter, err error)
	}
	cases := []testCase{
		{name: "nil handle", db: nilDB, namespace: "api-key", limit: 20, window: time.Minute, assert: refused("nil")},
		{name: "empty namespace", db: db, namespace: "", limit: 20, window: time.Minute, assert: refused("namespace")},
		{name: "colon in namespace", db: db, namespace: "a:b", limit: 20, window: time.Minute, assert: refused("colon")},
		{name: "65-byte namespace", db: db, namespace: strings.Repeat("n", 65), limit: 20, window: time.Minute, assert: refused("64")},
		{name: "64 bytes of multi-byte UTF-8 accepted", db: db, namespace: strings.Repeat("é", 32), limit: 20, window: time.Minute, assert: ok},
		{name: "65 bytes of multi-byte UTF-8 refused", db: db, namespace: strings.Repeat("é", 32) + "x", limit: 20, window: time.Minute, assert: refused("64")},
		{name: "zero limit", db: db, namespace: "api-key", limit: 0, window: time.Minute, assert: refused("limit")},
		{name: "limit 129", db: db, namespace: "api-key", limit: 129, window: time.Minute, assert: refused("128")},
		{name: "limit 128 accepted", db: db, namespace: "api-key", limit: 128, window: time.Minute, assert: ok},
		{name: "sub-microsecond window", db: db, namespace: "api-key", limit: 20, window: 999 * time.Nanosecond, assert: refused("microsecond")},
		{name: "nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(nil)}, assert: refused("clock")},
		{name: "nil logger", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterLogger(nil)}, assert: refused("logger")},
		{name: "unknown mode", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(99)}, assert: refused("mode")},
		{name: "zero timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(0)}, assert: refused("timeout")},
		{name: "zero probe interval", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterProbeInterval(0)}, assert: refused("probe")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := sqlstore.NewLimiter(tc.db, tc.namespace, tc.limit, tc.window, tc.opts...)
			tc.assert(t, l, err)
		})
	}
}
```

- [ ] **Step 2: Run it and see it fail.** Stub `NewLimiter` to return `&Limiter{}, nil`. Run: `go test -count=1 -run TestNewLimiter ./sqlstore/`. Expected: FAIL on every refusal row.

- [ ] **Step 3: Implement the options and validation.**
  - `limiterConfig` holds a `clock.Clock` (nil means database time), a `clockSet` bool, an `unavailable.Config` built from `unavailable.DefaultConfig()`, and the logger.
  - Validation order and messages mirror `redis/limiter.go:116`.
  - Add `len(namespace) > pgschema.LimiterMaxNamespace` (bytes) and `limit > pgschema.LimiterMaxLimit`.
  - Nil checks use `internal/nilcheck.IsNil`.
  - Refusals of `Wrap` (mode, timeout, probe interval) surface unchanged.

- [ ] **Step 4: Run it and see it pass.**

- [ ] **Step 5: Failing conformance run (4.2)** in `test/pg_ratelimit_test.go`. The harness uses app-clock mode, like `redisHarness`:
  - **Scope per subtest:** the namespace is prefixed with an 8-hex digest of `t.Name()`, then `-` and the suite's namespace. A hyphen, because colons are refused, and every resulting namespace stays at or under 64 bytes. New deletes its own namespace's rows: `DELETE FROM rate_limit_buckets WHERE namespace = $1`.
  - **`SecondInstance`** builds another limiter over the same DB and namespace.
  - **Clock:** `clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))`.
  - **Operation timeout:** `pgTestTimeout = 5 * time.Second`, for the same reason as `redisTestTimeout`.

  ```go
  func TestRateLimitConformance_SQLStore(t *testing.T) {
  	t.Parallel()
  	set := securitystate.Set() // as test/migrate_securitystate_test.go:44 obtains it
  	conn := RunTestPostgres(t, WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
  	h := newPGHarness(conn.DB, conn.DSN, sqlstoreBuilder).harness()
  	require.NotNil(t, h.SecondInstance)
  	ratelimittest.Run(t, h)
  }
  ```

  Add in the same file:
  - **"key of 512 and 513 bytes"** (Review Focus 1): record limit-many failures on the 513-byte key; the 512-byte key built from its first 512 bytes is not exceeded.
  - **"application clock behind the newest"** (Review Focus 2): record at T, step the fake clock back 10s and record again. Read the row out of band and assert two things:
    - `newest_at = T`;
    - the stamps are ascending.

- [ ] **Step 6: Run it and see it fail.** With `Exceeded` returning `false, nil` and `RecordFailure` returning `nil`, Run: `(cd test && go test -count=1 -run 'TestRateLimitConformance_SQLStore' ./...)`. Expected: FAIL on "limit reached is exceeded".

- [ ] **Step 7: Implement the backend** in `sqlstore/limiter.go`:

```go
type limiterBackend struct {
	db          *sql.DB
	namespace   string
	limit       int
	windowUS    int64
	clock       clock.Clock // nil: database time
	lockTimeout string      // e.g. "250ms", from the operation timeout
}

func (b *limiterBackend) now() any {
	if b.clock == nil {
		return nil
	}
	return b.clock.Now().UTC().Truncate(time.Microsecond)
}

func (b *limiterBackend) Exceeded(ctx context.Context, key string) (bool, error) {
	var n int
	err := b.db.QueryRowContext(ctx, pgschema.LimiterCheck,
		b.namespace, pgschema.LimiterKey(key), b.windowUS, b.now()).Scan(&n)
	if err != nil {
		return true, fmt.Errorf("sqlstore: rate-limit check: %w", err)
	}
	return n >= b.limit, nil
}

func (b *limiterBackend) RecordFailure(ctx context.Context, key string) error {
	_, err := b.db.ExecContext(ctx, pgschema.LimiterRecord,
		b.namespace, pgschema.LimiterKey(key), b.limit, b.windowUS, b.now(), b.lockTimeout)
	if err != nil {
		return fmt.Errorf("sqlstore: rate-limit record: %w", err)
	}
	return nil
}
```

  - `lockTimeout` is `strconv.FormatInt(timeout.Milliseconds(), 10) + "ms"`, with a floor of 1ms.
  - `NewLimiter` wraps the backend with `unavailable.Wrap(b, namespace, limit, window, cfg.unavailable)`, and keeps `limit` and `window.Truncate(time.Microsecond)` for `Policy`.
  - Errors from the driver are wrapped, never logged with their text.

- [ ] **Step 8: Run it and see it pass.** Then prove the suite catches the design's broken variants. In a scratch build tag or a test-only backend constructed in `test/pg_ratelimit_test.go`, run `ratelimittest.Run` against:
  1. a record statement that first removes stamps `<= now - window` (trimming by time);
  2. a record that calls `clock_timestamp()` twice, once for the stamp and once for `newest_at`.

  Both runs must fail; record which scenario failed for each. Keep them as `TestRateLimitConformance_SQLStoreRejectsBrokenVariants`, asserting that the inner run fails. Reuse the seen-to-fail mechanism already in `test/redis_ratelimit_test.go` if it has one, so the pattern matches.

- [ ] **Step 9: Failing factory and `Verify` tests (4.3).** Add tables to `test/pg_ratelimit_test.go`:
  - **Factory:**
    - the same namespace and policy twice returns a limiter over the same buckets;
    - the same namespace with a different policy is `ErrConfig`, naming both policies;
    - `Prune` removes an idle key of each of two namespaces and keeps a live one.
  - **`Verify`** (each case is `ErrConfig` and names its cause, except where it says success):

    | Case | Expected |
    |---|---|
    | `RunTestPostgresStandby(...).Standby.DB` | `ErrConfig` naming "standby" |
    | a fresh database with no migrations | `ErrConfig` naming "security-state migration set" |
    | `ALTER TABLE rate_limit_buckets SET UNLOGGED` | `ErrConfig` naming "unlogged" |
    | a role with `GRANT SELECT ON rate_limit_buckets` only | `ErrConfig` naming the refused statement ("record"), with SQLSTATE `42501` read through `sqlStater` |
    | the table only in schema `other`, with `search_path` excluding it (Review Focus 5) | `ErrConfig` naming the migration set |
    | a migrated primary | success, and no probe row left: `SELECT count(*) FROM rate_limit_buckets WHERE namespace = ''` is 0 |

- [ ] **Step 10: Run them and see them fail.** Stub `Verify` returning `nil`, and `Prune` returning `0, nil`. Expected: FAIL on every refusal and on the prune counts.

- [ ] **Step 11: Implement the factory and `Verify`.**
  - **Factory:** mirror `redis/factory.go:27-101`, with a `sync.Mutex`-guarded `built map[string]built{policy, limiter}`.
  - **`Prune`:** runs `pgschema.LimiterPrune` with the factory's `now()`, and returns `RowsAffected`. It applies no operation timeout; the runner's `WithRunTimeout` bounds it.
  - **`Verify`, in `sqlstore/limiter_verify.go`:**
    1. scan `LimiterServerFacts` into four values;
    2. refuse in this order: recovery, then version below `LimiterMinServerVersion`, then a missing table, then an unlogged table;
    3. probe with namespace `""` and a `crypto/rand` hex key:
       - run `LimiterRecord` (limit 1, window 1µs, `$now` from the configured clock or nil, lock timeout from the config);
       - then `LimiterCheck`;
       - then `LimiterDeleteKey`. This also proves the `DELETE` privilege the prune needs; `UPDATE` comes from the record.
    4. a `42501` on any step is `fmt.Errorf("%w: the role may not run the limiter's %s statement", ratelimit.ErrConfig, step)`;
    5. other errors wrap without the server's text.
  - `Limiter.Verify` runs the same checks over its own handle.

- [ ] **Step 12: Run them and see them pass** on both majors.

- [ ] **Step 13: Godoc and example (4.4).**
  - **Each exported identifier's godoc states its default, or the maximum it enforces:**
    - primary-only;
    - ambient transactions ignored, and why;
    - call `Verify` at startup;
    - the factory is the pruner: `ratelimit.ExpiryTask(f)`.
  - **`ExampleNewLimiterFactory`:** build the factory, `Verify`, `httpsec.WithRateLimiterFactory(f)`, and the expiry task. It has no `// Output:`, because it needs a database.
  - **`gorm/doc.go`:** a paragraph showing `sqlstore.NewLimiterFactory(gdb.DB())`, and why there is no gorm-native limiter.

  Check: `go vet ./sqlstore/ ./gorm/` and `go test -count=1 -run Example ./sqlstore/ ./gorm/` (they compile).

- [ ] **Step 14: Verify the lane:**
  - `go test -count=1 ./sqlstore/`
  - `(cd test && go test -count=1 -run 'TestRateLimitConformance_SQLStore|TestSQLStoreLimiter' ./...)` on 15 and 18
  - `gofmt -l .`

  Report the red outputs from steps 2, 6, 8 and 10.

---

### Task 5 (tasks 5.1–5.4): the pgx limiter

**Files:**
- Create:
  - `pgx/limiter_options.go`
  - `pgx/limiter.go`
  - `pgx/limiter_factory.go`
  - `pgx/limiter_verify.go`
  - `pgx/limiter_test.go`
  - `pgx/example_limiter_test.go`
- Modify: `test/pg_ratelimit_test.go`, adding the pgx builder and runs

**Interfaces:**
- Consumes: everything Task 4 consumes, plus Task 4's reviewed shapes, mirrored.
- Produces: the same API as Task 4, with `*pgxpool.Pool` in place of `*sql.DB`. Names are identical: `NewLimiter`, `NewLimiterFactory`, `LimiterOption`, `WithLimiterClock`, `WithLimiterOnUnavailable`, `WithLimiterOperationTimeout`, `WithLimiterProbeInterval`, `WithLimiterUnavailableLogInterval`, `WithLimiterLogger`.

- [ ] **Step 1: Failing construction table (5.1).** This is Task 4 Step 1's table, verbatim, with `*pgxpool.Pool` built by `pgxpool.NewWithConfig` on a config that never dials (`MinConns = 0`, so construction performs no I/O), and `var nilPool *pgxpool.Pool`.
- [ ] **Step 2: Run it and see it fail** against a stub returning `&Limiter{}, nil`: `(cd pgx && go test -count=1 -run TestNewLimiter ./...)`.
- [ ] **Step 3: Implement**, mirroring Task 4 Step 3.
- [ ] **Step 4: Run it and see it pass.**
- [ ] **Step 5: Failing conformance run (5.2)** in `test/pg_ratelimit_test.go`:

```go
func TestRateLimitConformance_Pgx(t *testing.T) {
	t.Parallel()
	set := securitystate.Set()
	conn := RunTestPostgres(t, WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
	h := newPGHarness(conn.DB, conn.DSN, pgxBuilder).harness()
	h.SecondInstance = newPGHarness(conn.DB, conn.DSN, sqlstoreBuilder).secondInstanceOver(h) // other backend, same scope and clock
	ratelimittest.Run(t, h)
}
```

  `pgxBuilder` opens a pool with `openPool`-style config from `conn.DSN`, closed at cleanup. `secondInstanceOver` shares the first harness's fake clock and its namespace scoping. This is the spec scenario "Backends share one table".

- [ ] **Step 6: Run it and see it fail** against stub methods (`false, nil` and `nil`).
- [ ] **Step 7: Implement.** The backend uses `pool.QueryRow(ctx, …).Scan` and `pool.Exec(ctx, …)` with the same `pgschema` statements and arguments as Task 4 Step 7. The `now()` value is `*time.Time` or nil (`pgtype` accepts both). SQLSTATE comes from `errors.As(err, &pgErr *pgconn.PgError)`.
- [ ] **Step 8: Run it and see it pass.**
- [ ] **Step 9: Factory and `Verify` (5.3).** Parameterise Task 4 Step 9's tables over a `[]pgLimiterBuilder{sqlstoreBuilder, pgxBuilder}`, not a copy, and see the pgx rows fail against stubs first.
- [ ] **Step 10: Implement**, mirroring Task 4 Step 11. **Step 11:** run all of them on both majors.
- [ ] **Step 12: Godoc and example (5.4),** mirroring Task 4 Step 13. Check with `(cd pgx && go vet ./... && go test -count=1 -run Example ./...)`.

---

### Task 6 (tasks 6.1–6.5): faults, clock, transactions and prune (both backends)

**Files:**
- Create: `test/pg_ratelimit_fault_test.go`
- Modify: `test/storetest/doc.go`, or the `RunAmbientTx` godoc in `test/storetest/ambient.go`

**Interfaces:**
- Consumes:
  - the `[]pgLimiterBuilder` from Tasks 4 and 5;
  - `PostgresConn.Stop` and `Start`;
  - `ratelimit.ExpiryTask`;
  - `sqlstore.WithTx` and `pgx.WithTx`, the attach functions;
  - `sqlstore.WithTxResolver` and the pgx equivalent.

Every test in this task loops over both backends and runs under both `SCRTY_TEST_POSTGRES_IMAGE` majors.

- [ ] **6.1 Held row.**
  - **Failing test:**
    1. record `k` once;
    2. a second `*sql.Conn` runs `BEGIN; SELECT 1 FROM rate_limit_buckets WHERE namespace=$1 AND key=$2 FOR UPDATE`;
    3. record `k` with `WithLimiterOperationTimeout(250*time.Millisecond)`, timing it.

    Assert that:
    - the error's SQLSTATE is `55P03` (lock_not_available), read through `sqlStater` for `sqlstore` and `*pgconn.PgError` for pgx;
    - `elapsed < 750ms`;
    - `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()` reaches 0 within 1s.
  - **Red:** use a test-only builder whose lock timeout argument is `'0'` (disabled). The record then ends only by the client's context cancel, so the SQLSTATE is `57014` (query_canceled), or a context error, not `55P03`. Confirm that failure message before going green.
  - **If the green build still sees `57014` or flakes,** `set_config` in the source row is not in force before the lock wait. Stop and report to the main session. The fallback of design decision 6 (an explicit transaction with `SET LOCAL lock_timeout`) is then dispatched as a fix to Tasks 4 and 5.
  - **Green:** `go test -count=1 -run 'HeldRow' ./...` in `test`.
- [ ] **6.2 Outage.**
  - **Failing tests,** one per mode on `RunTestPostgres(t, WithTestPostgresOwnServer(), WithTestPostgresMigrations(...))`, then `conn.Stop(t)`:

    | Mode | Expected |
    |---|---|
    | refuse | `Exceeded` is `true`, with `ErrBackendUnavailable` |
    | fall back | three local failures make the source exceeded on this instance |
    | allow | `false, nil` |

  - **Breaker:**
    1. stop the server;
    2. make one check, which waits up to the timeout;
    3. make ten more checks, each of which must return in `< 50ms`;
    4. `conn.Start(t)`, advance past the probe interval, and the next check reaches the database.
  - **Red** comes from asserting against a limiter built **without** `Wrap`, a test-only raw backend, where the breaker assertion fails.
  - **Green:** `-run 'Unavailable'`.
- [ ] **6.3 Database clock.**
  - **Failing test:** no `WithLimiterClock`; window 2s, limit 1; record; `Exceeded` is true; after 2.1s, `Exceeded` is false.
  - **Red:** a builder that passes a fake clock frozen at construction stays exceeded.
  - **Green:** `-run 'DatabaseClock'`.
- [ ] **6.4 Ambient transactions ignored.**
  - **Failing test:**
    1. begin a transaction on the same database and attach it with each backend's `WithTx`;
    2. save a session through that backend's session store, and record a failure with a limiter of limit 1;
    3. roll back;
    4. assert the session is absent and `Exceeded` is true.
  - **Second case:** the same flow through `WithTxResolver`, which the limiter does not accept as an option. The resolver is the session store's, and the limiter must still count.
  - **Red:** a test-only limiter variant that executes on the attached transaction is not exceeded after rollback.
  - **Documentation:** add to the `RunAmbientTx` godoc: "The shared PostgreSQL rate limiter does not run this suite: it ignores the caller's transaction by design, so a failure recorded in a request that rolls back still counts (rate-limiting)."
  - **Green:** `-run 'IgnoresAmbientTx'`, and `go doc ./storetest RunAmbientTx` in `test` shows the note.
- [ ] **6.5 Prune through the expiry task.** These are failing table cases over the factory, in app-clock mode, with the task `ratelimit.ExpiryTask(f)`:

  | Case | Steps | Expected |
  |---|---|---|
  | longest window protects | the 15-minute instance records `k` at T; the 1-minute instance records `k` at T+30s; run at T+10m30s | `removed == 0`, and the 15-minute instance's `Exceeded` with limit 2 is true |
  | idle removed | the 1-minute instance records at 12:00:00; run at 12:01:30 | `removed == 1` |
  | locked skipped | a second connection holds the idle row `FOR UPDATE`; run under a 2s context | returns in `< 500ms` with `removed == 0`, and the row still exists |
  | every namespace | idle keys in three namespaces; run | `removed == 3` |
  | race (Review Focus 4) | 50 goroutines record `k` (live) while the task runs 20 times | `k` is exceeded at the end, and no error |

  - **Red:** a test-only prune statement that uses the *checking* instance's window, not `longest_window_us`, fails "longest window protects".
  - **Green:** `-run 'Prune'` on both majors and both backends.

---

### Task 7 (tasks 7.1, 7.2): benchmark and its decisions

**Files:** Create `test/pg_ratelimit_bench_test.go`.

- [ ] **7.1 Benchmark.** `BenchmarkPostgresLimiter` runs sub-benchmarks named `ff=<n>/av=<default|low>/load=<hot|distinct|checkheavy>/pool=<own|shared>/backend=<sqlstore|pgx>`. For each:
  1. `RunTestPostgres(b, WithTestPostgresOwnServer(), WithTestPostgresMigrations(...))`;
  2. `ALTER TABLE rate_limit_buckets SET (fillfactor = n, autovacuum_vacuum_scale_factor = x, autovacuum_vacuum_insert_scale_factor = x)`, then `VACUUM FULL rate_limit_buckets`;
  3. drive the load with `b.RunParallel` and `b.SetParallelism`, matching 32 recorders for `hot`;
  4. for `pool=shared`, run a background goroutine issuing a login-like `SELECT … FROM login_attempts` and `INSERT` at a fixed rate on the same pool, and report its p99 through `b.ReportMetric`.

  It reports `p50-ns` and `p99-ns` per op kind, `hot-ratio` from `pg_stat_user_tables` (after `pg_stat_force_next_flush()` on 15+, if available, otherwise a short sleep-free poll), and `table-bytes` from `pg_total_relation_size`. `BenchmarkPostgresLimiterPrune` fills 10⁵ and 10⁶ idle rows with `INSERT … SELECT generate_series`, and times one `Prune`.

  Run on 18 and 15: `(cd test && go test -run '^$' -bench 'PostgresLimiter' -benchtime=20000x -count=3 ./... | tee <scratchpad>/pg-bench-<major>.txt)`. Report the raw files' paths.
- [ ] **7.2 (main session).** The main session reads both outputs with `benchstat`, then:
  - chooses the `fillfactor` and the two autovacuum values, and edits the migration (a few lines);
  - writes the figures, the pool recommendation and the prune interval into design decision 11;
  - edits the factories' godoc;
  - re-runs `(cd test && go test -count=1 -run 'SecurityState' ./...)`.

---

### Task 8 (tasks 8.1, 8.2): integration gate and whole-branch review

- [ ] **8.1 (main session),** in each module (root, `pgx`, `test`, `redis`, `gorm`):
  - `gofmt -l .` is empty;
  - `go vet ./...`;
  - `go test -race -count=1 ./...`, with `SCRTY_TEST_POSTGRES_IMAGE` set to 15 and to 18 for `test`;
  - the dependency guard (`go test -count=1 -run 'Layout' .`) passes.
- [ ] **8.2 Whole-branch review.** An Opus reviewer, with no write access, gets:
  - the diff `git diff main...HEAD`;
  - every delta under `specs/` and `design.md`;
  - the instruction to report each requirement as met (with the test that proves it) or unmet.

  Defects are reported `REPRODUCED`, with a failing test, or `UNREPRODUCED` (`defect-claims.md`). Findings go to fresh dispatches of the owning lane, and the main session records any accepted deviation in `design.md`.

---

## Self-review

- **Coverage:** every requirement in the five deltas maps to a task.

  | Requirement | Task |
  |---|---|
  | shares counts, gorm, database time | 4.2, 5.2, 6.3, 4.4 |
  | refuses a policy too large | 4.1, 5.1 |
  | ignores the caller's transaction | 6.4 |
  | primary only and `Verify` (standby, version, missing, unlogged, privilege) | 4.3, 5.3 |
  | held row | 6.1 |
  | prune | 4.3, 6.5 |
  | `expiry-sweeping` modified | 1.1, 6.5 |
  | `schema-migrations` modified | 2.1 |
  | `security-state-stores` modified | 6.4 |
  | `store-conformance` modified | 6.4 |

- **Placeholders:**
  - the benchmark's chosen values are deliberately decided in 7.2 from measurements (design decision 11). They are not a placeholder;
- **Type consistency:**
  - `LimiterOption` and the `WithLimiter*` names are identical in both backends;
  - `Pruner.Prune(ctx) (int, error)` is the same in Tasks 1, 4, 5 and 6;
  - `pgschema` names are used exactly as Task 2 defines them.
- **Scope:** nothing beyond `tasks.md`. 2.2's statement proofs live in Tasks 4–6, as `tasks.md` 2.2 states.
