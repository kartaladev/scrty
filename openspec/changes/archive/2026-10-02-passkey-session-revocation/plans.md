# Passkey Session Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session does not write code: each task below is one implementer dispatch, followed by verification and a fresh reviewer (`.claude/rules/subagent-delegation.md`). The main session commits.

**Goal:** Removing a passkey ends the user's other sessions, and suspending one as a suspected clone ends all of them, both by default with consumer overrides, on every session store.

**Architecture:**
- A new atomic store operation, `DeleteByUserExcept`, on `session.Store` and `*session.Manager`.
- The passkey core takes a narrow `SessionRevoker` port and decides both revocations itself: before the delete in `Remove`, and after a suspension in clone handling.
- `httpsec` only reads the per-request `other_sessions` field and maps a bad value to a new 400 sentinel.

**Tech Stack:** Go 1.27, go.work workspace; PostgreSQL through `database/sql` (`sqlstore`), pgx v5 (`pgx`) and GORM (`gorm`); testify and gomock (`--typed`); testcontainers PostgreSQL in the `test` module.

**Spec:**
- `openspec/changes/passkey-session-revocation/proposal.md`
- `openspec/changes/passkey-session-revocation/design.md`, decisions D1–D6
- `openspec/changes/passkey-session-revocation/specs/{passkey-authentication,multi-factor-auth,sessions}/spec.md`
- `openspec/changes/passkey-session-revocation/tasks.md`; every task below names its task number.

## Global Constraints

- Test-first for every task: write the failing test, run it focused, and confirm it fails for the intended reason. A compile error is not a red step: land the API shape with a stub first. Then implement and re-run (`.claude/rules/golang-tdd.md`).
- Table tests use the `assert` closure form, a `ctx` modifier where context matters, and `t.Context()`, never `context.Background()` (`.claude/skills/table-test`).
- Mocks come from `mockgen --typed` (`.claude/skills/use-mockgen`). PostgreSQL comes from the `test` module's testcontainers helpers (`.claude/skills/use-testcontainers`).
- A defect claimed during the work needs a failing test or an `UNREPRODUCED` label (`.claude/rules/defect-claims.md`).
- Every behaviour has a safe default and a consumer override. Godoc names the default each option replaces (`.claude/rules/library-design.md`).
- A dependency's error text never reaches a log record or a returned error. Use `internal/diag` (`diag.Wrap`, `diag.Failure`). `golangci-lint`'s forbidigo enforces this.
- One option never governs two subsystems: `WithoutSessionRevocationOnRemoval` and `WithoutSessionRevocationOnClone` are separate.
- A signature change owns every caller across all `go.work` modules: `.`, `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx` and `test`. That includes `_test.go` files, Examples and README snippets.
- Never commit the legacy snapshot and never cite it. No agent runs a git command that discards work (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`).
- Gate per module: `go build ./... && go vet ./... && gofmt -l .` (empty), `golangci-lint run ./...` (0 issues), and `go test -race ./...`.

## Review Focus

1. **A removing session whose identifier is empty or unknown to the store.** `DeleteByUserExcept(user, "")` must delete every session of the user and must never be a no-op or an error. Pinned in Task 1.1 ("an empty kept identifier deletes every session of the user").
2. **A kept identifier that cannot be stored**, such as one with a NUL byte or invalid UTF-8. The durable stores digest it, so it must still match nothing and delete the user's other sessions. Pinned in Task 1.3 (suite case "a kept identifier no store could hold").
3. **`other_sessions` posted twice, or posted empty.** `other_sessions=` and `other_sessions=keep&other_sessions=end` are malformed: neither is "absent", and the first value must not silently win. Pinned in Task 3.1.
4. **A clone detected twice at once.** Two concurrent clone assertions for one credential: exactly one suspends, so the sessions are deleted at least once and the notice is queued once. A second `DeleteByUser` is harmless. Pinned in Task 2.4 ("racing clone assertions suspend once and end the sessions").
5. **The MFA verify endpoint after the core deleted its session.** Nothing on the clone path may save, rotate or mark the deleted session, or a later request could load it again. Pinned in Task 3.2 ("the pending session does not load after the refusal").

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `session/store.go` | `Store` port gains `DeleteByUserExcept`; regenerate `store_mock_test.go` | 1.1 |
| `session/manager.go` | `(*Manager).DeleteByUserExcept` with fixed-text failure | 1.1 |
| `session/memory.go` | in-memory implementation through `removeWhere` | 1.1 |
| `session/encrypted.go` | decorator pass-through | 1.1 |
| `test/storetest/session_suite.go`, `test/storetest/broken_session_test.go` | shared suite cases; the broken fakes gain the method | 1.1, 1.2 |
| `internal/pgschema/sessions.go` | `SessionDeleteByUserExcept` statement | 1.3 |
| `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go` | durable implementations | 1.3 |
| `test/{sqlstore,pgxstore,gormstore}/ambient_test.go` | a rolled-back except-one delete leaves every session | 1.3 |
| `passkey/sessions.go` (new) | `SessionRevoker`, the two options, `RemoveOption` | 2.1, 2.3 |
| `passkey/manager.go` | `Deps.Sessions`, fields, `validate` rule, godoc | 2.1 |
| `passkey/messages.go` | `Notice.SessionsEnded`, default texts, `notify` parameter | 2.2 |
| `passkey/manage.go` | `Remove` order and options | 2.3 |
| `passkey/clone.go` | revocation after suspension | 2.4 |
| `httpsec/errors.go`, `httpsec/status.go` | `ErrMalformedRequest` (400) | 3.1 |
| `httpsec/passkeymanage.go` | the `other_sessions` field | 3.1 |
| `httpsec/passkeymfa_test.go`, `httpsec/passkeylogin_test.go` | clone revocation through HTTP | 3.2 |
| `test/httpsecconformance/passkey_scenarios.go`, `passkey/example_test.go`, `README.md` | conformance and docs | 3.1, 4.1 |

---

### Task 1.1: `DeleteByUserExcept` on the port, the manager, memory and the decorator

**Files:**
- Modify: `session/store.go` (Store interface, after `DeleteByUser`)
- Modify: `session/manager.go` (after `DeleteByUser`, ~line 278)
- Modify: `session/memory.go` (after `DeleteByUser`, ~line 259)
- Modify: `session/encrypted.go` (after `DeleteByUser`, ~line 185)
- Regenerate: `session/store_mock_test.go` (`go generate ./session/`)
- Modify: every other `session.Store` implementation in the workspace (found with `gopls implementation` on `session.Store`), including `test/storetest/broken_session_test.go`
- Test: `session/delete_test.go` (`TestDeletingByUserExceptOne`, through the manager over the memory store, where the per-user delete tests live) and `session/returned_errors_test.go` (the manager's and the decorator's fixed-text failures)

**Interfaces:**
- Produces:
  - `session.Store.DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)`
  - `(*session.Manager).DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)`

- [ ] **Step 1: Add the API shape with stubs so tests compile.** Add the interface method and stub bodies (`return 0, nil`) to the memory store, the decorator, the manager and every other implementation. Regenerate the mock.

```go
// DeleteByUserExcept removes every session of this user except the one with
// identifier keep, expired ones included, in one atomic operation, and reports
// how many it removed. A keep that names another user's session, or none, is
// left untouched and does not stop the user's sessions from being removed; an
// empty keep removes them all.
DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
```

- [ ] **Step 2: Write the failing tests.** Add cases to the memory store's table, matching the existing `DeleteByUser` case's fixtures:

```go
{
	name: "deleting by user except one keeps that session and removes the rest",
	assert: func(t *testing.T, ctx context.Context, s *session.MemoryStore) {
		create(ctx, t, s, rec("s-1", "u-1"), rec("s-2", "u-1"), rec("s-3", "u-1"), rec("s-9", "u-2"))
		n, err := s.DeleteByUserExcept(ctx, "u-1", "s-1")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		assertLoads(ctx, t, s, "s-1", "s-9")
		assertGone(ctx, t, s, "s-2", "s-3")
	},
},
{
	name: "a kept session of another user is untouched and every session of the user goes",
	assert: func(t *testing.T, ctx context.Context, s *session.MemoryStore) {
		create(ctx, t, s, rec("s-1", "u-1"), rec("s-2", "u-1"), rec("s-9", "u-2"))
		n, err := s.DeleteByUserExcept(ctx, "u-1", "s-9")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		assertLoads(ctx, t, s, "s-9")
		assertGone(ctx, t, s, "s-1", "s-2")
	},
},
{
	name: "an empty kept identifier deletes every session of the user",
	assert: func(t *testing.T, ctx context.Context, s *session.MemoryStore) {
		create(ctx, t, s, rec("s-1", "u-1"), rec("s-2", "u-1"))
		n, err := s.DeleteByUserExcept(ctx, "u-1", "")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		assertGone(ctx, t, s, "s-1", "s-2")
	},
},
```

Use the helper names the file already has. Add these cases too:
- **Manager:** a store failure (gomock `EXPECT().DeleteByUserExcept(...).Return(0, errBoom)`) yields an error whose text is `session: the user's other sessions could not be deleted`, and `errors.Is(err, errBoom)` holds.
- **Decorator:** the call reaches the inner store with the same arguments, and an inner failure is wrapped with fixed text.

- [ ] **Step 3: Run them and confirm they fail for the intended reason.**

Run: `go test -race -count=1 -run 'DeleteByUserExcept|except' ./session/`
Expected: FAIL with `expected: 2 actual: 0` and sessions still loading. The stubs delete nothing.

- [ ] **Step 4: Implement.**

```go
// memory.go
func (s *MemoryStore) DeleteByUserExcept(_ context.Context, user identity.UserID, keep string) (int, error) {
	return s.removeWhere(func(rec *Session) bool { return rec.UserID == user && rec.ID != keep }), nil
}

// manager.go
// DeleteByUserExcept removes every session of user except keep, which is what
// ending a user's other sessions after a factor change is written against.
func (m *Manager) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	n, err := m.store.DeleteByUserExcept(ctx, user, keep)
	if err != nil {
		return n, storeFailed(err, "session: the user's other sessions could not be deleted")
	}

	return n, nil
}

// encrypted.go
func (s *encryptedStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	n, err := s.inner.DeleteByUserExcept(ctx, user, keep)

	return n, storeFailed(err, "session: the inner store could not delete the user's other sessions")
}
```

Check that `storeFailed(nil, …)` returns nil, as its siblings rely on. If `rec.ID` is not the map key field, use the key the memory store indexes by: `removeWhere` ranges `s.records` keyed by identifier.

- [ ] **Step 5: Run the session package and build every module.**

Run: `go test -race -count=1 ./session/...`, then `go build ./...` in each `go.work` module.
Expected: PASS and clean builds.

- [ ] **Step 6: Commit (main session):** `feat(session): delete a user's sessions except one`

### Task 1.2: The shared session suite covers it (in-memory)

**Files:**
- Modify: `test/storetest/session_suite.go`, after the case "deleting by user removes every session of that user, expired ones included, and no other" (~line 688)
- Modify: `test/storetest/broken_session_test.go`: one broken variant that ignores `keep` (deletes all), registered in the guard so the suite is seen to fail on it

**Interfaces:**
- Consumes: `session.Store.DeleteByUserExcept` (Task 1.1)

- [ ] **Step 1: Write the suite cases.** Use the suite's own helpers (`createSessions`, `sessionRecord`, `idleExpiredSession`, `assertSessionsLoad`, `assertSessionsGone`):

```go
{
	name: "deleting by user except one removes the user's other sessions, expired ones included, and keeps that one",
	assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
		kept := sessionRecord("sess-x1", "u-x")
		others := []*session.Session{sessionRecord("sess-y", "u-y"), sessionRecord("sess-x9", "U-X")}
		createSessions(ctx, t, s, kept, sessionRecord("sess-x2", "u-x"), idleExpiredSession("sess-x3", "u-x"))
		createSessions(ctx, t, s, others...)

		n, err := s.DeleteByUserExcept(ctx, "u-x", "sess-x1")
		require.NoError(t, err)

		assert.Equal(t, 2, n)
		assertSessionsGone(ctx, t, s, "sess-x2", "sess-x3")
		assertSessionsLoad(ctx, t, s, append(others, kept)...)
	},
},
{
	name: "deleting by user except another user's session removes every session of the user and touches no other",
	assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
		foreign := sessionRecord("sess-z9", "u-z2")
		createSessions(ctx, t, s, sessionRecord("sess-z1", "u-z"), sessionRecord("sess-z2", "u-z"), foreign)

		n, err := s.DeleteByUserExcept(ctx, "u-z", "sess-z9")
		require.NoError(t, err)

		assert.Equal(t, 2, n)
		assertSessionsGone(ctx, t, s, "sess-z1", "sess-z2")
		assertSessionsLoad(ctx, t, s, foreign)
	},
},
{
	name: "deleting by user except an identifier naming no session removes every session of the user",
	assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
		createSessions(ctx, t, s, sessionRecord("sess-w1", "u-w"), sessionRecord("sess-w2", "u-w"))

		n, err := s.DeleteByUserExcept(ctx, "u-w", "sess-none")
		require.NoError(t, err)

		assert.Equal(t, 2, n)
		assertSessionsGone(ctx, t, s, "sess-w1", "sess-w2")
	},
},
```

If the case "deleting by user removes…" needs clock advances to make expired records load-checkable, mirror them exactly. Give each case its own user references, so the shared database never makes two cases meet.

- [ ] **Step 2: Add the broken variant.** It deletes every session of the user, `keep` included. Register it in the session variants with the first new case name as the case it must fail.

- [ ] **Step 3: Run it and confirm that the suite catches the broken variant and the memory store passes.**

Run: `go test -race -count=1 ./storetest/...` in `test`
Expected: PASS. The broken-store guard reports the new variant failing on "deleting by user except one…". Before Task 1.1's implementation existed, the memory store would have failed with `expected: 2 actual: 0`; confirm this by temporarily returning `0, nil` from `MemoryStore.DeleteByUserExcept`, then restore it.

- [ ] **Step 4: Commit (main session):** `test(stores): the session suite pins deleting a user's sessions except one`

### Task 1.3: Durable stores and transactions

**Files:**
- Modify: `internal/pgschema/sessions.go`: new statement after `SessionDeleteByUser`
- Modify: `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`: after `DeleteByUser`
- Modify: `test/storetest/session_suite.go`: one more case, "a kept identifier no store could hold"
- Modify: `test/sqlstore/ambient_test.go`, `test/pgxstore/ambient_test.go`, `test/gormstore/ambient_test.go`: one scenario each

**Interfaces:**
- Consumes: `storekit.SessionDigest(id string)`, `storekit.Storable(...)`, and each package's `exec` and `deleteWhere` helpers
- Produces: `pgschema.SessionDeleteByUserExcept`

- [ ] **Step 1: Write the failing cases.** Add a suite case using a kept identifier with a NUL byte:

```go
{
	name: "a kept identifier no store could hold still deletes the user's other sessions",
	assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
		createSessions(ctx, t, s, sessionRecord("sess-v1", "u-v"), sessionRecord("sess-v2", "u-v"))

		n, err := s.DeleteByUserExcept(ctx, "u-v", "bad\x00id")
		require.NoError(t, err)

		assert.Equal(t, 2, n)
		assertSessionsGone(ctx, t, s, "sess-v1", "sess-v2")
	},
},
```

Then add the ambient scenario to each backend's `ambient_test.go` table, next to "a session saved in a transaction the caller rolls back does not exist":

```go
{
	name: "deleting a user's other sessions in a transaction the caller rolls back deletes none",
	assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
		sessions := newSessionStore(t, db, c)
		keep, other := storefix.DurableSession("amb-keep", time.Now()), storefix.DurableSession("amb-other", time.Now())
		other.UserID = keep.UserID
		require.NoError(t, sessions.Create(ctx, keep))
		require.NoError(t, sessions.Create(ctx, other))

		txCtx, tx := begin(t, ctx, db)
		n, err := sessions.DeleteByUserExcept(txCtx, keep.UserID, keep.ID)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.NoError(t, tx.Rollback())

		_, err = sessions.Load(ctx, other.ID)
		require.NoError(t, err, "the rolled-back delete must leave the other session")
	},
},
```

Adapt `begin` and `db` to the pgx and gorm files' own shapes.

- [ ] **Step 2: Add stubs** in the three durable stores (`return 0, nil`) and run the suites to see them fail.

Run: `cd test && go test -race -count=1 -run 'TestSessionStore|TestAmbient' ./sqlstore/ ./pgxstore/ ./gormstore/`
Expected: FAIL on the new suite cases with `expected: 2 actual: 0`. The ambient scenario fails with `expected: 1 actual: 0`.

- [ ] **Step 3: Implement.**

```go
// internal/pgschema/sessions.go
// SessionDeleteByUserExcept removes every session of user $1 except the one
// with digest $2, expired or not.
SessionDeleteByUserExcept = `DELETE FROM sessions WHERE user_id = $1 AND id_digest <> $2`

// sqlstore/session.go and pgx/session.go (each with its own exec helper)
// DeleteByUserExcept removes every session of user except keep, expired ones
// included. A user reference PostgreSQL text cannot hold matches nothing; keep
// is compared by digest, so any keep can be named.
func (s *sessionStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete user's other sessions", pgschema.SessionDeleteByUserExcept,
		string(user), storekit.SessionDigest(keep))

	return int(n), err
}

// gorm/session.go
func (s *sessionStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return deleteWhere[sessionRow](ctx, s.c, "delete user's other sessions",
		"user_id = ? AND id_digest <> ?", string(user), storekit.SessionDigest(keep))
}
```

`exec` and `deleteWhere` already resolve a caller's transaction from `ctx` (`WithTx`) and the configured resolver, exactly as `DeleteByUser` does. Check the type `SessionDigest` returns: if the column is `bytea`, pass the value as `DeleteByUser`'s siblings pass `Delete`'s digest.

- [ ] **Step 4: Run the suites, the ambient scenarios and the module tests.**

Run: `cd test && go test -race -count=1 -run 'TestSessionStore|TestAmbient|TestBroken' ./sqlstore/ ./pgxstore/ ./gormstore/ ./storetest/`, then `go test -race ./...` in `gorm` and `pgx`, and `golangci-lint run ./...` in the root, `gorm`, `pgx` and `test`.
Expected: PASS, 0 issues.

- [ ] **Step 5: Commit (main session):** `feat(stores): durable stores delete a user's sessions except one`

### Task 2.1: The session port, the options and wiring

**Files:**
- Create: `passkey/sessions.go`
- Modify: `passkey/manager.go`: `Deps` (after `MFAMethods`), `Manager` fields, `New` copying `deps.Sessions`, `validate`, and `New`'s godoc list of wiring mistakes
- Modify: every `passkey.New` / `passkey.Deps{` caller:
  - `passkey/*_test.go` helpers (`manager_test.go`, and the fixtures used by `manage_test.go`, `clone_test.go` and `admit_test.go`);
  - `passkey/example_test.go`;
  - `httpsec/passkeyharness_test.go`, `passkeylogin_test.go`, `passkeyregister_test.go`, `passkeygates_test.go`, `passkeyrecovery_test.go`;
  - `test/httpsecconformance/passkey_scenarios.go`;
  - the README passkey snippet.
- Test: `passkey/manager_test.go` (`TestNew` wiring table)

**Interfaces:**
- Consumes: `(*session.Manager).DeleteByUser`, `(*session.Manager).DeleteByUserExcept` (Task 1.1)
- Produces:
  - `passkey.SessionRevoker`, `passkey.Deps.Sessions`
  - `passkey.WithoutSessionRevocationOnRemoval() Option`
  - `passkey.WithoutSessionRevocationOnClone() Option`
  - Manager fields `sessions SessionRevoker`, `keepOnRemoval bool`, `keepOnClone bool`

- [ ] **Step 1: Write the failing wiring cases** in `TestNew`'s table:

```go
{
	name: "no session port while revocation is on is a configuration error",
	deps: func(d *passkey.Deps) { d.Sessions = nil },
	assert: func(t *testing.T, m *passkey.Manager, err error) {
		require.ErrorIs(t, err, passkey.ErrConfig)
		assert.Contains(t, err.Error(), "session")
	},
},
{
	name: "a typed-nil session port is a configuration error",
	deps: func(d *passkey.Deps) { d.Sessions = (*session.Manager)(nil) },
	assert: func(t *testing.T, _ *passkey.Manager, err error) { require.ErrorIs(t, err, passkey.ErrConfig) },
},
{
	name: "no session port with only removal revocation off is still a configuration error",
	deps: func(d *passkey.Deps) { d.Sessions = nil },
	opts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
	assert: func(t *testing.T, _ *passkey.Manager, err error) { require.ErrorIs(t, err, passkey.ErrConfig) },
},
{
	name: "no session port with both revocations off builds",
	deps: func(d *passkey.Deps) { d.Sessions = nil },
	opts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval(), passkey.WithoutSessionRevocationOnClone()},
	assert: func(t *testing.T, m *passkey.Manager, err error) {
		require.NoError(t, err)
		assert.NotNil(t, m)
	},
},
```

Match the table's actual field names. The default deps helper must gain `Sessions` (a `*session.Manager` over `session.NewMemoryStore`, or a gomock `SessionRevoker` where calls are asserted), so that the existing cases keep passing.

- [ ] **Step 2: Add the shape** (`passkey/sessions.go`), so the cases compile and fail on behaviour:

```go
package passkey

// SessionRevoker ends sessions: what the manager needs to end a user's other
// sessions after a removal and all of them after a suspected clone.
// *session.Manager satisfies it; wire the same manager the chain uses.
type SessionRevoker interface {
	DeleteByUser(ctx context.Context, user identity.UserID) error
	DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
}

// WithoutSessionRevocationOnRemoval keeps the user's other sessions when a
// passkey is removed, replacing the default of ending every session but the
// removing one. A removal can still ask to end them (EndOtherSessions, or the
// posted other_sessions=end).
func WithoutSessionRevocationOnRemoval() Option {
	return func(m *Manager) { m.keepOnRemoval = true }
}

// WithoutSessionRevocationOnClone keeps the user's sessions when a suspected
// clone suspends a passkey, replacing the default of ending every one of them,
// the session that presented the clone included.
func WithoutSessionRevocationOnClone() Option {
	return func(m *Manager) { m.keepOnClone = true }
}
```

Add the doc to `Deps.Sessions`: required unless both revocations are off; `*session.Manager` satisfies it. Put `Sessions SessionRevoker` in `Deps` and `sessions: deps.Sessions` in `New`.

- [ ] **Step 3: Run it and confirm the red step.**

Run: `go test -race -count=1 -run 'TestNew' ./passkey/`
Expected: FAIL. The three refusal cases get `nil` instead of `ErrConfig`.

- [ ] **Step 4: Implement the rule** in `validate`, beside the other `nilcheck.IsNil` cases:

```go
case (!m.keepOnRemoval || !m.keepOnClone) && nilcheck.IsNil(m.sessions):
	missing = "a session revoker is required while session revocation is on"
```

Extend `New`'s godoc list with "no session revoker while either session revocation is on".

- [ ] **Step 5: Wire every caller** listed under Files with a session manager. Use the harness's own `*session.Manager` where one exists (`httpsec` harnesses have `h.sessions` or similar), and a memory-backed one in `passkey` tests. The README snippet passes the same `sessions` it gives `httpsec.PasskeyDeps`.

- [ ] **Step 6: Run the package and build everything.**

Run: `go test -race -count=1 ./passkey/... ./httpsec/...`, then `go build ./... && go vet ./...` in every module, and `cd test && go vet ./...`.
Expected: PASS, clean.

- [ ] **Step 7: Commit (main session):** `feat(passkey): a session revoker port and the revocation options`

### Task 2.2: Notices say what was ended

**Files:**
- Modify: `passkey/messages.go`: `Notice` (line ~15), `defaultMessages.Removed` and `Suspended`, `notify` and `sendNotice` signatures, and their three callers (`manage.go:144`, `clone.go:136`, `pending.go:397`)
- Test: `passkey/messages_test.go` (or the file holding `TestNotices`)

**Interfaces:**
- Produces:
  - `passkey.Notice.SessionsEnded bool`
  - internal `notify(ctx, kind, c, resolve, sessionsEnded bool)`

- [ ] **Step 1: Write the failing cases:**

```go
{
	name: "a removal notice says other sessions were signed out when they were",
	assert: func(t *testing.T, msgs passkey.Messages) {
		_, body := msgs.Removed(passkey.Notice{Name: "Old key", At: at, Repudiation: "help@example.com", SessionsEnded: true})
		assert.Contains(t, body, "Your other sessions were signed out.")
	},
},
{
	name: "a removal notice says nothing of sessions when none were ended",
	assert: func(t *testing.T, msgs passkey.Messages) {
		_, body := msgs.Removed(passkey.Notice{Name: "Old key", At: at, Repudiation: "help@example.com"})
		assert.NotContains(t, body, "signed out")
	},
},
{
	name: "a suspension notice says all sessions were signed out when they were",
	assert: func(t *testing.T, msgs passkey.Messages) {
		_, body := msgs.Suspended(passkey.Notice{Name: "Key", At: at, Repudiation: "help@example.com", SessionsEnded: true})
		assert.Contains(t, body, "All your sessions were signed out.")
	},
},
```

The default messages are reached through a manager built with default options. Use whatever accessor or sender capture `TestNotices` already uses.

- [ ] **Step 2: Run it and confirm the red step.** Run: `go test -race -count=1 -run 'TestNotices|TestMessages' ./passkey/`. Expected: FAIL on `Contains`, once `SessionsEnded` exists as a field. Add the field first so the case compiles.

- [ ] **Step 3: Implement.** Add the field with its doc: "SessionsEnded reports whether the change ended sessions: the user's other sessions for a removal, all of them for a suspension." Each default text appends its sentence before the repudiation paragraph when `n.SessionsEnded` is true. `sendNotice` sets `SessionsEnded` from the new parameter. Callers pass `false` for now: `pending.go` always passes `false`, and Tasks 2.3 and 2.4 pass the real value.

- [ ] **Step 4: Run the package.** Run: `go test -race -count=1 ./passkey/...`. Expected: PASS.

- [ ] **Step 5: Commit (main session):** `feat(passkey): notices say when sessions were signed out`

### Task 2.3: Removal ends the other sessions

**Files:**
- Modify: `passkey/sessions.go`: `RemoveOption`, `KeepOtherSessions`, `EndOtherSessions`
- Modify: `passkey/manage.go`: `Remove` (~line 121) and its godoc
- Modify: every `Remove` caller: `httpsec/passkeymanage.go:183`, tests and conformance. Variadic options keep existing calls compiling.
- Test: `passkey/manage_test.go` (`TestManageRemove`)

**Interfaces:**
- Consumes: `m.sessions`, `m.keepOnRemoval` (Task 2.1); `notify(…, sessionsEnded)` (Task 2.2)
- Produces:
  - `func (m *Manager) Remove(ctx context.Context, s *session.Session, cid id.ID, rc RegistrationContext, opts ...RemoveOption) error`
  - `type RemoveOption func(*removeConfig)`
  - `passkey.KeepOtherSessions() RemoveOption`
  - `passkey.EndOtherSessions() RemoveOption`

- [ ] **Step 1: Write the failing cases** in `TestManageRemove`, using a gomock `SessionRevoker` (generate it with `mockgen -source=sessions.go -package=passkey_test -destination=sessions_mock_test.go -typed`, its `//go:generate` line placed in `manager.go` beside the package's others) so order and arguments are asserted:

```go
{
	name: "a removal ends the other sessions before the passkey goes, then again after, and the notice says so",
	setup: func(t *testing.T, e *manageEnv) {
		first := e.revoker.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
			DoAndReturn(func(context.Context, identity.UserID, string) (int, error) {
				assert.True(t, e.exists(t, "u-1", e.cred.ID), "the passkey must still exist at the first pass")
				return 2, nil
			})
		e.revoker.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").Return(0, nil).After(first.Call)
	},
	assert: func(t *testing.T, e *manageEnv, err error) {
		require.NoError(t, err)
		assert.False(t, e.exists(t, "u-1", e.cred.ID))
		assert.Contains(t, e.lastNotice(t), "Your other sessions were signed out.")
	},
},
{
	name: "a failed first pass refuses with fixed text, keeps the passkey and queues no notice",
	setup: func(t *testing.T, e *manageEnv) {
		e.revoker.EXPECT().DeleteByUserExcept(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, errors.New("db down: secret-host"))
	},
	assert: func(t *testing.T, e *manageEnv, err error) {
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret-host")
		assert.True(t, e.exists(t, "u-1", e.cred.ID))
		assert.Empty(t, e.notices(t))
	},
},
{
	name: "a failed second pass is logged and the removal stands",
	// first pass ok, Delete ok, second pass returns error → err nil, passkey gone, an error record logged
},
{
	name: "KeepOtherSessions ends nothing and the notice says nothing of sessions",
	opts: []passkey.RemoveOption{passkey.KeepOtherSessions()},
	// no revoker expectations (gomock fails on any call)
},
{
	name: "with removal revocation off, the default keeps and EndOtherSessions still ends",
	managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
	opts: []passkey.RemoveOption{passkey.EndOtherSessions()},
	// expect both passes
},
{
	name: "with removal revocation off and no option, nothing ends",
	managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
},
{
	name: "the last option wins",
	opts: []passkey.RemoveOption{passkey.EndOtherSessions(), passkey.KeepOtherSessions()},
	// no revoker calls
},
```

Fill the three commented cases in the same shape as the first two: a gomock expectation per call, and assertions on the passkey's existence, the notices, and the captured log records. Use the env's own log capture; if none exists, add a `slog` handler writing into a `bytes.Buffer` through `passkey.WithLogger`. Keep every existing case green: the default env now expects the two `DeleteByUserExcept` calls, which an `AnyTimes()` on the env's default revoker covers for cases that do not assert revocation.

- [ ] **Step 2: Add the options shape** (`RemoveOption` and the two constructors as no-ops) and run.

Run: `go test -race -count=1 -run 'TestManageRemove' ./passkey/`
Expected: FAIL with gomock "missing call(s) to DeleteByUserExcept" on the first case, and the fixed-text case returning nil.

- [ ] **Step 3: Implement:**

```go
// sessions.go
// RemoveOption chooses, for one removal, whether the user's other sessions end.
type RemoveOption func(*removeConfig)

type removeConfig struct{ choice int8 } // 0 default, 1 end, -1 keep

// KeepOtherSessions keeps the user's other sessions for this removal, whatever
// the manager's default.
func KeepOtherSessions() RemoveOption { return func(c *removeConfig) { c.choice = -1 } }

// EndOtherSessions ends the user's other sessions for this removal, whatever
// the manager's default.
func EndOtherSessions() RemoveOption { return func(c *removeConfig) { c.choice = 1 } }

// endsOtherSessions resolves the options against the manager's default.
func (m *Manager) endsOtherSessions(opts []RemoveOption) bool {
	var c removeConfig
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}

	switch c.choice {
	case 1:
		return true
	case -1:
		return false
	default:
		return !m.keepOnRemoval
	}
}
```

```go
// manage.go, Remove after findOwn:
end := m.endsOtherSessions(opts)
if end && nilcheck.IsNil(m.sessions) {
	return fmt.Errorf("%w: a session revoker is required to end other sessions", ErrConfig)
}

if end {
	if _, err := m.sessions.DeleteByUserExcept(ctx, s.UserID, s.ID); err != nil {
		return diag.Wrap(err, "passkey: could not end the user's other sessions")
	}
}

removed, err := m.credentials.Delete(ctx, s.UserID, cid)
if err != nil {
	return diag.Wrap(err, "passkey: could not remove the passkey")
}

if !removed {
	return ErrNotFound
}

if end {
	// A login that finished between the first pass and the delete left a
	// session behind; one that records after the delete is refused.
	if _, err := m.sessions.DeleteByUserExcept(context.WithoutCancel(ctx), s.UserID, s.ID); err != nil {
		m.sampled(ctx, slog.LevelError, "remove|sessions-not-ended", msgSessionsNotEnded,
			append(diag.Failure("remove", err), credentialAttr(cid))...)
	}
}

m.notify(ctx, noticeRemoved, c, nil, end)
```

Define `msgSessionsNotEnded = "passkey: the user's sessions could not all be ended"` beside the other `msg*` constants. The `ErrConfig` guard covers a manager built with both revocations off that is then asked to end sessions: wiring allowed a nil port, so an explicit `EndOtherSessions` must fail loudly, not panic. Add a case for it. Update `Remove`'s godoc: the default, the two options, the order, the second pass, and the failure behaviour.

- [ ] **Step 4: Run the package and every caller.** Run: `go test -race -count=1 ./passkey/... ./httpsec/...`. Expected: PASS.

- [ ] **Step 5: Commit (main session):** `feat(passkey): removing a passkey ends the user's other sessions`

### Task 2.4: A suspected clone ends every session

**Files:**
- Modify: `passkey/clone.go`: the `default:` branch of `onCounterRefused` (~line 131)
- Test: `passkey/clone_test.go` (`TestClone` table)

**Interfaces:**
- Consumes: `m.sessions`, `m.keepOnClone` (Task 2.1); `notify(…, sessionsEnded)` (Task 2.2)

- [ ] **Step 1: Write the failing cases** in `TestClone`, with the gomock revoker:

```go
{
	name: "a suspected clone suspends, ends every session of the user, and says so",
	setup: func(t *testing.T, e *cloneEnv) {
		e.revoker.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil)
	},
	stored: 42, presented: 41,
	assert: func(t *testing.T, e *cloneEnv, err error) {
		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
		assert.Equal(t, passkey.StateSuspended, e.state(t))
		assert.Contains(t, e.lastNotice(t), "All your sessions were signed out.")
	},
},
{
	name: "a cancelled caller context still ends the sessions",
	ctx: func(ctx context.Context) context.Context { c, cancel := context.WithCancel(ctx); cancel(); return c },
	setup: func(t *testing.T, e *cloneEnv) {
		e.revoker.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).
			DoAndReturn(func(ctx context.Context, _ identity.UserID) error {
				assert.NoError(t, ctx.Err(), "revocation must not run on the cancelled context")
				return nil
			})
	},
	stored: 42, presented: 41,
	assert: func(t *testing.T, _ *cloneEnv, err error) { require.ErrorIs(t, err, passkey.ErrCloneSuspected) },
},
{
	name: "a failed revocation is logged and the refusal stands",
	setup: func(t *testing.T, e *cloneEnv) {
		e.revoker.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Return(errors.New("db down: secret-host"))
	},
	stored: 42, presented: 41,
	assert: func(t *testing.T, e *cloneEnv, err error) {
		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
		assert.Equal(t, passkey.StateSuspended, e.state(t))
		assert.Contains(t, e.logs(t), "clone|sessions-not-ended")
		assert.NotContains(t, e.logs(t), "secret-host")
		assert.NotContains(t, e.lastNotice(t), "signed out")
	},
},
{
	name: "signal only ends nothing",
	managerOpts: []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
	stored: 42, presented: 41,
	// no revoker expectations
},
{
	name: "a policy that only refuses ends nothing",
	managerOpts: []passkey.Option{passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction { return passkey.CloneRefuse })},
	stored: 42, presented: 41,
},
{
	name: "with clone revocation off the credential is suspended and nothing ends",
	managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnClone()},
	stored: 42, presented: 41,
},
```

The cancelled-context case uses a `ctx` modifier field. If `TestClone`'s table has none, add one per the table-test skill. Then add **Review Focus 4**, a separate test `TestCloneRacingAssertionsSuspendOnce`. Two goroutines are released together with a start channel, each driving an assertion with counter 41 over a stored 42. Assert that exactly one notice is queued, that the credential is suspended, and that `DeleteByUser` was called at least once. Use a counting fake revoker under `-race`, with no `require` inside goroutines.

- [ ] **Step 2: Run it and confirm the red step.**

Run: `go test -race -count=1 -run 'TestClone' ./passkey/`
Expected: FAIL with "missing call(s) to DeleteByUser" and a notice lacking the sentence.

- [ ] **Step 3: Implement:**

```go
default:
	// Detached from cancellation too (design D4): a client that disconnects
	// before the suspension must not leave the clone active.
	suspended, err := m.credentials.Suspend(context.WithoutCancel(ctx), c.ID)
	if err != nil {
		return diag.Wrap(err, "passkey: could not suspend the credential", ErrCloneSuspected)
	}

	if suspended {
		ended := m.endSessionsOnClone(ctx, c)
		m.notify(ctx, noticeSuspended, now, nil, ended)
	}

	return ErrCloneSuspected
```

```go
// endSessionsOnClone ends every session of c's user after a suspension,
// unless WithoutSessionRevocationOnClone was given, on a context the caller
// cannot cancel. A failure is logged; the refusal stands either way.
func (m *Manager) endSessionsOnClone(ctx context.Context, c *Credential) bool {
	if m.keepOnClone {
		return false
	}

	if err := m.sessions.DeleteByUser(context.WithoutCancel(ctx), c.User); err != nil {
		m.sampled(ctx, slog.LevelError, "clone|sessions-not-ended", msgSessionsNotEnded,
			append(diag.Failure("clone", err), credentialAttr(c.ID))...)
		return false
	}

	return true
}
```

`m.sessions` is non-nil whenever `keepOnClone` is false, because `validate` (Task 2.1) refuses that wiring.

- [ ] **Step 4: Run the package.** Run: `go test -race -count=3 ./passkey/...`. Expected: PASS.

- [ ] **Step 5: Commit (main session):** `feat(passkey): a suspected clone ends every session of the user`

### Task 3.1: The remove endpoint's `other_sessions` field

**Files:**
- Modify: `httpsec/errors.go`: `ErrMalformedRequest` in the sentinel block
- Modify: `httpsec/status.go`: `{ErrMalformedRequest, http.StatusBadRequest}`
- Modify: `httpsec/passkeymanage.go`: `remove` (~line 175)
- Modify: `httpsec/passkey.go`: `EnablePasskeys` godoc (remove bullet)
- Modify: `README.md`: passkey section and defaults table
- Test: `httpsec/passkeymanage_test.go` (`TestPasskeyManage`), `httpsec/status_test.go` (`TestStatusForErrorCoversEverySentinel`)

**Interfaces:**
- Consumes: `passkey.KeepOtherSessions`, `passkey.EndOtherSessions` (Task 2.3)
- Produces: `httpsec.ErrMalformedRequest`

- [ ] **Step 1: Write the failing cases** in `TestPasskeyManage`. The harness holds a real `*session.Manager`; create two extra sessions for `u-1` before the request:

```go
{
	name: "a removal ends the user's other sessions and keeps the removing one",
	body: "id=" + cred.ID.String(),
	assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
		require.NoError(t, out.err)
		h.assertSessionLoads(t, s.ID)
		h.assertSessionGone(t, h.otherSessions...)
	},
},
{
	name: "other_sessions=keep keeps them",
	body: "id=" + cred.ID.String() + "&other_sessions=keep",
	// all sessions load, passkey gone
},
{
	name: "other_sessions=end with a keep default ends them",
	managerOpts: []passkey.Option{passkey.WithoutSessionRevocationOnRemoval()},
	body: "id=" + cred.ID.String() + "&other_sessions=end",
},
{
	name: "an unknown other_sessions value is a malformed request that changes nothing",
	body: "id=" + cred.ID.String() + "&other_sessions=maybe",
	assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
		require.ErrorIs(t, out.err, httpsec.ErrMalformedRequest)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
		assert.True(t, h.passkeyExists(t, cred.ID))
		h.assertSessionLoads(t, h.otherSessions...)
	},
},
{ name: "an empty other_sessions value is malformed", body: "id=" + cred.ID.String() + "&other_sessions=" },
{ name: "other_sessions given twice is malformed", body: "id=" + cred.ID.String() + "&other_sessions=keep&other_sessions=end" },
```

The last two cases are Review Focus 3. Give them the same assertions as "unknown value". If the harness lacks `assertSessionLoads`, `assertSessionGone` or `otherSessions`, add them to `passkeyharness_test.go`.

- [ ] **Step 2: Add `ErrMalformedRequest` (shape only) and run.**

Run: `go test -race -count=1 -run 'TestPasskeyManage|TestStatusForError' ./httpsec/`
Expected: FAIL. Other sessions still load in the first case, the unknown value removes the passkey, and the status test reports `ErrMalformedRequest` unmapped.

- [ ] **Step 3: Implement.**

```go
// errors.go
// ErrMalformedRequest refuses a request whose fields are present but carry a
// value the endpoint does not accept. Nothing has changed when it is returned.
ErrMalformedRequest = errors.New("httpsec: malformed request")
```

```go
// passkeymanage.go
func (p *passkeyInterceptor) remove(ex *Exchange, s *session.Session) error {
	cid, values, err := postedPasskeyID(ex.Request)
	if err != nil {
		return err
	}

	opts, err := otherSessionsChoice(values)
	if err != nil {
		return err
	}

	if err := p.deps.Passkeys.Remove(ex.Context(), s, cid, p.registrationContext(s), opts...); err != nil {
		return err
	}

	return p.respondRemove(ex, cid)
}

// otherSessionsChoice reads the optional other_sessions field: keep or end, or
// absent for the manager's default. Any other value, an empty one, or the field
// given more than once is ErrMalformedRequest.
func otherSessionsChoice(values url.Values) ([]passkey.RemoveOption, error) {
	got, ok := values["other_sessions"]
	switch {
	case !ok:
		return nil, nil
	case len(got) != 1:
		return nil, ErrMalformedRequest
	case got[0] == "keep":
		return []passkey.RemoveOption{passkey.KeepOtherSessions()}, nil
	case got[0] == "end":
		return []passkey.RemoveOption{passkey.EndOtherSessions()}, nil
	default:
		return nil, ErrMalformedRequest
	}
}
```

Add the status row. Document the field in `EnablePasskeys`'s remove bullet and in the README (the field, the default, `WithoutSessionRevocationOnRemoval`), and add a defaults-table row.

- [ ] **Step 4: Run the package and the adapters.** Run: `go test -race -count=1 ./httpsec/...`, then `go test ./...` in `fibersec` and `ginsec`. Expected: PASS.

- [ ] **Step 5: Commit (main session):** `feat(httpsec): the passkey remove endpoint chooses whether other sessions end`

### Task 3.2: Clone revocation through HTTP

**Files:**
- Test: `httpsec/passkeymfa_test.go` (`TestPasskeyMFA`), `httpsec/passkeylogin_test.go` (`TestPasswordless`)
- Modify (only if a test shows it): `httpsec/mfaverify.go`. Expected: no change, because the clone error returns before any save.

**Interfaces:**
- Consumes: Tasks 2.1 and 2.4 behaviour through `EnablePasskeys` and `EnableMFA`

- [ ] **Step 1: Write the cases.**
  - **`TestPasskeyMFA`:** extend the existing clone case. Give `u-1` one other session, have the pending session answer with a regressed counter, and assert:
    - `ErrCloneSuspected` and 403;
    - no `RecordFailure`;
    - **Review Focus 5:** neither the pending session nor the other one loads from `h.sessions`;
    - a follow-up request with the pending session's token is `ErrAuthenticationRequired`.
  - **`TestPasskeyMFA`, new case:** with `passkey.WithoutSessionRevocationOnClone()`, the pending session still loads, its handle is unchanged, and the challenge is still pending.
  - **`TestPasswordless`:** with `u-1` holding two sessions, a passwordless finish with a regressed counter gives `ErrCloneSuspected`, neither session loads, and no new session exists (count through the session store, as `sessionCount` does).

- [ ] **Step 2: Run them.**

Run: `go test -race -count=1 -run 'TestPasskeyMFA|TestPasswordless' ./httpsec/`
Expected: these pass if Task 2.4 is wired through the harnesses (Task 2.1 Step 5). For the red step, temporarily make `endSessionsOnClone` return `false` without deleting. Watch the "neither session loads" assertions fail, then restore the file exactly and report the failure seen. If a case fails on unmodified code because the verify endpoint saves or rotates after the refusal, that is a defect. Fix `mfaverify.go` so the clone error path returns before any `Save` or `Rotate`, with the failing case as its red step.

- [ ] **Step 3: Run the package.** Run: `go test -race -count=3 ./httpsec/...`. Expected: PASS.

- [ ] **Step 4: Commit (main session):** `test(httpsec): a clone at verify or passwordless finish ends the user's sessions`

### Task 4.1: Conformance and examples

**Files:**
- Modify: `test/httpsecconformance/passkey_scenarios.go`: removal scenarios, and the existing clone scenario
- Modify: `passkey/example_test.go`: wiring `Deps.Sessions`, and an `Example` for the two options; the README snippets it mirrors (Task 3.1) stay in step

**Interfaces:**
- Consumes: everything above

- [ ] **Step 1: Write the scenarios.** Run each on net/http, gin and fiber over the durable backend the file already uses:
  - **Removal ends the others:** sign `u-1` in twice (two tokens). Remove a passkey with the first token. The second token is refused (`ErrAuthenticationRequired`, 401) and the first still works.
  - **Removal with keep:** the same flow, posting `other_sessions=keep`. Both tokens still work.
  - **Clone:** the existing clone scenario now also asserts that a token issued to `u-1` before the clone is refused afterwards.

- [ ] **Step 2: Run them.**

Run: `cd test && go test -race -count=1 -run 'Passkey|Conformance' .`
Expected: PASS. For the red step, temporarily pass `passkey.KeepOtherSessions()` unconditionally in `httpsec`'s `remove`. Watch the first scenario fail on all three adapters, then restore.

- [ ] **Step 3: Update the Examples** so they mirror the README snippet. Run: `go test ./passkey/ -run Example`. Expected: PASS.

- [ ] **Step 4: Commit (main session):** `test(conformance): passkey removal and clone end sessions on every adapter`

### Task 4.2: Final gate and whole-branch review

- [ ] **Step 1:** In every module (`.`, `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx`, `test`):
  - `go build ./... && go vet ./... && gofmt -l .` (empty)
  - `golangci-lint run ./...` (0 issues)
  - `go test -race ./...`

  The `test` module needs Docker. Run its root package apart from the store packages to avoid container contention.
- [ ] **Step 2:** `openspec validate passkey-session-revocation --strict`.
- [ ] **Step 3:** Dispatch one fresh reviewer, on the strongest model, against every requirement and scenario in this change's three spec deltas and decisions D1–D6. Findings are marked `REPRODUCED` (with a failing test) or `UNREPRODUCED`. Fold them through fresh dispatches, then re-run Steps 1–2.
- [ ] **Step 4:** Tick 4.2 in `tasks.md` and commit (main session): `chore(openspec): tick passkey-session-revocation task 4.2`.
