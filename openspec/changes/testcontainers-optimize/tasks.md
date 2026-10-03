# Tasks

Every code task is test-first: write the failing test, run it and see it fail for the intended reason (a compile error is not a red step), make it pass, then refactor. Each task names how it is verified. No caller of `RunTestPostgres` changes. Every existing test in the `test` module must pass unchanged at the end of every task group. Section names in parentheses are the spec requirements in `specs/test-provisioning/spec.md`.

## 1. Baseline

- [x] 1.1 Record the baseline (D8):
  - per-package wall time of the `test` module from one local `go test -race -count=1 ./...` and from both CI jobs of `1f76d35`;
  - the number of passed tests and subtests from `go test -json`;
  - the number of PostgreSQL containers started per package.

  Verify by the figures appearing in design.md D8 under "Before".

## 2. A shared server and a database per call

- [x] 2.1 The per-process server registry keyed by resolved image (D1):
  - lazy start on a context no test owns;
  - a failed start remembered and returned to every later call;
  - the `CI` rule unchanged;
  - the new `WithTestPostgresOwnServer()` option giving a call its own container, terminated with its test.

  Tests in `test/testutils_postgres_test.go` cover "Calls in one test process share a server per image" (many calls, one server; another image) and "An unavailable container runtime fails PostgreSQL tests in CI and skips them elsewhere" (both scenarios), plus the own-server option. Verify with `go test -race -count=1 -run 'TestRunTestPostgres|TestPostgresServer' .` in `test`.
- [x] 2.2 A cloned database per call (D2):
  - an empty database from `template1` when no set is named;
  - `DSN` and `DB` pointing at the clone, with the 32-connection limit kept;
  - the clone dropped after teardown;
  - a parallel-clone test that first shows whether concurrent clones of one template conflict (the unverified claim in D2; if they do, clones of a template are serialised in-process).

  Covers "Every PostgreSQL call gets a database of its own" (both scenarios) and "A call's migration sets give the schema of a fresh application" scenario "No sets". Verify with `go test -race -count=1 -run 'TestRunTestPostgres' .` in `test`.
- [x] 2.3 Templates per migration list (D2, D3):
  - a content fingerprint over the ordered sets;
  - a build once per server, under an in-process single flight and a server advisory lock;
  - the `datistemplate` marker, with `ALLOW_CONNECTIONS false`;
  - a half-built leftover dropped and rebuilt;
  - a failed build that drops its database, names the set and caches nothing;
  - the per-call rollback, finalize scripts and leftover-table check running on the clone, followed by the drop.

  `TestPostgresTeardown` is adapted to the new set-up with every assertion kept. Covers "A call's migration sets give the schema of a fresh application" (both remaining scenarios), "Per-call teardown checks still run on the call's database", "A migration set that fails is never handed out half applied" and "Concurrent first calls apply a migration set once". Verify with `go test -race -count=1 -run 'TestRunTestPostgres|TestPostgresTeardown|TestPostgresTemplate' .` and then `go test -race -count=1 ./...` in `test` (Docker).
- [ ] 2.4 Rewrite the godoc of `RunTestPostgres`, `PostgresConn` and the options for sharing, cloning, the own-server option and the Ryuk limit (D1, D9). Verify with `go doc -all github.com/kartaladev/scrty/test RunTestPostgres` reading as the design states, and `golangci-lint run ./...` in `test`.

## 3. Child processes and server tuning

- [ ] 3.1 Child processes reuse their parent's servers (D5):
  - the registry publishes its servers in an unexported environment variable and reads it first;
  - a new exported `test.EnsureTestPostgresServer(t, opts...)` starts or reuses the shared server for the resolved image;
  - the PostgreSQL broken-variant parents (`sqlstore`, `pgxstore`, `gormstore`) and the cross-backend naming check call it before spawning children, and `storefix` is unchanged.

  A test shows that a child process of a broken-variant run starts no PostgreSQL container and still gets a database of its own ("Child test processes reuse their parent's servers"). Verify with `go test -race -count=1 ./sqlstore/ ./pgxstore/ ./gormstore/ ./crossbackend/` and the helper's tests in `test`.
- [ ] 3.2 Tune the server (D6):
  - measure the peak connection count of a full local run and of a CI run, and record it in D6;
  - set `max_connections` with headroom over it;
  - add `fsync=off`, `synchronous_commit=off` and `full_page_writes=off`;
  - mount the data directory on a tmpfs, with the path verified on the PostgreSQL 15 and 18 images;
  - give own servers the same tuning.

  A serialization-conflict test pins "Server tuning never changes what a test can observe". The race, ambient-transaction and lock-wait suites pass unchanged. Verify with `go test -race -count=1 ./...` in `test` under `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine` and under the default image.

## 4. Convention, measurement and close out

- [ ] 4.1 Update `.claude/skills/use-testcontainers/SKILL.md` practice 6 and its examples to "one server per process, one database per call". Say when to use `WithTestPostgresOwnServer`, and why a testify suite is not the sharing mechanism (D9). Verify by reading the skill against D1, D2 and D9, with no remaining "one container per test, by default".
- [ ] 4.2 Measure after the change (D7, D8):
  - per-package wall times, the test count and the container count, recorded in D8 under "After", with the test count equal to the baseline;
  - the Keycloak ready time from three CI runs of each job. Restore `keycloakStartupTimeout` to three minutes if every run is ready within 90 seconds, otherwise keep five minutes, and record the reading in D7.

  Verify with green CI on both jobs, and with "Provisioned containers do not outlive the test run" checked by `docker ps --filter label=org.testcontainers` being empty shortly after a local run.
- [ ] 4.3 Final gate across every module in `go.work`:
  - `go build ./...`, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run ./...` with 0 issues and `go test -race ./...` green;
  - `openspec validate testcontainers-optimize --strict`;
  - then one whole-branch review against every requirement in this change's spec.
