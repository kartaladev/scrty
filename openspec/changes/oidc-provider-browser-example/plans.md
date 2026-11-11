# OIDC Provider Browser Example Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every task to a subagent and reviews it (`.claude/rules/subagent-delegation.md`).

**Goal:** A runnable, generic OpenID Provider under `examples/`, and tests that prove in Chromium, Firefox and WebKit what Go tests cannot.

**Architecture:** A nested, never-published module holds one readable provider program and its browser tests. Tests start the provider in-process, wrapped to log the headers it received, and assert on those as well as on what the page saw. A gate keeps ordinary runs free of browsers, and a required CI job runs them.

**Tech Stack:** Go 1.27; `oidcprovider`, `httpsec`; `github.com/mxschmitt/playwright-go`, pinned; testify.

**Spec:** `openspec/changes/oidc-provider-browser-example/` (`proposal.md`, `design.md` D1 to D8, `specs/`, `tasks.md`).

## Global Constraints

- Test-first: a red run failing on an assertion (`.claude/rules/golang-tdd.md`). A browser test that passes at once, because it pins existing behaviour, is shown to detect by a temporary inversion.
- The example imports nothing from `test`, and nothing imports the example. It is not tagged, not in the release gate and not in the SBOM.
- Provider `http://localhost:P`, attacker `http://127.0.0.1:Q` or `http://evil.localhost:Q`, sibling `http://localhost:Q`. The issuer is never `a.localhost`. An http relying party is `Native`, with `http://127.0.0.1:PORT/callback`.
- Browser tests skip unless `SCRTY_BROWSER=1`, and the CI job fails if they did not run.
- Fixtures and in-memory stores are labelled as such in the code, the log and the README. No brand anywhere.
- A failing browser check is a defect with its output recorded (`.claude/rules/defect-claims.md`). The library is not edited in this change: the finding goes to the main session, and its fix is its own change.
- Tests order events with the server's log and barriers, not sleeps.
- Never read or cite `.claude/.legacy`. Never edit `openspec/` from an implementer. Run `golangci-lint run ./...` in every module changed.

## Review Focus

1. A skipped engine reading as a pass. Expected: the job fails when an engine did not run. Task 1.4.
2. A stream's answer differing between a signed-in and a signed-out browser in one engine only. Expected: the test names the engine and fails. Task 2.1.
3. WebKit's `Secure` cookie behaviour hiding a real failure over http. Expected: the row runs over https as well. Tasks 1.3 and 3.4.
4. More than six streams from one origin over HTTP/1.1. Expected: the report says what happens, and no test depends on it by accident. Task 2.3.
5. A reader running the README's commands from a clean checkout, with no browser installed. Expected: `go run .` works, and the tests skip. Task 4.1.

---

## Dispatch map (main session)

| Wave | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 | G1 | 1.1 | `go.work`, `layout_guard_test.go`, `Makefile`'s `sbom` and release gate | Opus: guards every module compiles against |
| 2 | G2 | 1.2 | `examples/oidc-provider` | Sonnet: wiring a working program, `test/cmd/conformanceop` shows, under a stated design |
| 3 | G3 | 1.3–1.4 | its browser rig, `Makefile`, `.github/workflows/ci.yml` | Opus: findings here can change the design |
| 4 | G4 | 2.1 | `TestBrowser_Stream_CrossSiteLearnsNothing` | Opus: any dispatch where a mistake would pass and still be wrong. It may find a defect, and this group stops if so |
| 5 | G5 | 2.2–2.5 | stream tests | Sonnet: known checks in a settled rig |
| 6 | G6 | 3.1–3.4 | provider tests | Sonnet: as G5 |
| 7 | G7 | 4.1 | `README.md` | Sonnet: documentation |
| 8 | main, one reviewer | 4.2, then 4.3 | | Opus reviewer |

The module is one lane and its dispatches run in order. Each gets a fresh reviewer that edits nothing. Run browser tests one engine set at a time, because a memory shortage has killed runs on the shared machine.

---

### Task 1.1: The module and its guards (G1)

**Files:** Create: `examples/oidc-provider/go.mod`. Modify: `go.work`, `layout_guard_test.go`, `Makefile`.

**Interfaces produced:** `var exampleModules = []string{"examples/oidc-provider"}`, in `layout_guard_test.go`.

- [ ] **Step 1 Red:** `TestExampleModules`: an unlisted example fails, importing one fails, and an example importing `test` fails, on a fixture tree as the other guards do. Expect a failure naming the guard.
- [ ] **Step 2 Green:** add the list, keep `TestNoUnlistedIntegrationModule` passing by excluding it, and have `sbom` and the release gate skip it. Run the `tasks.md` 1.1 commands.

### Task 1.2: The provider (G2)

**Files:** Create: `examples/oidc-provider/{main,provider,pages,fixtures}.go`, `README.md`, and tests.

**Interfaces produced:**
```go
type Config struct { Issuer, Addr, TLSCert, TLSKey string; Clients []oidcprovider.Client; Users []FixtureUser }
func NewHandler(ctx context.Context, cfg Config) (http.Handler, *Provider, error) // tests start this in-process
```

**Decisions:** a new program and not `conformanceop` (design D2). A login page resumes by `fetch` with `Authorization: Bearer`. Stream on, with CORS naming the sibling only through a flag. Default address `localhost:8080`, and issuer derived from it.

- [ ] **Step 1 Red:** `TestProvider_CodeFlow`, with `net/http/httptest` and a PKCE relying party. Expect a failure on the discovery document.
- [ ] **Step 2 Green.** Run the `tasks.md` 1.2 commands.

### Tasks 1.3–1.4: The rig and the job (G3)

**Files:** Create: `examples/oidc-provider/browser_test.go`. Modify: `Makefile`, `.github/workflows/ci.yml`.

**Interfaces produced:**
```go
func engines(t *testing.T) []playwright.BrowserType // skips without SCRTY_BROWSER=1; fails if one cannot start
type served struct { URL string; Requests func() []LoggedRequest } // provider or static page, logging headers and statuses
func startProvider(t *testing.T, opts ...providerOption) served
func startPage(t *testing.T, host, html string) served
```

- [ ] **1.3:** `TestBrowser_Sites` and `TestBrowser_CookieTable`, repeating the design's tables on Linux in CI and on the local machine, each engine a subtest. Report every difference and whether a self-signed certificate works, so the main session corrects the design.
- [ ] **1.4:** the job, by `tasks.md` 1.4. Prove it fails when an engine cannot start, by a temporary edit, then edit back.

### Tasks 2.1–2.5: The stream (G4, G5)

- [ ] **2.1 G4:** `TestBrowser_Stream_CrossSiteLearnsNothing`, a table of victim states (signed in, signed out, throttled, at a cap, a failing dependency) by request kinds (`<script>`, `<img>`, `fetch` no-cors, `EventSource` with credentials) by engine and scheme, comparing every observable with a signed-out browser's. Record the table of outcomes whether it passes or not. **If a row differs, stop:** report it with its output.
- [ ] **2.2–2.5 G5:** by `tasks.md`, each named as it says. `TestBrowser_ReadmeClients` reads both `js` blocks between `## Session signals` and the next section at test time, and fails if there are not exactly two.

### Tasks 3.1–3.4: Sign-in (G6)

- [ ] **3.1–3.4:** by `tasks.md`, each named as it says, asserting on `served.Requests()` as well as on the page. Foreign pages come from `startPage` on `127.0.0.1`.

### Tasks 4.1–4.3: Finish (G7, main)

- [ ] **4.1:** the README by `tasks.md` 4.1, running each command as written from a clean checkout.
- [ ] **4.2:** an Opus reviewer, by `tasks.md` 4.2.
- [ ] **4.3:** the gate, by `tasks.md` 4.3, marking the pull request ready so that CI runs.
