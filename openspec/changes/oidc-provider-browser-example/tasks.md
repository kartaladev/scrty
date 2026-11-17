## 1. The example and its gate (D1 to D6)

- [ ] 1.1 Create the `examples/oidc-provider` module, in `go.work`, and add `exampleModules` and its guards in `layout_guard_test.go`, test-first: an unlisted example fails, importing an example fails, an example importing `test` fails. Have `sbom` and the release gate skip examples. Verify: `go test -run 'TestGoWorkListsEveryModule|TestNoUnlistedIntegrationModule|TestModuleLayoutEveryWorkspaceModule|TestExampleModules' -count=1 -v .`, and `GOWORK=off go build ./...` in the module.
- [ ] 1.2 Write the provider, test-first through `net/http/httptest`: fixture client and user, flags for issuer, address and a client and user file, pages for login with a `fetch` resume, consent, logout and a stream, the wiring of design D2, and a start-up log saying in-memory and fixtures. A code flow with PKCE passes in a Go test. Verify: `go test -count=1 -race ./...` in the module, and `go run . -h`.
- [ ] 1.3 Add `playwright-go` at a pinned version, `make browser-test`, the `SCRTY_BROWSER=1` gate, and a first test that starts all three engines on Linux and repeats design D4's site table and D3's cookie table against the example. Correct the design where they differ, including whether a self-signed certificate works in all three. Verify: `make browser-test`, with every row named in `-v` output; and `go test ./...` in the module with no gate reports skipped.
- [ ] 1.4 Add the `browser` CI job calling `make browser-test`, in `ci-ok`'s `needs`, with pinned actions, failing if the tests did not run. Verify: `make pincheck`, `.github/scripts/ci-needs-check.sh`, and the job green on the pull request.

## 2. The stream in a browser (D7, D8)

- [ ] 2.1 Write the oracle test first (design D7), as its own commit: signed-in and signed-out, throttled, at a cap and with a failing dependency, by `<script>`, `<img>`, `fetch` and `EventSource`, in all three engines, and over http and https. If it fails, record the output, stop this group, and put the finding to the main session, whose fix is its own change: this is the proof the design's claim needs. Verify: `SCRTY_BROWSER=1 go test -run 'TestBrowser_Stream_CrossSiteLearnsNothing' -count=1 -v .` in the module.
- [ ] 2.2 Add `TestBrowser_Stream_Requests`: same origin, cross-site, a same-site sibling unnamed and named by CORS with credentials, and a sandboxed frame, asserting on the headers the server saw. Verify: the test with `-v`.
- [ ] 2.3 Add `TestBrowser_Stream_Lifecycle`: an ended sign-in in another tab, a place refused at the cap, a maximum age, a shutdown, and a note in the report of what six connections per host on HTTP/1.1 does to more tabs. Verify: the test with `-v`.
- [ ] 2.4 Add `TestBrowser_Stream_Headers`: every answer on the stream's path with an event-stream body carries `X-Content-Type-Options: nosniff`. If it does not, this is the same defect route as 2.1. Verify: the test with `-v`.
- [ ] 2.5 Add `TestBrowser_ReadmeClients`, running the README's two client snippets unchanged, read from `README.md` at test time, against the example. Verify: the test with `-v`.

## 3. Sign-in in a browser

- [ ] 3.1 Add `TestBrowser_Provider_CodeFlow`: sign-in, `fetch` resume with a bearer, consent, a redirect with a code, and a Go relying party's exchange, showing the flow cookie bound the handle to that browser. Verify: the test with `-v`.
- [ ] 3.2 Add `TestBrowser_Provider_CrossSite`: foreign posts to resume, logout confirmation and consent revocation give 403; foreign posts to authorize and end-session with no flow cookie give 303 as a GET. Verify: the test with `-v`.
- [ ] 3.3 Add `TestBrowser_Provider_Logout`: with and without an `id_token_hint`, a registered `post_logout_redirect_uri`, and the cookies cleared. Verify: the test with `-v`.
- [ ] 3.4 Add `TestBrowser_Provider_Cookies` and `TestBrowser_Provider_Framing`: attributes over http and https in each engine, naming where an engine differs, and a foreign page's frame refused. Verify: the tests with `-v`.

## 4. Finish

- [ ] 4.1 Add the example to `README.md`: how to run it, what it does not do, and how to run the browser tests. Verify: the README's commands run as written from a clean checkout.
- [ ] 4.2 Review the change against every requirement and decision here, on Opus, with each finding reproduced or labelled UNREPRODUCED. Verify: the review is recorded and its findings are resolved.
- [ ] 4.3 Run `make check`, `make browser-test` for 3 rounds with no flake, and CI green on the pull request. Verify: every command's output is clean.
