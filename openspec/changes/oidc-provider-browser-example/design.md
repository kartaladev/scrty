# Design

## Context

`test/cmd/conformanceop` is an unbranded provider in the `test` module, built for the conformance suite: https only with a self-signed certificate, script-free forms because HtmlUnit struggles with modern JavaScript, and no signals or CORS. A browser example needs the opposite on each point. The guards require every `go.mod` to be in `go.work`, and every workspace module but core, `test` and `tools` to be a row in `integrationTable`, which means a module under the concept it extends, tagged and released.

## Goals / Non-Goals

**Goals:** an example a consumer can read and run with one command; real engines answering what Go tests cannot; a required CI job, so that it keeps working.

**Non-goals:** a replacement for conformance, which proves the protocol. A production template, since the example uses in-memory stores and fixture users and says so. Real Safari: Playwright's WebKit is built from WebKit's main branch and is not Safari. Reverse-proxy buffering checks, which can follow.

## Decisions

### D1. The example is a nested module under `examples/`, never published

`examples/oidc-provider/`, module `github.com/kartaladev/scrty/examples/oidc-provider`, in `go.work`, with `replace` lines to the local modules. This follows the user's instruction for an `examples` directory, and dex and go-pkgz, which keep examples as nested modules. A nested module also keeps a browser driver out of the core and of `test/go.mod`, which is published.

**Default:** the module is not tagged, not in the release gate and not in the SBOM. `layout_guard_test.go` gains `exampleModules`, a list beside `integrationTable`, and a test that nothing imports an example and an example imports nothing from `test`. **Override:** none: this is the repository's layout, not a consumer's choice. `make fmt-check`, `vet`, `lint`, `vuln` and `generate-check` cover it automatically, because they loop over the workspace.

*Rejected:* inside the `test` module, which needs no guard change but is not where a consumer looks. *Rejected:* a package in the root module, as zitadel has: the core must stay free of drivers. *Rejected:* an `integrationTable` row, because an example extends no concept and must not be released.

### D2. A new command, not an extension of `conformanceop`

Conformance gates the tag, and its forms exist for HtmlUnit, so changing it for browsers risks that gate. The example shares no code with it, because no other module may import `test`. *Rejected:* a shared library for both, since nothing else would use it, and an example is clearest as a single readable program.

**Generic means (proposal):** flags for the issuer and listen address, and an optional file of clients and users, with one fixture client and user as the default, labelled as fixtures. Pages: login with a `fetch` resume by `Authorization: Bearer`, the README's documented path; consent; logout; and a page opening the stream. Everything in memory.

**Wiring:** `oidcprovider.New` with `Deps{Issuer, Clients, Keys, Users, LoginURL, ConsentURL, LogoutURL, LoggedOutURL}`, `session.New(session.WithEndObserver(op))`, and `httpsec.New` with `EnableSessionBearer`, `EnableJWKSEndpoint`, `EnableSecurityHeaders`, `EnableCSRFProtection`, `EnableCORS`, `EnableSessionSignals` and `EnableOIDCProvider`.

### D3. Plain http on loopback by default, with an https run for what needs it

**Default:** `http://localhost:PORT` through `oidcprovider.WithLoopbackHTTPIssuer()`. This is what a reader runs with no certificate, and it is forced for WebKit: observed here, it rejects `Secure` and `__Host-` cookies over http, even on localhost, and `WithLoopbackHTTPIssuer` drops both. **Override:** `-tls-cert` and `-tls-key` for https, which gets `__Host-` cookies and HTTP/2. The browser tests run both modes where they differ, because the README's cross-site claim is stated for https, and `Secure` cookies and HTTP/2 exist only there. Whether Playwright's `ignoreHTTPSErrors` covers a self-signed certificate in all three engines is unverified, and task 1.3 finds out.

### D4. Two real sites with no DNS setup

| Role | Origin | To the provider |
|---|---|---|
| Provider | `http://localhost:P` | |
| Attacker | `http://127.0.0.1:Q` or `http://evil.localhost:Q` | cross-site |
| Sibling | `http://localhost:Q` | same-site |

Observed in Chromium, Firefox and WebKit on macOS arm64 with a scratch server (not scrty), on Playwright builds slightly off the driver's expected revisions. Linux is unverified, and CI runs there, so task 1.3 proves it there first. `--host-resolver-rules` is rejected: Chromium only. `a.localhost` cannot be the issuer: `isLoopbackHost` accepts only `localhost` or a loopback IP. A relying party over http registers as `Native`, with `http://127.0.0.1:PORT/callback`.

### D5. playwright-go, in Go tests

**Default:** `github.com/mxschmitt/playwright-go` in `examples/oidc-provider`, whose tests start the provider in-process, wrap it to log the headers it received, and assert on those as well as on what the page saw. It is the only Go option reaching all three engines. WebKit matters most here: it is the one engine that ran a cross-site event-stream body as a script. **Cost, accepted:** a downloaded Node driver, a driver tied to each Playwright minor, and a module path still under `mxschmitt`. **Override:** none needed: this is the repository's own test tooling.

*Rejected:* chromedp and Rod, which reach only the Chromium family. *Rejected:* the Go Selenium client, last pushed in 2025. *Rejected:* `@playwright/test` in Node: better tooling, but a second toolchain and lockfile in a Go repository.

### D6. A gate, and a required job

The gate, the make target and the job carry general names, because another browser sample may join later: `make browser-test` runs the browser tests of every module on `exampleModules`, and only this one exists for now.

**Default:** tests skip unless `SCRTY_BROWSER=1`, as `test-isolated` uses its own variable, so `make test` needs no browser. `make browser-test` installs the pinned driver and browsers and runs them, outside `make check`, as `make conformance` is. A CI job `browser` calls it, joins `ci-ok`'s `needs`, and uses pinned actions. A skipped run is never reported as a pass: the job fails if the tests do not run.

### D7. A cross-site page learns nothing from the stream: a promise, pending proof

Observed with a scratch server (UNREPRODUCED against scrty): a cross-site `<script src>` of a 200 `text/event-stream` body of `retry: 5000` fires `onload` in WebKit, because that body parses as a JavaScript label; Chromium and Firefox fire `onerror`; `nosniff` makes all three fail; a 204 fires `onload` everywhere. Whether `EnableSecurityHeaders` puts `nosniff` on the stream's response is unverified. scrty's cross-site check should mean an untrusted request never gets a 200 or 204 there, which group 9 of `session-signals` tightened for a throttle.

So the first browser task writes this test, for a signed-in and a signed-out victim in each engine. **If it passes,** the promise stands. **If it fails,** that is a defect with a failing test (`.claude/rules/defect-claims.md`), and its fix gets its own change, starting from that test. **Known residue:** a dependency failure's retry was noted as answering a cross-site request with 200 in `session-signals`' review, so the test includes it, and it is the likeliest failure.

**Default, if confirmed:** the promise, with no option. **Override:** none: it protects a signed-in user from a foreign page.

### D8. The Node harness goes

The scratch harness runs the README's snippets against stubs. Task 2.5 runs those snippets unchanged against the example in real engines, so it can be retired. Reading the snippets out of `README.md` means the README cannot drift from what is tested.

## Risks / Trade-offs

- **[A monthly driver bump]** Playwright minors move monthly, and each needs its driver. → Pinned, and upgraded on purpose, as the tools are.
- **[A slow, flaky job]** Real engines are slower than Go tests. → Three engines per check, each sequential; timeouts by barriers and server logs, not sleeps. A flaky row is a failure to fix, not to retry silently.
- **[Observations from one machine]** → Task 1.3 repeats the site and cookie probes on Linux, and the design is corrected if they differ.
- **[A reader copying fixtures to production]** → The README and the program's start-up log say in-memory and fixtures.

## Migration Plan

None: new files only, and the module is never published.

## Open Questions

- HTTP/2's stream limit against six connections per host on HTTP/1.1: left as a README note unless task 2.3 shows a problem.

## References

### Layout (D1, D2)

**Researched (accessed 2026-11-05):**
- [zitadel/oidc](https://github.com/zitadel/oidc), [dexidp/dex](https://github.com/dexidp/dex), [go-pkgz/auth](https://github.com/go-pkgz/auth), [ory/fosite](https://github.com/ory/fosite): tree listings of how each lays out examples; none shows a real-browser test. Whether their CI builds their examples was not verified.

### Sites, headers and cookies (D3, D4)

**Researched (accessed 2026-11-05):**
- [W3C Fetch Metadata](https://www.w3.org/TR/fetch-metadata/): the `Sec-Fetch-Site` values, and only on potentially trustworthy URLs.
- [HTML Standard, same site](https://html.spec.whatwg.org/multipage/browsers.html#same-site): IPs match only on an identical host, and the port is ignored.
- [MDN Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site): values and availability.
- [MDN HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies): `Secure` on localhost and Safari's exception, `SameSite` defaults, `__Host-`.
- [Mozilla bug 1523367](https://bugzilla.mozilla.org/show_bug.cgi?id=1523367) and [WebKit bug 127676](https://www2.webkit.org/show_bug.cgi?id=127676): no host-resolver equivalent, read from search snippets only.

### The stream in a browser (D7, D8)

**Researched (accessed 2026-11-05):**
- [HTML Standard, server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html): non-200 or the wrong type fails the connection, with no retry.
- [MDN EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource): six connections per browser and domain off HTTP/2.

### Driver (D5)

**Researched (accessed 2026-11-05; stars and releases drift):**
- [playwright-community/playwright-go](https://github.com/playwright-community/playwright-go): v0.6401.0, 3.5k stars, three engines, module path under `mxschmitt`.
- [chromedp/chromedp](https://github.com/chromedp/chromedp): v0.22.1, 13.4k stars, Chromium family.
- [go-rod/rod](https://github.com/go-rod/rod): v0.116.2 of 2024-07, 7.1k stars.
- [tebeka/selenium](https://github.com/tebeka/selenium): last pushed 2025-01.
- [Playwright browsers](https://playwright.dev/docs/browsers): engines, and WebKit is not Safari.

### Wiring and the gate (D2, D6)

Reasoned from scrty's own settled specs, `test/cmd/conformanceop` and the established design.
