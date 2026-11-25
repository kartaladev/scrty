# Proposal

## Why

scrty is headless: every page a person sees during sign-in is the consumer's to build. A consumer
needs about a dozen of them (sign-in, magic-link confirmation, second factor, enrolment, password
change, recovery, re-authentication, sessions, error), and each is easy to get subtly wrong: a
cached page carrying a handle, a framable form, an open `next` redirect, an error that reveals
whether an account exists. The project's own conformance harness hand-writes three of them in about
330 lines without styling.

With `browser-session` in place, scrty can serve these pages itself, polished by default and
replaceable in whole or in part, so a consumer starts on their own domain instead of security
screens. This is opinionated in the way Spring Security's generated login page is, but it is
switched on deliberately and every part can be replaced.

## What Changes

- **A pages package in the core module** (`httpsec/pages`, standard library only): server-rendered
  `html/template` pages with embedded assets and a small vanilla script only where the browser
  requires one (passkeys, the TOTP QR code).
- **Explicit opt-in:** the consumer builds the page set and hands it to the chain with
  `httpsec.EnablePages`. All pages are then on. Nothing appears without that call.
- **The override ladder**, each step per page:
  - not importing the package (fully headless, as today);
  - switching a page off;
  - theming through `--scrty-*` CSS variables;
  - an extra stylesheet;
  - overriding named template blocks;
  - replacing wording and language through message bundles;
  - replacing a page with the consumer's own handler.
- **Construction-time checks:**
  - a page whose endpoint is off;
  - a chain without the cookie session, CSRF protection or security headers;
  - a missing product name;
  - a path collision;
  - an override that drops a required field.
  Each fails `New` with a configuration error.
- **The sign-in pages:**
  - sign-in (password, magic-link request, passkey and SSO buttons, each shown only when its
    endpoint is on);
  - magic-link confirmation (a button, so link scanners spend nothing);
  - second-factor challenge and method choice;
  - second-factor enrolment;
  - re-authentication;
  - password change;
  - account recovery;
  - my sessions;
  - sign-out confirmation.
- **A browser error page:** refusals of requests that prefer HTML are rendered as a page, with one
  message for every sign-in failure so no page reveals whether an account exists.
- **Styling:** scrty's CSS is authored with Tailwind (standalone CLI, no Node), compiled and
  committed. The public styling contract is the `--scrty-*` variables and `.scrty-*` classes only.

## Capabilities

### New Capabilities
- `hosted-pages`: how scrty-served pages are enabled, mounted, secured, styled, overridden and
  checked at construction.
- `sign-in-pages`: the behaviour of each sign-in, second-factor, recovery, session and error page.

### Modified Capabilities
- None. The pages talk to existing endpoints through their existing contracts, as amended by
  `browser-session`.

## Impact

- **Code:** new `httpsec/pages` package; `httpsec` gains `EnablePages` and a `PageSet` port, so the
  chain can run the page checks inside `New` and render refusals; adapters (`ginsec`, `fibersec`)
  gain the hook that renders a refusal through the page set.
- **Build:** a committed generated CSS file, and a CI check that it is current; the Tailwind
  standalone CLI pinned as a tool.
- **Depends on:** `browser-session` archived.
- **Dependencies:** none added to any Go module.
