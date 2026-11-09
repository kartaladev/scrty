# Security policy

## Reporting a vulnerability

Report a vulnerability through this repository's **private vulnerability reporting**. It is the only
channel. Open the repository's **Security** tab, choose **Report a vulnerability**, and describe the
problem there. The report is visible only to you and the maintainers.

Do not open a public issue, pull request or discussion for a vulnerability, and do not post it
anywhere public before it is disclosed as described below.

A useful report names the affected module and version, the code or request that triggers the
problem, what an attacker gains, and, where you have one, a failing test.

## What to expect

- **Acknowledgement** within 7 days of the report.
- **An assessment and a fix plan** within 30 days of the report: whether the report is accepted as a
  vulnerability, how severe it is, and which release will carry the fix.
- **Coordinated disclosure** within 90 days of the report. The advisory is published sooner when a
  fix is released sooner, and the reporter is told the date beforehand.

The reporter is credited in the advisory unless they ask not to be.

## Supported versions

While the major version is 0, only the latest minor release receives security fixes. Every published
module is released in lockstep, so the version below names all of them.

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| earlier than 0.1.0 | No |

This table is updated at each release. When `0.2.0` is released, the `0.2.x` line is the one
supported.

scrty requires **Go 1.27** or later and supports Go 1.27 and each later Go release while the Go
project supports it.

## Disclosure

A fixed vulnerability is disclosed in three places:

1. a **repository security advisory** on this repository, published once the fix is released;
2. a **report to the Go vulnerability database**, made once the advisory is public, so that
   `govulncheck` reports the affected versions to consumers;
3. an entry under **Security** in [CHANGELOG.md](CHANGELOG.md) for the release that fixes it, with
   the advisory identifier once one exists.
