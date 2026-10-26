# Proposal

## Why

scrty's layout and names make it hard to read:

- **Too many root directories.** About 36 directories sit at the root of the repository, and 25 of them are public packages. They mix three levels of abstraction in one flat list: domain concepts (`session`, `policy`), login methods (`passkey`, `magiclink`), and plumbing (`storeerr`, `expiry`, `migrate`). Some are tiny: `storeerr` holds one sentinel.
- **Scattered files inside packages.**
  - `httpsec` has 60 production files and 153 test files.
  - Its `options.go` is 2,659 lines and holds the options of ten features, while four other features keep theirs beside them.
  - Feature families are spelled three ways: glued (`mfaenrolconfirm`), underscored (`oidc_callback`) and mixed (`mfabegin_race`).
  - One unit's tests are spread over up to eleven scenario files.
  - Satellite files under 100 lines sit apart from the code they serve.
- **Names that do not say what a type is.**
  - Nine packages name their main type `Manager` (`oidc.Manager`, `oidc.HandoffManager`, `signingkey.KeyManager` and others).
  - A few outliers break rules the rest of the API follows: `JwtOption`, `GetSigner`, `token.VerifyWith…`, and `ErrMFAEnrollmentRequired` beside "Enrolment" everywhere else.

Nothing is tagged yet and there are no consumers, so moving and renaming public packages is free now. It becomes a breaking change at `v0.1.0`. This change therefore lands before `release-readiness` tags the first release. It does not change any behaviour.

## What Changes

**BREAKING** for import paths and exported identifiers. There is no behaviour change.

- **Directories regrouped by concept.** The root drops from about 36 directories to 18. A parent directory is a real package wherever one exists.
  - Under `authenticate/`: `factor`, `password`, `apikey`, `magiclink`, `oidc`, `passkey` (with the nested module `passkey/webauthn`), and `mfa`.
  - Under `token/`: `signingkey` and `onetime`.
  - `policy` is split: the account-lockout group becomes `policy/lockout`.
  - `storeerr` becomes the parent package `store`. Under it: `sqlstore`, `migrate`, `seal`, and the nested modules `pgxstore` (was `pgx`) and `gormstore` (was `gorm`).
  - The Redis limiter module moves to `ratelimit/redisstore` (package `redisstore`, was `scrtyredis`).
  - The scheduler module moves to `expiry/sweep`.
  - The framework adapters move to `httpsec/ginsec` and `httpsec/fibersec`.
  - Unchanged: `identity`, `authorize`, `session`, `recovery`, `ratelimit`, `outbound`, `notify`, `pkg/`, `internal/`, `test/` and `tools/`.
- **Files consolidated into feature families inside every package.**
  - Files are named `<concept>_<aspect>.go`.
  - Each feature's options sit beside that feature. `httpsec/options.go` keeps only the chain-level options.
  - A production file under about 100 lines folds into its family's main file.
  - One test file per production file. Scenarios become table cases or subtests, and harnesses fold into the test file they serve.
  - Generated mocks, example tests and `export_test.go` keep their own files.
  - Shared code is filed by what it is, for example the login tail every feature uses.
- **Identical helpers in the three SQL backends move into `internal/storekit`.** This covers `bestEffort`, `checkUser`, `parseUserID`, `survivingRoles`, the detached-error family, `txKey`, `optionKind` and `sqlStater`.
- **`Manager` removed from every type name.**
  - `oidc.Manager` → `RelyingParty`
  - `oidc.HandoffManager` → `Handoff`
  - `authenticate.Manager` and `authorize.Manager` → `FirstOf`
  - `session.Manager` → `Sessions`
  - `passkey.Manager` → `Passkeys`
  - `signingkey.KeyManager` → `Keys`
  - `apikey.Manager` → `Keys`
  - `onetime.Manager` → `Tokens`
  - `magiclink.Manager` → `Links`

  Their constructors and option types follow the new names. Where a package has one main type, its constructor is `New`.
- **Outlier names corrected:**
  - initialisms (`JWT…`);
  - getter prefix (`Signer`);
  - spelling (`ErrMFAEnrolmentRequired`, `UnavailableFallbackToLocal`, `NormalizeName`);
  - the shared sentinel name (`seal.ErrConfig`);
  - option form (`token.WithVerify…`);
  - structs that read as constructors (`identity.UserChange`, `passkey.CredentialInput`);
  - sibling consistency (`LimiterFactory`, `NewMemoryKeyStore`, `UserVerificationRequired`).
- **Naming rules applied across the API:**
  - Sentinel errors drop the package noun (`session.ErrNotFound`, `password.ErrTooLong`, `token.ErrInvalid`, `policy.ErrDenied`).
  - Policy types drop the `Policy` suffix (`policy.IdleTimeout`, `policy.ConcurrentSessions`, `policy.PasswordAge`, `lockout.Policy`).
  - Options are `Option`/`With<Thing>` in a package with one configurable type, and `<Type>Option`/`With<Stem><Thing>` where several types share a package.
  - Typed enum constants carry their type's prefix.
- **Repository wiring updated to the new paths:**
  - every `go.mod` `replace` directive, `go.work`, CI workflows, `Makefile` targets and the layout-check fixtures;
  - the `config.yaml` context;
  - the path references in active changes' artifacts.

### Not in this change

- **Changes to API shape or behaviour.** These go to a separate later change, `idiomatic-api-shape`, before `v0.1.0`:
  - constructors returning concrete types;
  - `context.Context` on key ports;
  - consistent construction errors for in-memory stores;
  - one lifecycle convention;
  - the exported mutable `oidc.DefaultScopes`.
- **Any new feature.**
- **Any change to what a test asserts.** Assertions move unchanged when tests become table cases. The only text that may change is an error-message prefix, which follows its new package name.

### Order

1. `fix/stabilize-intermittent-tests` merges. It is complete on its branch, and a reliable gate is this change's proof that nothing broke.
2. This change.
3. `idiomatic-api-shape`.
4. `trusted-proxy-client-ip`.
5. `release-readiness`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `module-layout`:
  - the WebAuthn adapter's module path becomes `github.com/kartaladev/scrty/authenticate/passkey/webauthn`;
  - the nested integration modules are named at their new paths;
  - the list of modules the core must never require gains the four that the layout guard already refuses (`github.com/redis/go-redis`, `github.com/pressly/goose`, and the testcontainers `postgres` and `redis` modules);
  - the supported Go release becomes 1.27 only, matching every `go.mod` and the CI matrix.

  The last two only bring the spec in line with what the code and CI already enforce.

No other requirement changes. Behaviour specs that use "manager" as plain English, not as an identifier, keep their wording.

## Impact

- **Code:** every package in the core module, and every nested module (`fibersec`, `ginsec`, `gorm`, `pgx`, `redis`, `sweep`, `passkey/webauthn`, `test`, `tools`). Import paths and exported names change, and files are reorganised.
- **Module paths:**
  - `passkey/webauthn` → `authenticate/passkey/webauthn`
  - `pgx` → `store/pgxstore`
  - `gorm` → `store/gormstore`
  - `redis` → `ratelimit/redisstore`
  - `sweep` → `expiry/sweep`
  - `ginsec` → `httpsec/ginsec`
  - `fibersec` → `httpsec/fibersec`

  `release-readiness`'s tag prefixes change to match.
- **Proof of no regression:**
  - the set of test names is the same before and after, mapped through the renames;
  - every former test survives, as itself or as a named table case;
  - no package's coverage drops;
  - test diffs touch only import paths, identifiers, file placement, error-message prefixes, and assertions moved unchanged into table cases;
  - an old-to-new map of every exported identifier is checked against an API diff, so nothing disappears without a successor;
  - `make check`, including the Docker-backed suites, is green in CI.
- **Dependencies, migrations, stored data:** unchanged.
- **Consumers:** none yet. Nothing is tagged.

## References

### Directory grouping

**Researched (accessed 2026-10-25):**
- [Organizing a Go module](https://go.dev/doc/modules/layout): a module's packages may be structured hierarchically and nested, and supporting packages belong in `internal/`.
- [Go blog: Package names](https://go.dev/blog/package-names): a directory only arranges files and implies no relationship between packages; avoid stutter and catch-all packages.
- [volatiletech/authboss](https://github.com/volatiletech/authboss): a flat layout with one package per feature, considered and not chosen.
- [ory/fosite](https://github.com/ory/fosite): a concept-grouped layout (`handler/oauth2`, `handler/openid`, `token`, `storage`).

### Type names

**Researched (accessed 2026-10-25):**
- [OpenID Connect Core 1.0, Terminology](https://openid.net/specs/openid-connect-core-1_0.html): the component that requests authentication from an OpenID Provider is the Relying Party; OAuth 2.0 clients using OpenID Connect are also called Relying Parties.
- [zitadel/oidc, package rp](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rp): a Go relying party exported as `RelyingParty`.
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc): a Go OIDC library with no `Manager` type, naming its parts `Provider` and `IDTokenVerifier`.

**Primary documentation:**
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments): initialisms, getters, error strings and receiver names.
- [Effective Go: Names](https://go.dev/doc/effective_go#names): getters without `Get`, `-er` interface names, MixedCaps.

### Adapter package names

**Researched (accessed 2026-10-25):**
- [alexedwards/scs](https://github.com/alexedwards/scs): every storage adapter is named `<driver>store` (`pgxstore`, `gormstore`, `redisstore`), which avoids clashing with the driver's own package name.
