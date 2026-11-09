# Releasing scrty

Every release gives all nine published modules the same version, and tags them at one commit. Pushing
the tags and publishing the release are the **maintainer's** actions: no automation and no agent
creates or pushes a tag.

The published modules are listed in `release-modules.txt` (the eight nested ones) plus the root:

| Module | Tag for `vX.Y.Z` |
|---|---|
| `github.com/kartaladev/scrty` | `vX.Y.Z` |
| `github.com/kartaladev/scrty/httpsec/fibersec` | `httpsec/fibersec/vX.Y.Z` |
| `github.com/kartaladev/scrty/httpsec/ginsec` | `httpsec/ginsec/vX.Y.Z` |
| `github.com/kartaladev/scrty/store/gormstore` | `store/gormstore/vX.Y.Z` |
| `github.com/kartaladev/scrty/authenticate/passkey/webauthn` | `authenticate/passkey/webauthn/vX.Y.Z` |
| `github.com/kartaladev/scrty/store/pgxstore` | `store/pgxstore/vX.Y.Z` |
| `github.com/kartaladev/scrty/ratelimit/redisstore` | `ratelimit/redisstore/vX.Y.Z` |
| `github.com/kartaladev/scrty/expiry/sweep` | `expiry/sweep/vX.Y.Z` |
| `github.com/kartaladev/scrty/test` | `test/vX.Y.Z` |

The `tools` module is never tagged. Every nested `go.mod` keeps its `replace` lines, which point only
inside the repository.

Set the version once, in the shell you release from:

```sh
export VERSION=vX.Y.Z   # for example v0.1.0
```

## The steps

### 1. Date the changelog and update the supported versions

In `CHANGELOG.md`, move the contents of `## [Unreleased]` into a new entry headed
`## [X.Y.Z] - YYYY-MM-DD` with the release date, and leave `Unreleased` empty. List any fixed
vulnerability under `Security`. Add or update the link references at the foot of the changelog
(`[Unreleased]` comparing the new tag with `HEAD`, and `[X.Y.Z]` comparing it with the previous tag;
for the first release, `[0.1.0]` links to the tag itself). In `SECURITY.md`, make the supported-versions table name the new
`X.Y.x` line only, and update the same sentence in `README.md`.

```sh
git diff -- CHANGELOG.md SECURITY.md README.md
```

### 2. Require the release version in every nested module

Each nested module's requirements on scrty modules must name the release version, not an older one.
Run from the repository root; `go mod edit -C <dir>` edits that directory's `go.mod`:

```sh
go mod edit -C httpsec/fibersec                 -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C httpsec/ginsec                   -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C store/gormstore                  -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C authenticate/passkey/webauthn    -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C store/pgxstore                   -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C ratelimit/redisstore             -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C expiry/sweep                     -require=github.com/kartaladev/scrty@$VERSION
go mod edit -C test                             -require=github.com/kartaladev/scrty@$VERSION
```

The `test` module also requires six sibling modules:

```sh
go mod edit -C test -require=github.com/kartaladev/scrty/authenticate/passkey/webauthn@$VERSION
go mod edit -C test -require=github.com/kartaladev/scrty/httpsec/fibersec@$VERSION
go mod edit -C test -require=github.com/kartaladev/scrty/httpsec/ginsec@$VERSION
go mod edit -C test -require=github.com/kartaladev/scrty/ratelimit/redisstore@$VERSION
go mod edit -C test -require=github.com/kartaladev/scrty/store/gormstore@$VERSION
go mod edit -C test -require=github.com/kartaladev/scrty/store/pgxstore@$VERSION
```

Leave every `replace` line as it is. Check the result before committing:

```sh
git diff -- '*/go.mod' go.mod
```

### 3. Merge

Open a pull request with the changes of steps 1 and 2, let CI pass, and merge it. The release is cut
from the merged commit on `main`, so update your checkout to it, with a clean working tree:

```sh
git switch main && git pull --ff-only
git status --short   # prints nothing
```

### 4. Run the release gate on the merged commit

```sh
make release-check VERSION=$VERSION
```

The gate builds and tests every published module with the workspace off, checks that every nested
module's scrty requirements name `$VERSION`, runs `release-gate` (the vulnerability check, then an
SBOM per published module, each naming `$VERSION`) and reports each module's public API against the
previous release. Before it builds anything, it refuses:

- a working tree that is not clean, untracked files included, whatever `status.showUntrackedFiles`
  says;
- a `$VERSION` that is not a semantic version;
- a shallow clone, which lacks the tags the API report compares against;
- a clone with no previous `v` tag, for any `$VERSION` but `v0.1.0` or one of its prereleases: fetch
  the tags (`git fetch --tags`) and run it again;
- a relative `TMPDIR`, or one holding characters other than letters, digits and `._+@/-`;
- a non-empty `go env GOFLAGS`, which would change what is built and tested: unset it
  (`go env -u GOFLAGS`, and `unset GOFLAGS`);
- an `SBOM_DIR` that is not strictly inside `.bin`, after resolving symlinks and `..`. Leave
  `SBOM_DIR` unset: the gate removes that directory, and a value such as `.` would remove the
  checkout.

A failure stops the release: fix it, merge, and run it again. It needs `jq`, and refuses to start
without it. It also needs Docker, for the PostgreSQL and Redis tests, and runs them on the default
images only.

Run the same gate in CI as well, which tests both supported PostgreSQL majors, and wait for it to
pass:

```sh
gh workflow run release-check --ref main -f version=$VERSION
gh run watch "$(gh run list --workflow release-check --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The CI run's SBOMs are not kept; step 9 attaches the ones from your local run.

The gate reads `HEAD` once, when it starts, and gates that commit. It fails if `HEAD` moves or the
working tree changes before it ends, and on success prints a line starting `release-check: passed
for $VERSION at commit <sha>`. Note the commit: step 6 tags it.

With `SBOM_DIR` unset, the gate empties `.bin/sbom` when it starts, before any of its other refusals, and writes the nine SBOMs to
`.bin/sbom/*.cdx.json` only when every step has passed, so a refused or failed run leaves the
directory empty. Keep them: step 9 attaches
exactly these files. They must come from this run, on the commit that step 6 tags, not from an earlier
run. Do not run `make sbom` or `make release-gate` before step 9: either rewrites `.bin/sbom` with SBOMs
that name the commit's pseudo-version instead of `$VERSION`.

### 5. Confirm that private vulnerability reporting is on

```sh
gh api repos/kartaladev/scrty/private-vulnerability-reporting
```

The output must show `"enabled": true`, for example `{"enabled":true}`. If it shows `false`, enable
it under the repository's Settings (Advanced Security) and run the command again. Do not tag until it
is on, because `SECURITY.md` names it as the only reporting channel.

### 6. Create the annotated tags

```sh
make release-tags VERSION=$VERSION
```

The target prints nine `git tag -a` commands for the current commit, one for the root and one for
each nested module, and creates nothing. Check that the commit is the one step 4 gated, then run the
printed commands. `git tag --points-at HEAD` lists the nine tags afterwards.

### 7. Push the tags

Pushing a tag is the maintainer's action. Push the nine tags in one atomic push, so either all of
them reach the remote or none does, and the probe never starts with only some of them there:

```sh
git push --atomic origin \
  $VERSION \
  httpsec/fibersec/$VERSION \
  httpsec/ginsec/$VERSION \
  store/gormstore/$VERSION \
  authenticate/passkey/webauthn/$VERSION \
  store/pgxstore/$VERSION \
  ratelimit/redisstore/$VERSION \
  expiry/sweep/$VERSION \
  test/$VERSION
```

If the push is refused, nothing was published: fix the cause and push again.

### 8. Watch the probe

Pushing the root tag starts the `release-probe` workflow. It fetches every published module at
`$VERSION` through the public module proxy, with the workspace off, and builds a program importing a
package from each.

```sh
gh run list --workflow release-probe --limit 1
gh run watch "$(gh run list --workflow release-probe --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The release is proven only when the probe passes. The proxy may take a few minutes to serve a new
tag; the probe retries. If it fails, the release is recorded as failed and the fix is a new version:
see "Never move a tag" below. To run the probe by hand:

```sh
scripts/release-probe.sh $VERSION
```

### 9. Publish the release notes and attach the SBOMs

Write the changelog entry for `$VERSION` to a file, without its heading, and publish it with the nine
SBOMs of step 4:

```sh
gh release create $VERSION --verify-tag --title $VERSION --notes-file <entry> .bin/sbom/*.cdx.json
```

`--verify-tag` aborts if the tag is not on the remote, so `gh` never creates a tag for you. Before
running it, check that `.bin/sbom` holds nine files, each naming `$VERSION`:

```sh
ls .bin/sbom/*.cdx.json | wc -l   # prints 9
for f in .bin/sbom/*.cdx.json; do jq -e --arg v "$VERSION" '.metadata.component.version == $v' "$f" >/dev/null || echo "wrong: $f"; done   # prints nothing
```

Only a passing step 4 leaves such files there, and any later run of the gate with `SBOM_DIR` unset,
even a refused one, empties the directory when it starts. If the files are missing, run step 4 again
on the same commit: with the tags now in place, it compares against the previous release, not
against `$VERSION` itself.

## Never move a tag

A pushed release tag is never moved or deleted. The module proxy and the checksum database keep the
first content they saw for a version, so a moved tag breaks every consumer that already fetched it.

When a published version is defective, whether the probe failed or a defect was found later:

1. fix it in a new patch version, for example `v0.1.1`, and release that through the steps above;
2. where consumers must not select the defective version, retract it in the new version's `go.mod`
   files, in each affected module, and keep the `retract` in every later version:

   ```sh
   go mod edit -C <module directory> -retract=v0.1.0
   ```

3. leave the defective version's tags exactly as they are.
