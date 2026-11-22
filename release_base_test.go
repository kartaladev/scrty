package scrty_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// releaseTestEnv returns the environment for the git and make commands of these tests:
// the caller's, without anything that selects a repository or configures make, with
// the user's git configuration ignored and git discovery stopped above dir, so a case
// that runs outside a repository cannot find the one these tests live in.
func releaseTestEnv(dir string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GIT_") || name == "MAKEFLAGS" || name == "MFLAGS" || name == "MAKELEVEL" {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
	)
}

// fixtureGit runs git in dir with the fixture's identity, failing the test on error,
// and returns its output, trimmed.
func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	//nolint:gosec // G204: fixed binary, test-supplied fixture args
	cmd := exec.CommandContext(t.Context(), "git", append([]string{
		"-c", "user.name=fixture", "-c", "user.email=fixture@localhost",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main",
	}, args...)...)
	cmd.Dir = dir
	cmd.Env = releaseTestEnv(dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// fixtureCommit is one commit of a fixture repository: the module directories whose
// go.mod it adds (`.` for the root) or removes, and the tags it carries, annotated
// (the kind `make release-tags` prints) and lightweight.
type fixtureCommit struct {
	add         []string
	remove      []string
	tags        []string
	lightweight []string
}

// newFixtureRepo creates a git repository holding commits in order, each changing the
// go.mod files the earlier ones left and carrying its tags.
func newFixtureRepo(t *testing.T, commits []fixtureCommit) string {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	fixtureGit(t, dir, "init", "-q")
	for i, c := range commits {
		for _, m := range c.add {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, m), 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(dir, m, "go.mod"), []byte("module fixture\n"), 0o600))
		}
		for _, m := range c.remove {
			require.NoError(t, os.Remove(filepath.Join(dir, m, "go.mod")))
		}
		fixtureGit(t, dir, "add", "-A")
		fixtureGit(t, dir, "commit", "-q", "--allow-empty", "-m", "fixture "+strconv.Itoa(i))
		for _, tag := range c.tags {
			fixtureGit(t, dir, "tag", "-a", "-m", tag, tag)
		}
		for _, tag := range c.lightweight {
			fixtureGit(t, dir, "tag", tag)
		}
	}
	return dir
}

// runReleaseModuleBase runs the Makefile's release_module_base for base and module in
// dir, through make with the real Makefile included, and returns its standard output,
// trimmed, and its standard error.
func runReleaseModuleBase(t *testing.T, dir, base, module string) (string, string, error) {
	t.Helper()

	makefile, err := filepath.Abs("Makefile")
	require.NoError(t, err)
	require.NotContains(t, makefile, " ", "make cannot include a path with a space")

	probe := filepath.Join(t.TempDir(), "probe.mk")
	script := "include " + makefile + "\n.PHONY: probe\nprobe:\n" +
		"\t@set -eu -o pipefail; $(RELEASE_MODULE_BASE) release_module_base \"$$PROBE_BASE\" \"$$PROBE_DIR\"\n"
	require.NoError(t, os.WriteFile(probe, []byte(script), 0o600))

	//nolint:gosec // G204: fixed binary, probe path built by the test
	cmd := exec.CommandContext(t.Context(), "make", "--no-print-directory", "-s", "-f", probe, "probe")
	cmd.Dir = dir
	cmd.Env = append(releaseTestEnv(dir), "PROBE_BASE="+base, "PROBE_DIR="+module)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

func TestReleaseModuleBase(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		repo    bool // false runs outside any git repository
		commits []fixtureCommit
		mangle  func(t *testing.T, dir string) // breaks the fixture after it is built; nil leaves it
		base    string
		module  string
		assert  func(t *testing.T, out, stderr string, err error)
	}

	reportedAgainst := func(want string) func(t *testing.T, out, stderr string, err error) {
		return func(t *testing.T, out, stderr string, err error) {
			require.NoError(t, err, "stderr: %s", stderr)
			assert.Equal(t, want, out)
		}
	}
	refused := func(why ...string) func(t *testing.T, out, stderr string, err error) {
		return func(t *testing.T, out, stderr string, err error) {
			require.Error(t, err, "stdout: %s", out)
			for _, w := range why {
				assert.Contains(t, stderr, w)
			}
			assert.NotContains(t, stderr, "deliberately", "no option to choose a base exists")
			assert.NotEqual(t, "none", out, "a refused lookup must not also print none")
		}
	}

	cases := []testCase{
		{
			name: "the root with its tag at base is reported against base",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.0", "v0.1.1", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: ".",
			assert: reportedAgainst("v0.1.1"),
		},
		{
			name: "a nested module present at base with its tag is reported against base",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.1", "store/pgxstore/v0.1.0", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: reportedAgainst("v0.1.1"),
		},
		{
			name: "a lightweight tag at base is followed to its commit",
			repo: true,
			commits: []fixtureCommit{{
				add:         []string{".", "store/pgxstore"},
				lightweight: []string{"v0.1.1", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: reportedAgainst("v0.1.1"),
		},
		{
			name: "a nested module absent at base is released for the first time and reported against none",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.0", "v0.1.1", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "httpsec/prblmsec",
			assert: reportedAgainst("none"),
		},
		{
			name: "a first-release module already tagged at the release version is still reported against none",
			repo: true,
			commits: []fixtureCommit{
				{
					add:  []string{".", "store/pgxstore"},
					tags: []string{"v0.1.1", "store/pgxstore/v0.1.1"},
				},
				{
					add:  []string{"httpsec/prblmsec"},
					tags: []string{"v0.2.0", "store/pgxstore/v0.2.0", "httpsec/prblmsec/v0.2.0"},
				},
			},
			base:   "v0.1.1",
			module: "httpsec/prblmsec",
			assert: reportedAgainst("none"),
		},
		{
			name: "a module dropped before base and published again is reported against none",
			repo: true,
			commits: []fixtureCommit{
				{
					add:  []string{".", "store/pgxstore"},
					tags: []string{"v0.1.0", "store/pgxstore/v0.1.0"},
				},
				{
					remove: []string{"store/pgxstore"},
					tags:   []string{"v0.1.1"},
				},
			},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: reportedAgainst("none"),
		},
		{
			name: "a module whose name only prefixes one present at base is reported against none",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "httpsec/prblmsecx"},
				tags: []string{"v0.1.1", "httpsec/prblmsecx/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "httpsec/prblmsec",
			assert: reportedAgainst("none"),
		},
		{
			name:   "base none is none for every module without asking git",
			repo:   false,
			base:   "none",
			module: "httpsec/prblmsec",
			assert: reportedAgainst("none"),
		},
		{
			name:   "base none is none for the root",
			repo:   false,
			base:   "none",
			module: ".",
			assert: reportedAgainst("none"),
		},
		{
			name:   "a failed tag lookup for a nested module fails rather than falling back to none",
			repo:   false,
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("looking up tag v0.1.1 failed"),
		},
		{
			name:   "a failed tag lookup for the root fails too",
			repo:   false,
			base:   "v0.1.1",
			module: ".",
			assert: refused("looking up tag v0.1.1 failed"),
		},
		{
			name: "the root without its tag at base is refused",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.0", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: ".",
			assert: refused("the root has no tag v0.1.1"),
		},
		{
			name: "a nested module is refused when the root has no tag at base",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.0", "store/pgxstore/v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("the root has no tag v0.1.1"),
		},
		{
			name: "a nested module present at base without its tag is refused, asking for the tags",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("store/pgxstore", "no tag store/pgxstore/v0.1.1", "git fetch --tags"),
		},
		{
			name: "a nested module with an earlier release, present at base without its tag, is refused",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.0", "v0.1.1", "store/pgxstore/v0.1.0"},
			}},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("no tag store/pgxstore/v0.1.1", "git fetch --tags"),
		},
		{
			name: "a base tag that names no commit fails rather than counting the module as absent",
			repo: true,
			commits: []fixtureCommit{{
				add: []string{".", "store/pgxstore"},
			}},
			mangle: func(t *testing.T, dir string) {
				blob := fixtureGit(t, dir, "rev-parse", "HEAD:store/pgxstore/go.mod")
				fixtureGit(t, dir, "tag", "v0.1.1", blob)
			},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("tag v0.1.1 does not resolve to a commit"),
		},
		{
			name: "a failed lookup of the module at base fails rather than counting it as absent",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{".", "store/pgxstore"},
				tags: []string{"v0.1.1", "store/pgxstore/v0.1.1"},
			}},
			mangle: func(t *testing.T, dir string) {
				tree := fixtureGit(t, dir, "rev-parse", "v0.1.1^{tree}")
				require.NoError(t, os.Remove(filepath.Join(dir, ".git", "objects", tree[:2], tree[2:])))
			},
			base:   "v0.1.1",
			module: "store/pgxstore",
			assert: refused("looking up store/pgxstore/go.mod at v0.1.1 failed"),
		},
		{
			name: "a directory that makes no valid tag name is refused",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{"."},
				tags: []string{"v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "store/../pgxstore",
			assert: refused("is not a valid tag name"),
		},
		{
			name: "an empty directory is refused",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{"."},
				tags: []string{"v0.1.1"},
			}},
			base:   "v0.1.1",
			module: "",
			assert: refused("needs a base and a module directory"),
		},
		{
			name: "an empty base is refused",
			repo: true,
			commits: []fixtureCommit{{
				add:  []string{"."},
				tags: []string{"v0.1.1"},
			}},
			base:   "",
			module: ".",
			assert: refused("needs a base and a module directory"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dir string
			if tc.repo {
				dir = newFixtureRepo(t, tc.commits)
			} else {
				var err error
				dir, err = filepath.EvalSymlinks(t.TempDir())
				require.NoError(t, err)
			}
			if tc.mangle != nil {
				tc.mangle(t, dir)
			}

			out, stderr, err := runReleaseModuleBase(t, dir, tc.base, tc.module)
			tc.assert(t, out, stderr, err)
		})
	}
}

// TestReleaseCheckUsesModuleBase pins the wiring TestReleaseModuleBase cannot reach
// without running the whole gate: release-check defines release_module_base, looks up
// every module's base before it builds the export and clears GIT_DIR (the lookup reads
// this repository's tags, which the export does not have), stops when a lookup fails,
// and hands gorelease each module's own base, never the shared one. It reads the
// recipe as text because running release-check needs the tools, the network and a
// clean tagged repository; the selection itself is tested by behaviour above, so this
// only guards against the call being dropped, moved or made non-fatal.
func TestReleaseCheckUsesModuleBase(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("Makefile")
	require.NoError(t, err)
	mk := string(data)
	assert.Contains(t, mk, `-base="$$mb"`)
	assert.NotContains(t, mk, `-base="$$base"`)

	start := strings.Index(mk, "\nrelease-check:\n")
	require.GreaterOrEqual(t, start, 0, "the release-check recipe")
	recipe := mk[start:]
	if end := strings.Index(recipe, "\n\n"); end >= 0 {
		recipe = recipe[:end]
	}

	define := strings.Index(recipe, "$(RELEASE_MODULE_BASE) \\")
	lookup := strings.Index(recipe, `release_module_base "$$base" "$$d"`)
	archive := strings.Index(recipe, "git archive")
	unset := strings.Index(recipe, "unset GIT_DIR")
	require.GreaterOrEqual(t, define, 0, "release-check defines release_module_base")
	require.GreaterOrEqual(t, lookup, 0, "release-check looks up each module's base")
	require.GreaterOrEqual(t, archive, 0, "release-check builds the export with git archive")
	require.GreaterOrEqual(t, unset, 0, "release-check clears GIT_DIR")
	assert.Less(t, define, lookup, "the function is defined before the lookup")
	assert.Less(t, lookup, archive, "the bases are looked up before the export is built")
	assert.Less(t, lookup, unset, "the bases are looked up before GIT_DIR is cleared")

	line := recipe[lookup:]
	if end := strings.Index(line, "\n"); end >= 0 {
		line = line[:end]
	}
	assert.Regexp(t, regexp.MustCompile(`\|\| \{ [^}]*exit 2; \}`), line,
		"a failed lookup must stop the gate")
}
