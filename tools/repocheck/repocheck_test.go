package repocheck_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/kartaladev/scrty/tools/repocheck"
)

const dependabotFull = `
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule: {interval: weekly}
  - package-ecosystem: gomod
    directory: /httpsec/ginsec
    schedule:
      interval: daily
  - package-ecosystem: gomod
    directory: /tools
    schedule: {interval: weekly}
  - package-ecosystem: github-actions
    directory: /
    schedule: {interval: weekly}
`

func TestMissingUpdateEntries(t *testing.T) {
	modules := []string{".", "./httpsec/ginsec", "tools"}
	tests := []struct {
		name       string
		dependabot string
		modules    []string
		assert     func(t *testing.T, got []string, err error)
	}{
		{
			name:       "every module covered",
			dependabot: dependabotFull,
			modules:    modules,
			assert: func(t *testing.T, got []string, err error) {
				if err != nil || len(got) != 0 {
					t.Fatalf("got %v, %v; want nothing", got, err)
				}
			},
		},
		{
			name: "a module without an entry is listed",
			dependabot: `
updates:
  - {package-ecosystem: gomod, directory: /, schedule: {interval: weekly}}
  - {package-ecosystem: gomod, directory: /tools, schedule: {interval: weekly}}
  - {package-ecosystem: github-actions, directory: /, schedule: {interval: weekly}}
`,
			modules: modules,
			assert: func(t *testing.T, got []string, err error) {
				if err != nil || !slices.Equal(got, []string{"httpsec/ginsec"}) {
					t.Fatalf("got %v, %v; want [httpsec/ginsec]", got, err)
				}
			},
		},
		{
			name: "a monthly schedule does not count",
			dependabot: `
updates:
  - {package-ecosystem: gomod, directory: /, schedule: {interval: weekly}}
  - {package-ecosystem: gomod, directory: /httpsec/ginsec, schedule: {interval: monthly}}
  - {package-ecosystem: gomod, directory: /tools, schedule: {interval: weekly}}
  - {package-ecosystem: github-actions, directory: /, schedule: {interval: weekly}}
`,
			modules: modules,
			assert: func(t *testing.T, got []string, err error) {
				if err != nil || !slices.Equal(got, []string{"httpsec/ginsec"}) {
					t.Fatalf("got %v, %v; want [httpsec/ginsec]", got, err)
				}
			},
		},
		{
			name: "no github-actions entry",
			dependabot: `
updates:
  - {package-ecosystem: gomod, directory: /, schedule: {interval: weekly}}
  - {package-ecosystem: gomod, directory: /httpsec/ginsec, schedule: {interval: weekly}}
  - {package-ecosystem: gomod, directory: /tools, schedule: {interval: weekly}}
`,
			modules: modules,
			assert: func(t *testing.T, got []string, err error) {
				if err != nil || !slices.Equal(got, []string{"github-actions"}) {
					t.Fatalf("got %v, %v; want [github-actions]", got, err)
				}
			},
		},
		{
			name:       "invalid yaml is an error",
			dependabot: "updates: [",
			modules:    modules,
			assert: func(t *testing.T, got []string, err error) {
				if err == nil {
					t.Fatalf("got %v, nil; want an error", got)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repocheck.MissingUpdateEntries([]byte(tc.dependabot), tc.modules)
			tc.assert(t, got, err)
		})
	}
}

func TestAutoMergeSteps(t *testing.T) {
	wrap := func(step string) string {
		return "on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + step
	}
	tests := []struct {
		name      string
		workflows map[string]string
		assert    func(t *testing.T, got []string)
	}{
		{
			name:      "plain CI",
			workflows: map[string]string{"ci.yml": wrap("      - uses: actions/checkout@0123456789012345678901234567890123456789\n      - run: go test ./...\n")},
			assert: func(t *testing.T, got []string) {
				if len(got) != 0 {
					t.Fatalf("got %v; want nothing", got)
				}
			},
		},
		{
			name:      "gh pr merge",
			workflows: map[string]string{"bot.yml": wrap("      - run: gh pr merge --auto --squash \"$URL\"\n")},
			assert:    assertNamed("bot.yml"),
		},
		{
			name:      "gh pr review approve",
			workflows: map[string]string{"approve.yml": wrap("      - run: |\n          gh pr review --approve \"$URL\"\n")},
			assert:    assertNamed("approve.yml"),
		},
		{
			name:      "gh pr review comment only",
			workflows: map[string]string{"note.yml": wrap("      - run: gh pr review --comment -b hi\n")},
			assert: func(t *testing.T, got []string) {
				if len(got) != 0 {
					t.Fatalf("got %v; want nothing", got)
				}
			},
		},
		{
			name:      "auto-approve action",
			workflows: map[string]string{"aa.yml": wrap("      - uses: hmarr/auto-approve-action@0123456789012345678901234567890123456789 # v4\n")},
			assert:    assertNamed("aa.yml"),
		},
		{
			name:      "automerge action",
			workflows: map[string]string{"am.yaml": wrap("      - uses: pascalgn/automerge-action@v0.16.0\n")},
			assert:    assertNamed("am.yaml"),
		},
		{
			name:      "graphql mutation text",
			workflows: map[string]string{"gql.yml": wrap("      - run: gh api graphql -f query='mutation { enablePullRequestAutoMerge(input: {}) { clientMutationId } }'\n")},
			assert:    assertNamed("gql.yml"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := make(map[string][]byte, len(tc.workflows))
			for k, v := range tc.workflows {
				in[k] = []byte(v)
			}
			tc.assert(t, repocheck.AutoMergeSteps(in))
		})
	}
}

func assertNamed(file string) func(t *testing.T, got []string) {
	return func(t *testing.T, got []string) {
		t.Helper()
		if len(got) != 1 || len(got[0]) <= len(file)+2 || got[0][:len(file)+2] != file+": " {
			t.Fatalf("got %v; want one %q entry of the form \"file: reason\"", got, file)
		}
	}
}

func TestRepository_DependabotAndWorkflows(t *testing.T) {
	workData, err := os.ReadFile("../../go.work")
	if err != nil {
		t.Fatal(err)
	}
	work, err := modfile.ParseWork("go.work", workData, nil)
	if err != nil {
		t.Fatal(err)
	}
	modules := []string{"tools"}
	for _, u := range work.Use {
		modules = append(modules, u.Path)
	}
	t.Logf("modules: %v", modules)

	dependabot, err := os.ReadFile("../../.github/dependabot.yml")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := repocheck.MissingUpdateEntries(dependabot, modules)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("no daily or weekly Dependabot entry for: %v", missing)
	}

	workflows := map[string][]byte{}
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		files, err := filepath.Glob("../../.github/workflows/" + pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // f comes from a Glob of the repository's own workflow directory
			if err != nil {
				t.Fatal(err)
			}
			workflows[filepath.Base(f)] = b
		}
	}
	if len(workflows) == 0 {
		t.Fatal("no workflows found")
	}
	if offending := repocheck.AutoMergeSteps(workflows); len(offending) != 0 {
		t.Errorf("workflows that approve or merge pull requests: %v", offending)
	}
}
