package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sha40 = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"

func TestCheck(t *testing.T) {
	one := func(t *testing.T, got []Finding, err error) {
		t.Helper()
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v; want exactly one finding", got, err)
		}
	}
	none := func(t *testing.T, got []Finding, err error) {
		t.Helper()
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v; want no findings", got, err)
		}
	}

	tests := []struct {
		name   string
		files  map[string]string
		assert func(t *testing.T, got []Finding, err error)
	}{
		{
			name:  "refuses a tag reference naming workflow and action",
			files: map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@v5\n"},
			assert: func(t *testing.T, got []Finding, err error) {
				t.Helper()
				one(t, got, err)
				msg := got[0].String()
				for _, want := range []string{"ci.yml", "actions/checkout@v5"} {
					if !strings.Contains(msg, want) {
						t.Errorf("finding %q does not name %q", msg, want)
					}
				}
			},
		},
		{
			name:  "refuses a short SHA",
			files: map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@fbc6f39 # v5.1.0\n"},
			assert: func(t *testing.T, got []Finding, err error) {
				t.Helper()
				one(t, got, err)
				if !strings.Contains(got[0].String(), "actions/checkout@fbc6f39") {
					t.Errorf("finding %q does not name the action", got[0])
				}
			},
		},
		{
			name:   "refuses a branch reference",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@main\n"},
			assert: one,
		},
		{
			name:   "refuses a full SHA with no tag comment",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@" + sha40 + "\n"},
			assert: one,
		},
		{
			name:   "refuses a reference with no ref at all",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout\n"},
			assert: one,
		},
		{
			name:   "accepts a full SHA with its tag",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@" + sha40 + " # v5.1.0\n"},
			assert: none,
		},
		{
			name:   "accepts a quoted reusable workflow pinned to a SHA",
			files:  map[string]string{"ci.yml": "jobs:\n  j:\n    uses: \"org/repo/.github/workflows/w.yml@" + sha40 + "\" # v1.2.3\n"},
			assert: none,
		},
		{
			name:   "exempts a local action and a local reusable workflow",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: ./.github/actions/setup\n  - uses: ./.github/workflows/w.yml\n"},
			assert: none,
		},
		{
			name: "container actions need a digest",
			files: map[string]string{
				"a.yml": "steps:\n  - uses: docker://alpine:3.20\n",
				"b.yml": "steps:\n  - uses: docker://alpine@sha256:" + strings.Repeat("a", 64) + " # 3.20\n",
			},
			assert: func(t *testing.T, got []Finding, err error) {
				t.Helper()
				one(t, got, err)
				if !strings.Contains(got[0].String(), "a.yml") {
					t.Errorf("finding %q does not name a.yml", got[0])
				}
			},
		},
		{
			name:   "ignores commented-out uses and the word uses elsewhere",
			files:  map[string]string{"ci.yml": "# uses: actions/checkout@v5\nname: reuses x\n"},
			assert: none,
		},
		{
			name:   "refuses a flow-mapping step",
			files:  map[string]string{"ci.yml": "steps:\n  - {uses: actions/checkout@v5}\n"},
			assert: one,
		},
		{
			name:   "ignores uses text inside a run block scalar",
			files:  map[string]string{"ci.yml": "steps:\n  - run: |\n      echo\n      uses: foo@v1\n"},
			assert: none,
		},
		{
			name:   "accepts a tab before the tag comment",
			files:  map[string]string{"ci.yml": "steps:\n  - uses: actions/checkout@" + sha40 + "\t# v5\n"},
			assert: none,
		},
		{
			name:   "reads the yaml extension and ignores other files",
			files:  map[string]string{"ci.yaml": "- uses: a/b@v1\n", "notes.txt": "uses: a/b@v1\n"},
			assert: one,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Check(dir)
			tt.assert(t, got, err)
		})
	}
}

func TestCheck_WalksNestedDirectories(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "actions", "setup")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	body := "runs:\n  steps:\n    - uses: a/b@v1\n"
	if err := os.WriteFile(filepath.Join(nested, "action.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Check(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v; want one finding", got, err)
	}
}

func TestCheck_MissingDirectoryIsAnError(t *testing.T) {
	if _, err := Check(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("Check on a missing directory returned no error")
	}
}
