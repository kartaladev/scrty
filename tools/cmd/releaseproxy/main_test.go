package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	version = "v0.1.0"
	rootMod = "module example.com/m\n\ngo 1.21\n"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// snapshot lists every path under root, or "<missing>" when root does not exist.
func snapshot(t *testing.T, root string) []string {
	t.Helper()
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return []string{"<missing>"}
	}
	var got []string
	err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		got = append(got, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	return got
}

func zipNames(t *testing.T, out, path, ver string) []string {
	t.Helper()
	esc := strings.ReplaceAll(path, "/", string(filepath.Separator))
	r, err := zip.OpenReader(filepath.Join(out, esc, "@v", ver+".zip"))
	if err != nil {
		t.Fatalf("open zip of %s: %v", path, err)
	}
	defer func() { _ = r.Close() }()
	var names []string
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	slices.Sort(names)
	return names
}

func TestWriteProxy_ExcludesNestedModule(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"go.mod":     rootMod,
		"m.go":       "package m\n",
		"sub/go.mod": "module example.com/m/sub\n\ngo 1.21\n",
		"sub/sub.go": "package sub\n",
	}
	rootZip := []string{"example.com/m@v0.1.0/go.mod", "example.com/m@v0.1.0/m.go"}

	tests := []struct {
		name   string
		dirs   []string
		assert func(t *testing.T, out string, err error)
	}{
		{
			name: "the root zip leaves out the nested module's files",
			dirs: []string{"."},
			assert: func(t *testing.T, out string, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				if got := zipNames(t, out, "example.com/m", version); !slices.Equal(got, rootZip) {
					t.Errorf("root zip holds %v, want %v", got, rootZip)
				}
			},
		},
		{
			name: "the nested module is its own zip, and the root's stays clean",
			dirs: []string{".", "sub"},
			assert: func(t *testing.T, out string, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				wantSub := []string{"example.com/m/sub@v0.1.0/go.mod", "example.com/m/sub@v0.1.0/sub.go"}
				if got := zipNames(t, out, "example.com/m/sub", version); !slices.Equal(got, wantSub) {
					t.Errorf("nested zip holds %v, want %v", got, wantSub)
				}
				if got := zipNames(t, out, "example.com/m", version); !slices.Equal(got, rootZip) {
					t.Errorf("root zip holds %v, want %v", got, rootZip)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := t.TempDir()
			writeTree(t, src, files)
			out := filepath.Join(t.TempDir(), "proxy")
			tc.assert(t, out, writeProxy(src, version, tc.dirs, out))
		})
	}
}

func TestWriteProxy_EscapesPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		module string
		assert func(t *testing.T, out string, err error)
	}{
		{
			name:   "a capital in the host is escaped",
			module: "example.com/Foo",
			assert: func(t *testing.T, out string, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				if got := snapshot(t, filepath.Join(out, "example.com", "!foo", "@v")); !slices.Contains(got, version+".zip") {
					t.Errorf("escaped directory holds %v, want it to hold %s.zip", got, version)
				}
				entries, err := os.ReadDir(filepath.Join(out, "example.com"))
				if err != nil || len(entries) != 1 || entries[0].Name() != "!foo" {
					t.Errorf("example.com holds %v (%v), want only !foo", entries, err)
				}
			},
		},
		{
			name:   "a capital in a later element is escaped",
			module: "example.com/foo/Bar",
			assert: func(t *testing.T, out string, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				if got := snapshot(t, filepath.Join(out, "example.com", "foo", "!bar", "@v")); !slices.Contains(got, version+".info") {
					t.Errorf("escaped directory holds %v, want it to hold %s.info", got, version)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := t.TempDir()
			writeTree(t, src, map[string]string{"go.mod": "module " + tc.module + "\n\ngo 1.21\n", "m.go": "package m\n"})
			out := filepath.Join(t.TempDir(), "proxy")
			tc.assert(t, out, writeProxy(src, version, []string{"."}, out))
		})
	}
}

// One case: the other tests pin zips and paths; this one pins the three small files.
func TestWriteProxy_WritesListInfoAndMod(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeTree(t, src, map[string]string{"go.mod": rootMod, "m.go": "package m\n"})
	out := filepath.Join(t.TempDir(), "proxy")
	if err := writeProxy(src, version, []string{"."}, out); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(out); err != nil {
		t.Errorf("output after the run: %v", err)
	} else if perm := info.Mode().Perm(); !info.IsDir() || perm != 0o700 {
		t.Errorf("output after the run is %v, want a directory with mode 0700", info.Mode())
	}
	dir := filepath.Join(out, "example.com", "m", "@v")

	list, err := os.ReadFile(filepath.Join(dir, "list")) //nolint:gosec // G304: a path under this test's temporary directories
	if err != nil || string(list) != version+"\n" {
		t.Errorf("list = %q (%v), want %q", list, err, version+"\n")
	}
	mod, err := os.ReadFile(filepath.Join(dir, version+".mod")) //nolint:gosec // G304: a path under this test's temporary directories
	if err != nil || string(mod) != rootMod {
		t.Errorf(".mod = %q (%v), want the go.mod bytes", mod, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, version+".info")) //nolint:gosec // G304: a path under this test's temporary directories
	if err != nil {
		t.Fatal(err)
	}
	var info struct{ Version, Time string }
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf(".info %q is not JSON: %v", raw, err)
	}
	ts, err := time.Parse(time.RFC3339, info.Time)
	if info.Version != version || err != nil || time.Since(ts).Abs() > time.Minute {
		t.Errorf(".info = %q, want Version %s and a current RFC 3339 Time (%v)", raw, version, err)
	}
}

func TestWriteProxy_Refuses(t *testing.T) {
	t.Parallel()

	// refusesNaming asserts the error exists and names the offending input.
	refusesNaming := func(inputs ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			if err == nil {
				t.Fatal("got nil error, want a refusal")
			}
			for _, in := range inputs {
				if !strings.Contains(err.Error(), in) {
					t.Errorf("error %q does not name %q", err, in)
				}
			}
		}
	}
	good := map[string]string{"go.mod": rootMod, "m.go": "package m\n"}
	// badName holds a file name a module zip cannot carry, so its zip fails.
	badName := map[string]string{
		"go.mod": rootMod, "m.go": "package m\n",
		"bad/go.mod": "module example.com/bad\n\ngo 1.21\n", "bad/bad:name.go": "package bad\n",
	}

	tests := []struct {
		name    string
		version string // "" means the valid default
		files   map[string]string
		dirs    []string
		noOut   bool // the output argument is the empty string
		prepOut func(t *testing.T, out string)
		assert  func(t *testing.T, err error)
	}{
		{name: "blank version", version: " ", files: good, dirs: []string{"."}, assert: refusesNaming("version")},
		{name: "empty output path", files: good, dirs: []string{"."}, noOut: true, assert: refusesNaming("output")},
		{name: "version without the v prefix", version: "0.1.0", files: good, dirs: []string{"."}, assert: refusesNaming("0.1.0")},
		{name: "version that is not canonical", version: "v1.2", files: good, dirs: []string{"."}, assert: refusesNaming("v1.2")},
		{name: "version with build metadata", version: "v0.1.0+meta", files: good, dirs: []string{"."}, assert: refusesNaming("v0.1.0+meta")},
		{name: "missing directory", files: good, dirs: []string{"nope"}, assert: refusesNaming("nope")},
		{name: "good directory then a missing one", files: good, dirs: []string{".", "nope"}, assert: refusesNaming("nope")},
		{name: "directory without go.mod", files: map[string]string{"bare/x.go": "package x\n"}, dirs: []string{"bare"}, assert: refusesNaming("bare")},
		{name: "go.mod without a module line", files: map[string]string{"odd/go.mod": "go 1.21\n"}, dirs: []string{"odd"}, assert: refusesNaming("odd")},
		{name: "directory that is a file", files: map[string]string{"file.txt": "x"}, dirs: []string{"file.txt"}, assert: refusesNaming("file.txt")},
		{name: "directory outside the source tree", files: good, dirs: []string{"../escape"}, assert: refusesNaming("../escape")},
		{name: "no module directories", files: good, dirs: nil, assert: refusesNaming("module")},
		{
			name: "two directories with one module path", files: map[string]string{"go.mod": rootMod, "copy/go.mod": rootMod},
			dirs: []string{".", "copy"}, assert: refusesNaming("example.com/m", "copy"),
		},
		{
			name: "output directory that is not empty", files: good, dirs: []string{"."},
			prepOut: func(t *testing.T, out string) { writeTree(t, out, map[string]string{"keep.txt": "x"}) },
			assert:  refusesNaming("proxy", "exists"),
		},
		{
			name: "output directory that exists and is empty", files: good, dirs: []string{"."},
			prepOut: func(t *testing.T, out string) {
				if err := os.Mkdir(out, 0o750); err != nil {
					t.Fatal(err)
				}
			},
			assert: refusesNaming("proxy", "exists"),
		},
		{
			name: "output that is a regular file", files: good, dirs: []string{"."},
			prepOut: func(t *testing.T, out string) {
				if err := os.WriteFile(out, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			assert: refusesNaming("proxy"),
		},
		{name: "failing zip leaves a missing output missing", files: badName, dirs: []string{".", "bad"}, assert: refusesNaming("example.com/bad")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := t.TempDir()
			writeTree(t, src, tc.files)
			out := filepath.Join(t.TempDir(), "proxy")
			if tc.noOut {
				out = ""
			}
			if tc.prepOut != nil {
				tc.prepOut(t, out)
			}
			before := snapshot(t, out)
			ver := tc.version
			if ver == "" {
				ver = version
			}

			err := writeProxy(src, ver, tc.dirs, out)

			tc.assert(t, err)
			if after := snapshot(t, out); !slices.Equal(before, after) {
				t.Errorf("output changed from %v to %v, want it untouched", before, after)
			}
		})
	}
}

// goEnv returns an environment that cannot reach the developer's module cache,
// settings or the network: every directory is temporary and the only proxy is
// the file tree under test. The module cache is read-only after use, so a
// cleanup empties it with `go clean -modcache`, which Go supports for exactly
// that, before t.TempDir removes the directory.
func goEnv(t *testing.T, proxy string) []string {
	t.Helper()
	modcache, gocache, gopath, home := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GOENV=off",
		"GOWORK=off",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"GOMODCACHE=" + modcache,
		"GOCACHE=" + gocache,
		"GOPATH=" + gopath,
		"GOPROXY=file://" + filepath.ToSlash(proxy),
		"GONOSUMDB=example.com/m",
	}
	t.Cleanup(func() {
		cmd := exec.CommandContext(context.WithoutCancel(t.Context()), "go", "clean", "-modcache")
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("go clean -modcache: %v\n%s", err, out)
		}
	})
	return env
}

func runGo(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", args...) //nolint:gosec // G204: the go tool with arguments written in this file
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// One case: its setup (a fixture, a consumer, the go tool) shares nothing with the table tests.
func TestWriteProxy_GoGetResolves(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"go.mod": rootMod,
		"m.go":   "package m\n\n// Hello returns a greeting.\nfunc Hello() string { return \"hello\" }\n",
	})
	out := filepath.Join(t.TempDir(), "proxy")
	if err := writeProxy(src, version, []string{"."}, out); err != nil {
		t.Fatal(err)
	}

	consumer := t.TempDir()
	writeTree(t, consumer, map[string]string{
		"go.mod":      "module example.com/consumer\n\ngo 1.21\n",
		"consumer.go": "package consumer\n\nimport \"example.com/m\"\n\nvar _ = m.Hello\n",
	})
	env := goEnv(t, out)

	runGo(t, consumer, env, "get", "example.com/m@"+version)
	runGo(t, consumer, env, "build", "./...")

	mod, err := os.ReadFile(filepath.Join(consumer, "go.mod")) //nolint:gosec // G304: a path under this test's temporary directories
	if err != nil || !strings.Contains(string(mod), "example.com/m "+version) {
		t.Errorf("consumer go.mod = %q (%v), want a requirement on example.com/m %s", mod, err, version)
	}
}

// refuses asserts a refusal whose message names every one of inputs.
func refuses(inputs ...string) func(t *testing.T, base, out string, err error) {
	return func(t *testing.T, _, _ string, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("got nil error, want a refusal")
		}
		for _, in := range inputs {
			if !strings.Contains(err.Error(), in) {
				t.Errorf("error %q does not name %q", err, in)
			}
		}
	}
}

func symlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

// TestWriteProxy_TouchesOnlyWhatItOwns pins that a refused or failed run
// leaves everything around the source tree and the output exactly as it was:
// each case lays out a whole base directory, and the whole of it must be
// unchanged afterwards, symlinks included.
func TestWriteProxy_TouchesOnlyWhatItOwns(t *testing.T) {
	t.Parallel()

	good := map[string]string{"go.mod": rootMod, "m.go": "package m\n"}
	// deepBad's second module zip fails after its deep @v directory is written.
	deepBad := map[string]string{
		"go.mod": rootMod, "m.go": "package m\n",
		"bad/go.mod": "module example.com/x/y/z/bad\n\ngo 1.21\n", "bad/bad:name.go": "package bad\n",
	}

	tests := []struct {
		name  string
		files map[string]string
		dirs  []string
		// setup lays out base and returns the -out argument; src is base/src.
		setup  func(t *testing.T, base, src string) string
		assert func(t *testing.T, base, out string, err error)
	}{
		{
			name:  "dangling symlink as output is refused and kept",
			files: good, dirs: []string{"."},
			setup: func(t *testing.T, base, _ string) string {
				out := filepath.Join(base, "out1")
				symlink(t, filepath.Join(base, "nonexistent", "zzz"), out)
				return out
			},
			assert: func(t *testing.T, base, out string, err error) {
				t.Helper()
				refuses("out1")(t, base, out, err)
				if info, lerr := os.Lstat(out); lerr != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Errorf("output symlink after the run: %v, %v; want it still a symlink", info, lerr)
				}
			},
		},
		{
			name:  "symlink to an empty directory as output is refused",
			files: good, dirs: []string{"."},
			setup: func(t *testing.T, base, _ string) string {
				mkdir(t, filepath.Join(base, "target"))
				out := filepath.Join(base, "out1")
				symlink(t, filepath.Join(base, "target"), out)
				return out
			},
			assert: refuses("out1"),
		},
		{
			name:  "output through a symlink and .. never removes an unrelated directory",
			files: deepBad, dirs: []string{".", "bad"},
			setup: func(t *testing.T, base, _ string) string {
				mkdir(t, filepath.Join(base, "other", "deep"))
				symlink(t, filepath.Join(base, "other", "deep"), filepath.Join(base, "link"))
				writeTree(t, base, map[string]string{"new/keep": "x"})
				// Concatenated, not joined: filepath.Join would clean the ".." away.
				return base + string(filepath.Separator) + "link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "new"
			},
			// The path is cleaned once, to base/new, which exists.
			assert: func(t *testing.T, base, out string, err error) {
				t.Helper()
				refuses("new", "exists")(t, base, out, err)
				if _, lerr := os.Lstat(filepath.Join(base, "new", "keep")); lerr != nil {
					t.Errorf("new/keep after the run: %v; want it kept", lerr)
				}
			},
		},
		{
			name:  "output directly inside the source tree is refused",
			files: good, dirs: []string{"."},
			setup:  func(_ *testing.T, _, src string) string { return filepath.Join(src, "proxy") },
			assert: refuses("proxy", "source"),
		},
		{
			name:  "output deeper inside the source tree is refused",
			files: map[string]string{"go.mod": rootMod, "m.go": "package m\n", "a/b/keep.txt": "x"}, dirs: []string{"."},
			setup:  func(_ *testing.T, _, src string) string { return filepath.Join(src, "a", "b", "proxy") },
			assert: refuses("proxy", "source"),
		},
		{
			name:  "output inside the source tree through a symlink is refused",
			files: good, dirs: []string{"."},
			setup: func(t *testing.T, base, src string) string {
				symlink(t, src, filepath.Join(base, "srclink"))
				return filepath.Join(base, "srclink", "proxy")
			},
			assert: refuses("proxy", "source"),
		},
		{
			// On a case-insensitive file system SRC is src; on a case-sensitive
			// one the parent is missing. Either way the output is refused.
			name:  "output inside the source tree by a different letter case is refused",
			files: good, dirs: []string{"."},
			setup:  func(_ *testing.T, base, _ string) string { return filepath.Join(base, "SRC", "proxy") },
			assert: refuses("proxy"),
		},
		{
			name:  "output whose parent is missing is refused",
			files: good, dirs: []string{"."},
			setup:  func(_ *testing.T, base, _ string) string { return filepath.Join(base, "missing", "proxy") },
			assert: refuses("missing"),
		},
		{
			name:  "module directory that is a symlink out of the source tree is refused",
			files: good, dirs: []string{"ext"},
			setup: func(t *testing.T, base, src string) string {
				writeTree(t, base, map[string]string{"outside/go.mod": "module example.com/outside\n\ngo 1.21\n"})
				symlink(t, filepath.Join(base, "outside"), filepath.Join(src, "ext"))
				return filepath.Join(base, "proxy")
			},
			assert: refuses("ext"),
		},
		{
			name:  "failure after a deep tree leaves a missing output missing",
			files: deepBad, dirs: []string{".", "bad"},
			setup:  func(_ *testing.T, base, _ string) string { return filepath.Join(base, "proxy") },
			assert: refuses("example.com/x/y/z/bad"),
		},
		{
			name:  "existing empty output is refused before a module that would fail is written",
			files: deepBad, dirs: []string{".", "bad"},
			setup: func(t *testing.T, base, _ string) string {
				out := filepath.Join(base, "proxy")
				mkdir(t, out)
				return out
			},
			assert: refuses("proxy", "exists"),
		},
		{
			name:  "output that cannot be created removes nothing",
			files: good, dirs: []string{"."},
			setup: func(t *testing.T, base, _ string) string {
				if os.Geteuid() == 0 {
					t.Skip("root ignores directory permissions, so the parent cannot be made read-only")
				}
				ro := filepath.Join(base, "ro")
				writeTree(t, ro, map[string]string{"keep": "x"})
				if err := os.Chmod(ro, 0o500); err != nil { //nolint:gosec // G302: read-only on purpose, so creating the output inside it fails
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(ro, 0o700); err != nil { //nolint:gosec // G302: restores a test directory so t.TempDir can remove it
						t.Error(err)
					}
				})
				return filepath.Join(ro, "proxy")
			},
			assert: refuses("proxy"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			src := filepath.Join(base, "src")
			writeTree(t, src, tc.files)
			out := tc.setup(t, base, src)
			before := snapshot(t, base)

			err := writeProxy(src, version, tc.dirs, out)

			tc.assert(t, base, out, err)
			if after := snapshot(t, base); !slices.Equal(before, after) {
				t.Errorf("base changed from %v to %v, want it untouched", before, after)
			}
		})
	}
}

// TestWriteProxy_ExistingOutputWithConcurrentWriter pins that an output
// directory which already exists is refused before anything is written, even
// while another process writes into it: what that process wrote is kept, and
// the run adds nothing beside it. The writer races the run on purpose; every
// interleaving must end the same way.
func TestWriteProxy_ExistingOutputWithConcurrentWriter(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	src := filepath.Join(base, "src")
	writeTree(t, src, map[string]string{
		"go.mod": rootMod, "m.go": "package m\n",
		"bad/go.mod": "module example.com/bad\n\ngo 1.21\n", "bad/bad:name.go": "package bad\n",
	})
	out := filepath.Join(base, "proxy")
	mkdir(t, out)
	foreign := filepath.Join(out, "example.com", "foreign", "keep")

	wrote := make(chan error, 1)
	go func() {
		if err := os.MkdirAll(filepath.Dir(foreign), 0o750); err != nil {
			wrote <- err
			return
		}
		wrote <- os.WriteFile(foreign, []byte("other process"), 0o600)
	}()
	err := writeProxy(src, version, []string{".", "bad"}, out)
	if werr := <-wrote; werr != nil {
		t.Fatal(werr)
	}

	refuses("proxy", "exists")(t, base, out, err)
	if got, want := snapshot(t, out), []string{".", "example.com", "example.com/foreign", "example.com/foreign/keep"}; !slices.Equal(got, want) {
		t.Errorf("output holds %v, want only the other process's %v", got, want)
	}
}

// TestWriteProxy_OutputCreatedByAnotherProcessAfterTheCheck pins the race
// between the check that out is absent and its creation: when another process
// creates out in that gap, the run is refused naming out, and what the other
// process wrote is kept. The gap is opened deterministically by the hook.
func TestWriteProxy_OutputCreatedByAnotherProcessAfterTheCheck(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeTree(t, src, map[string]string{"go.mod": rootMod, "m.go": "package m\n"})
	out := filepath.Join(t.TempDir(), "proxy")
	other := func(path string) { writeTree(t, path, map[string]string{"example.com/foreign/keep": "other process"}) }

	err := writeProxyWith(src, version, []string{"."}, out, other)

	refuses("proxy")(t, "", out, err)
	if got, want := snapshot(t, out), []string{".", "example.com", "example.com/foreign", "example.com/foreign/keep"}; !slices.Equal(got, want) {
		t.Errorf("output holds %v, want only the other process's %v", got, want)
	}
}
