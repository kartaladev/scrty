// Command releaseproxy lays modules out as a GOPROXY file tree, so the API
// report can resolve a release that has no tag yet.
//
// Every module directory is published at one version: its zip is built by
// golang.org/x/mod/zip, which leaves out nested modules and files outside the
// module directory. A nested module's zip therefore lacks the repository-root
// LICENSE that cmd/go adds when it builds a subdirectory module from a tagged
// repository; the API report does not read that file.
//
// Usage: releaseproxy -src <dir> -version <vX.Y.Z> -out <dir> <module-dir>...
//
// Module directories are relative to -src, and "." is the root; a directory
// that resolves outside -src, through a symlink or otherwise, is refused. -out
// must not lie inside -src, its parent directory must already exist, and -out
// itself must not exist: any existing path there, even an empty directory or a
// symlink, is refused. The run creates -out with mode 0700 and owns it alone.
// Nothing is written unless every input is valid, and a failure while writing
// removes -out and nothing else.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/zip"
)

const (
	outMode  = 0o700
	dirMode  = 0o750
	fileMode = 0o600
)

// source is one validated module directory.
type source struct {
	dir   string // as the caller wrote it, for messages
	path  string // directory on disk
	mod   module.Version
	gomod []byte
}

// writeProxy writes each directory in moduleDirs, taken relative to srcRoot,
// as a module at version under out, laid out as the GOPROXY protocol serves
// it. It refuses, writing nothing, when version is not canonical semantic
// versioning with a "v" prefix, when no directory is given, when a directory
// is missing, holds no go.mod, leaves srcRoot (by its name or through a
// symlink), or names the same module as another, or when out is unusable.
// out is usable when its parent directory exists, it does not lie in srcRoot,
// and nothing exists at it, as os.Lstat sees it.
//
// out is created with os.Mkdir, so this call owns it alone; when creation
// fails, including because another process created it first, nothing is
// removed. A failure while writing removes out, and nothing outside it.
func writeProxy(srcRoot, version string, moduleDirs []string, out string) error {
	return writeProxyWith(srcRoot, version, moduleDirs, out, nil)
}

// writeProxyWith is writeProxy with a hook that, when not nil, runs with the
// canonical output path after every check and before out is created. Tests
// use it to create out from "another process" in that gap.
func writeProxyWith(srcRoot, version string, moduleDirs []string, out string, beforeCreate func(path string)) (err error) {
	if !semver.IsValid(version) || semver.Canonical(version) != version {
		return fmt.Errorf("version %q is not canonical semantic versioning with a v prefix", version)
	}
	if len(moduleDirs) == 0 {
		return errors.New("no module directories given")
	}
	src, err := canonicalSrc(srcRoot)
	if err != nil {
		return err
	}
	srcs, err := load(src, version, moduleDirs)
	if err != nil {
		return err
	}
	dst, err := resolveOut(out, src)
	if err != nil {
		return err
	}
	if beforeCreate != nil {
		beforeCreate(dst)
	}
	// Mkdir, not MkdirAll: a directory that appeared since resolveOut, by a
	// race or otherwise, is not ours, so it is an error and is left alone.
	if err := os.Mkdir(dst, outMode); err != nil {
		return fmt.Errorf("create output %q: %w", out, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(dst))
		}
	}()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, s := range srcs {
		if err := writeModule(dst, s, version, now); err != nil {
			return fmt.Errorf("write module %s (%s): %w", s.mod.Path, s.dir, err)
		}
	}
	return nil
}

// canonicalSrc returns srcRoot as an absolute path with every symlink resolved.
func canonicalSrc(srcRoot string) (string, error) {
	abs, err := filepath.Abs(srcRoot)
	if err != nil {
		return "", fmt.Errorf("source tree %q: %w", srcRoot, err)
	}
	src, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("source tree %q: %w", srcRoot, err)
	}
	return src, nil
}

// within reports whether path is root or lies under it. Both are canonical.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && filepath.IsLocal(rel)
}

// load validates every directory, taken relative to the canonical src, before
// anything is written.
func load(src, version string, dirs []string) ([]source, error) {
	srcs := make([]source, 0, len(dirs))
	seen := make(map[string]string, len(dirs))
	for _, d := range dirs {
		if !filepath.IsLocal(d) {
			return nil, fmt.Errorf("module directory %q is not inside the source tree", d)
		}
		path, err := filepath.EvalSymlinks(filepath.Join(src, d))
		if err != nil {
			return nil, fmt.Errorf("module directory %q: %w", d, err)
		}
		if !within(src, path) {
			return nil, fmt.Errorf("module directory %q resolves to %q, outside the source tree", d, path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("module directory %q: %w", d, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("module directory %q is not a directory", d)
		}
		data, err := os.ReadFile(filepath.Join(path, "go.mod")) //nolint:gosec // G304: the directory is a command-line argument, checked to lie in the source tree; reading its go.mod is the tool's job
		if err != nil {
			return nil, fmt.Errorf("module directory %q has no readable go.mod: %w", d, err)
		}
		modPath := modfile.ModulePath(data)
		if modPath == "" {
			return nil, fmt.Errorf("module directory %q: go.mod has no module line", d)
		}
		if _, err := module.EscapePath(modPath); err != nil {
			return nil, fmt.Errorf("module directory %q: %w", d, err)
		}
		if first, dup := seen[modPath]; dup {
			return nil, fmt.Errorf("module %s is named by both %q and %q", modPath, first, d)
		}
		seen[modPath] = d
		srcs = append(srcs, source{dir: d, path: path, mod: module.Version{Path: modPath, Version: version}, gomod: data})
	}
	return srcs, nil
}

// resolveOut validates out against the canonical src without writing
// anything, and returns the canonical path to create. The path is cleaned and
// made absolute once, its parent must exist and is resolved through symlinks,
// and every later operation uses only the result, so the path checked is the
// path created and the path removed. Nothing may exist at that path.
func resolveOut(out, src string) (string, error) {
	if out == "" {
		return "", errors.New("output directory is not given")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("output %q: %w", out, err)
	}
	base := filepath.Base(abs)
	if base == "." || base == ".." || base == "" || filepath.Dir(abs) == abs {
		return "", fmt.Errorf("output %q does not name a directory that can be created", out)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("output %q: its parent directory must exist: %w", out, err)
	}
	path := filepath.Join(parent, base)
	if within(src, path) || sameFileAncestor(src, path) {
		return "", fmt.Errorf("output %q lies inside the source tree %q", out, src)
	}
	switch _, err := os.Lstat(path); {
	case err == nil:
		return "", fmt.Errorf("output %q already exists; it must be absent", out)
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("output %q: %w", out, err)
	}
	return path, nil
}

// sameFileAncestor reports whether src is path or one of path's existing
// ancestors, compared by file identity. It catches what a comparison of names
// cannot, such as a different letter case on a case-insensitive file system.
func sameFileAncestor(src, path string) bool {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		if info, err := os.Stat(p); err == nil && os.SameFile(srcInfo, info) {
			return true
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}

func writeModule(out string, s source, version, now string) (err error) {
	esc, err := module.EscapePath(s.mod.Path)
	if err != nil {
		return err
	}
	dir := filepath.Join(out, filepath.FromSlash(esc), "@v")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, version+".mod"), s.gomod, fileMode); err != nil {
		return err
	}
	info := fmt.Sprintf(`{"Version":%q,"Time":%q}`, version, now)
	if err := os.WriteFile(filepath.Join(dir, version+".info"), []byte(info), fileMode); err != nil {
		return err
	}
	if err := writeZip(filepath.Join(dir, version+".zip"), s); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "list"), []byte(version+"\n"), fileMode)
}

func writeZip(name string, s source) (err error) {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // G304: a path under the output directory this run created
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return zip.CreateFromDir(f, s.mod, s.path)
}

func main() {
	fs := flag.NewFlagSet("releaseproxy", flag.ExitOnError)
	src := fs.String("src", ".", "root of the source tree the module directories are relative to")
	version := fs.String("version", "", "version to publish every module at, such as v0.1.0")
	out := fs.String("out", "", "directory to write the proxy tree to, outside -src; it must not exist (its parent must), and is created with mode 0700")
	_ = fs.Parse(os.Args[1:]) // ExitOnError: a bad flag exits with status 2 itself
	if err := writeProxy(*src, *version, fs.Args(), *out); err != nil {
		fmt.Fprintln(os.Stderr, "releaseproxy:", err)
		os.Exit(2)
	}
}
