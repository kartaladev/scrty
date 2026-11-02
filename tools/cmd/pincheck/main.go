// Command pincheck fails when a GitHub Actions workflow or action references
// an action or reusable workflow by anything other than a full commit SHA.
//
// The rule, applied to every `uses:` value in every .yml and .yaml file under
// the directories given as arguments (default .github):
//
//   - a local reference (starting with "./") is exempt;
//   - a container action (docker://) must be pinned by an @sha256: digest;
//   - any other reference must end in @ followed by a full 40-character
//     lowercase hexadecimal commit SHA;
//   - a pinned reference must carry a trailing "# <tag>" comment naming the
//     release the pin corresponds to.
//
// Usage: pincheck [dir...]
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Finding is one reference that breaks the rule.
type Finding struct {
	File string
	Line int
	Uses string
	Why  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Uses, f.Why)
}

var (
	fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Check scans dir recursively for .yml and .yaml files and reports every
// unpinned reference. It returns an error when dir cannot be read.
func Check(dir string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		found, err := checkFile(path)
		findings = append(findings, found...)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", dir, err)
	}
	return findings, nil
}

func isYAML(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yml" || ext == ".yaml"
}

func checkFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	dec := yaml.NewDecoder(f)
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return findings, nil
			}
			return findings, fmt.Errorf("parse %s: %w", path, err)
		}
		walk(&doc, func(v *yaml.Node) {
			ref := strings.TrimSpace(v.Value)
			comment := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v.LineComment), "#"))
			if why := violation(ref, comment); why != "" {
				findings = append(findings, Finding{File: path, Line: v.Line, Uses: ref, Why: why})
			}
		})
	}
}

// walk calls fn with the value node of every scalar "uses" key found in any
// mapping, block or flow, at any depth.
func walk(n *yaml.Node, fn func(value *yaml.Node)) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "uses" && v.Kind == yaml.ScalarNode {
				fn(v)
			}
		}
	}
	for _, c := range n.Content {
		walk(c, fn)
	}
}

func violation(ref, comment string) string {
	switch {
	case ref == "", strings.HasPrefix(ref, "./"):
		return ""
	case strings.HasPrefix(ref, "docker://"):
		_, d, ok := strings.Cut(ref, "@sha256:")
		if !ok || !digest.MatchString(d) {
			return "container action is not pinned by an @sha256: digest"
		}
	default:
		_, sha, ok := strings.Cut(ref, "@")
		if !ok || !fullSHA.MatchString(sha) {
			return "not pinned to a full 40-character commit SHA"
		}
	}
	if comment == "" {
		return "pin has no trailing # tag comment"
	}
	return ""
}

func main() {
	dirs := os.Args[1:]
	if len(dirs) == 0 {
		dirs = []string{".github"}
	}
	failed := false
	for _, dir := range dirs {
		findings, err := Check(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pincheck:", err)
			os.Exit(2)
		}
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, f)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
