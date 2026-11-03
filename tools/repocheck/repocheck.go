// Package repocheck enforces two repository rules of the supply chain.
//
// Every module is kept current: each module in go.work, and the tools module,
// has a gomod entry in .github/dependabot.yml with a daily or weekly schedule,
// and GitHub Actions has an entry too. Dependabot only updates a directory it
// has an entry for and does not descend into sub-directories, so a module
// without an entry silently falls behind on security fixes.
//
// No workflow approves or merges a pull request. Dependabot only proposes
// updates; a maintainer reviews and merges each one by hand, so that no
// dependency change reaches the main branch without a human reading it.
package repocheck

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const actionsEcosystem = "github-actions"

type dependabotConfig struct {
	Updates []struct {
		Ecosystem string `yaml:"package-ecosystem"`
		Directory string `yaml:"directory"`
		Schedule  struct {
			Interval string `yaml:"interval"`
		} `yaml:"schedule"`
	} `yaml:"updates"`
}

// MissingUpdateEntries returns each directory in modules that has no gomod
// entry in the Dependabot configuration with a daily or weekly schedule, in
// the order given, followed by "github-actions" when that ecosystem has no such
// entry. Directories are compared cleaned and without a leading "./" or "/",
// so go.work's "./store/pgxstore" matches Dependabot's "/store/pgxstore", and
// "." matches "/". It returns an error when dependabot is not valid YAML.
func MissingUpdateEntries(dependabot []byte, modules []string) ([]string, error) {
	var cfg dependabotConfig
	if err := yaml.Unmarshal(dependabot, &cfg); err != nil {
		return nil, fmt.Errorf("repocheck: parse dependabot configuration: %w", err)
	}
	covered := map[string]bool{}
	for _, u := range cfg.Updates {
		if u.Schedule.Interval != "daily" && u.Schedule.Interval != "weekly" {
			continue
		}
		covered[u.Ecosystem+" "+normalize(u.Directory)] = true
	}
	var missing []string
	for _, m := range modules {
		if !covered["gomod "+normalize(m)] {
			missing = append(missing, normalize(m))
		}
	}
	if !covered[actionsEcosystem+" "+normalize("/")] {
		missing = append(missing, actionsEcosystem)
	}
	return missing, nil
}

func normalize(dir string) string {
	dir = path.Clean(strings.TrimSpace(dir))
	dir = strings.TrimPrefix(dir, "./")
	dir = strings.TrimLeft(dir, "/")
	if dir == "." {
		return ""
	}
	return dir
}

var (
	ghPRMerge  = regexp.MustCompile(`\bgh\s+pr\s+merge\b`)
	ghPRReview = regexp.MustCompile(`\bgh\s+pr\s+review\b[^\n]*--approve\b`)

	mergeActions = []string{
		"peter-evans/enable-pull-request-automerge",
		"pascalgn/automerge-action",
		"hmarr/auto-approve-action",
		"ahmadnassri/action-dependabot-auto-merge",
	}
	mergeMutations = []string{"enablePullRequestAutoMerge", "mergePullRequest", "addPullRequestReview"}
)

// AutoMergeSteps returns one "file: reason" entry, in file-name order, for each
// workflow that approves or merges a pull request: a run step with "gh pr
// merge" or "gh pr review --approve", a use of one of the known auto-merge or
// auto-approve actions at any ref, or text naming the GraphQL mutations
// enablePullRequestAutoMerge, mergePullRequest or addPullRequestReview. A
// workflow that is not valid YAML is reported too, since it cannot be shown
// clean.
func AutoMergeSteps(workflows map[string][]byte) []string {
	names := make([]string, 0, len(workflows))
	for n := range workflows {
		names = append(names, n)
	}
	slices.Sort(names)

	var out []string
	for _, name := range names {
		src := workflows[name]
		var reasons []string
		var doc yaml.Node
		if err := yaml.Unmarshal(src, &doc); err != nil {
			reasons = append(reasons, "workflow is not valid YAML, so it cannot be shown free of auto-merge")
		} else {
			reasons = append(reasons, scan(&doc)...)
		}
		for _, m := range mergeMutations {
			if strings.Contains(string(src), m) {
				reasons = append(reasons, "mentions "+m)
			}
		}
		if len(reasons) > 0 {
			out = append(out, name+": "+strings.Join(reasons, "; "))
		}
	}
	return out
}

// scan walks every mapping in the document, so a step is found wherever it
// sits in the workflow, including in composite or reusable structures.
func scan(n *yaml.Node) []string {
	var reasons []string
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, n.Content[i+1]
			if val.Kind != yaml.ScalarNode {
				continue
			}
			switch key {
			case "run":
				if ghPRMerge.MatchString(val.Value) {
					reasons = append(reasons, "runs gh pr merge")
				}
				if ghPRReview.MatchString(val.Value) {
					reasons = append(reasons, "runs gh pr review --approve")
				}
			case "uses":
				for _, a := range mergeActions {
					if strings.HasPrefix(val.Value, a) {
						reasons = append(reasons, "uses "+a)
					}
				}
			}
		}
	}
	for _, c := range n.Content {
		reasons = append(reasons, scan(c)...)
	}
	return reasons
}
