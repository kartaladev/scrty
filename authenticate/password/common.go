package password

import (
	_ "embed"
	"strings"
	"sync"
)

// commonList is the bundled list of common passwords, one per line, most
// common first. It is the "xato-net-10-million-passwords-10000" list from the
// SecLists project, distributed under the MIT licence; the notice is in
// common_LICENSE.txt beside it.
//
//go:embed common.txt
var commonList string

// bundledCommonPasswords returns the bundled list as a set of lower-cased
// entries, parsed once. Callers must not modify it.
var bundledCommonPasswords = sync.OnceValue(func() map[string]struct{} {
	return commonSet(strings.Split(commonList, "\n"))
})

// commonSet lower-cases list into a set, leaving out blank entries and the
// carriage return of a CRLF line.
func commonSet(list []string) map[string]struct{} {
	set := make(map[string]struct{}, len(list))

	for _, entry := range list {
		entry = strings.TrimSuffix(entry, "\r")
		if entry == "" {
			continue
		}

		set[strings.ToLower(entry)] = struct{}{}
	}

	return set
}
