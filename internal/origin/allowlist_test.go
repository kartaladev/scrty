// The allowlist tests are in the package rather than beside it, because
// Resolve re-checks the entry it matched and no caller of the exported API can
// produce an entry that fails that re-check. Building the value directly is
// the only way to watch the re-check refuse something.
package origin

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The option names a caller would pass. They appear in every refusal, because
// the consumer has to be told which of the values they configured is at fault.
const (
	optEntries = "WithRedirectAllowlist"
	optOrigins = "WithAllowedRedirectOrigins"
)

func TestAllowlistConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		entries  []string
		declared []string
		assert   func(t *testing.T, list *Allowlist, err error)
	}

	accepted := func(t *testing.T, list *Allowlist, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, list)
	}
	// refused asserts the configuration error names every value the consumer
	// has to go and change.
	refused := func(names ...string) func(t *testing.T, list *Allowlist, err error) {
		return func(t *testing.T, list *Allowlist, err error) {
			t.Helper()
			require.ErrorIs(t, err, ErrConfig)
			assert.Nil(t, list, "a refused configuration must not yield a usable allowlist")
			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	cases := []testCase{
		{
			name:    "a protocol-relative entry is refused",
			entries: []string{"//partner.example.com/landing"},
			assert:  refused("//partner.example.com/landing", optEntries),
		},
		{
			name:    "a backslash after the leading slash is refused",
			entries: []string{`/\evil.example.net`},
			// The message quotes the entry, so a backslash reaches the reader
			// escaped. strconv.Quote spells the same rendering here.
			assert: refused(strconv.Quote(`/\evil.example.net`), optEntries),
		},
		{
			name:    "whitespace in an entry is refused",
			entries: []string{"/ /x"},
			assert:  refused("/ /x", optEntries),
		},
		{
			name:    "a control character in an entry is refused",
			entries: []string{"/a\tb"},
			assert:  refused(strconv.Quote("/a\tb"), optEntries),
		},
		{
			name:    "an empty entry is refused",
			entries: []string{""},
			assert:  refused(optEntries),
		},
		{
			name:    "an absolute entry with no declared origin names the declaration it needs",
			entries: []string{"https://partner.example.com/landing"},
			assert:  refused("https://partner.example.com/landing", optEntries, optOrigins),
		},
		{
			name:     "an absolute entry carrying userinfo is refused",
			entries:  []string{"https://user:pw@partner.example.com/x"},
			declared: []string{"https://partner.example.com"},
			assert:   refused("https://user:pw@partner.example.com/x", optEntries),
		},
		{
			name:    "an entry that is neither host-relative nor absolute is refused",
			entries: []string{"landing"},
			assert:  refused("landing", optEntries),
		},

		{
			name:     "a cleartext declared origin off loopback is refused",
			declared: []string{"http://partner.example.com"},
			assert:   refused("http://partner.example.com", optOrigins),
		},
		{
			name:     "a declared origin carrying a path is refused",
			declared: []string{"https://partner.example.com/path"},
			assert:   refused("https://partner.example.com/path", optOrigins),
		},
		{
			name:     "a declared origin carrying a query is refused",
			declared: []string{"https://partner.example.com?q=1"},
			assert:   refused("https://partner.example.com?q=1", optOrigins),
		},
		{
			name:     "a declared origin carrying a fragment is refused",
			declared: []string{"https://partner.example.com#f"},
			assert:   refused("https://partner.example.com#f", optOrigins),
		},
		{
			name:     "a declared origin carrying userinfo is refused",
			declared: []string{"https://user:pw@partner.example.com"},
			assert:   refused("https://user:pw@partner.example.com", optOrigins),
		},
		{
			name:     "a declared origin with no host is refused",
			declared: []string{"partner.example.com"},
			assert:   refused("partner.example.com", optOrigins),
		},
		{
			name:     "a declared origin on another scheme is refused",
			declared: []string{"ftp://partner.example.com"},
			assert:   refused("ftp://partner.example.com", optOrigins),
		},

		{
			name:    "host-relative entries are accepted",
			entries: []string{"/landing", "/a/b?c=d", "/"},
			assert:  accepted,
		},
		{
			name:     "an absolute entry on a declared origin is accepted",
			entries:  []string{"https://partner.example.com/landing"},
			declared: []string{"https://partner.example.com"},
			assert:   accepted,
		},
		{
			name:     "cleartext is accepted on a loopback name",
			declared: []string{"http://localhost:3000"},
			assert:   accepted,
		},
		{
			name:     "cleartext is accepted on a loopback address",
			declared: []string{"http://127.0.0.1:8080", "http://[::1]:8080"},
			assert:   accepted,
		},
		{
			name:     "a declared origin may carry a lone trailing slash",
			entries:  []string{"https://partner.example.com/landing"},
			declared: []string{"https://partner.example.com/"},
			assert:   accepted,
		},
		{
			// The default: a consumer who declares nothing still gets a working
			// allowlist, and only host-relative targets can ever be accepted.
			name:   "no entries and no declared origins is the default",
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			list, err := NewAllowlist(tc.entries, tc.declared, optEntries, optOrigins)
			tc.assert(t, list, err)
		})
	}
}

func TestAllowlistConstructionCopiesItsInput(t *testing.T) {
	t.Parallel()

	entries := []string{"/landing", "https://partner.example.com/x"}
	declared := []string{"https://partner.example.com"}

	list, err := NewAllowlist(entries, declared, optEntries, optOrigins)
	require.NoError(t, err)

	// A caller that keeps its slices must not be able to change the allowlist
	// after it has been checked. Both replacements would pass the checks on
	// their own, so only a copy tells them apart.
	entries[0] = "/evil"
	declared[0] = "https://evil.example.net"

	assert.Equal(t, "/landing", list.Resolve("/landing"), "a configured entry was swapped out")
	assert.Equal(t, "/", list.Resolve("/evil"), "an entry was added after construction")
	assert.Equal(t, "https://partner.example.com/x", list.Resolve("https://partner.example.com/x"),
		"the declared origin the entry rests on was swapped out")
}

func TestAllowlistResolve(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		entries   []string
		declared  []string
		list      func(t *testing.T) *Allowlist // nil builds from entries and declared
		requested string
		assert    func(t *testing.T, got string)
	}

	resolvesTo := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}
	fallsBack := resolvesTo("/")

	cases := []testCase{
		{
			name:      "a declared partner URL resolves to itself",
			entries:   []string{"https://partner.example.com/landing"},
			declared:  []string{"https://partner.example.com"},
			requested: "https://partner.example.com/landing",
			assert:    resolvesTo("https://partner.example.com/landing"),
		},
		{
			name:      "a host-relative entry resolves to itself",
			entries:   []string{"/landing"},
			requested: "/landing",
			assert:    resolvesTo("/landing"),
		},
		{
			name:      "an unlisted target falls back",
			entries:   []string{"/landing"},
			requested: `/\evil.example.net`,
			assert:    fallsBack,
		},
		{
			name:      "a prefix of an entry is not a match",
			entries:   []string{"/landing"},
			requested: "/land",
			assert:    fallsBack,
		},
		{
			name:      "an entry is not a prefix of the request either",
			entries:   []string{"/land"},
			requested: "/landing",
			assert:    fallsBack,
		},
		{
			name:      "matching is case-sensitive",
			entries:   []string{"/Landing"},
			requested: "/landing",
			assert:    fallsBack,
		},
		{
			name:      "an empty request falls back",
			entries:   []string{"/landing"},
			requested: "",
			assert:    fallsBack,
		},
		{
			name:      "an allowlist with no entries falls back",
			requested: "/landing",
			assert:    fallsBack,
		},
		{
			// The re-check. No caller of NewAllowlist can reach this, which is
			// why the value is built directly: Resolve must not hand back an
			// entry that would be refused if it were configured today.
			name: "an entry that no longer passes the construction rules is not used",
			list: func(*testing.T) *Allowlist {
				return &Allowlist{
					entries:      []string{"//evil.example.net"},
					entryOption:  optEntries,
					originOption: optOrigins,
				}
			},
			requested: "//evil.example.net",
			assert:    fallsBack,
		},
		{
			name: "an absolute entry whose origin is no longer declared is not used",
			list: func(*testing.T) *Allowlist {
				return &Allowlist{
					entries:      []string{"https://partner.example.com/landing"},
					entryOption:  optEntries,
					originOption: optOrigins,
				}
			},
			requested: "https://partner.example.com/landing",
			assert:    fallsBack,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			build := tc.list
			if build == nil {
				build = func(t *testing.T) *Allowlist {
					t.Helper()
					list, err := NewAllowlist(tc.entries, tc.declared, optEntries, optOrigins)
					require.NoError(t, err)

					return list
				}
			}

			tc.assert(t, build(t).Resolve(tc.requested))
		})
	}
}
