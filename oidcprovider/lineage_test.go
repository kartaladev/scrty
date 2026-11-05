package oidcprovider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// lineageIdentifier names a lineage record. The tests need only one the two stores
// could confuse if they were one.
const lineageIdentifier = "lineage-record-1"

// lineageRecord is a record that lives from start for an hour.
func lineageRecord(ident string, start time.Time) *session.Session {
	return &session.Session{
		ID:                ident,
		UserID:            "u-1",
		FamilyID:          id.MustParse("01926a4e-0000-7000-8000-000000000001"),
		FamilyCreatedAt:   start,
		CreatedAt:         start,
		LastAccessedAt:    start,
		IdleExpiresAt:     start.Add(time.Hour),
		AbsoluteExpiresAt: start.Add(time.Hour),
	}
}

func TestRefreshTokenStore(t *testing.T) {
	t.Parallel()

	supplied, err := session.NewMemoryStore()
	require.NoError(t, err)
	var typedNil *session.MemoryStore

	refused := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.ErrorContains(t, err, "WithRefreshTokenStore")
		assert.Nil(t, p)
	}

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}{
		{
			name:   "the zero store is refused",
			opts:   []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oidcprovider.RefreshTokenStore{})},
			assert: refused,
		},
		{
			name:   "a store built over nothing is refused",
			opts:   []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oplineage.New(nil))},
			assert: refused,
		},
		{
			name:   "a store built over a typed nil is refused",
			opts:   []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(oplineage.New(typedNil))},
			assert: refused,
		},
		{
			name: "a store an adapter built replaces the default",
			opts: []oidcprovider.Option{
				oidcprovider.WithRefreshTokenStore(oplineage.New(supplied)),
				oidcprovider.WithRefreshSuccessorKey(successorKeyA),
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, supplied, p.LineageForTest().(*session.MemoryStore))
			},
		},
		{
			name: "with no option, the default is private: a sign-in store a test builds shares nothing with it",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				lineage := p.LineageForTest()
				require.NotNil(t, lineage)
				signIns, err := session.NewMemoryStore()
				require.NoError(t, err)
				now := time.Now()

				require.NoError(t, lineage.Create(t.Context(), lineageRecord(lineageIdentifier, now)))
				_, err = signIns.Load(t.Context(), lineageIdentifier)
				require.ErrorIs(t, err, session.ErrNotFound, "a lineage is not a sign-in")

				require.NoError(t, signIns.Create(t.Context(), lineageRecord("sign-in-1", now)))
				_, err = lineage.Load(t.Context(), "sign-in-1")
				require.ErrorIs(t, err, session.ErrNotFound, "and a sign-in is not a lineage")
			},
		},
		{
			name: "nothing a provider exports hands its lineage store back as a session store",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				typ := reflect.TypeOf(p)
				for i := range typ.NumMethod() {
					m := typ.Method(i)
					if strings.HasSuffix(m.Name, "ForTest") {
						continue // the test build's own read-backs
					}
					for out := range m.Type.NumOut() {
						assert.NotEqual(t, reflect.TypeFor[session.Store](), m.Type.Out(out), m.Name)
						assert.NotEqual(t, reflect.TypeFor[oidcprovider.RefreshTokenStore](), m.Type.Out(out), m.Name)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := oidcprovider.New(validDeps(t), tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

// Each provider's default is its own, as a shared one would let one provider's refresh
// token name another's lineage. A single case: there is no second variant of the call.
func TestRefreshTokenStore_DefaultIsPerProvider(t *testing.T) {
	t.Parallel()

	first, err := oidcprovider.New(validDeps(t))
	require.NoError(t, err)
	second, err := oidcprovider.New(validDeps(t))
	require.NoError(t, err)
	require.NotNil(t, first.LineageForTest())

	require.NoError(t, first.LineageForTest().Create(t.Context(), lineageRecord(lineageIdentifier, time.Now())))
	_, err = second.LineageForTest().Load(t.Context(), lineageIdentifier)
	require.ErrorIs(t, err, session.ErrNotFound)
}

// The default judges by the provider's clock, and stays bounded with nothing started:
// a write forgets what that clock says has expired, so a provider nobody wires a sweep
// for does not grow without bound. The record dates from long before the wall clock, so
// a store left on the system clock would not load it at all.
func TestRefreshTokenStore_DefaultFollowsProviderClockAndForgets(t *testing.T) {
	t.Parallel()

	start := time.Date(2001, 1, 1, 10, 0, 0, 0, time.UTC)
	clk := clockwork.NewFakeClockAt(start)
	p, err := oidcprovider.New(validDeps(t), oidcprovider.WithClock(clk))
	require.NoError(t, err)
	lineage := p.LineageForTest()
	require.NotNil(t, lineage)
	ctx := t.Context()

	require.NoError(t, lineage.Create(ctx, lineageRecord(lineageIdentifier, start)))
	_, err = lineage.Load(ctx, lineageIdentifier)
	require.NoError(t, err, "the record is live on the provider's clock")
	require.Equal(t, 1, p.LineageHeldForTest())

	clk.Advance(2 * time.Hour)
	require.NoError(t, lineage.Create(ctx, lineageRecord("lineage-record-2", clk.Now())))

	assert.Equal(t, 1, p.LineageHeldForTest(), "the write forgot what had expired")
}

// A reflecting caller meets the same wall. A single case: it is the one route at run time.
func TestRefreshTokenStore_ReflectionCannotFillIt(t *testing.T) {
	t.Parallel()

	memory, err := session.NewMemoryStore()
	require.NoError(t, err)

	assert.Panics(t, func() {
		var s oidcprovider.RefreshTokenStore
		reflect.ValueOf(&s).Elem().Field(0).Set(reflect.ValueOf(memory))
	})
}

// consumerGoMod is the module a consumer outside scrty's import path would be. It is
// outside for the internal rule's sake, which goes by import path, so no test file in
// this repository could show it.
const consumerGoMod = `module example.com/consumer

go 1.27

require github.com/kartaladev/scrty v0.0.0

replace github.com/kartaladev/scrty => `

// T7's guarantee, shown by the compiler from where a consumer stands: a
// RefreshTokenStore cannot be built from a session.Store outside scrty, by a literal, a
// conversion, an assignment or by reaching the internal package. The first row must
// build, or every other row could be failing for a reason of its own, and each row names
// the refusal it must fail with for the same reason.
func TestRefreshTokenStore_CannotBeBuiltOutsideScrty(t *testing.T) {
	t.Parallel()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH, so nothing can be compiled")
	}

	root := moduleRoot(t, goTool)
	//nolint:gosec // G304: this module's own go.sum, at the path the go tool named
	sums, err := os.ReadFile(filepath.Join(root, "go.sum"))
	require.NoError(t, err)

	const prelude = `package consumer

import (
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

var s session.Store

var _ = s
var _ oidcprovider.Option
`

	refusedWith := func(want string) func(*testing.T, string, error) {
		return func(t *testing.T, output string, err error) {
			t.Helper()
			require.Error(t, err, "this must not compile:\n%s", output)
			assert.Contains(t, output, want)
		}
	}

	cases := []struct {
		name   string
		source string
		assert func(t *testing.T, output string, err error)
	}{
		{
			name:   "the zero value compiles, which is why New refuses it",
			source: prelude + `var _ = oidcprovider.WithRefreshTokenStore(oidcprovider.RefreshTokenStore{})`,
			assert: func(t *testing.T, output string, err error) {
				t.Helper()
				require.NoError(t, err, "the consumer module must build, or the refusals below show nothing:\n%s", output)
			},
		},
		{
			name:   "a literal naming the field",
			source: prelude + `var _ = oidcprovider.RefreshTokenStore{sessions: s}`,
			assert: refusedWith("cannot refer to unexported field sessions"),
		},
		{
			name:   "a literal by position",
			source: prelude + `var _ = oidcprovider.RefreshTokenStore{s}`,
			assert: refusedWith("implicit assignment to unexported field sessions"),
		},
		{
			name:   "a session store passed as one",
			source: prelude + `var _ = oidcprovider.WithRefreshTokenStore(s)`,
			assert: refusedWith("cannot use s"),
		},
		{
			name:   "a conversion from the interface",
			source: prelude + `var _ = oidcprovider.RefreshTokenStore(s)`,
			assert: refusedWith("cannot convert s"),
		},
		{
			name: "a conversion from a look-alike struct",
			source: prelude + `type lookalike struct{ sessions session.Store }
var _ = oidcprovider.RefreshTokenStore(lookalike{s})`,
			assert: refusedWith("cannot convert"),
		},
		{
			name:   "a conversion from an anonymous look-alike struct",
			source: prelude + `var _ = oidcprovider.RefreshTokenStore(struct{ sessions session.Store }{s})`,
			assert: refusedWith("cannot convert"),
		},
		{
			name: "an embedding wrapper passed as one",
			source: prelude + `type wrapper struct{ oidcprovider.RefreshTokenStore }
var _ = oidcprovider.WithRefreshTokenStore(wrapper{})`,
			assert: refusedWith("cannot use wrapper{}"),
		},
		{
			name: "the internal package imported",
			source: `package consumer

import "github.com/kartaladev/scrty/internal/oplineage"

var _ = oplineage.New(nil)
`,
			assert: refusedWith("use of internal package github.com/kartaladev/scrty/internal/oplineage not allowed"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(name string, content []byte) {
				t.Helper()
				//nolint:gosec // G703: a name this test fixes, in the test's own directory
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
			}
			write("go.mod", []byte(consumerGoMod+root+"\n"))
			write("go.sum", sums)
			write("consumer.go", []byte(tc.source))

			output, err := runGo(t, goTool, dir, "build", ".")
			tc.assert(t, output, err)
		})
	}
}

// The compiler's own words for the plan's negative example, kept out of the build by its
// tag: go vet reads the file only with the tag on. A single case: the table above runs
// the other routes.
func TestRefreshTokenStore_NegativeExampleFailsToCompile(t *testing.T) {
	t.Parallel()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH, so nothing can be compiled")
	}

	output, err := runGo(t, goTool, ".", "vet", "-tags", "oplineage_negative", ".")
	require.Error(t, err, "the example must not compile:\n%s", output)
	assert.Contains(t, output, "cannot refer to unexported field")
}

// moduleRoot returns the directory of the module these tests belong to.
func moduleRoot(t *testing.T, goTool string) string {
	t.Helper()

	output, err := runGo(t, goTool, ".", "env", "GOMOD")
	require.NoError(t, err, output)

	return filepath.Dir(strings.TrimSpace(output))
}

// runGo runs the go tool in dir, outside any workspace, and returns what it printed.
func runGo(t *testing.T, goTool, dir string, args ...string) (string, error) {
	t.Helper()

	//nolint:gosec // G204: the go tool, with arguments this test fixes
	cmd := exec.CommandContext(t.Context(), goTool, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()

	return string(out), err
}
