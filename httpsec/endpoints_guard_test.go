package httpsec_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// guardSegment is the sample a request puts where an entry reads a segment.
const guardSegment = "sample"

// guardMethods are the methods the guard tries on an entry's path, to find the
// ones it does not list.
var guardMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
}

// operationConstants reads every Operation* constant's value from the source of
// the inventory, so a constant added without an entry fails the guard instead of
// going unlisted.
func operationConstants(t *testing.T) []string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "endpoints.go", nil, 0)
	require.NoError(t, err)

	var ids []string

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}

		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Operation") || i >= len(vs.Values) {
					continue
				}

				lit, ok := vs.Values[i].(*ast.BasicLit)
				require.True(t, ok, "%s is a string literal", name.Name)

				id, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)

				ids = append(ids, id)
			}
		}
	}

	require.NotEmpty(t, ids, "the operation constants are found")

	return ids
}

// guardPrefix is the part of an entry's path before its first {…} segment.
func guardPrefix(e httpsec.Endpoint) string {
	before, _, _ := strings.Cut(e.Path, "/{")

	return before
}

// guardConcrete is a request path the entry answers: its path with the sample
// where it reads a segment.
func guardConcrete(e httpsec.Endpoint) string {
	if e.Match == httpsec.MatchExact {
		return e.Path
	}

	return guardPrefix(e) + "/" + guardSegment
}

// claims reports whether an entry's match covers the path, by what it declares.
func claims(e httpsec.Endpoint, p string) bool {
	pre := guardPrefix(e)

	switch e.Match {
	case httpsec.MatchExact:
		return p == e.Path
	case httpsec.MatchSegment:
		rest, ok := strings.CutPrefix(p, pre+"/")

		return ok && rest != "" && !strings.Contains(rest, "/")
	case httpsec.MatchSubtree:
		return p == pre || strings.HasPrefix(p, pre+"/")
	default:
		return false
	}
}

// declaredAnswer is what the inventory says becomes of a request: answered when
// an entry covers the path and either lists the method or refuses the others.
func declaredAnswer(inv []httpsec.Endpoint, method, p string) bool {
	for _, e := range inv {
		if !claims(e, p) {
			continue
		}

		if slices.Contains(e.Methods, method) || e.OtherMethods == httpsec.OtherMethodsRefused {
			return true
		}
	}

	return false
}

// guardAnswered sends the request through the chain and reports whether the
// chain answered it, rather than the application behind or a gate in front of it.
// The request's context is cancelled when the exchange ends, so a stream the
// endpoint opens ends with it, and bounded, so a hang fails instead of stalling.
func guardAnswered(t *testing.T, c *httpsec.Chain, method, target string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, method, target, nil)
	req.RemoteAddr = "203.0.113.7:51000"

	out := serveContext(ctx, t, c, req)

	var challenge *httpsec.ChallengeError

	return !out.handlerRan && !errors.As(out.err, &challenge)
}

// guardProbe is one request, and where the entry it was made from puts it.
type guardProbe struct {
	why    string
	method string
	path   string
}

// probesFor are the requests that pin an entry: each listed method on a path it
// reads, each unlisted method there, and the near misses around the path.
func probesFor(e httpsec.Endpoint) []guardProbe {
	concrete := guardConcrete(e)
	pre := guardPrefix(e)
	first := e.Methods[0]

	var probes []guardProbe

	for _, m := range e.Methods {
		probes = append(probes, guardProbe{"listed method", m, concrete})
	}

	for _, m := range guardMethods {
		if !slices.Contains(e.Methods, m) {
			probes = append(probes, guardProbe{"unlisted method", m, concrete})
		}
	}

	probes = append(probes,
		guardProbe{"sibling, prefix extended", first, pre + "x"},
		guardProbe{"sibling beside the path", first, path.Dir(pre) + "/x-sibling"},
		guardProbe{"parent path", first, path.Dir(pre)},
		guardProbe{"upper case", first, strings.ToUpper(concrete)},
		guardProbe{"concrete path extended", first, concrete + "x"},
	)

	switch e.Match {
	case httpsec.MatchExact:
		probes = append(probes,
			guardProbe{"path with a segment beneath", first, e.Path + "/extra"},
			guardProbe{"path with a trailing slash", first, e.Path + "/"},
		)
	case httpsec.MatchSegment:
		probes = append(probes,
			guardProbe{"two segments", first, concrete + "/b"},
			guardProbe{"empty segment", first, pre + "/"},
			guardProbe{"the prefix alone", first, pre},
		)
	case httpsec.MatchSubtree:
		probes = append(probes,
			guardProbe{"the prefix alone", first, pre},
			guardProbe{"deeper beneath", first, concrete + "/deeper"},
		)
	}

	return probes
}

// TestChainEndpoints_EveryEntryIsAnswered keeps the inventory from drifting from
// the chain: every operation constant is listed, and every entry is answered as
// it declares. Each listed method on its path is answered and never reaches the
// handler behind; the near misses, the parent and the unlisted methods go where
// the entries' Match, OtherMethods and shared paths say, passed on or refused.
//
// The built-ins sit in several chains, because their enabling options pull in
// different sessions and stores; every chain is under one base path, and between
// them they enable every endpoint, which the first row pins.
func TestChainEndpoints_EveryEntryIsAnswered(t *testing.T) {
	// Not parallel: the chains share harness fixtures built on this test.
	type chainRow struct {
		name  string
		chain func(t *testing.T) (*httpsec.Chain, error)
	}

	underBase := func(opts []httpsec.Option) []httpsec.Option {
		return append(opts, httpsec.WithBasePath(endpointsBase))
	}

	var rows []chainRow

	for _, r := range coreEndpoints() {
		rows = append(rows, chainRow{r.name, func(t *testing.T) (*httpsec.Chain, error) {
			return httpsec.New(underBase(r.options(t, ""))...)
		}})
	}

	for _, r := range featureEndpoints() {
		rows = append(rows, chainRow{r.name, func(t *testing.T) (*httpsec.Chain, error) {
			return httpsec.New(underBase(r.options(t, ""))...)
		}})
	}

	rows = append(rows,
		chainRow{"re-authentication", func(t *testing.T) (*httpsec.Chain, error) {
			return httpsec.New(underBase(endpointsReauth(t))...)
		}},
		chainRow{"federated login", func(t *testing.T) (*httpsec.Chain, error) {
			return httpsec.New(underBase(endpointsOIDCLogin(t))...)
		}},
		chainRow{"provider", func(t *testing.T) (*httpsec.Chain, error) {
			return bpChain(t, newOPFixture(t), true)
		}},
		chainRow{"every built-in enabled", func(t *testing.T) (*httpsec.Chain, error) {
			// The fixture's issuer does not carry the base path, which the
			// issuer check would refuse; this row judges the inventory, not it.
			popts := []httpsec.OIDCProviderOption{httpsec.WithoutOIDCIssuerBasePathCheck()}

			// The federated login of everyOtherBuiltIn (third) registers a
			// redirect URL outside the base; it is swapped for one registered
			// under it. A drift in that list shows as a duplicate endpoint.
			others := slices.Concat(everyOtherBuiltIn[:2],
				[]func(*testing.T, *session.Sessions) []httpsec.Option{
					func(t *testing.T, m *session.Sessions) []httpsec.Option {
						flows, err := oidc.NewMemoryFlowStore()
						require.NoError(t, err)

						return []httpsec.Option{httpsec.EnableOIDCLogin(
							httpsec.OIDCDeps{
								RelyingParty: oidcManagerAt(t, flows, endpointsBase+httpsec.DefaultOIDCCallbackPath),
								Handoff:      newTestHandoffManager(t),
							},
							httpsec.WithOIDCSessions(m))}
					},
				},
				everyOtherBuiltIn[3:])

			return httpsec.New(underBase(providerBeside(t, newOPFixture(t), popts, others...))...)
		}},
	)

	type built struct {
		name string
		c    *httpsec.Chain
		inv  []httpsec.Endpoint
	}

	var (
		chains []built
		listed []string
	)

	for _, r := range rows {
		c, err := r.chain(t)
		require.NoError(t, err, r.name)

		chains = append(chains, built{r.name, c, c.Endpoints()})
		listed = append(listed, operationIDs(c.Endpoints())...)
	}

	t.Run("the inventory lists every operation", func(t *testing.T) {
		for _, id := range operationConstants(t) {
			assert.True(t, slices.Contains(listed, id), "operation constant with no entry in any chain: %s", id)
		}
	})

	// answersEverything reports whether the chain answers every listed method of
	// the entry on a path it reads.
	answersEverything := func(t *testing.T, b built, e httpsec.Endpoint) bool {
		t.Helper()

		return !slices.ContainsFunc(e.Methods, func(m string) bool {
			return !guardAnswered(t, b.c, m, guardConcrete(e))
		})
	}

	// An enrolment endpoint serves a session confined to enrolling, so only the
	// chain carrying one answers it. Each operation is probed in the first chain
	// that answers it, or the first that lists it when none does, which fails.
	probed := map[string]bool{}

	for _, b := range chains {
		for _, e := range b.inv {
			if probed[e.OperationID] {
				continue
			}

			probed[e.OperationID] = true

			chosen := b

			if !answersEverything(t, b, e) {
				for _, other := range chains {
					i := slices.IndexFunc(other.inv, func(o httpsec.Endpoint) bool { return o.OperationID == e.OperationID })
					if i >= 0 && answersEverything(t, other, other.inv[i]) {
						chosen, e = other, other.inv[i]

						break
					}
				}
			}

			t.Run(e.OperationID, func(t *testing.T) {
				for _, m := range e.Methods {
					target := guardConcrete(e)
					assert.True(t, guardAnswered(t, chosen.c, m, target),
						"%s %s is listed (%s) but passes through to the handler", m, target, chosen.name)
				}

				for _, p := range probesFor(e) {
					t.Run(p.why+" "+p.method, func(t *testing.T) {
						want := declaredAnswer(chosen.inv, p.method, p.path)
						got := guardAnswered(t, chosen.c, p.method, p.path)

						assert.Equal(t, want, got, "%s %s should be answered=%v as declared (%s %v, %s)",
							p.method, p.path, want, e.Match, e.Methods, e.OtherMethods)
					})
				}
			})
		}
	}

	// The chain with every built-in enabled is also probed whole, entry by
	// entry: its shared paths and sessions are where one endpoint could shadow
	// another, which the per-feature chains cannot show.
	t.Run("every built-in enabled, all entries together", func(t *testing.T) {
		all := chains[len(chains)-1]
		require.Equal(t, "every built-in enabled", all.name)

		for _, e := range all.inv {
			// An enrolment endpoint serves only a session confined to enrolling,
			// which the guard probes do not carry; the per-feature rows above
			// probe it where one is.
			if strings.HasPrefix(e.OperationID, "scrty.mfa.enrolment.") {
				continue
			}

			t.Run(e.OperationID, func(t *testing.T) {
				for _, m := range e.Methods {
					target := guardConcrete(e)
					assert.True(t, guardAnswered(t, all.c, m, target),
						"%s %s is listed (%s) but passes through to the handler", m, target, all.name)
				}

				for _, p := range probesFor(e) {
					t.Run(p.why+" "+p.method, func(t *testing.T) {
						want := declaredAnswer(all.inv, p.method, p.path)
						got := guardAnswered(t, all.c, p.method, p.path)

						assert.Equal(t, want, got, "%s %s should be answered=%v as declared (%s %v, %s)",
							p.method, p.path, want, e.Match, e.Methods, e.OtherMethods)
					})
				}
			})
		}
	})
}
