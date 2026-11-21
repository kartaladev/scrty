package oidcprovider_test

//go:generate mockgen -source=../pkg/id/generator.go -destination=generator_mock_test.go -package=oidcprovider_test -typed

// TestProvider_RefusesANilIdentifierFromTheGenerator pins the four places the provider draws an
// identifier from the consumer's generator: a pending request's record, a grant's family, an
// opaque access token's identifier and an ID token's jti. A generator that answers the nil
// identifier with no error is a failing dependency at each, answered as a plain outage of the
// generator is, with nothing stored or issued under the nil identifier.

import (
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

type idNilSite int

const (
	idNilRecord idNilSite = iota // Authorize parks: the first identifier is the record's
	idNilFamily                  // Resume issues a code: the first identifier is the grant family
	idNilToken                   // Token mints an opaque access token: the first identifier
	idNilJTI                     // Token signs the ID token: the second identifier
)

type idNilKind int

const (
	idNilGood idNilKind = iota
	idNilNil
	idNilOutage
)

// idNilOutcome is what one run answered.
type idNilOutcome struct {
	err      error
	answered bool
}

// idNilRun asks the provider to reach site while its generator answers kind at the identifier
// site draws. A code written under a bad family fails the test.
func idNilRun(t *testing.T, site idNilSite, kind idNilKind) idNilOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)
	realGen := id.NewV7Generator()

	var armed, drawn atomic.Int32

	at := map[idNilSite]int32{idNilRecord: 1, idNilFamily: 1, idNilToken: 1, idNilJTI: 2}[site]
	gen := NewMockGenerator(ctrl)
	gen.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
		if armed.Load() == 1 && drawn.Add(1) == at {
			switch kind {
			case idNilNil:
				return id.Nil, nil
			case idNilOutage:
				return id.Nil, errOutage
			case idNilGood:
			}
		}

		return realGen.NewID()
	}).AnyTimes()

	opts := []oidcprovider.Option{oidcprovider.WithIDGenerator(gen)}
	if site == idNilFamily && kind != idNilGood {
		// No Create is expected: a code written under a bad family fails the test.
		opts = append(opts, oidcprovider.WithCodeStore(NewMockCodeStore(ctrl)))
	}

	x := newExchangeFixture(t, opts...)

	var out idNilOutcome

	switch site {
	case idNilRecord:
		armed.Store(1)

		res, err := x.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
		out = idNilOutcome{err: err, answered: res.Location != ""}

		// A dependency failure on a validated request is answered at the redirect URI.
		loc, perr := url.Parse(res.Location)
		require.NoError(t, perr)

		if err == nil && loc.Query().Get("error") == "server_error" {
			out = idNilOutcome{err: fmt.Errorf("%w: answered server_error at the redirect URI", oidcprovider.ErrDependency)}
		}
	case idNilFamily:
		signIn := testSignIn(x.parkFixture, "u-1")
		require.NoError(t, x.consents.Give(t.Context(), signIn.User, "billing-web", []string{"openid"}, true, x.clk.Now()))
		r := park(t, x.parkFixture, func(v url.Values) { v.Set("scope", "openid") })
		armed.Store(1)

		res, err := x.p.Resume(t.Context(), r.input(&signIn))
		out = idNilOutcome{err: err, answered: res.RedirectTo != ""}
	case idNilToken, idNilJTI:
		c := issueOpaque(t, x)
		armed.Store(1)

		res, err := x.p.Token(t.Context(), opaqueExchange(c))
		out = idNilOutcome{err: err, answered: res != nil}
	}

	if kind != idNilGood {
		require.GreaterOrEqual(t, drawn.Load(), at, "the flow reached the identifier")
	}

	return out
}

func TestProvider_RefusesANilIdentifierFromTheGenerator(t *testing.T) {
	t.Parallel()

	sites := map[string]idNilSite{
		"pending record": idNilRecord,
		"nil family":     idNilFamily,
		"access token":   idNilToken,
		"jti":            idNilJTI,
	}

	type testCase struct {
		name   string
		site   idNilSite
		kind   idNilKind
		assert func(t *testing.T, got idNilOutcome, plain func() idNilOutcome)
	}

	var tests []testCase

	for name, site := range sites {
		tests = append(tests,
			testCase{
				name: name + "/good id", site: site, kind: idNilGood,
				assert: func(t *testing.T, got idNilOutcome, _ func() idNilOutcome) {
					t.Helper()
					require.NoError(t, got.err)
					assert.True(t, got.answered)
				},
			},
			testCase{
				name: name + "/nil id", site: site, kind: idNilNil,
				assert: func(t *testing.T, got idNilOutcome, plain func() idNilOutcome) {
					t.Helper()
					require.ErrorIs(t, got.err, oidcprovider.ErrDependency)
					assert.NotContains(t, got.err.Error(), idgen.ErrNil.Error())
					assert.False(t, got.answered, "nothing is issued or sent under the nil identifier")

					want := plain()
					require.Error(t, want.err)
					assert.Equal(t, want.err.Error(), got.err.Error(), "the outcome of a plain outage")
					assert.Equal(t, want.answered, got.answered)
				},
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := idNilRun(t, tt.site, tt.kind)
			tt.assert(t, got, func() idNilOutcome { return idNilRun(t, tt.site, idNilOutage) })
		})
	}
}
