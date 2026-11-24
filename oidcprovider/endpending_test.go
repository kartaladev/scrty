package oidcprovider_test

// The EndPending tests are split by setup: the answered codes and the refusals as unknown
// handles run over the memory store, and the codes outside the set over a strict store mock,
// which fails the row if the request is ever read.

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

const tenantRedirect = "https://rp.example.com/cb?tenant=a"

// asTenant parks as tenant-web, whose registered redirect URI carries a query of its own.
func asTenant(state string) func(url.Values) {
	return func(v url.Values) {
		asClient(v, "tenant-web", tenantRedirect)
		v.Set("scope", "openid")
		if state == "" {
			v.Del("state")
		} else {
			v.Set("state", state)
		}
	}
}

func (r parked) end(code string) oidcprovider.EndPendingInput {
	return oidcprovider.EndPendingInput{Handle: r.handle, FlowSecret: r.flow, Code: code}
}

// TestEndPending_AnswersRedirectURIWithCode ends a login-stage request with each code of the
// set, at the client's redirect URI, keeping the registered query.
func TestEndPending_AnswersRedirectURIWithCode(t *testing.T) {
	t.Parallel()

	// answered asserts an error response carrying code, the registered query, iss, and state
	// when one was sent, and nothing else; and that the handle is spent.
	answered := func(code, state string) func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, oidcprovider.ResumeOutcomeClientError, res.Outcome)
			assert.Empty(t, res.BrowserSessionSecret)

			loc, perr := url.Parse(res.RedirectTo)
			require.NoError(t, perr)
			assert.Equal(t, "https://rp.example.com/cb", loc.Scheme+"://"+loc.Host+loc.Path)
			want := url.Values{"tenant": {"a"}, "error": {code}, "iss": {issuer}}
			if state != "" {
				want.Set("state", state)
			}
			assert.Equal(t, want, loc.Query(), "no error_description, no code, nothing else")
			assert.True(t, strings.HasPrefix(res.RedirectTo, tenantRedirect+"&"), "the registered query is kept as registered")

			assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r), "the request is spent")
			_, again := f.p.EndPending(t.Context(), r.end(code))
			require.ErrorIs(t, again, oidcprovider.ErrUnknownHandle, "a second end is an unknown handle")
			signIn := testSignIn(f, "u-1")
			_, again = f.p.Resume(t.Context(), r.input(&signIn))
			require.ErrorIs(t, again, oidcprovider.ErrUnknownHandle, "a later resume is an unknown handle")
		}
	}

	type testCase struct {
		name   string
		code   string
		state  string
		assert func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}
	cases := []testCase{
		{name: "access_denied", code: oidcprovider.CodeAccessDenied, state: "s-1", assert: answered("access_denied", "s-1")},
		{
			name: "temporarily_unavailable", code: oidcprovider.CodeTemporarilyUnavailable, state: "s-1",
			assert: answered("temporarily_unavailable", "s-1"),
		},
		{name: "server_error", code: oidcprovider.CodeServerError, state: "s-1", assert: answered("server_error", "s-1")},
		{name: "no state sent, so none answered", code: oidcprovider.CodeAccessDenied, assert: answered("access_denied", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			r := park(t, f, asTenant(tc.state))

			res, err := f.p.EndPending(t.Context(), r.end(tc.code))
			tc.assert(t, f, r, res, err)
		})
	}
}

// TestEndPending_RefusesCodeOutsideSet refuses any code but the three as a wiring mistake,
// before the request is read (F5).
func TestEndPending_RefusesCodeOutsideSet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		code   string
		assert func(*testing.T, oidcprovider.ResumeResult, error)
	}
	refused := func(t *testing.T, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.Empty(t, res.RedirectTo)
		assert.NotContains(t, err.Error(), "rh.", "the error holds no handle")
	}
	cases := []testCase{
		{name: "a code the set does not hold", code: oidcprovider.CodeInvalidGrant, assert: refused},
		{name: "no code", code: "", assert: refused},
		{name: "a code of the set in another case", code: "ACCESS_DENIED", assert: refused},
		{name: "a code of the set with a space", code: "access_denied ", assert: refused},
		{name: "a rejudge code, which only the provider answers", code: oidcprovider.CodeInvalidScope, assert: refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			r := park(t, f, nil)

			// A strict mock with no Load expected: reading the request fails the row.
			p := rebuilt(t, f, oidcprovider.WithPendingRequestStore(passThroughPending(t, f.store)))
			res, err := p.EndPending(t.Context(), r.end(tc.code))
			tc.assert(t, res, err)
			assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the request stays parked")
		})
	}
}

// TestEndPendingInput_Redacted prints and logs nothing an input holds.
func TestEndPendingInput_Redacted(t *testing.T) {
	t.Parallel()

	in := oidcprovider.EndPendingInput{Handle: "rh.handle-secret", FlowSecret: "flow-secret", Code: "access_denied"}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "in", in)

	for _, out := range []string{fmt.Sprintf("%v %+v %#v %s %q", in, in, in, in, in), logged.String()} {
		assert.NotContains(t, out, "handle-secret")
		assert.NotContains(t, out, "flow-secret")
		assert.Contains(t, out, "[REDACTED]")
	}
}

// TestEndPending_RefusesAsUnknownHandle refuses what EndPending must not end as an unknown
// handle, with no redirect, and leaves the request as it was (F4).
func TestEndPending_RefusesAsUnknownHandle(t *testing.T) {
	t.Parallel()

	other := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	// subject is what a row ends, and how to read its stage afterwards.
	type subject struct {
		p     *oidcprovider.Provider
		in    oidcprovider.EndPendingInput
		stage func(*testing.T) oidcprovider.Stage
	}
	parkedAt := func(t *testing.T, f *parkFixture, r parked, in oidcprovider.EndPendingInput) subject {
		t.Helper()

		return subject{p: f.p, in: in, stage: func(t *testing.T) oidcprovider.Stage { t.Helper(); return stageOf(t, f, r) }}
	}

	type testCase struct {
		name   string
		setup  func(*testing.T) subject
		assert func(*testing.T, subject, oidcprovider.ResumeResult, error)
	}
	unknownLeaving := func(want oidcprovider.Stage) func(*testing.T, subject, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, s subject, res oidcprovider.ResumeResult, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			assert.Empty(t, res.RedirectTo, "no redirect")
			assert.Equal(t, oidcprovider.ResumeOutcomeUnknown, res.Outcome)
			assert.Equal(t, want, s.stage(t), "the request is left as it was")
		}
	}
	cases := []testCase{
		{
			name: "a wrong flow secret",
			setup: func(t *testing.T) subject {
				f := newParkFixture(t, issuer+"/login")
				r := park(t, f, nil)
				in := r.end(oidcprovider.CodeAccessDenied)
				in.FlowSecret = other

				return parkedAt(t, f, r, in)
			},
			assert: unknownLeaving(oidcprovider.StageLogin),
		},
		{
			name: "no flow secret",
			setup: func(t *testing.T) subject {
				f := newParkFixture(t, issuer+"/login")
				r := park(t, f, nil)
				in := r.end(oidcprovider.CodeAccessDenied)
				in.FlowSecret = ""

				return parkedAt(t, f, r, in)
			},
			assert: unknownLeaving(oidcprovider.StageLogin),
		},
		{
			name: "an unknown handle",
			setup: func(t *testing.T) subject {
				f := newParkFixture(t, issuer+"/login")
				r := park(t, f, nil)
				recordID, _ := handleParts(t, r.handle)
				in := r.end(oidcprovider.CodeAccessDenied)
				in.Handle = "rh." + recordID + "." + other

				return parkedAt(t, f, r, in)
			},
			assert: unknownLeaving(oidcprovider.StageLogin),
		},
		{
			name: "a request at its consent stage",
			setup: func(t *testing.T) subject {
				f := newParkFixture(t, issuer+"/login")
				r, _ := atConsent(t, f, nil, testSignIn(f, "u-1"))

				return parkedAt(t, f, r, r.end(oidcprovider.CodeAccessDenied))
			},
			assert: unknownLeaving(oidcprovider.StageConsent),
		},
		{
			name: "a request already spent",
			setup: func(t *testing.T) subject {
				f := newParkFixture(t, issuer+"/login")
				rememberAll(t, f)
				r := park(t, f, nil)
				signIn := testSignIn(f, "u-1")
				_, err := f.p.Resume(t.Context(), r.input(&signIn))
				require.NoError(t, err)

				return parkedAt(t, f, r, r.end(oidcprovider.CodeAccessDenied))
			},
			assert: unknownLeaving(oidcprovider.StageDone),
		},
		{
			name: "a device request at its login stage",
			setup: func(t *testing.T) subject {
				f := newDeviceConsentFixture(t, deviceConsentSetup{})
				handle, flow := f.atLogin(t)

				return subject{
					p:     f.p,
					in:    oidcprovider.EndPendingInput{Handle: handle, FlowSecret: flow, Code: oidcprovider.CodeAccessDenied},
					stage: func(t *testing.T) oidcprovider.Stage { t.Helper(); return f.stage(t, handle) },
				}
			},
			assert: unknownLeaving(oidcprovider.StageLogin),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.setup(t)

			res, err := s.p.EndPending(t.Context(), s.in)
			tc.assert(t, s, res, err)
		})
	}
}
