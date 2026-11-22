package httpsec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// siteRun is what one request through a refusal-path site produced.
type siteRun struct {
	// err is what the chain's run returned, and status what was answered.
	err    error
	status int
	// dispatched is set when the request went through the chain's own
	// dispatch, which classified err and reported an abort it met. A run
	// that returned err without a dispatch is classified afterwards, as the
	// dispatch would, so every row counts the same records.
	dispatched bool
	// aborts counts the records a harness's own logger took, for a harness
	// whose chain logs where the row's logger cannot.
	aborts int
}

// hostileLoadStore is a session store whose Load answers err.
type hostileLoadStore struct {
	session.Store

	err error
}

func (s *hostileLoadStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	if s.err == nil {
		return s.Store.Load(ctx, sid)
	}

	return nil, s.err
}

// hostileEnroller is the TOTP method whose enrolment begin answers err.
type hostileEnroller struct {
	*mfa.TOTP

	err error
}

func (e hostileEnroller) BeginEnrolmentGeneration(context.Context, identity.UserID, string) (mfa.Provisioning, id.ID, error) {
	return mfa.Provisioning{}, id.ID{}, e.err
}

// hostileStreamWriter is a consumer's response writer whose Stream answers err.
type hostileStreamWriter struct {
	httpsec.ResponseWriter

	err error
}

func (w hostileStreamWriter) Stream(context.Context, string, func(context.Context, httpsec.EventWriter) error) error {
	return w.err
}

// TestRefusalPath_SiteAborts pins that the remaining inspections of a
// consumer's error on the refusal path read it under the bounded, recovering
// walk. Each row routes a hostile error through the site's own path: a cycle,
// where nothing before the site walks the chain unbounded, and a link whose Is
// method panics only for a sentinel the site asks about and the status lookup
// never does. Each request returns with no hang and no escaped panic, the
// event or challenge the site would add is dropped, and the request writes
// exactly one record, by the quiet sites' rule (reportQuietly).
func TestRefusalPath_SiteAborts(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		run    func(t *testing.T, w *refusalWorld, err error) siteRun
		assert func(t *testing.T, w *refusalWorld, got siteRun)
	}

	// dropped asserts the row reported none of events.
	dropped := func(events ...string) func(t *testing.T, w *refusalWorld, got siteRun) {
		return func(t *testing.T, w *refusalWorld, _ siteRun) {
			t.Helper()

			for _, e := range events {
				assert.NotContains(t, w.emitted(), e, "an aborted walk reports no event")
			}
		}
	}

	// onAChain runs inspect from inside an interceptor of a chain built from
	// opts, then refuses with err, so the site reads the request's own
	// exchange and the chain's dispatch answers what it returned.
	onAChain := func(inspect httpsec.QuietSite, opts func(t *testing.T, w *refusalWorld) []httpsec.Option) func(*testing.T, *refusalWorld, error) siteRun {
		return func(t *testing.T, w *refusalWorld, err error) siteRun {
			t.Helper()

			at := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
				inspect(ex, err)

				return err
			}), httpsec.Order(100))

			h := behindChain(t, nil, append(opts(t, w), at)...)
			rec := serveRefusalWithin(t, h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil))

			return siteRun{status: rec.Code, dispatched: true}
		}
	}

	dpopChain := func(t *testing.T, w *refusalWorld) []httpsec.Option {
		t.Helper()

		bearer, _ := signedInBearer(t)

		return []httpsec.Option{w.logger(), bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})}
	}

	// responseRefused answers a second-factor response with err from the
	// consumer's method.
	responseRefused := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		h := newMFAHarness(t)
		h.channel(factor.AuthenticatorApp).allows()
		h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(err)
		h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		s := h.pendingSession(t, factor.Password)
		chain := h.chain(t, s, w.logger(), w.securityEvents())
		rec := serveRefusalWithin(t, chain.Middleware()(http.NotFoundHandler()), postCode(t.Context(), testMFAVerifyPath))

		return siteRun{status: rec.Code, dispatched: true}
	}

	// sessionLoad presents a session whose store's load answers err.
	sessionLoad := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		store := &hostileLoadStore{Store: must.Must(session.NewMemoryStore())}
		sessions, nerr := session.New(session.WithStore(store))
		require.NoError(t, nerr)

		s, nerr := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
		require.NoError(t, nerr)

		store.err = err

		h := behindChain(t, nil, w.logger(), w.securityEvents(),
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: usersAnswering(t)}))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil)
		req.Header.Set("Authorization", "Bearer "+s.ID)

		rec := serveRefusalWithin(t, h, req)

		return siteRun{status: rec.Code, dispatched: true}
	}

	// nonceOpen presents a DPoP proof whose nonce the consumer's nonce cipher
	// cannot open, answering err.
	nonceOpen := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		world := newDPoPBearerWorld(t)
		cipher := NewMockNonceCipher(gomock.NewController(t))
		cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err).AnyTimes()

		chain, nerr := httpsec.New(httpsec.WithClock(world.clk), w.logger(), w.securityEvents(),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: world.gen, Sessions: world.sessions, Users: world.users}),
			httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher}))
		require.NoError(t, nerr)

		key := newDPoPKey(t, elliptic.P256())
		tok := world.token(token.Confirmation{JKT: key.jkt})
		proof := key.validProof("j-1").with(map[string]any{
			"ath": tokenHash(tok), "iat": world.clk.Now().Unix(), "nonce": "c2VhbGVk",
		}).sign(t)

		out := withinWatchdog(t, func() served { return world.present(chain, "DPoP", tok, proof) })

		return siteRun{err: out.err}
	}

	// streamRetry answers a dependency failure on the signal stream's path
	// through a consumer's response writer whose Stream answers err.
	streamRetry := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		bearer, _ := signedInBearer(t)
		chain, nerr := httpsec.New(w.logger(), bearer,
			httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
			refusedOnThePath(errors.New("the store is down"), httpsec.Before(httpsec.OrderBearerToken)))
		require.NoError(t, nerr)

		run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
		req := streamRequest(t.Context(), "")
		writer := hostileStreamWriter{ResponseWriter: httpsec.NewHTTPResponseWriter(httptest.NewRecorder()), err: err}

		out := withinWatchdog(t, func() served {
			return served{err: run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), writer))}
		})

		return siteRun{err: out.err}
	}

	// oidcCallbackBrokered runs one OIDC callback whose consumer broker
	// answers err.
	oidcCallbackBrokered := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		h := newOIDCHarness(t)
		registry := must.Must(oidc.NewRegistry(h.provider.provider()))
		client := must.Must(outbound.New(outbound.WithHTTPClient(h.provider.srv.Client())))
		h.manager = must.Must(oidc.NewRelyingParty(registry, scriptedBroker{run: func(context.Context) error { return err }},
			oidc.WithOutboundClient(client), oidc.WithFlowStore(h.flows)))
		h.chainOpts = append(h.chainOpts, w.securityEvents())
		c := h.chain(t)

		l := startLogin(t, c, "")
		q := url.Values{"code": {l.nonce}, "state": {l.state}}.Encode()

		out := withinWatchdog(t, func() served { return serveWithContext(t.Context(), c, callbackRequest(t.Context(), q, l.handle)) })

		// The harness's chain logs to the harness's own buffer.
		return siteRun{err: out.err, aborts: strings.Count(h.logs.String(), msgClassificationAborted)}
	}

	// passkeyLoginChecked logs in with a passkey whose consumer login check
	// answers err.
	passkeyLoginChecked := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		d := newPwlDeployment(t)
		d.extra = append(d.extra, w.logger(), w.securityEvents())
		d.pkOpts = append(d.pkOpts, passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error { return err }))
		d.build(t)

		handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
		out := withinWatchdog(t, func() served { return d.login(t, "cred-1", handle) })

		return siteRun{err: out.err}
	}

	// enrolmentBegun begins an enrolment whose method answers err.
	enrolmentBegun := func(t *testing.T, w *refusalWorld, err error) siteRun {
		t.Helper()

		h := newEnrolHarness(t)
		h.method = hostileEnroller{TOTP: h.totp, err: err}
		h.extra = append(h.extra, w.logger(), w.securityEvents())

		s := h.enrolmentOnly(t, factor.Password)
		c := h.chain(t, s)
		rec := serveRefusalWithin(t, c.Middleware()(http.NotFoundHandler()), post(t.Context(), enrolBeginPath, ""))

		return siteRun{status: rec.Code, dispatched: true}
	}

	// proofCharged redeems the single-use material of a charging issuing
	// endpoint with a proof whose nonce the consumer's cipher cannot open,
	// answering err: the proof check's failure then carries err, and the
	// endpoint asks whether to charge it.
	proofCharged := func(ep chargingEndpoint) func(t *testing.T, w *refusalWorld, err error) siteRun {
		return func(t *testing.T, w *refusalWorld, err error) siteRun {
			t.Helper()

			cipher := NewMockNonceCipher(gomock.NewController(t))
			cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err).AnyTimes()

			f := ep.build(t, httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher},
				countingLimiter(t, 0), w.securityEvents())
			send := f.prepare(t, "")
			key := newDPoPKey(t, elliptic.P256())

			out := withinWatchdog(t, func() served {
				return send(t, func(t *testing.T, path, _ string) string {
					return key.issuingProofParts(path, "j-1", "").with(map[string]any{"nonce": "c2VhbGVk"}).sign(t)
				})
			})

			return siteRun{err: out.err}
		}
	}

	cases := []testCase{
		{
			name: "the OIDC sign-in challenge's DPoP check, a selective Is",
			err:  selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
			run:  onAChain(httpsec.QuietSiteOIDCConsent, dpopChain),
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, got.status)
			},
		},
		{
			// The challenge looks the refusal up first, and leaves a 500 alone,
			// so a cycle never reaches the DPoP check; the row pins that.
			name: "the OIDC sign-in challenge's DPoP check, a cycle",
			err:  &cycleOne{},
			run:  onAChain(httpsec.QuietSiteOIDCConsent, dpopChain),
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, got.status)
			},
		},
		{
			name:   "the response-refused event's switch, a selective Is",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: mfa.ErrVerifyAttemptsExhausted},
			run:    responseRefused,
			assert: dropped(event.ExcessRateLimitExceeded, event.MFAVerifyFail),
		},
		{
			name:   "the session load's refusal event, a selective Is",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: session.ErrExpired},
			run:    sessionLoad,
			assert: dropped(event.SessionUseAfterExpire, event.AuthnLoginFail),
		},
		{
			name:   "the session load's refusal event, a cycle",
			err:    &cycleOne{},
			run:    sessionLoad,
			assert: dropped(event.SessionUseAfterExpire, event.AuthnLoginFail),
		},
		{
			name: "the DPoP nonce cipher's open, a selective Is",
			err:  selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: session.ErrCipherUnavailable},
			run:  nonceOpen,
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(got.err),
					"a cipher whose error cannot be read is a cipher that failed")
			},
		},
		{
			name: "the DPoP nonce cipher's open, a cycle",
			err:  &cycleOne{},
			run:  nonceOpen,
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(got.err))
			},
		},
		{
			// A cipher that answers a cycle is read by the nonce check's own
			// walk first, which stands a library error in its place, so only
			// the selective Is reaches the charge.
			name: "the magic link's proof charge, a selective Is",
			err:  selectiveIs{matches: session.ErrCipherUnavailable, panicsOn: httpsec.ErrInvalidDPoPProof},
			run:  proofCharged(chargingEndpoints[0]),
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Error(t, got.err, "the proof check failed, and was charged to no one")
			},
		},
		{
			name: "the OIDC handoff's proof charge, a selective Is",
			err:  selectiveIs{matches: session.ErrCipherUnavailable, panicsOn: httpsec.ErrInvalidDPoPProof},
			run:  proofCharged(chargingEndpoints[1]),
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.Error(t, got.err, "the proof check failed, and was charged to no one")
			},
		},
		{
			name: "the signal stream's retry, a writer whose Stream answers a selective Is",
			err:  selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrStreamingUnsupported},
			run:  streamRetry,
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.EqualError(t, got.err, "the store is down", "the refusal it could not write")
			},
		},
		{
			name: "the signal stream's retry, a writer whose Stream answers a cycle",
			err:  &cycleOne{},
			run:  streamRetry,
			assert: func(t *testing.T, _ *refusalWorld, got siteRun) {
				t.Helper()
				assert.EqualError(t, got.err, "the store is down", "the refusal it could not write")
			},
		},
		{
			name:   "the OIDC callback's refusal event, a selective Is",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: oidc.ErrProvisioningRefused},
			run:    oidcCallbackBrokered,
			assert: dropped(event.AuthnLoginFail),
		},
		{
			name:   "the OIDC callback's refusal event, a cycle",
			err:    &cycleOne{},
			run:    oidcCallbackBrokered,
			assert: dropped(event.AuthnLoginFail),
		},
		{
			name:   "the passkey login's refusal event, a selective Is",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: passkey.ErrSuspended},
			run:    passkeyLoginChecked,
			assert: dropped(event.AuthnLoginFail),
		},
		{
			name:   "the passkey login's refusal event, a cycle",
			err:    &cycleOne{},
			run:    passkeyLoginChecked,
			assert: dropped(event.AuthnLoginFail),
		},
		{
			name:   "the enrolment refusal's reason, a selective Is",
			err:    selectiveIs{matches: mfa.ErrAlreadyEnrolled, panicsOn: mfa.ErrSameChannel},
			run:    enrolmentBegun,
			assert: func(*testing.T, *refusalWorld, siteRun) {},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			got := tc.run(t, w, tc.err)
			if !got.dispatched {
				// The dispatch's own classification, which reports an abort
				// it meets to the chain's logger; slog.Default() stands for it.
				_, _ = httpsec.LookupStatus(got.err)
			}

			tc.assert(t, w, got)

			chainAborts, defaultAborts := abortRecords(w.chainLogs.records()), abortRecords(defaultLogs.records())
			assert.Equal(t, 1, len(chainAborts)+len(defaultAborts)+got.aborts,
				"one record per request whose classification aborted (chain %d, default %d, harness %d)",
				len(chainAborts), len(defaultAborts), got.aborts)
		})
	}
}

// withinWatchdog runs serve on its own goroutine, and fails the row when it
// does not return within refusalWatchdog or lets a panic escape.
func withinWatchdog(t *testing.T, serve func() served) served {
	t.Helper()

	type outcome struct {
		out      served
		panicked bool
		value    any
	}

	done := make(chan outcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- outcome{panicked: true, value: recover()}
			}
		}()

		out := serve()
		returned = true
		done <- outcome{out: out}
	}()

	select {
	case o := <-done:
		if o.panicked {
			t.Fatalf("a panic escaped the refusal path: %v", o.value)
		}

		return o.out
	case <-time.After(refusalWatchdog):
		t.Fatalf("the refusal path did not return within %v", refusalWatchdog)

		return served{}
	}
}
