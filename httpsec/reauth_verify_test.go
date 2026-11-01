package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// The second-factor re-proof paths under the default prefix.
const (
	reauthBeginPrefix   = httpsec.DefaultReauthenticationPrefix + "/begin"
	reauthVerifyPrefix  = httpsec.DefaultReauthenticationPrefix + "/verify"
	reauthBeginPasskey  = reauthBeginPrefix + "/" + passkey.MethodName
	reauthVerifyPasskey = reauthVerifyPrefix + "/" + passkey.MethodName
)

// reauthBearer is the re-authentication harness on a bearer chain: every
// request names its session through the token it carries, so a rotation is
// observable end to end and one chain serves several sessions.
func reauthBearer(t *testing.T) *reauthHarness {
	t.Helper()

	h := newReauthHarness(t)
	h.chainOpts = append(h.chainOpts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
		Verifier: h.tokens,
		Sessions: h.sessions,
		Users:    h.users,
	}))

	return h
}

// reauthEnv is one bearer chain with re-authentication and the full session a
// case re-proves.
type reauthEnv struct {
	h    *reauthHarness
	stub *challengeStub
	c    *httpsec.Chain
	s    *session.Session
}

// token is the credential the case's full session is reached with.
func (e *reauthEnv) token() string { return mfaTokenFor(e.s.ID) }

// serve runs req through the case's chain.
func (e *reauthEnv) serve(t *testing.T, req *http.Request) served {
	t.Helper()

	return serve(t, e.c, req)
}

// begin begins a passkey re-proof with tok and returns what it answered.
func (e *reauthEnv) begin(t *testing.T, tok string) served {
	t.Helper()

	return e.serve(t, bearerPost(t.Context(), reauthBeginPasskey, tok))
}

// begun begins a passkey re-proof with tok, requires it to succeed, and returns
// the challenge it issued.
func (e *reauthEnv) begun(t *testing.T, tok string) string {
	t.Helper()

	out := e.begin(t, tok)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	return issuedChallenge(t, out)
}

// answer answers challenge at the passkey verify path with tok.
func (e *reauthEnv) answer(t *testing.T, tok, challenge string) served {
	t.Helper()

	return e.serve(t, bearerJSON(t.Context(), reauthVerifyPasskey, tok, answer(challenge)))
}

// reproved asserts out is a successful re-proof of s that left the session
// rotated, freshly authenticated at the chain's now, and its second factor
// satisfied at that time, and returns the rotated session.
func reproved(t *testing.T, h *reauthHarness, s *session.Session, out served) *session.Session {
	t.Helper()

	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

	issued, ok := h.issuedFor.Load().(string)
	require.True(t, ok, "a credential was issued")
	assert.NotEqual(t, s.ID, issued, "the session was rotated")
	assert.Equal(t, mfaTokenFor(issued), accessTokenFrom(t, out), "the credential names the rotated session")

	_, err := h.sessions.Load(t.Context(), s.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the handle the caller arrived with is gone")

	rotated := h.stored(t, issued)
	now := h.clock.Now()
	assert.True(t, rotated.AuthenticatedAt.Equal(now), "authenticated at the chain's now: %s", rotated.AuthenticatedAt)
	assert.True(t, rotated.MFASatisfiedAt.Equal(now), "second factor satisfied at the chain's now: %s", rotated.MFASatisfiedAt)
	assert.Equal(t, session.MFASatisfied, rotated.MFA)

	return rotated
}

// unchanged asserts the session s is still stored under its own handle, as it
// was, and that no credential was issued.
func unchanged(t *testing.T, h *reauthHarness, s *session.Session) {
	t.Helper()

	stored := h.stored(t, s.ID)
	assert.True(t, stored.AuthenticatedAt.Equal(s.AuthenticatedAt), "the authentication time is unchanged")
	assert.Equal(t, s.MFA, stored.MFA)
	assert.Nil(t, h.issuedFor.Load(), "no credential was issued")
}

// TestReauthVerify pins the second-factor re-proof at POST
// <prefix>/verify/<method>: the order it judges a submission in, what it
// counts against the user's second-factor throttle, and what it changes.
//
// The chain authenticates by bearer token, and the clock has moved on since the
// session signed in, so a refreshed authentication time is observable.
func TestReauthVerify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(h *reauthHarness)
		request func(ctx context.Context, t *testing.T, token string) *http.Request
		assert  func(t *testing.T, h *reauthHarness, s *session.Session, out served)
	}

	code := func(path string) func(context.Context, *testing.T, string) *http.Request {
		return func(ctx context.Context, _ *testing.T, token string) *http.Request {
			return bearerRequestTo(ctx, http.MethodPost, path, token, "code="+testMFACode)
		}
	}

	unread := func(path string) func(context.Context, *testing.T, string) *http.Request {
		return func(ctx context.Context, t *testing.T, token string) *http.Request {
			req := postUnread(ctx, t, path)
			req.Header.Set("Authorization", "Bearer "+token)

			return req
		}
	}

	refusedWith := func(want error) func(*testing.T, *reauthHarness, *session.Session, served) {
		return func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "nothing was written")
			unchanged(t, h, s)
		}
	}

	// untouched is a refusal decided before the throttle is consulted, which
	// counts nothing and verifies nothing.
	untouched := func(h *reauthHarness) { h.neverChecked().recordsNoFailure().neverVerifies() }

	errLookup := errors.New("reauthverify_test: enrolment store unavailable for ana@example.com")

	cases := []testCase{
		{
			// "Valid TOTP code".
			name:    "a valid TOTP code re-proves",
			wire:    func(h *reauthHarness) { h.allows().accepts().recordsNoFailure() },
			request: code(reauthVerifyTOTP),
			assert: func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
				reproved(t, h, s, out)
			},
		},
		{
			// "Unknown method".
			name:    "an unknown method is refused before anything is counted",
			wire:    untouched,
			request: unread(reauthVerifyPrefix + "/sms"),
			assert: func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
				refusedWith(httpsec.ErrUnknownMFAMethod)(t, h, s, out)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
			},
		},
		{
			// A method name is matched exactly, never case-folded.
			name:    "a method named in another case is unknown",
			wire:    untouched,
			request: unread(reauthVerifyPrefix + "/TOTP"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			// "A method segment is required".
			name:    "a verify path with an empty method segment is unknown",
			wire:    untouched,
			request: unread(reauthVerifyPrefix + "/"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:    "the bare verify path is unknown",
			wire:    untouched,
			request: unread(reauthVerifyPrefix),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:    "a verify path with an extra segment is unknown",
			wire:    untouched,
			request: unread(reauthVerifyTOTP + "/extra"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			// "Method the user is not enrolled on".
			name: "a method the user is not enrolled on is refused before anything is counted",
			wire: func(h *reauthHarness) {
				untouched(h)
				h.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel}}
			},
			request: unread(reauthVerifyPasskey),
			assert: func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
				refusedWith(httpsec.ErrReauthenticationMethodNotUsable)(t, h, s, out)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			// "Lookup failure" at verify: no downgrade, nothing verified.
			name: "a lookup failure refuses and verifies nothing",
			wire: func(h *reauthHarness) {
				untouched(h)
				h.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel, enrolledErr: errLookup}}
			},
			request: unread(reauthVerifyTOTP),
			assert: func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
				refusedWith(errLookup)(t, h, s, out)
				assert.NotContains(t, out.err.Error(), "ana@example.com", "the store's own text stays out")
			},
		},
		{
			name:    "a throttled user is refused before the code is read",
			wire:    func(h *reauthHarness) { h.throttles().recordsNoFailure().neverVerifies() },
			request: unread(reauthVerifyTOTP),
			assert:  refusedWith(mfa.ErrVerifyThrottled),
		},
		{
			// "Wrong code".
			name:    "a wrong code is counted once against the user and leaves the session",
			wire:    func(h *reauthHarness) { h.allows().refuses().recordsFailure() },
			request: code(reauthVerifyTOTP),
			assert: func(t *testing.T, h *reauthHarness, s *session.Session, out served) {
				refusedWith(mfa.ErrInvalidCode)(t, h, s, out)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a response that cannot be read is not counted",
			wire: func(h *reauthHarness) { h.allows().recordsNoFailure().neverVerifies() },
			request: func(ctx context.Context, _ *testing.T, token string) *http.Request {
				return bearerRequestTo(ctx, http.MethodPost, reauthVerifyTOTP, token, "")
			},
			assert: refusedWith(httpsec.ErrCredentialsMissing),
		},
		{
			// A refusal of the authenticator is not a guess at the response.
			name: "a refused authenticator is returned unchanged and not counted",
			wire: func(h *reauthHarness) {
				h.allows().recordsNoFailure()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).
					Return(errors.Join(mfa.ErrAuthenticatorRefused, passkey.ErrSuspended))
			},
			request: code(reauthVerifyTOTP),
			assert:  refusedWith(passkey.ErrSuspended),
		},
		{
			// A refused attempt charge compared nothing.
			name: "a refused attempt charge is not counted",
			wire: func(h *reauthHarness) {
				h.allows().recordsNoFailure()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(mfa.ErrVerifyThrottled)
			},
			request: code(reauthVerifyTOTP),
			assert:  refusedWith(mfa.ErrVerifyThrottled),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := reauthBearer(t)
			tc.wire(h)

			s := h.fullSession(t, factor.Password)

			// Time has passed since the sign-in, so a refreshed
			// authentication time differs from the one the session holds.
			h.clock.Advance(10 * time.Minute)

			c, err := h.build(nil)
			require.NoError(t, err)

			tc.assert(t, h, s, serve(t, c, tc.request(t.Context(), t, mfaTokenFor(s.ID))))
		})
	}
}

// TestReauthBegin pins the begin endpoint of a challenge method under
// re-authentication, and the re-proof challenges it issues: their own purpose,
// bound to the session that asked, with their own lifetime, issuance limit and
// store.
//
// The chain authenticates by bearer token over a scripted challenge method
// named "passkey" the user is enrolled on, and keeps login and re-proof
// challenges in one store.
func TestReauthBegin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// wire configures the harness and the method before the chain is
		// built.
		wire func(h *reauthHarness, stub *challengeStub)
		// act serves whatever requests the case is about and returns the last
		// response.
		act    func(t *testing.T, e *reauthEnv) served
		assert func(t *testing.T, e *reauthEnv, out served)
	}

	// underAllowance lets the throttle be consulted any number of times and
	// expects failures failures recorded.
	underAllowance := func(failures int) func(*reauthHarness, *challengeStub) {
		return func(h *reauthHarness, _ *challengeStub) {
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).AnyTimes()
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(nil).Times(failures)
		}
	}

	with := func(base func(*reauthHarness, *challengeStub), opts ...httpsec.ReauthenticationOption) func(*reauthHarness, *challengeStub) {
		return func(h *reauthHarness, stub *challengeStub) {
			base(h, stub)
			h.reauthOpts = append(h.reauthOpts, opts...)
		}
	}

	untouched := func(h *reauthHarness, _ *challengeStub) { h.neverChecked().recordsNoFailure() }

	beginAt := func(path string) func(*testing.T, *reauthEnv) served {
		return func(t *testing.T, e *reauthEnv) served {
			return e.serve(t, bearerPost(t.Context(), path, e.token()))
		}
	}

	// invalidAndUnverified is a re-proof refused as an invalid code before the
	// method was asked, leaving the session as it was.
	invalidAndUnverified := func(t *testing.T, e *reauthEnv, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
		assert.False(t, out.handlerRan)
		assert.Equal(t, int32(0), e.stub.verifyCalls.Load(), "the method was never asked")
		unchanged(t, e.h, e.s)
	}

	// refusedBegin is a begin refused before anything was issued.
	refusedBegin := func(want error) func(*testing.T, *reauthEnv, served) {
		return func(t *testing.T, e *reauthEnv, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "nothing was written")
			assert.Empty(t, e.stub.lastIssued(), "no challenge was issued")
		}
	}

	cases := []testCase{
		{
			// "Begin".
			name: "a begin answers the method's challenge document, not to be cached",
			wire: underAllowance(0),
			act:  func(t *testing.T, e *reauthEnv) served { return e.begin(t, e.token()) },
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint is the library's own")
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				challenge := issuedChallenge(t, out)
				require.NotEmpty(t, challenge)
				assert.Equal(t, e.stub.lastIssued(), challenge, "the method's document is written unchanged")
				assert.Equal(t, int32(0), e.stub.verifyCalls.Load(), "a begin verifies nothing")
				unchanged(t, e.h, e.s)
			},
		},
		{
			name: "a consumer begin responder owns the response",
			wire: with(underAllowance(0), httpsec.WithReauthenticationBeginResponder(
				func(ex *httpsec.Exchange, _ json.RawMessage) error {
					ex.Writer.WriteHeader(http.StatusAccepted)

					return nil
				})),
			act: func(t *testing.T, e *reauthEnv) served { return e.begin(t, e.token()) },
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusAccepted, out.rec.Code)
				assert.Empty(t, out.rec.Header().Get("Cache-Control"), "the consumer's responder owns its headers")
				assert.NotEmpty(t, e.stub.lastIssued(), "the challenge was issued")
			},
		},
		{
			name: "a challenge answered within its lifetime re-proves",
			wire: underAllowance(0),
			act: func(t *testing.T, e *reauthEnv) served {
				challenge := e.begun(t, e.token())
				e.h.clock.Advance(4 * time.Minute)

				return e.answer(t, e.token(), challenge)
			},
			assert: func(t *testing.T, e *reauthEnv, out served) {
				reproved(t, e.h, e.s, out)
				assert.Equal(t, int32(1), e.stub.verifyCalls.Load())
			},
		},
		{
			// A spent challenge stays spent, whatever the method answered.
			name: "a challenge the method refused cannot be answered again",
			wire: func(h *reauthHarness, stub *challengeStub) {
				underAllowance(2)(h, stub)
				stub.verifyErr = mfa.ErrInvalidCode
			},
			act: func(t *testing.T, e *reauthEnv) served {
				challenge := e.begun(t, e.token())

				first := e.answer(t, e.token(), challenge)
				require.ErrorIs(t, first.err, mfa.ErrInvalidCode)

				e.stub.verifyErr = nil

				return e.answer(t, e.token(), challenge)
			},
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, int32(1), e.stub.verifyCalls.Load(), "the second answer never reached the method")
				unchanged(t, e.h, e.s)
			},
		},
		{
			// "A login challenge is refused".
			name: "a login challenge does not answer a re-proof, and is counted",
			wire: underAllowance(1),
			act: func(t *testing.T, e *reauthEnv) served {
				pending := e.h.newSession(t, factor.Password, session.MFAPending)

				out := e.serve(t, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(pending.ID)))
				require.NoError(t, out.err)

				return e.answer(t, e.token(), issuedChallenge(t, out))
			},
			assert: invalidAndUnverified,
		},
		{
			name: "a re-proof challenge does not answer a login, and is counted",
			wire: underAllowance(1),
			act: func(t *testing.T, e *reauthEnv) served {
				pending := e.h.newSession(t, factor.Password, session.MFAPending)
				challenge := e.begun(t, e.token())

				return e.serve(t, bearerJSON(t.Context(), httpsec.DefaultMFAVerifyPrefix+"/"+passkey.MethodName,
					mfaTokenFor(pending.ID), answer(challenge)))
			},
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, int32(0), e.stub.verifyCalls.Load(), "the method was never asked")
			},
		},
		{
			// "Another session's challenge".
			name: "another session's re-proof challenge is refused, and counted",
			wire: underAllowance(1),
			act: func(t *testing.T, e *reauthEnv) served {
				other := e.h.fullSession(t, factor.Password)
				challenge := e.begun(t, mfaTokenFor(other.ID))

				return e.answer(t, e.token(), challenge)
			},
			assert: invalidAndUnverified,
		},
		{
			// "Expired challenge".
			name: "a challenge answered six minutes after it was issued is refused",
			wire: underAllowance(1),
			act: func(t *testing.T, e *reauthEnv) served {
				challenge := e.begun(t, e.token())
				e.h.clock.Advance(6 * time.Minute)

				return e.answer(t, e.token(), challenge)
			},
			assert: invalidAndUnverified,
		},
		{
			// "Consumer lifetime".
			name: "a consumer lifetime of two minutes refuses an answer at three",
			wire: with(underAllowance(1), httpsec.WithReauthenticationChallengeTTL(2*time.Minute)),
			act: func(t *testing.T, e *reauthEnv) served {
				challenge := e.begun(t, e.token())
				e.h.clock.Advance(3 * time.Minute)

				return e.answer(t, e.token(), challenge)
			},
			assert: invalidAndUnverified,
		},
		{
			// "Issuance limit".
			name: "the eleventh begin within an hour is refused and issues nothing",
			wire: underAllowance(0),
			act: func(t *testing.T, e *reauthEnv) served {
				for range httpsec.DefaultMFAChallengeLimit {
					e.begun(t, e.token())
				}

				return e.begin(t, e.token())
			},
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.Zero(t, out.rec.Body.Len(), "nothing was written")
				assert.Len(t, e.stub.issued, httpsec.DefaultMFAChallengeLimit, "no eleventh challenge was issued")
			},
		},
		{
			name: "a consumer issuance limit refuses the begin past it",
			wire: with(underAllowance(0), httpsec.WithReauthenticationChallengeLimit(2)),
			act: func(t *testing.T, e *reauthEnv) served {
				e.begun(t, e.token())
				e.begun(t, e.token())

				return e.begin(t, e.token())
			},
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.Len(t, e.stub.issued, 2)
			},
		},
		{
			// The re-proof limit is its own: a user who used up the login
			// challenge limit can still begin a re-proof.
			name: "the login challenge limit does not govern re-proof challenges",
			wire: with(underAllowance(0)),
			act: func(t *testing.T, e *reauthEnv) served {
				pending := e.h.newSession(t, factor.Password, session.MFAPending)
				for range httpsec.DefaultMFAChallengeLimit {
					out := e.serve(t, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(pending.ID)))
					require.NoError(t, out.err)
				}

				return e.begin(t, e.token())
			},
			assert: func(t *testing.T, _ *reauthEnv, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "a throttled user's begin is refused and issues nothing",
			wire: func(h *reauthHarness, _ *challengeStub) { h.throttles().recordsNoFailure() },
			act:  func(t *testing.T, e *reauthEnv) served { return e.begin(t, e.token()) },
			assert: func(t *testing.T, e *reauthEnv, out served) {
				refusedBegin(mfa.ErrVerifyThrottled)(t, e, out)
			},
		},
		{
			name:   "a begin for a method without a begin step is unknown",
			wire:   untouched,
			act:    beginAt(reauthBeginPrefix + "/totp"),
			assert: refusedBegin(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:   "a begin for an unknown method is unknown",
			wire:   untouched,
			act:    beginAt(reauthBeginPrefix + "/sms"),
			assert: refusedBegin(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:   "a begin path with an empty method segment is unknown",
			wire:   untouched,
			act:    beginAt(reauthBeginPrefix + "/"),
			assert: refusedBegin(httpsec.ErrUnknownMFAMethod),
		},
		{
			name: "a begin for a method the user is not enrolled on is refused",
			wire: func(h *reauthHarness, stub *challengeStub) {
				untouched(h, stub)
				stub.enrolled = false
			},
			act:    beginAt(reauthBeginPasskey),
			assert: refusedBegin(httpsec.ErrReauthenticationMethodNotUsable),
		},
		{
			name: "a consumer store keeps the re-proof challenges under their own purpose",
			wire: func(h *reauthHarness, stub *challengeStub) {
				underAllowance(0)(h, stub)
			},
			act: func(t *testing.T, e *reauthEnv) served { return e.begin(t, e.token()) },
			assert: func(t *testing.T, e *reauthEnv, out served) {
				require.NoError(t, out.err)

				store := e.h.reauthStore
				n, err := store.CountRecentBySubject(t.Context(), "reauth-challenge:passkey", string(testMFAUser), time.Time{})
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the challenge is in the consumer's store under the re-proof purpose")

				n, err = store.CountRecentBySubject(t.Context(), "mfa-challenge:passkey", string(testMFAUser), time.Time{})
				require.NoError(t, err)
				assert.Zero(t, n, "nothing was issued under the login purpose")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := reauthBearer(t)
			h.neverVerifies()

			stub := newChallengeStub()
			h.extra = []mfa.Method{stub}

			store, err := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(h.clock))
			require.NoError(t, err)

			// One store for login and re-proof challenges, so only their
			// purposes keep them apart.
			h.reauthStore = store
			h.reauthOpts = append(h.reauthOpts, httpsec.WithReauthenticationChallengeStore(store))
			h.mfaOpts = append(h.mfaOpts, httpsec.WithMFAChallengeStore(store))

			tc.wire(h, stub)

			c, err := h.build(nil)
			require.NoError(t, err)

			e := &reauthEnv{h: h, stub: stub, c: c, s: h.fullSession(t, factor.Password)}

			tc.assert(t, e, tc.act(t, e))
		})
	}
}

// reauthDeployment is the end-to-end deployment with re-authentication on:
// form login, a bearer, the MFA slot over the real TOTP method and the passkey
// method, and passwordless passkey login.
func reauthDeployment(t *testing.T) *pwlDeployment {
	t.Helper()

	// The deployment's chain enables re-authentication already: MFA and
	// passkeys on one chain need it.
	return newPwlDeployment(t)
}

// enrolledTOTP enrols the user on the deployment's TOTP method and returns the
// secret, moving the TOTP clock past the step the enrolment confirmed.
func enrolledTOTP(t *testing.T, d *pwlDeployment) string {
	t.Helper()

	prov, err := d.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, d.totpClock.Now())
	require.NoError(t, err)

	require.NoError(t, d.totp.ConfirmEnrolment(t.Context(), e2eUser, code))
	d.totpClock.Advance(30 * time.Second)

	return prov.Secret
}

// totpCode is the code of secret at the TOTP clock's current step.
func totpCode(t *testing.T, d *pwlDeployment, secret string) string {
	t.Helper()

	code, err := totp.GenerateCode(secret, d.totpClock.Now())
	require.NoError(t, err)

	return code
}

// wrongCode is a code differing from code in its first digit.
func wrongCode(code string) string {
	return string('0'+(code[0]-'0'+1)%10) + code[1:]
}

// postTOTP posts code to path with tok.
func postTOTP(t *testing.T, d *pwlDeployment, path, tok, code string) served {
	t.Helper()

	return serve(t, d.chain, bearerRequestTo(t.Context(), http.MethodPost, path, tok,
		url.Values{"code": {code}}.Encode()))
}

// fullAfterTOTP signs the user in with their password and completes the
// second factor with the TOTP code at the current step, returning the full
// session's credential.
func fullAfterTOTP(t *testing.T, d *pwlDeployment, secret string) string {
	t.Helper()

	ch := challenged(t, d.passwordLogin(t))
	out := postTOTP(t, d, httpsec.DefaultMFAVerifyPrefix+"/totp", ch.Token, totpCode(t, d, secret))
	require.NoError(t, out.err)

	return accessTokenFrom(t, out)
}

// passkeyLogin signs the user in with passkey credID and returns the full
// session's credential.
func passkeyLogin(t *testing.T, d *pwlDeployment, credID string) string {
	t.Helper()

	out := d.login(t, credID, d.seed(t, e2eUser, credID, passkey.StateActive))
	require.NoError(t, out.err)

	return accessTokenFrom(t, out)
}

// reauthPasskey begins and answers a passkey re-proof from credential credID
// with tok.
func reauthPasskey(t *testing.T, d *pwlDeployment, tok, credID string) served {
	t.Helper()

	begun := serve(t, d.chain, bearerPost(t.Context(), reauthBeginPasskey, tok))
	require.NoError(t, begun.err)
	require.Equal(t, http.StatusOK, begun.rec.Code)

	return serve(t, d.chain, bearerJSON(t.Context(), reauthVerifyPasskey, tok,
		assertionBody(d.verifier.lastRequest(t), credID)))
}

// TestReauthVerifyEndToEnd drives second-factor re-proofs through a whole
// deployment, over the real TOTP method, the real passkey core and the MFA
// slot's default throttle, for the scenarios a scripted method cannot show.
func TestReauthVerifyEndToEnd(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		act    func(t *testing.T, d *pwlDeployment) (tok string, out served)
		assert func(t *testing.T, d *pwlDeployment, tok string, out served)
	}

	// metAt is when the passkey-login row's session met its second factor.
	var metAt time.Time

	cases := []testCase{
		{
			// "Valid TOTP code", on the real method.
			name:  "a valid TOTP code re-proves",
			setup: func(t *testing.T, d *pwlDeployment) { d.mfaLimiter = limiterCounting(t, 0) },
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				secret := enrolledTOTP(t, d)
				tok := fullAfterTOTP(t, d, secret)
				d.totpClock.Advance(30 * time.Second)

				return tok, postTOTP(t, d, reauthVerifyTOTP, tok, totpCode(t, d, secret))
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.NoError(t, out.err)

				rotated := accessTokenFrom(t, out)
				assert.NotEqual(t, tok, rotated)
				d.sessionGone(t, sessionIDOf(t, tok), "the handle the caller arrived with is gone")
				assert.Equal(t, session.MFASatisfied, d.sessionOf(t, rotated).MFA)
			},
		},
		{
			// "A code already used".
			name:  "a TOTP code whose step was already accepted is refused",
			setup: func(t *testing.T, d *pwlDeployment) { d.mfaLimiter = limiterCounting(t, 1) },
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				secret := enrolledTOTP(t, d)
				tok := fullAfterTOTP(t, d, secret)

				return tok, postTOTP(t, d, reauthVerifyTOTP, tok, totpCode(t, d, secret))
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, sessionIDOf(t, tok), d.sessionOf(t, tok).ID, "the session is unchanged")
			},
		},
		{
			// "One throttle with the login second factor", on the default
			// throttle: five failures per user in fifteen minutes.
			name: "failures at login and at re-proof share one throttle",
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				secret := enrolledTOTP(t, d)

				pending := challenged(t, d.passwordLogin(t))
				tok := fullAfterTOTP(t, d, secret)
				d.totpClock.Advance(30 * time.Second)

				wrong := wrongCode(totpCode(t, d, secret))
				for range 4 {
					out := postTOTP(t, d, httpsec.DefaultMFAVerifyPrefix+"/totp", pending.Token, wrong)
					require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				}

				out := postTOTP(t, d, reauthVerifyTOTP, tok, wrong)
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)

				return tok, postTOTP(t, d, reauthVerifyTOTP, tok, totpCode(t, d, secret))
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.Equal(t, sessionIDOf(t, tok), d.sessionOf(t, tok).ID, "the session is unchanged")
			},
		},
		{
			// "A passkey login re-proves with the passkey".
			name:  "a passkey login re-proves with the passkey",
			setup: func(t *testing.T, d *pwlDeployment) { d.mfaLimiter = limiterCounting(t, 0) },
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				tok := passkeyLogin(t, d, "cred-1")
				login := d.sessionOf(t, tok)
				require.Equal(t, factor.Passkey, login.FirstFactor)
				require.Equal(t, session.MFASatisfied, login.MFA, "the passkey login met the second factor")
				metAt = login.MFASatisfiedAt

				return tok, reauthPasskey(t, d, tok, "cred-1")
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.NoError(t, out.err, "no same-channel refusal")
				assert.NotErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				rotated := accessTokenFrom(t, out)
				assert.NotEqual(t, tok, rotated)
				d.sessionGone(t, sessionIDOf(t, tok), "the handle the caller arrived with is gone")

				s := d.sessionOf(t, rotated)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.Equal(t, factor.Passkey, s.FirstFactor)
				assert.True(t, s.MFASatisfiedAt.Equal(metAt),
					"a same-channel re-proof leaves the time the second factor was met: %s, was %s", s.MFASatisfiedAt, metAt)
			},
		},
		{
			// "Suspected clone".
			name:  "a suspected clone is refused unchanged, not counted, and ends the user's sessions",
			setup: func(t *testing.T, d *pwlDeployment) { d.mfaLimiter = limiterCounting(t, 0) },
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				tok := passkeyLogin(t, d, "cred-1")
				d.seedCounted(t, e2eUser, "cred-2", passkey.StateActive, 5)
				d.otherSession(t)

				return tok, reauthPasskey(t, d, tok, "cred-2")
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, out.err, mfa.ErrAuthenticatorRefused)
				assert.NotErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

				d.sessionGone(t, sessionIDOf(t, tok), "the re-proving session is ended")
				assert.Zero(t, d.sessionCount(t, out), "no session of the user is left")
			},
		},
		{
			// "Suspended passkey".
			name:  "a suspended passkey is refused unchanged and not counted",
			setup: func(t *testing.T, d *pwlDeployment) { d.mfaLimiter = limiterCounting(t, 0) },
			act: func(t *testing.T, d *pwlDeployment) (string, served) {
				tok := passkeyLogin(t, d, "cred-1")
				d.seed(t, e2eUser, "cred-2", passkey.StateSuspended)

				return tok, reauthPasskey(t, d, tok, "cred-2")
			},
			assert: func(t *testing.T, d *pwlDeployment, tok string, out served) {
				require.ErrorIs(t, out.err, passkey.ErrSuspended)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Equal(t, sessionIDOf(t, tok), d.sessionOf(t, tok).ID, "the session is unchanged")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := reauthDeployment(t)
			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)

			tok, out := tc.act(t, d)
			tc.assert(t, d, tok, out)
		})
	}
}
