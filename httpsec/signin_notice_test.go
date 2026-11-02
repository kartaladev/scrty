package httpsec_test

// The sign-in notice tests run form login on a real session manager over the
// memory store, because what they pin is how a stored sign-in compares with
// the user's other live sign-ins in that store.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// User agents of common browsers, as they send them.
const (
	uaFirefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	uaSafariMac    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/18.5 Safari/605.1.15"
	uaChromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)

// nonBlockingSender is a mocked sender that reports it does not wait for
// delivery, as a queued sender does.
type nonBlockingSender struct{ *MockSender }

func (nonBlockingSender) NonBlocking() bool { return true }

// noticeStore is the fixture's memory store, whose creating write fails once
// armed, and whose listing waits for listGate when one is set and counts its
// calls.
type noticeStore struct {
	session.Store

	failCreate atomic.Bool
	listGate   <-chan struct{}
	lists      atomic.Int32
}

func (s *noticeStore) Create(ctx context.Context, sess *session.Session) error {
	if s.failCreate.Load() {
		return errors.New("pq: could not insert into sessions on 10.0.0.7")
	}

	return s.Store.Create(ctx, sess)
}

func (s *noticeStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	s.lists.Add(1)

	if s.listGate != nil {
		select {
		case <-s.listGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return s.Store.ListByUser(ctx, user, now)
}

// noticeFixture is a chain with form login and the sign-in notice over one
// session manager that records sign-in metadata.
type noticeFixture struct {
	clk      *clockwork.FakeClock
	store    *noticeStore
	sessions *session.Sessions
	chain    *httpsec.Chain
	logs     *lockedBuffer

	// pending counts the notice's background work, which await waits for.
	pending sync.WaitGroup

	mu   sync.Mutex
	sent []notify.Message
}

// noticeSetup is what one case changes about the fixture.
type noticeSetup struct {
	opts    []httpsec.SignInNoticeOption
	sendErr error

	// seen, when set, wires a mocked seen-devices port it sets expectations
	// on.
	seen func(m *MockSeenDevices)

	// listGate, when set, holds every listing until it is closed.
	listGate <-chan struct{}
}

func newNoticeFixture(t *testing.T, setup noticeSetup) *noticeFixture {
	t.Helper()

	f := &noticeFixture{
		clk:  clockwork.NewFakeClockAt(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)),
		logs: &lockedBuffer{},
	}
	ctrl := gomock.NewController(t)

	f.store = &noticeStore{
		Store:    must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))),
		listGate: setup.listGate,
	}
	f.sessions = must.Must(session.New(session.WithClock(f.clk), session.WithStore(f.store),
		session.WithSessionMetadata()))

	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			return &authenticate.Authentication{
				Principal: &identity.Principal{ID: "u-1", Username: "ada@example.com"},
				Time:      f.clk.Now(),
			}, nil
		}).AnyTimes()

	sender := NewMockSender(ctrl)
	sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, m notify.Message) error {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.sent = append(f.sent, m)

		return setup.sendErr
	}).AnyTimes()

	opts := append([]httpsec.SignInNoticeOption{httpsec.WithSignInNoticeTracker(&f.pending)}, setup.opts...)
	if setup.seen != nil {
		seen := NewMockSeenDevices(ctrl)
		setup.seen(seen)
		opts = append(opts, httpsec.WithSeenDevices(seen))
	}

	lockoutPolicy := must.Must(lockout.New())

	var err error

	f.chain, err = httpsec.New(
		httpsec.WithClock(f.clk),
		httpsec.WithLogger(slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: f.sessions, Attempts: lockoutPolicy.Attempts(),
		}),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: NewMockUserLoader(ctrl)}),
		httpsec.EnableSignInNotice(nonBlockingSender{sender}, opts...),
	)
	require.NoError(t, err)

	return f
}

// signedIn stores a live sign-in of user from userAgent, as an earlier login
// would have.
func (f *noticeFixture) signedIn(t *testing.T, user identity.UserID, userAgent string) *session.Session {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password),
		session.WithClientMetadata("198.51.100.4", userAgent))
	require.NoError(t, err)

	return s
}

// loginRequest is a form login from userAgent.
func loginRequest(ctx context.Context, userAgent string) *http.Request {
	req := formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=pw")
	req.Header.Set("User-Agent", userAgent)
	req.RemoteAddr = "203.0.113.7:51000"

	return req
}

// login runs a form login from userAgent, and waits for the notice's
// background work to finish.
func (f *noticeFixture) login(t *testing.T, userAgent string) served {
	t.Helper()

	out := serve(t, f.chain, loginRequest(t.Context(), userAgent))
	f.pending.Wait()

	return out
}

// loginOn runs a form login from userAgent on ctx, and returns as soon as the
// chain answers, without waiting for the notice's background work.
func (f *noticeFixture) loginOn(ctx context.Context, userAgent string) served {
	out := served{rec: httptest.NewRecorder()}
	run := f.chain.Assemble(func(*httpsec.Exchange) error { return nil }) //nolint:contextcheck // the exchange carries the request context, and begin reads it through ex.Context()

	ex := httpsec.NewExchange(ctx,
		httpsec.NewHTTPRequest(loginRequest(ctx, userAgent)), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

func (f *noticeFixture) messages() []notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]notify.Message(nil), f.sent...)
}

// answersWithin runs fn and fails the test when it has not returned within
// d: the response was held up.
func answersWithin(t *testing.T, d time.Duration, fn func() served) served {
	t.Helper()

	done := make(chan served, 1)
	go func() { done <- fn() }()

	select {
	case out := <-done:
		return out
	case <-time.After(d):
		t.Fatalf("the sign-in's response did not return within %s: the notice is on the request path", d)

		return served{}
	}
}

// TestSignInNotice pins when a sign-in from an unseen device notifies the
// user, what the notice says, and that the notice never changes the sign-in.
func TestSignInNotice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  noticeSetup
		assert func(t *testing.T, f *noticeFixture)
	}

	succeeded := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		require.Equal(t, http.StatusOK, out.rec.Code)
	}

	cases := []testCase{
		{
			name: "New browser: a sign-in beside a live one from another browser notifies the user",
			assert: func(t *testing.T, f *noticeFixture) {
				laptop := f.signedIn(t, "u-1", uaFirefoxLinux)

				out := f.login(t, uaSafariMac)
				succeeded(t, out)

				msgs := f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "ada@example.com", msgs[0].To)
				assert.Contains(t, msgs[0].TextBody, "Safari on macOS")
				assert.Contains(t, msgs[0].TextBody, "2026-11-02")

				signIns, err := f.sessions.ListSignIns(t.Context(), "u-1", nil)
				require.NoError(t, err)
				for _, si := range signIns {
					assert.NotContains(t, msgs[0].TextBody, si.Handle.String(), "no session handle")
				}

				var body loginBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
				require.NotEmpty(t, body.AccessToken)

				for _, leak := range []string{body.AccessToken, laptop.ID, "203.0.113.7", uaSafariMac, "Macintosh"} {
					assert.NotContains(t, msgs[0].TextBody+msgs[0].Subject, leak,
						"no credential, session identifier, client address or raw user agent")
				}
			},
		},
		{
			name: "the sign-in records the client address and the user agent",
			assert: func(t *testing.T, f *noticeFixture) {
				succeeded(t, f.login(t, uaSafariMac))

				signIns, err := f.sessions.ListSignIns(t.Context(), "u-1", nil)
				require.NoError(t, err)
				require.Len(t, signIns, 1)
				assert.Equal(t, "203.0.113.7", signIns[0].ClientIP)
				assert.Equal(t, uaSafariMac, signIns[0].UserAgent)
			},
		},
		{
			name: "Known browser: a sign-in from a browser a live sign-in used sends nothing",
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaFirefoxLinux))
				assert.Empty(t, f.messages())
			},
		},
		{
			name: "First sign-in: a user with no other live sign-in is not notified",
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-2", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Empty(t, f.messages())
			},
		},
		{
			name: "a device the seen-devices port knows sends nothing",
			setup: noticeSetup{seen: func(m *MockSeenDevices) {
				m.EXPECT().Seen(gomock.Any(), identity.UserID("u-1"), uaSafariMac).Return(true, nil)
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Empty(t, f.messages())
			},
		},
		{
			name: "a device the seen-devices port does not know is notified",
			setup: noticeSetup{seen: func(m *MockSeenDevices) {
				m.EXPECT().Seen(gomock.Any(), identity.UserID("u-1"), uaSafariMac).Return(false, nil)
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Len(t, f.messages(), 1)
			},
		},
		{
			name: "a seen-devices port that fails sends nothing, is logged, and the sign-in stands",
			setup: noticeSetup{seen: func(m *MockSeenDevices) {
				m.EXPECT().Seen(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, errors.New("redis: 10.0.0.9 timed out"))
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Empty(t, f.messages())
				assert.Contains(t, f.logs.String(), "sign-in notice")
				assert.NotContains(t, f.logs.String(), "10.0.0.9")
			},
		},
		{
			name: "a replaced matcher decides what counts as the same device",
			setup: noticeSetup{opts: []httpsec.SignInNoticeOption{
				httpsec.WithSignInMatcher(func(signedIn, known session.SignIn) bool {
					return strings.Contains(signedIn.UserAgent, "Firefox/") &&
						strings.Contains(known.UserAgent, "Firefox/")
				}),
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, strings.Replace(uaFirefoxLinux, "140.0", "141.0", 2)))
				assert.Empty(t, f.messages(), "the consumer's matcher counts any Firefox as seen")

				succeeded(t, f.login(t, uaSafariMac))
				assert.Len(t, f.messages(), 1)
			},
		},
		{
			name: "Sign-in not stored: a sign-in whose session was never stored sends nothing and lists nothing",
			assert: func(t *testing.T, f *noticeFixture) {
				// Another live sign-in from another device, so the first-sign-in
				// rule cannot be what keeps the notice quiet.
				f.signedIn(t, "u-1", uaFirefoxLinux)
				f.store.failCreate.Store(true)

				out := f.login(t, uaSafariMac)
				require.Error(t, out.err)
				assert.Empty(t, f.messages())
				assert.Zero(t, f.store.lists.Load(), "the notice does no work for a sign-in never stored")
			},
		},
		{
			name:  "a send failure is logged without its text and does not affect the sign-in",
			setup: noticeSetup{sendErr: errors.New("smtp: 10.0.0.8 refused ada@example.com")},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Len(t, f.messages(), 1)

				logs := f.logs.String()
				assert.Contains(t, logs, "sign-in notice")
				for _, leak := range []string{"10.0.0.8", "ada@example.com", uaSafariMac, "203.0.113.7"} {
					assert.NotContains(t, logs, leak)
				}
			},
		},
		{
			name: "the consumer's recipient and message replace the defaults",
			setup: noticeSetup{opts: []httpsec.SignInNoticeOption{
				httpsec.WithSignInNoticeRecipient(func(_ context.Context, p *identity.Principal) (string, error) {
					return string(p.ID) + "@users.example.com", nil
				}),
				httpsec.WithSignInNoticeMessage(func(facts httpsec.SignInNoticeFacts) (string, string) {
					return "Hello", "device=" + facts.Device + " at=" + facts.At.Format(time.RFC3339)
				}),
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaChromeWindows))

				msgs := f.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "u-1@users.example.com", msgs[0].To)
				assert.Equal(t, "Hello", msgs[0].Subject)
				assert.Equal(t, "device=Chrome on Windows at=2026-11-02T09:00:00Z", msgs[0].TextBody)
			},
		},
		{
			name: "a matcher that panics sends nothing, is logged, and the sign-in stands",
			setup: noticeSetup{opts: []httpsec.SignInNoticeOption{
				httpsec.WithSignInMatcher(func(session.SignIn, session.SignIn) bool {
					panic("matcher bug on 10.0.0.6")
				}),
			}},
			assert: func(t *testing.T, f *noticeFixture) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				succeeded(t, f.login(t, uaSafariMac))
				assert.Empty(t, f.messages())
				assert.Contains(t, f.logs.String(), "sign-in notice")
				assert.NotContains(t, f.logs.String(), "10.0.0.6")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newNoticeFixture(t, tc.setup))
		})
	}
}

// TestSignInNotice_OffTheRequestPath pins that the notice's work never holds
// up the sign-in's response, outlives the request's context, and ends at its
// timeout.
func TestSignInNotice_OffTheRequestPath(t *testing.T) {
	t.Parallel()

	const prompt = 5 * time.Second

	type testCase struct {
		name   string
		setup  func(release <-chan struct{}) noticeSetup
		assert func(t *testing.T, f *noticeFixture, release chan struct{})
	}

	// blockingSeen holds the port until release is closed or its context
	// ends, and records in ended, when it is given, whether the context had
	// ended when it answered.
	blockingSeen := func(release <-chan struct{}, ended *atomic.Bool) func(m *MockSeenDevices) {
		return func(m *MockSeenDevices) {
			m.EXPECT().Seen(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ identity.UserID, _ string) (bool, error) {
					select {
					case <-release:
						if ended != nil {
							ended.Store(ctx.Err() != nil)
						}

						return false, nil
					case <-ctx.Done():
						return false, ctx.Err()
					}
				})
		}
	}

	// respondsThenNotifies serves a sign-in on a context it cancels as soon as
	// the response is in, then releases the blocked port and waits for the
	// notice.
	respondsThenNotifies := func(t *testing.T, f *noticeFixture, release chan struct{}) {
		t.Helper()

		f.signedIn(t, "u-1", uaFirefoxLinux)

		ctx, cancel := context.WithCancel(t.Context())
		out := answersWithin(t, prompt, func() served { return f.loginOn(ctx, uaSafariMac) })
		cancel()

		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.Empty(t, f.messages(), "the notice is still waiting on its port")

		close(release)
		f.pending.Wait()

		assert.Len(t, f.messages(), 1, "the notice is sent once its port answers")
	}

	cases := []testCase{
		func() testCase {
			// Only this case reads whether the port's context had ended.
			var ended atomic.Bool

			return testCase{
				name: "a seen-devices port that blocks does not delay the response, nor does the request's end stop it",
				setup: func(release <-chan struct{}) noticeSetup {
					return noticeSetup{seen: blockingSeen(release, &ended)}
				},
				assert: func(t *testing.T, f *noticeFixture, release chan struct{}) {
					respondsThenNotifies(t, f, release)
					assert.False(t, ended.Load(), "the notice's context is not the request's")
				},
			}
		}(),
		{
			name: "a listing that blocks does not delay the response",
			setup: func(release <-chan struct{}) noticeSetup {
				return noticeSetup{listGate: release}
			},
			assert: func(t *testing.T, f *noticeFixture, release chan struct{}) {
				// The seeding sign-in lists nothing; the gate holds the
				// notice's listing only.
				respondsThenNotifies(t, f, release)
			},
		},
		{
			name: "a port that never answers is abandoned at the notice's timeout, which is logged",
			setup: func(release <-chan struct{}) noticeSetup {
				return noticeSetup{
					seen: blockingSeen(release, nil),
					opts: []httpsec.SignInNoticeOption{httpsec.WithSignInNoticeTimeout(20 * time.Millisecond)},
				}
			},
			assert: func(t *testing.T, f *noticeFixture, _ chan struct{}) {
				f.signedIn(t, "u-1", uaFirefoxLinux)

				out := answersWithin(t, prompt, func() served { return f.loginOn(t.Context(), uaSafariMac) })
				require.NoError(t, out.err)

				f.pending.Wait() // ends only because the timeout ended the port's wait

				assert.Empty(t, f.messages())
				assert.Contains(t, f.logs.String(), "sign-in notice")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			release := make(chan struct{})
			tc.assert(t, newNoticeFixture(t, tc.setup(release)), release)
		})
	}
}

// TestSignInNotice_DeviceDescription pins the device text a notice carries:
// a browser and platform family from a fixed vocabulary, never the raw user
// agent or any part of it.
func TestSignInNotice_DeviceDescription(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		userAgent string
		assert    func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	cases := []testCase{
		{name: "Firefox on Linux", userAgent: uaFirefoxLinux, assert: is("Firefox on Linux")},
		{name: "Safari on macOS", userAgent: uaSafariMac, assert: is("Safari on macOS")},
		{name: "Chrome on Windows", userAgent: uaChromeWindows, assert: is("Chrome on Windows")},
		{
			name: "Edge on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
				"Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
			assert: is("Edge on Windows"),
		},
		{
			name: "Opera on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
				"Chrome/138.0.0.0 Safari/537.36 OPR/120.0.0.0",
			assert: is("Opera on Windows"),
		},
		{
			name: "Chrome on Android",
			userAgent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) " +
				"Chrome/138.0.0.0 Mobile Safari/537.36",
			assert: is("Chrome on Android"),
		},
		{
			name: "Samsung Internet on Android",
			userAgent: "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) " +
				"SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36",
			assert: is("Samsung Internet on Android"),
		},
		{
			name: "Safari on iOS",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 " +
				"(KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
			assert: is("Safari on iOS"),
		},
		{
			name: "Chrome on iOS",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 " +
				"(KHTML, like Gecko) CriOS/138.0.7204.119 Mobile/15E148 Safari/604.1",
			assert: is("Chrome on iOS"),
		},
		{
			name: "Firefox on iOS",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 " +
				"(KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15",
			assert: is("Firefox on iOS"),
		},
		{
			name: "Chrome on ChromeOS",
			userAgent: "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) " +
				"Chrome/138.0.0.0 Safari/537.36",
			assert: is("Chrome on ChromeOS"),
		},
		{name: "a known browser on an unknown platform names the browser", userAgent: "Firefox/140.0",
			assert: is("Firefox")},
		{name: "no user agent", userAgent: "", assert: is("an unrecognised device")},
		{name: "a command-line client", userAgent: "curl/8.7.1", assert: is("an unrecognised device")},
		{
			name:      "a crawler naming a URL",
			userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			assert:    is("an unrecognised device"),
		},
		{
			name:      "a phishing link dressed as a browser keeps only the families",
			userAgent: "Mozilla/5.0 (Windows NT 10.0) Firefox/140.0 call +1-555-0100 or visit https://evil.example/reset",
			assert: func(t *testing.T, got string) {
				t.Helper()
				assert.Equal(t, "Firefox on Windows", got)
			},
		},
		{name: "markup", userAgent: "<script>alert(1)</script>", assert: is("an unrecognised device")},
		{name: "header injection", userAgent: "Safari/19\r\nBcc: x@example.com", assert: is("an unrecognised device")},
		{name: "invalid UTF-8", userAgent: "\xff\xfe Chrome", assert: is("an unrecognised device")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.SignInDeviceDescription(tc.userAgent))
		})
	}
}

// blockingSender is a sender that waits for delivery: it does not report
// notify.NonBlocking.
type blockingSender struct{}

func (blockingSender) Send(context.Context, notify.Message) error { return nil }

// TestSignInNotice_Construction pins the wiring the chain refuses.
func TestSignInNotice_Construction(t *testing.T) {
	t.Parallel()

	withMetadata := must.Must(session.New(session.WithSessionMetadata()))
	withoutMetadata := must.Must(session.New())
	sender := nonBlockingSender{NewMockSender(gomock.NewController(t))}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(want ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
		}
	}

	cases := []testCase{
		{
			name:   "with a sender and a manager recording metadata",
			opts:   []httpsec.Option{httpsec.WithSessions(withMetadata), httpsec.EnableSignInNotice(sender)},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "Notice without metadata",
			opts:   []httpsec.Option{httpsec.WithSessions(withoutMetadata), httpsec.EnableSignInNotice(sender)},
			assert: refused("EnableSignInNotice", "WithSessionMetadata"),
		},
		{
			name:   "without a session manager",
			opts:   []httpsec.Option{httpsec.EnableSignInNotice(sender)},
			assert: refused("EnableSignInNotice"),
		},
		{
			name:   "without a sender",
			opts:   []httpsec.Option{httpsec.WithSessions(withMetadata), httpsec.EnableSignInNotice(nil)},
			assert: refused("EnableSignInNotice", "sender"),
		},
		{
			name:   "a sender that waits for delivery builds",
			opts:   []httpsec.Option{httpsec.WithSessions(withMetadata), httpsec.EnableSignInNotice(blockingSender{})},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "given twice",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender), httpsec.EnableSignInNotice(sender)},
			assert: refused("EnableSignInNotice"),
		},
		{
			name: "a nil matcher",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInMatcher(nil))},
			assert: refused("WithSignInMatcher"),
		},
		{
			name: "a nil seen-devices port",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSeenDevices(nil))},
			assert: refused("WithSeenDevices"),
		},
		{
			name: "a nil recipient",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInNoticeRecipient(nil))},
			assert: refused("WithSignInNoticeRecipient"),
		},
		{
			name: "a nil message",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInNoticeMessage(nil))},
			assert: refused("WithSignInNoticeMessage"),
		},
		{
			name: "a zero timeout",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInNoticeTimeout(0))},
			assert: refused("WithSignInNoticeTimeout"),
		},
		{
			name: "a negative timeout",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInNoticeTimeout(-time.Second))},
			assert: refused("WithSignInNoticeTimeout"),
		},
		{
			name: "a positive timeout",
			opts: []httpsec.Option{httpsec.WithSessions(withMetadata),
				httpsec.EnableSignInNotice(sender, httpsec.WithSignInNoticeTimeout(time.Second))},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.opts...)
			tc.assert(t, err)
		})
	}
}

// TestSignInMetadata_RecordedWithoutNotice pins that the chain records the
// resolved client address and the request's user agent on every first
// factor's sign-in when its session manager records metadata, with no sign-in
// notice enabled.
func TestSignInMetadata_RecordedWithoutNotice(t *testing.T) {
	t.Parallel()

	const userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

	type testCase struct {
		name string
		// signIn signs in over sessions from userAgent, and returns the user
		// and the address the request came from.
		signIn func(t *testing.T, sessions *session.Sessions) (identity.UserID, string)
	}

	cases := []testCase{
		{
			name: "a magic-link sign-in",
			signIn: func(t *testing.T, sessions *session.Sessions) (identity.UserID, string) {
				t.Helper()

				h := newMagicLinkHarness(t)
				h.sessions = sessions
				c := h.chain(t)

				out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
					magicLinkSource, url.Values{"email": {magicLinkKnown}}))
				require.NoError(t, out.err)

				req := consumeWithNext(t, h.sender.lastToken(t),
					cookieNamed(out.rec, httpsec.DefaultBindingCookieName).Value, "/")
				req.Header.Set("User-Agent", userAgent)
				require.NoError(t, serve(t, c, req).err)

				return magicLinkUserID, magicLinkSource
			},
		},
		{
			name: "a passwordless passkey sign-in",
			signIn: func(t *testing.T, sessions *session.Sessions) (identity.UserID, string) {
				t.Helper()

				d := newPwlDeployment(t)
				d.sessions = sessions
				d.withoutPasskeyMFA = true
				d.required.on.Store(false)
				d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UserVerificationPreferred))
				d.verifier.notUserVerified.Store(true)
				d.build(t)

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				req := jsonPost(t.Context(), passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
				req.RemoteAddr = e2eSource + ":51000"
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie
				req.Header.Set("User-Agent", userAgent)
				require.NoError(t, serve(t, d.chain, req).err)

				return e2eUser, e2eSource
			},
		},
		{
			name: "an OIDC handoff sign-in",
			signIn: func(t *testing.T, sessions *session.Sessions) (identity.UserID, string) {
				t.Helper()

				h := newOIDCHarness(t)
				h.issueTokens()
				h.sessions = sessions

				req := handoffRequest(t.Context(), oidcTestSource, h.issueHandoff(t, ""))
				req.Header.Set("User-Agent", userAgent)
				require.NoError(t, serve(t, h.chain(t), req).err)

				return oidcTestUserID, oidcTestSource
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions := must.Must(session.New(session.WithSessionMetadata()))

			user, source := tc.signIn(t, sessions)

			signIns, err := sessions.ListSignIns(t.Context(), user, nil)
			require.NoError(t, err)
			require.Len(t, signIns, 1)
			assert.Equal(t, source, signIns[0].ClientIP)
			assert.Equal(t, userAgent, signIns[0].UserAgent)
		})
	}
}
