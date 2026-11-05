package httpsec_test

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// countingLoadStore counts the session reads a store is asked for. A manager with no end
// observer reads nothing before a Delete, so it shows whether a chain left one on it.
type countingLoadStore struct {
	session.Store

	loads atomic.Int64
}

func (s *countingLoadStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	s.loads.Add(1)

	return s.Store.Load(ctx, sid)
}

// waitlessClock is a chain clock with no After.
type waitlessClock struct{}

func (waitlessClock) Now() time.Time { return time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC) }

// constructionFixture is what a construction row builds a chain over.
type constructionFixture struct {
	sessions *session.Sessions
	store    *countingLoadStore
	users    *MockUserLoader
	bearer   httpsec.Option
}

func newConstructionFixture(t *testing.T, opts ...session.Option) *constructionFixture {
	t.Helper()

	store := &countingLoadStore{Store: must.Must(session.NewMemoryStore())}

	sessions, err := session.New(append([]session.Option{
		session.WithStore(store),
		session.WithIdleTimeout(30 * time.Minute),
	}, opts...)...)
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))

	return &constructionFixture{
		sessions: sessions,
		store:    store,
		users:    users,
		bearer:   httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
	}
}

// refusedNamingField asserts construction failed with a configuration error naming what.
func refusedNamingField(what ...string) func(*testing.T, *constructionFixture, *httpsec.Chain, error) {
	return func(t *testing.T, _ *constructionFixture, chain *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, chain)

		for _, w := range what {
			assert.Contains(t, err.Error(), w)
		}
	}
}

// resolved asserts construction succeeded, and checks what the stream settled on.
func resolved(check func(*testing.T, httpsec.SessionSignals)) func(*testing.T, *constructionFixture, *httpsec.Chain, error) {
	return func(t *testing.T, _ *constructionFixture, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)

		cfg, ok := httpsec.ResolvedSessionSignals(chain)
		require.True(t, ok, "the chain has no signal stream")

		if check != nil {
			check(t, cfg)
		}
	}
}

func TestSessionSignals_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// signals is what EnableSessionSignals is given.
		signals httpsec.SessionSignals

		// sessionOpts are added to the session manager's.
		sessionOpts []session.Option

		// opts replaces the bearer the chain is otherwise built with.
		opts func(t *testing.T, f *constructionFixture) []httpsec.Option

		assert func(t *testing.T, f *constructionFixture, chain *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "every default is filled",
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, "/session/signals", cfg.Path)
				assert.Equal(t, []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}, cfg.Signals)
				assert.Equal(t, 15*time.Second, cfg.Heartbeat)
				assert.Equal(t, 2*time.Minute, cfg.ExpiryWarning)
				assert.Equal(t, httpsec.DefaultRecentAuthenticationWindow, cfg.AssuranceWindow)
				assert.Equal(t, 4, cfg.MaxPerSignIn)
				assert.Equal(t, 16, cfg.MaxPerUser)
				assert.Equal(t, 10_000, cfg.MaxStreams)
				assert.Zero(t, cfg.MaxPerSource)
				assert.Equal(t, time.Hour, cfg.MaxAge)
				assert.Equal(t, 5*time.Second, cfg.ReconnectDelay)
				assert.Equal(t, 30*time.Second, cfg.BusyDelay)
				assert.NotNil(t, cfg.Users, "the built-in bearer's loader")
				assert.Equal(t, 7500*time.Millisecond, cfg.ReloadTimeout)
				assert.Nil(t, cfg.Bus)
			}),
		},
		{
			name: "a consumer's values are kept",
			signals: httpsec.SessionSignals{
				Path:           "/api/me/signals",
				Signals:        []httpsec.Signal{httpsec.SignalSessionExpiring, httpsec.SignalCredentialChanged},
				Heartbeat:      30 * time.Second,
				ExpiryWarning:  5 * time.Minute,
				MaxPerSignIn:   1,
				MaxPerUser:     2,
				MaxStreams:     3,
				MaxPerSource:   2,
				MaxAge:         10 * time.Minute,
				ReconnectDelay: time.Second,
				BusyDelay:      time.Minute,
				ReloadTimeout:  3 * time.Second,
			},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, "/api/me/signals", cfg.Path)
				assert.Equal(t, []httpsec.Signal{httpsec.SignalSessionExpiring, httpsec.SignalCredentialChanged}, cfg.Signals)
				assert.Equal(t, 30*time.Second, cfg.Heartbeat)
				assert.Equal(t, 5*time.Minute, cfg.ExpiryWarning)
				assert.Equal(t, 1, cfg.MaxPerSignIn)
				assert.Equal(t, 2, cfg.MaxPerUser)
				assert.Equal(t, 3, cfg.MaxStreams)
				assert.Equal(t, 2, cfg.MaxPerSource)
				assert.Equal(t, 10*time.Minute, cfg.MaxAge)
				assert.Equal(t, time.Second, cfg.ReconnectDelay)
				assert.Equal(t, time.Minute, cfg.BusyDelay)
				assert.Equal(t, 3*time.Second, cfg.ReloadTimeout)
			}),
		},
		{
			name:    "an unknown signal name is refused, naming it",
			signals: httpsec.SessionSignals{Signals: []httpsec.Signal{"authn_login_fail"}},
			assert:  refusedNamingField("SessionSignals.Signals", "authn_login_fail"),
		},
		{
			name:    "a heartbeat of 4 seconds is refused",
			signals: httpsec.SessionSignals{Heartbeat: 4 * time.Second},
			assert:  refusedNamingField("SessionSignals.Heartbeat"),
		},
		{
			name:    "a heartbeat of 61 seconds is refused",
			signals: httpsec.SessionSignals{Heartbeat: 61 * time.Second},
			assert:  refusedNamingField("SessionSignals.Heartbeat"),
		},
		{
			name:    "a heartbeat at each end of its range builds",
			signals: httpsec.SessionSignals{Heartbeat: 5 * time.Second},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 5*time.Second, cfg.Heartbeat)
			}),
		},
		{
			name:    "a negative warning window is refused",
			signals: httpsec.SessionSignals{ExpiryWarning: -time.Second},
			assert:  refusedNamingField("SessionSignals.ExpiryWarning"),
		},
		{
			name:    "a warning window of zero means the default",
			signals: httpsec.SessionSignals{ExpiryWarning: 0},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 2*time.Minute, cfg.ExpiryWarning)
			}),
		},
		{
			name:    "a warning window as long as the idle timeout is refused",
			signals: httpsec.SessionSignals{ExpiryWarning: 30 * time.Minute},
			assert:  refusedNamingField("SessionSignals.ExpiryWarning", "idle timeout"),
		},
		{
			name:        "a warning window leaving less than the touch interval is refused",
			signals:     httpsec.SessionSignals{ExpiryWarning: 26 * time.Minute},
			sessionOpts: []session.Option{session.WithTouchInterval(5 * time.Minute)},
			assert:      refusedNamingField("SessionSignals.ExpiryWarning", "touch interval"),
		},
		{
			name:        "a warning window leaving exactly the touch interval builds",
			signals:     httpsec.SessionSignals{ExpiryWarning: 25 * time.Minute},
			sessionOpts: []session.Option{session.WithTouchInterval(5 * time.Minute)},
			assert:      resolved(nil),
		},
		{
			name:        "the default warning window against a shorter idle timeout is refused",
			sessionOpts: []session.Option{session.WithIdleTimeout(time.Minute)},
			assert:      refusedNamingField("SessionSignals.ExpiryWarning"),
		},
		{
			name:        "with no session_expiring the window is not judged against the idle timeout",
			signals:     httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalSessionEnded}},
			sessionOpts: []session.Option{session.WithIdleTimeout(time.Minute)},
			assert:      resolved(nil),
		},
		{
			name:    "a negative assurance window is refused",
			signals: httpsec.SessionSignals{AssuranceWindow: -time.Second},
			assert:  refusedNamingField("SessionSignals.AssuranceWindow"),
		},
		{
			name:    "an assurance window of zero means the default",
			signals: httpsec.SessionSignals{AssuranceWindow: 0},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, httpsec.DefaultRecentAuthenticationWindow, cfg.AssuranceWindow)
			}),
		},
		{
			name:    "a warning window set without session_expiring is refused",
			signals: httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalSessionEnded}, ExpiryWarning: time.Minute},
			assert:  refusedNamingField("SessionSignals.ExpiryWarning", string(httpsec.SignalSessionExpiring)),
		},
		{
			name:    "an assurance window set without assurance_lapsed is refused",
			signals: httpsec.SessionSignals{AssuranceWindow: 5 * time.Minute},
			assert:  refusedNamingField("SessionSignals.AssuranceWindow", string(httpsec.SignalAssuranceLapsed)),
		},
		{
			name: "an assurance window set with assurance_lapsed is kept",
			signals: httpsec.SessionSignals{
				Signals:         []httpsec.Signal{httpsec.SignalAssuranceLapsed},
				AssuranceWindow: 5 * time.Minute,
			},
			opts: func(t *testing.T, f *constructionFixture) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					f.bearer,
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      f.sessions,
						Attempts:      NewMockAttemptStore(gomock.NewController(t)),
					}),
					httpsec.EnableReauthentication(),
				}
			},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 5*time.Minute, cfg.AssuranceWindow)
			}),
		},
		{
			name:    "a negative MaxPerSignIn is refused",
			signals: httpsec.SessionSignals{MaxPerSignIn: -1},
			assert:  refusedNamingField("SessionSignals.MaxPerSignIn"),
		},
		{
			name:    "a negative MaxPerUser is refused",
			signals: httpsec.SessionSignals{MaxPerUser: -1},
			assert:  refusedNamingField("SessionSignals.MaxPerUser"),
		},
		{
			name:    "a negative MaxStreams is refused",
			signals: httpsec.SessionSignals{MaxStreams: -1},
			assert:  refusedNamingField("SessionSignals.MaxStreams"),
		},
		{
			name:    "a cap of zero means its default",
			signals: httpsec.SessionSignals{MaxPerSignIn: 0, MaxPerUser: 0, MaxStreams: 0},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 4, cfg.MaxPerSignIn)
				assert.Equal(t, 16, cfg.MaxPerUser)
				assert.Equal(t, 10_000, cfg.MaxStreams)
			}),
		},
		{
			name:    "MaxPerSignIn above MaxPerUser is refused",
			signals: httpsec.SessionSignals{MaxPerSignIn: 5, MaxPerUser: 4},
			assert:  refusedNamingField("SessionSignals.MaxPerSignIn", "SessionSignals.MaxPerUser"),
		},
		{
			name:    "MaxPerSignIn above the default MaxPerUser is refused",
			signals: httpsec.SessionSignals{MaxPerSignIn: 17},
			assert:  refusedNamingField("SessionSignals.MaxPerSignIn", "SessionSignals.MaxPerUser"),
		},
		{
			name:    "MaxPerUser above MaxStreams is refused",
			signals: httpsec.SessionSignals{MaxPerUser: 8, MaxPerSignIn: 2, MaxStreams: 4},
			assert:  refusedNamingField("SessionSignals.MaxPerUser", "SessionSignals.MaxStreams"),
		},
		{
			name:    "assurance_lapsed without re-authentication is refused",
			signals: httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalAssuranceLapsed}},
			assert:  refusedNamingField("EnableReauthentication"),
		},
		{
			name:    "assurance_lapsed with re-authentication builds",
			signals: httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalAssuranceLapsed}},
			opts: func(t *testing.T, f *constructionFixture) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					f.bearer,
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      f.sessions,
						Attempts:      NewMockAttemptStore(gomock.NewController(t)),
					}),
					httpsec.EnableReauthentication(),
				}
			},
			assert: resolved(nil),
		},
		{
			name:    "the path session management answers is refused",
			signals: httpsec.SessionSignals{Path: "/sessions"},
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{f.bearer, httpsec.EnableSessionManagement()}
			},
			assert: refusedNamingField("SessionSignals.Path", "/sessions"),
		},
		{
			name:    "a path under session management's prefix is refused",
			signals: httpsec.SessionSignals{Path: "/sessions/signals"},
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{f.bearer, httpsec.EnableSessionManagement()}
			},
			assert: refusedNamingField("SessionSignals.Path", "/sessions"),
		},
		{
			name:    "the logout path is refused",
			signals: httpsec.SessionSignals{Path: httpsec.DefaultLogoutPath},
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{f.bearer, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions})}
			},
			assert: refusedNamingField("SessionSignals.Path", httpsec.DefaultLogoutPath),
		},
		{
			name: "the renewal path is refused",
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{
					f.bearer,
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: f.users}),
				}
			},
			signals: httpsec.SessionSignals{Path: httpsec.DefaultSessionRenewalPath},
			assert:  refusedNamingField("SessionSignals.Path", httpsec.DefaultSessionRenewalPath),
		},
		{
			name:    "the re-authentication prefix is refused",
			signals: httpsec.SessionSignals{Path: httpsec.DefaultReauthenticationPrefix},
			opts: func(t *testing.T, f *constructionFixture) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					f.bearer,
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: NewMockAuthenticator(gomock.NewController(t)),
						Sessions:      f.sessions,
						Attempts:      NewMockAttemptStore(gomock.NewController(t)),
					}),
					httpsec.EnableReauthentication(),
				}
			},
			assert: refusedNamingField("SessionSignals.Path", httpsec.DefaultReauthenticationPrefix),
		},
		{
			name: "enabled twice is refused",
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{f.bearer, httpsec.EnableSessionSignals(httpsec.SessionSignals{})}
			},
			assert: refusedNamingField("EnableSessionSignals", "twice"),
		},
		{
			name:        "a manager that already has an end observer builds",
			sessionOpts: []session.Option{session.WithEndObserver(session.EndObserverFunc(func(context.Context, session.EndReport) {}))},
			assert:      resolved(nil),
		},
		{
			name: "no session manager is refused",
			opts: func(*testing.T, *constructionFixture) []httpsec.Option {
				return nil
			},
			assert: refusedNamingField("EnableSessionSignals", "session manager"),
		},
		{
			name: "no user loader and no built-in bearer's is refused",
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions)}
			},
			assert: refusedNamingField("SessionSignals.Users"),
		},
		{
			name: "a consumer's loader builds with no built-in bearer",
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions)}
			},
			signals: httpsec.SessionSignals{Users: NewMockUserLoader(nil)},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.NotNil(t, cfg.Users)
			}),
		},
		{
			name:    "a nil pointer as the loader is refused",
			signals: httpsec.SessionSignals{Users: (*MockUserLoader)(nil)},
			assert:  refusedNamingField("SessionSignals.Users"),
		},
		{
			name:    "an empty path means the default",
			signals: httpsec.SessionSignals{Path: ""},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, "/session/signals", cfg.Path)
			}),
		},
		{
			name:    "a path with no leading slash is refused",
			signals: httpsec.SessionSignals{Path: "session/signals"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path ending in a slash is refused",
			signals: httpsec.SessionSignals{Path: "/session/signals/"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "the root path is refused",
			signals: httpsec.SessionSignals{Path: "/"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a query is refused",
			signals: httpsec.SessionSignals{Path: "/session/signals?x=1"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a fragment is refused",
			signals: httpsec.SessionSignals{Path: "/session/signals#x"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a space is refused",
			signals: httpsec.SessionSignals{Path: "/session /signals"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a tab is refused",
			signals: httpsec.SessionSignals{Path: "/session\t/signals"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a line break is refused",
			signals: httpsec.SessionSignals{Path: "/session\n/signals"},
			assert:  refusedNamingField("SessionSignals.Path"),
		},
		{
			name:    "a path holding a percent is refused, because paths are compared decoded",
			signals: httpsec.SessionSignals{Path: "/session%20signals"},
			assert:  refusedNamingField("SessionSignals.Path", "%"),
		},
		{
			name:    "a MaxAge below twice the heartbeat is refused",
			signals: httpsec.SessionSignals{Heartbeat: 10 * time.Second, MaxAge: 19 * time.Second},
			assert:  refusedNamingField("SessionSignals.MaxAge"),
		},
		{
			name:    "a MaxAge of exactly twice the heartbeat builds",
			signals: httpsec.SessionSignals{Heartbeat: 10 * time.Second, MaxAge: 20 * time.Second, ReloadTimeout: time.Second},
			assert:  resolved(nil),
		},
		{
			name:    "NoMaxAge builds and stays off",
			signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, httpsec.NoMaxAge, cfg.MaxAge)
			}),
		},
		{
			name:    "another negative MaxAge is refused",
			signals: httpsec.SessionSignals{MaxAge: -2},
			assert:  refusedNamingField("SessionSignals.MaxAge"),
		},
		{
			name:    "MaxPerSource above MaxStreams is refused",
			signals: httpsec.SessionSignals{MaxPerSource: 10_001},
			assert:  refusedNamingField("SessionSignals.MaxPerSource", "SessionSignals.MaxStreams"),
		},
		{
			name:    "a negative MaxPerSource is refused",
			signals: httpsec.SessionSignals{MaxPerSource: -1},
			assert:  refusedNamingField("SessionSignals.MaxPerSource"),
		},
		{
			name:    "a negative ReconnectDelay is refused",
			signals: httpsec.SessionSignals{ReconnectDelay: -time.Second},
			assert:  refusedNamingField("SessionSignals.ReconnectDelay"),
		},
		{
			name:    "a negative BusyDelay is refused",
			signals: httpsec.SessionSignals{BusyDelay: -time.Second},
			assert:  refusedNamingField("SessionSignals.BusyDelay"),
		},
		{
			name:    "a ReconnectDelay under a millisecond is refused, as it would be sent as retry: 0",
			signals: httpsec.SessionSignals{ReconnectDelay: time.Millisecond - 1},
			assert:  refusedNamingField("SessionSignals.ReconnectDelay"),
		},
		{
			name:    "a BusyDelay under a millisecond is refused, as it would be sent as retry: 0",
			signals: httpsec.SessionSignals{BusyDelay: time.Millisecond - 1},
			assert:  refusedNamingField("SessionSignals.BusyDelay"),
		},
		{
			name:    "a ReconnectDelay and a BusyDelay of exactly a millisecond build",
			signals: httpsec.SessionSignals{ReconnectDelay: time.Millisecond, BusyDelay: time.Millisecond},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, time.Millisecond, cfg.ReconnectDelay)
				assert.Equal(t, time.Millisecond, cfg.BusyDelay)
			}),
		},
		{
			name:    "a ReloadTimeout not shorter than the heartbeat is refused",
			signals: httpsec.SessionSignals{Heartbeat: 10 * time.Second, ReloadTimeout: 10 * time.Second},
			assert:  refusedNamingField("SessionSignals.ReloadTimeout"),
		},
		{
			name:    "a negative ReloadTimeout is refused",
			signals: httpsec.SessionSignals{ReloadTimeout: -time.Second},
			assert:  refusedNamingField("SessionSignals.ReloadTimeout"),
		},
		{
			name:    "ReloadTimeout defaults to half of a 5 second heartbeat",
			signals: httpsec.SessionSignals{Heartbeat: 5 * time.Second},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 2500*time.Millisecond, cfg.ReloadTimeout)
			}),
		},
		{
			name:    "ReloadTimeout defaults to half of a 15 second heartbeat",
			signals: httpsec.SessionSignals{Heartbeat: 15 * time.Second},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 7500*time.Millisecond, cfg.ReloadTimeout)
			}),
		},
		{
			name:    "ReloadTimeout of a 60 second heartbeat stops at 10 seconds",
			signals: httpsec.SessionSignals{Heartbeat: 60 * time.Second},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 10*time.Second, cfg.ReloadTimeout)
			}),
		},
		{
			name:    "a negative BusQueue is refused",
			signals: httpsec.SessionSignals{BusQueue: -1},
			assert:  refusedNamingField("SessionSignals.BusQueue"),
		},
		{
			name:    "a BusQueue above 1048576 is refused, naming the field and the limit",
			signals: httpsec.SessionSignals{Bus: NewMockSignalBus(nil), BusQueue: 1_048_577},
			assert:  refusedNamingField("SessionSignals.BusQueue", "1048576"),
		},
		{
			name:    "the largest int as a BusQueue is refused",
			signals: httpsec.SessionSignals{Bus: NewMockSignalBus(nil), BusQueue: math.MaxInt},
			assert:  refusedNamingField("SessionSignals.BusQueue", "1048576"),
		},
		{
			name:    "a BusQueue of exactly 1048576 is kept",
			signals: httpsec.SessionSignals{Bus: NewMockSignalBus(nil), BusQueue: 1_048_576},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 1_048_576, cfg.BusQueue)
			}),
		},
		{
			name:    "a negative BusTimeout is refused",
			signals: httpsec.SessionSignals{BusTimeout: -time.Second},
			assert:  refusedNamingField("SessionSignals.BusTimeout"),
		},
		{
			name:    "a BusQueue with no Bus is refused, because nothing would read it",
			signals: httpsec.SessionSignals{BusQueue: 8},
			assert:  refusedNamingField("SessionSignals.BusQueue", "SessionSignals.Bus"),
		},
		{
			name:    "a BusTimeout with no Bus is refused, because nothing would read it",
			signals: httpsec.SessionSignals{BusTimeout: time.Second},
			assert:  refusedNamingField("SessionSignals.BusTimeout", "SessionSignals.Bus"),
		},
		{
			name:    "a nil pointer as the bus is refused",
			signals: httpsec.SessionSignals{Bus: (*MockSignalBus)(nil)},
			assert:  refusedNamingField("SessionSignals.Bus"),
		},
		{
			name:    "a consumer's bus gets its queue and timeout defaults",
			signals: httpsec.SessionSignals{Bus: NewMockSignalBus(nil)},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.NotNil(t, cfg.Bus)
				assert.Equal(t, 1024, cfg.BusQueue)
				assert.Equal(t, 5*time.Second, cfg.BusTimeout)
			}),
		},
		{
			name:    "a consumer's bus keeps its queue and timeout",
			signals: httpsec.SessionSignals{Bus: NewMockSignalBus(nil), BusQueue: 8, BusTimeout: time.Second},
			assert: resolved(func(t *testing.T, cfg httpsec.SessionSignals) {
				assert.Equal(t, 8, cfg.BusQueue)
				assert.Equal(t, time.Second, cfg.BusTimeout)
			}),
		},
		{
			name: "a chain clock that cannot wait is refused",
			opts: func(_ *testing.T, f *constructionFixture) []httpsec.Option {
				return []httpsec.Option{f.bearer, httpsec.WithClock(waitlessClock{})}
			},
			assert: refusedNamingField("EnableSessionSignals", "clock"),
		},
		{
			name: "a built chain's hub is on its manager",
			assert: func(t *testing.T, f *constructionFixture, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.True(t, f.sessions.ReportsEndsTo(httpsec.SignalHubOf(chain)))
				assert.True(t, httpsec.SignalHubSharesSampler(chain), "the hub logs through the chain's sampler")
			},
		},
		{
			name:    "a build the stream refuses leaves no observer on the manager",
			signals: httpsec.SessionSignals{Heartbeat: time.Second},
			assert: func(t *testing.T, f *constructionFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.False(t, f.observed(t), "a failed build left an observer on the manager")
			},
		},
		{
			name: "a build refused after the stream's own checks leaves no observer on the manager",
			opts: func(t *testing.T, f *constructionFixture) []httpsec.Option {
				t.Helper()

				engine, err := policy.NewEngine(declaring{kinds: []policy.ChallengeKind{policy.ChallengeMFA}})
				require.NoError(t, err)

				return []httpsec.Option{f.bearer, httpsec.WithPolicyEngine(engine)}
			},
			assert: func(t *testing.T, f *constructionFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.False(t, f.observed(t), "a failed build left an observer on the manager")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newConstructionFixture(t, tc.sessionOpts...)

			opts := []httpsec.Option{f.bearer}
			if tc.opts != nil {
				opts = tc.opts(t, f)
			}

			opts = append(opts, httpsec.EnableSessionSignals(tc.signals))

			chain, err := httpsec.New(opts...)
			tc.assert(t, f, chain, err)
		})
	}
}

// observed reports whether the manager has an end observer: with one, a Delete reads the
// session first for its report, and with none it reads nothing.
func (f *constructionFixture) observed(t *testing.T) bool {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	f.store.loads.Store(0)
	require.NoError(t, f.sessions.Delete(t.Context(), s.ID))

	return f.store.loads.Load() > 0
}

// TestSessionSignals_Construction_RefusedByLaterCheck pins that a build refused by a check
// that runs after the wiring, here the provider's reporting check, leaves no observer on
// the manager. The row without signals is the control: it shows the manager is one that
// observed reports on correctly.
func TestSessionSignals_Construction_RefusedByLaterCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		signals bool
	}

	cases := []testCase{
		{name: "without signals"},
		{name: "with signals", signals: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newConstructionFixture(t)
			w := newGrantWorld(t)

			opts := []httpsec.Option{
				f.bearer,
				httpsec.EnableJWKSEndpoint(tokenKeys()),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCProvider(w.p),
			}
			if tc.signals {
				opts = append(opts, httpsec.EnableSessionSignals(httpsec.SessionSignals{}))
			}

			_, err := httpsec.New(opts...)

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, "does not report sign-in ends to the provider")
			assert.False(t, f.observed(t), "a failed build left an observer on the manager")
		})
	}
}

// TestSessionSignals_Construction_ConsumerObserverStillTold pins that a manager's own
// observer is told after the chain added its hub, and that the positive control of
// observed holds.
func TestSessionSignals_Construction_ConsumerObserverStillTold(t *testing.T) {
	t.Parallel()

	var told atomic.Int64

	f := newConstructionFixture(t, session.WithEndObserver(session.EndObserverFunc(
		func(context.Context, session.EndReport) { told.Add(1) })))

	chain, err := httpsec.New(f.bearer, httpsec.EnableSessionSignals(httpsec.SessionSignals{}))
	require.NoError(t, err)

	assert.True(t, f.sessions.ReportsEndsTo(httpsec.SignalHubOf(chain)))
	assert.True(t, f.observed(t))
	assert.EqualValues(t, 1, told.Load())
}

// TestSessionSignals_Construction_EndReports is the hub's mapping: one row per cause, and
// the shape of what it raises.
func TestSessionSignals_Construction_EndReports(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01890000-0000-7000-8000-000000000001")
	kept := id.MustParse("01890000-0000-7000-8000-000000000002")

	type testCase struct {
		name   string
		report session.EndReport
		assert func(t *testing.T, e httpsec.SignalEnvelope, ok bool)
	}

	reason := func(want string) func(*testing.T, httpsec.SignalEnvelope, bool) {
		return func(t *testing.T, e httpsec.SignalEnvelope, ok bool) {
			t.Helper()

			require.True(t, ok)
			assert.Equal(t, string(httpsec.SignalSessionEnded), e.Name)
			assert.Equal(t, want, e.Reason)
			assert.Nil(t, e.Data)
		}
	}

	const user = identity.UserID("u-1")

	cases := []testCase{
		{"logout says logout", session.EndReport{Cause: session.EndLogout, User: user, Family: family}, reason("logout")},
		{"a deleted session says ended", session.EndReport{Cause: session.EndDeleted, User: user, Family: family}, reason("ended")},
		{"an ended handle says ended", session.EndReport{Cause: session.EndByHandle, User: user, Family: family}, reason("ended")},
		{"reuse says reuse", session.EndReport{Cause: session.EndReuse, User: user, Family: family}, reason("reuse")},
		{"a revoked family says ended", session.EndReport{Cause: session.EndFamilyRevoked, Family: family}, reason("ended")},
		{"a user's sessions say all_ended", session.EndReport{Cause: session.EndUserSessions, User: user}, reason("all_ended")},
		{"a user's other sessions say all_ended", session.EndReport{Cause: session.EndUserSessionsExcept, User: user, KeptFamily: kept}, reason("all_ended")},
		{"other sign-ins say all_ended", session.EndReport{Cause: session.EndOtherSignIns, User: user, KeptFamily: kept}, reason("all_ended")},
		{
			"a user's sessions from a provider say provider_logout",
			session.EndReport{Cause: session.EndUserExternalIssuer, User: user, ExternalIssuer: "https://idp.example"},
			reason("provider_logout"),
		},
		{
			"an upstream session says provider_logout",
			session.EndReport{Cause: session.EndExternalSession, ExternalIssuer: "https://idp.example", ExternalSessionID: "sid-1"},
			reason("provider_logout"),
		},
		{"a cause the table has not heard of says ended", session.EndReport{Cause: session.EndCause(200), User: user}, reason("ended")},
		{
			name:   "the names travel as they were reported",
			report: session.EndReport{Cause: session.EndOtherSignIns, User: user, Family: family, KeptFamily: kept},
			assert: func(t *testing.T, e httpsec.SignalEnvelope, ok bool) {
				require.True(t, ok)
				assert.Equal(t, user, e.User)
				assert.Equal(t, family, e.Family)
				assert.Equal(t, kept, e.Kept)
				assert.Empty(t, e.Upstream)
			},
		},
		{
			name:   "a nil KeptFamily stays nil",
			report: session.EndReport{Cause: session.EndUserSessionsExcept, User: user},
			assert: func(t *testing.T, e httpsec.SignalEnvelope, ok bool) {
				require.True(t, ok)
				assert.Equal(t, id.Nil, e.Kept)
			},
		},
		{
			name:   "an upstream session travels as a digest, never raw",
			report: session.EndReport{Cause: session.EndExternalSession, ExternalIssuer: "https://idp.example", ExternalSessionID: "sid-1"},
			assert: func(t *testing.T, e httpsec.SignalEnvelope, ok bool) {
				require.True(t, ok)
				assert.Equal(t, httpsec.UpstreamDigest("https://idp.example", "sid-1"), e.Upstream)
				assert.Len(t, e.Upstream, 64, "a hexadecimal SHA-256")
				assert.NotContains(t, e.Upstream, "sid-1")
				assert.NotEqual(t, httpsec.UpstreamDigest("https://idp.other", "sid-1"), e.Upstream)
				assert.NotEqual(t, httpsec.UpstreamDigest("https://idp.exam", "plesid-1"), e.Upstream,
					"the separator keeps the issuer and the session apart")
			},
		},
		{
			name:   "an issuer with no upstream session has no digest",
			report: session.EndReport{Cause: session.EndUserExternalIssuer, User: user, ExternalIssuer: "https://idp.example"},
			assert: func(t *testing.T, e httpsec.SignalEnvelope, ok bool) {
				require.True(t, ok)
				assert.Empty(t, e.Upstream)
			},
		},
		{
			name:   "a report naming no one raises nothing",
			report: session.EndReport{Cause: session.EndDeleted},
			assert: func(t *testing.T, _ httpsec.SignalEnvelope, ok bool) {
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, ok := httpsec.EnvelopeForEnd(tc.report)
			tc.assert(t, e, ok)
		})
	}
}
