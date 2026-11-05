package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
)

// withCredentialChanged is a set holding credential_changed beside the signal that is always sent.
var withCredentialChanged = []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged}

// twoStreams signs the user in twice and opens a stream on each, with the query on both.
func twoStreams(t *testing.T, r *streamRig, query ...string) []*riggedStream {
	t.Helper()

	return []*riggedStream{
		r.open(t, r.signIn(t).ID, query...),
		r.open(t, r.signIn(t).ID, query...),
	}
}

// requireNoneSent asserts no stream sent anything but its opening session event.
func requireNoneSent(t *testing.T, streams []*riggedStream) {
	t.Helper()

	for i, s := range streams {
		assert.Equal(t, []string{"session"}, s.sent(), "stream %d sent something", i)
	}
}

func TestSessionSignals_ReportCredentialChange(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  streamSetup
		assert func(t *testing.T, r *streamRig)
	}

	enabled := streamSetup{signals: httpsec.SessionSignals{Signals: withCredentialChanged}}

	cases := []testCase{
		{
			name:  "a password change reaches every stream of the user",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				streams := twoStreams(t, r)

				r.act(func() {
					require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword))
				})

				for i, s := range streams {
					require.Len(t, s.events("credential_changed"), 1, "stream %d", i)
					assert.JSONEq(t, `{"kind":"password"}`, s.events("credential_changed")[0].Data)
				}
			},
		},
		{
			name:  "each known kind is named as itself",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				for _, kind := range []httpsec.CredentialKind{
					httpsec.CredentialPassword, httpsec.CredentialPasskey, httpsec.CredentialSecondFactor,
				} {
					r.act(func() { require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-1", kind)) })
				}

				var got []string
				for _, f := range stream.events("credential_changed") {
					got = append(got, f.Data)
				}

				assert.Equal(t, []string{
					`{"kind":"password"}`, `{"kind":"passkey"}`, `{"kind":"second_factor"}`,
				}, got)
			},
		},
		{
			name:  "an unknown kind is refused and no stream sends anything",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				streams := twoStreams(t, r)

				for _, kind := range []httpsec.CredentialKind{"", "pin", "Password", "password\n"} {
					err := r.chain.ReportCredentialChange(t.Context(), "u-1", kind)
					require.ErrorIs(t, err, httpsec.ErrInvalidSignal, "kind %q", kind)
				}

				synctest.Wait()
				requireNoneSent(t, streams)
			},
		},
		{
			name:  "a set without credential_changed sends nothing and returns no error",
			setup: streamSetup{signals: httpsec.SessionSignals{Signals: endedOnly}},
			assert: func(t *testing.T, r *streamRig) {
				streams := twoStreams(t, r)

				r.act(func() {
					require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword))
				})

				requireNoneSent(t, streams)
			},
		},
		{
			name:  "a user with no open stream is no error",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-9", httpsec.CredentialPasskey))
			},
		},
		{
			name:  "a chain without signals returns ErrSessionSignalsDisabled",
			setup: enabled,
			assert: func(t *testing.T, _ *streamRig) {
				chain, err := httpsec.New()
				require.NoError(t, err)

				err = chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword)
				assert.ErrorIs(t, err, httpsec.ErrSessionSignalsDisabled)
			},
		},
		{
			name:  "after a close, a set holding credential_changed answers busy",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				require.NoError(t, r.chain.CloseSessionSignals(t.Context()))

				err := r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword)
				assert.ErrorIs(t, err, httpsec.ErrSignalsBusy)
			},
		},
		{
			name: "after a close, the default set answers nil, as it raises nothing",
			assert: func(t *testing.T, r *streamRig) {
				require.NoError(t, r.chain.CloseSessionSignals(t.Context()))

				require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) { tc.assert(t, newStreamRig(t, tc.setup)) })
		})
	}
}

func TestSessionSignals_Publish(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  streamSetup
		assert func(t *testing.T, r *streamRig)
	}

	enabled := streamSetup{signals: httpsec.SessionSignals{Signals: withCredentialChanged}}

	indented, err := json.MarshalIndent(map[string]any{"roles": []string{"editor"}}, "", "  ")
	require.NoError(t, err)

	refused := func(name string, signal string, data []byte) testCase {
		return testCase{
			name:  name,
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				streams := twoStreams(t, r)

				err := r.chain.PublishSignal(t.Context(), "u-1", signal, data)
				require.ErrorIs(t, err, httpsec.ErrInvalidSignal)

				synctest.Wait()
				requireNoneSent(t, streams)
			},
		}
	}

	cases := []testCase{
		{
			name:  "an app signal reaches every stream of the user, data unchanged",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				streams := twoStreams(t, r)
				data := json.RawMessage(`{"roles":["editor"],"n":1.50,"s":"éé"}`)

				r.act(func() { require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.roles_changed", data)) })

				for i, s := range streams {
					require.Len(t, s.events("app.roles_changed"), 1, "stream %d", i)
					assert.Equal(t, string(data), s.events("app.roles_changed")[0].Data)
				}
			},
		},
		{
			name:  "the data may be any JSON value",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				for _, v := range []string{`null`, `true`, `7`, `"x"`, `[]`} {
					r.act(func() { require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.v", json.RawMessage(v))) })
				}

				var got []string
				for _, f := range stream.events("app.v") {
					got = append(got, f.Data)
				}

				assert.Equal(t, []string{`null`, `true`, `7`, `"x"`, `[]`}, got)
			},
		},
		{
			name:  "the longest and shortest names are accepted",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				longest := "app." + strings.Repeat("a", 63)

				for _, name := range []string{"app.a", longest, "app.0.-_"} {
					r.act(func() { require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", name, json.RawMessage(`{}`))) })
					assert.Len(t, stream.events(name), 1, name)
				}
			},
		},
		refused("a library name is refused", "session_ended", []byte(`{}`)),
		refused("credential_changed is refused", "credential_changed", []byte(`{"kind":"password"}`)),
		refused("a name that injects an event is refused", "app.x\nevent: session_ended", []byte(`{}`)),
		refused("a name with a carriage return is refused", "app.x\rretry: 1", []byte(`{}`)),
		refused("a name with a trailing line break is refused", "app.x\n", []byte(`{}`)),
		refused("a name with a colon is refused", "app.x:y", []byte(`{}`)),
		refused("an empty name after the prefix is refused", "app.", []byte(`{}`)),
		refused("a name starting with a separator is refused", "app..x", []byte(`{}`)),
		refused("an upper case name is refused", "app.Roles", []byte(`{}`)),
		refused("a name over 63 characters after the prefix is refused", "app."+strings.Repeat("a", 64), []byte(`{}`)),
		refused("data over 8 KiB is refused", "app.big", []byte(`"`+strings.Repeat("a", 8<<10)+`"`)),
		refused("data one byte over 8 KiB is refused", "app.big", []byte(`"`+strings.Repeat("a", 8<<10-1)+`"`)),
		refused("data that is not JSON is refused", "app.x", []byte(`{not json`)),
		refused("empty data is refused", "app.x", nil),
		refused("data that is not valid UTF-8 is refused", "app.x", []byte("\"\xff\xfe\"")),
		refused("indented JSON with raw line breaks is refused", "app.x", indented),
		{
			name:  "data of exactly 8 KiB is accepted",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				data := json.RawMessage(`"` + strings.Repeat("a", 8<<10-2) + `"`)
				require.Len(t, data, 8<<10)

				r.act(func() { require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.big", data)) })
				assert.Len(t, stream.events("app.big"), 1)
			},
		},
		{
			name:  "a chain without signals returns ErrSessionSignalsDisabled",
			setup: enabled,
			assert: func(t *testing.T, _ *streamRig) {
				chain, err := httpsec.New()
				require.NoError(t, err)

				err = chain.PublishSignal(t.Context(), "u-1", "app.x", json.RawMessage(`{}`))
				assert.ErrorIs(t, err, httpsec.ErrSessionSignalsDisabled)
			},
		},
		{
			name:  "a user with no open stream is no error",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				require.NoError(t, r.chain.PublishSignal(t.Context(), "u-9", "app.x", json.RawMessage(`{}`)))
				synctest.Wait()

				assert.Empty(t, stream.events("app.x"), "another user's stream heard it")
			},
		},
		{
			name:  "a client narrowed to session_ended does not hear it",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID, "signals=session_ended")

				r.act(func() {
					require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.roles_changed", json.RawMessage(`{}`)))
				})

				assert.Empty(t, stream.events("app.roles_changed"))
			},
		},
		{
			name:  "a client that names the signal hears it, and one that names another does not",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				named := r.open(t, r.signIn(t).ID, "signals=app.roles_changed")
				other := r.open(t, r.signIn(t).ID, "signals=app.other")

				r.act(func() {
					require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.roles_changed", json.RawMessage(`{"a":1}`)))
				})

				require.Len(t, named.events("app.roles_changed"), 1)
				assert.Equal(t, `{"a":1}`, named.events("app.roles_changed")[0].Data)
				assert.Empty(t, other.events("app.roles_changed"))
			},
		},
		{
			name:  "the caller's slice may be reused after the call returns",
			setup: enabled,
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				buf := []byte(`{"a":1}`)

				// Inside act, so the buffer changes before the stream has written the event.
				r.act(func() {
					require.NoError(t, r.chain.PublishSignal(t.Context(), "u-1", "app.x", buf))
					copy(buf, `{"b":2}`)
				})

				require.Len(t, stream.events("app.x"), 1)
				assert.Equal(t, `{"a":1}`, stream.events("app.x")[0].Data)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) { tc.assert(t, newStreamRig(t, tc.setup)) })
		})
	}
}

// TestSessionSignals_Publish_BusyBus pins that a consumer's bus whose queue is full is
// ErrSignalsBusy for both calls, not a blocked caller.
func TestSessionSignals_Publish_BusyBus(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		call func(c *httpsec.Chain) error
	}

	cases := []testCase{
		{name: "PublishSignal", call: func(c *httpsec.Chain) error {
			return c.PublishSignal(context.Background(), "u-1", "app.x", json.RawMessage(`{}`))
		}},
		{name: "ReportCredentialChange", call: func(c *httpsec.Chain) error {
			return c.ReportCredentialChange(context.Background(), "u-1", httpsec.CredentialPassword)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			release := make(chan struct{})
			var once sync.Once

			bus := NewMockSignalBus(gomock.NewController(t))
			subscribeBlocks(bus)
			bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ httpsec.SignalEnvelope) error {
					select {
					case <-release:
					case <-ctx.Done():
					}

					return nil
				}).AnyTimes()

			r := newStreamRig(t, streamSetup{signals: httpsec.SessionSignals{
				Signals: withCredentialChanged, Bus: bus, BusQueue: 1, BusTimeout: time.Minute,
			}})

			t.Cleanup(func() {
				once.Do(func() { close(release) })
				httpsec.SignalHubProbeOf(r.chain).Close()
			})

			// One signal is held inside Publish and one waits in the queue of one, so the
			// third finds it full whichever the publisher took first.
			var err error

			for range 3 {
				if err = tc.call(r.chain); err != nil {
					break
				}
			}

			require.ErrorIs(t, err, httpsec.ErrSignalsBusy)
		})
	}
}

// TestSessionSignals_CredentialChanged_OnlyWhenTheSetHoldsIt is the signal on its way to a shared bus.
// With no stream able to send it, a broker is handed nothing, and it cannot take a place in the queue
// from anything else or report busy for what was never going to be sent.
func TestSessionSignals_CredentialChanged_OnlyWhenTheSetHoldsIt(t *testing.T) {
	t.Parallel()

	const changePath = "/account/password"

	changeOpts := func(r *streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.EnablePasswordChangeGate(r.sessions,
			httpsec.WithPasswordChangeEndpoint(changePath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			}))}
	}

	report := func(t *testing.T, r *streamRig) {
		t.Helper()

		require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword))
	}

	endpoint := func(t *testing.T, r *streamRig) {
		t.Helper()

		require.Equal(t, http.StatusNoContent, r.callAs(t, r.signIn(t).ID, changePath, "change"))
	}

	nothing := func(t *testing.T, published []string) {
		t.Helper()

		assert.Empty(t, published)
	}

	theSignal := func(t *testing.T, published []string) {
		t.Helper()

		assert.Equal(t, []string{"credential_changed"}, published)
	}

	type testCase struct {
		name   string
		set    []httpsec.Signal
		act    func(t *testing.T, r *streamRig)
		assert func(t *testing.T, published []string)
	}

	cases := []testCase{
		{name: "a report on the default set publishes nothing", act: report, assert: nothing},
		{name: "an endpoint on the default set publishes nothing", act: endpoint, assert: nothing},
		{name: "a report on a set without it publishes nothing", set: endedOnly, act: report, assert: nothing},
		{name: "a report on a set holding it publishes", set: withCredentialChanged, act: report, assert: theSignal},
		{name: "an endpoint on a set holding it publishes", set: withCredentialChanged, act: endpoint, assert: theSignal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var (
					mu        sync.Mutex
					published []string
				)

				bus := NewMockSignalBus(gomock.NewController(t))
				subscribeBlocks(bus)
				bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, e httpsec.SignalEnvelope) error {
						mu.Lock()
						defer mu.Unlock()

						published = append(published, e.Name)

						return nil
					}).AnyTimes()

				r := newStreamRig(t, streamSetup{
					signals: httpsec.SessionSignals{Bus: bus, Signals: tc.set},
					opts:    changeOpts,
				})
				t.Cleanup(httpsec.SignalHubProbeOf(r.chain).Close)

				tc.act(t, r)
				synctest.Wait()

				mu.Lock()
				defer mu.Unlock()

				tc.assert(t, published)
			})
		})
	}
}

// TestSessionSignals_ReportCredentialChange_FullQueue is a bus that has stopped taking signals: a chain
// able to send this one reports busy, and one that cannot has nothing to be busy with.
func TestSessionSignals_ReportCredentialChange_FullQueue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		set    []httpsec.Signal
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "on the default set it never answers busy",
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "on a set holding it a full queue answers busy",
			set:  withCredentialChanged,
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, httpsec.ErrSignalsBusy)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				bus := NewMockSignalBus(gomock.NewController(t))
				subscribeBlocks(bus)
				bus.EXPECT().Publish(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ httpsec.SignalEnvelope) error {
						<-ctx.Done()

						return ctx.Err()
					}).AnyTimes()

				r := newStreamRig(t, streamSetup{
					signals: httpsec.SessionSignals{Bus: bus, BusQueue: 1, BusTimeout: time.Minute, Signals: tc.set},
				})
				t.Cleanup(httpsec.SignalHubProbeOf(r.chain).Close)

				var err error

				for range 3 {
					if err = r.chain.ReportCredentialChange(t.Context(), "u-1", httpsec.CredentialPassword); err != nil {
						break
					}

					synctest.Wait()
				}

				tc.assert(t, err)
			})
		})
	}
}

// TestSessionSignals_CredentialChanged_FromABusOnADefaultSet is a signal from a replica running another
// set, which is a misconfiguration: this replica's streams still send only what their set holds.
func TestSessionSignals_CredentialChanged_FromABusOnADefaultSet(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newStreamRig(t, streamSetup{})
		s := r.open(t, r.signIn(t).ID)

		httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
			User: "u-1", Name: string(httpsec.SignalCredentialChanged), Data: json.RawMessage(`{"kind":"password"}`),
		})
		synctest.Wait()

		assert.Equal(t, []string{"session"}, s.sent())
	})
}

// TestChain_ZeroValueAnswersSignalsDisabled pins that a Chain nobody built, which has no per-request
// phase, answers as a chain without signals does, rather than panicking.
func TestChain_ZeroValueAnswersSignalsDisabled(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, c *httpsec.Chain)
	}

	cases := []testCase{
		{
			name: "report credential change",
			assert: func(t *testing.T, c *httpsec.Chain) {
				err := c.ReportCredentialChange(t.Context(), "u", httpsec.CredentialPassword)
				assert.ErrorIs(t, err, httpsec.ErrSessionSignalsDisabled)
			},
		},
		{
			name: "publish signal",
			assert: func(t *testing.T, c *httpsec.Chain) {
				err := c.PublishSignal(t.Context(), "u", "app.notice", json.RawMessage(`{}`))
				assert.ErrorIs(t, err, httpsec.ErrSessionSignalsDisabled)
			},
		},
		{
			name: "close session signals",
			assert: func(t *testing.T, c *httpsec.Chain) {
				assert.ErrorIs(t, c.CloseSessionSignals(t.Context()), httpsec.ErrSessionSignalsDisabled)
			},
		},
		{
			name: "session signal stats are the zero value",
			assert: func(t *testing.T, c *httpsec.Chain) {
				assert.Equal(t, httpsec.SessionSignalStats{}, c.SessionSignalStats())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, &httpsec.Chain{})
		})
	}
}

// signalTenantKey is where these rows' requests carry a tenant, as a multi-tenant consumer's do.
type signalTenantKey struct{}

// TestSessionSignals_UserIDIsUniqueAcrossOneChain pins the stated rule: a UserID is the only key a
// consumer's signal or a credential change routes by, whatever tenant a request or ReloadContext
// carries, so a multi-tenant consumer encodes its tenant into the UserID. A session's end routes by
// its family, so it is not affected.
func TestSessionSignals_UserIDIsUniqueAcrossOneChain(t *testing.T) {
	t.Parallel()

	type openFunc func(tenant, sid string) *riggedStream

	type testCase struct {
		name   string
		assert func(t *testing.T, r *streamRig, open openFunc)
	}

	cases := []testCase{
		{
			name: "two tenants sharing a user id hear each other's signal",
			assert: func(t *testing.T, r *streamRig, open openFunc) {
				a, b := open("A", r.signIn(t).ID), open("B", r.signIn(t).ID)

				r.act(func() {
					ctx := context.WithValue(t.Context(), signalTenantKey{}, "B")
					require.NoError(t, r.chain.PublishSignal(ctx, "u-1", "app.invoice", json.RawMessage(`{"for":"B"}`)))
				})

				assert.Len(t, b.events("app.invoice"), 1, "the tenant it was meant for")
				assert.Len(t, a.events("app.invoice"), 1, "a tenant on the context separates nothing: the user id is the key")
			},
		},
		{
			name: "a tenant encoded in the user id hears only its own signal",
			assert: func(t *testing.T, r *streamRig, open openFunc) {
				a, b := open("A", r.signInOf(t, "A/u-1").ID), open("B", r.signInOf(t, "B/u-1").ID)

				r.act(func() {
					require.NoError(t, r.chain.PublishSignal(t.Context(), "B/u-1", "app.invoice", json.RawMessage(`{"for":"B"}`)))
				})

				assert.Len(t, b.events("app.invoice"), 1, "the tenant it was meant for")
				assert.Empty(t, a.events("app.invoice"), "tenant B's signal reached tenant A")
			},
		},
		{
			name: "a tenant encoded in the user id hears only its own credential change",
			assert: func(t *testing.T, r *streamRig, open openFunc) {
				a, b := open("A", r.signInOf(t, "A/u-1").ID), open("B", r.signInOf(t, "B/u-1").ID)

				r.act(func() {
					require.NoError(t, r.chain.ReportCredentialChange(t.Context(), "B/u-1", httpsec.CredentialPassword))
				})

				assert.Len(t, b.events(string(httpsec.SignalCredentialChanged)), 1, "the tenant it was meant for")
				assert.Empty(t, a.events(string(httpsec.SignalCredentialChanged)), "tenant B's change reached tenant A")
			},
		},
		{
			name: "one tenant's logout, naming a family, does not end the other's stream",
			assert: func(t *testing.T, r *streamRig, open openFunc) {
				ended := r.signIn(t)
				a, b := open("A", ended.ID), open("B", r.signIn(t).ID)

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), ended.UserID, ended.FamilyID)
					require.NoError(t, err)
				})

				require.Len(t, a.events(string(httpsec.SignalSessionEnded)), 1)
				assert.JSONEq(t, `{"reason":"logout"}`, a.events(string(httpsec.SignalSessionEnded))[0].Data)
				assert.Empty(t, b.events(string(httpsec.SignalSessionEnded)), "tenant A's end reached tenant B")
				assert.False(t, b.closed(), "tenant A's end closed tenant B's stream")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var tenant atomic.Value

				r := newStreamRig(t, streamSetup{
					signals: httpsec.SessionSignals{
						Signals: withCredentialChanged,
						ReloadContext: func(ctx context.Context) context.Context {
							return context.WithValue(context.Background(), signalTenantKey{}, ctx.Value(signalTenantKey{}))
						},
					},
					requestCtx: func(ctx context.Context) context.Context {
						return context.WithValue(ctx, signalTenantKey{}, tenant.Load())
					},
				})

				tc.assert(t, r, func(name, sid string) *riggedStream {
					tenant.Store(name)

					return r.open(t, sid)
				})
			})
		})
	}
}
