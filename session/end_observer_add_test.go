package session_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// countingObserver is an observer safe to tell from several goroutines.
type countingObserver struct{ told atomic.Int64 }

func (c *countingObserver) SignInsEnded(context.Context, session.EndReport) { c.told.Add(1) }

func TestSessions_AddEndObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// observe is the observers given at construction.
		observe func(f *observedFixture) []session.EndObserver
		// add returns the observers to add, in order.
		add    func(f *observedFixture) []session.EndObserver
		assert func(t *testing.T, f *observedFixture, errs []error)
	}

	panicking := session.EndObserverFunc(func(context.Context, session.EndReport) { panic(endPanicValue) })
	addedRecorder := func(f *observedFixture) *endRecorder {
		return &endRecorder{name: "added", calls: &f.calls, written: &f.written}
	}
	order := func(f *observedFixture) []string {
		names := make([]string, 0, len(f.calls))
		for _, c := range f.calls {
			names = append(names, c.observer)
		}

		return names
	}
	refused := func(t *testing.T, f *observedFixture, errs []error) {
		t.Helper()

		require.Len(t, errs, 1)
		require.ErrorIs(t, errs[0], session.ErrConfig)
		assert.Contains(t, errs[0].Error(), "end observer")

		// Nothing changed: a later end is still reported, to the two given at
		// construction and to no one else.
		require.NoError(t, f.m.DeleteByUser(t.Context(), endUser))
		assert.Equal(t, []string{"first", "second"}, order(f))
	}

	cases := []testCase{
		{
			name:    "a nil observer is a configuration error and changes nothing",
			observe: recordingObservers,
			add:     func(*observedFixture) []session.EndObserver { return []session.EndObserver{nil} },
			assert:  refused,
		},
		{
			name:    "a typed-nil pointer is a configuration error and changes nothing",
			observe: recordingObservers,
			add: func(*observedFixture) []session.EndObserver {
				return []session.EndObserver{(*pointerObserver)(nil)}
			},
			assert: refused,
		},
		{
			name:    "a nil func adapter is a configuration error and changes nothing",
			observe: recordingObservers,
			add: func(*observedFixture) []session.EndObserver {
				return []session.EndObserver{session.EndObserverFunc(nil)}
			},
			assert: refused,
		},
		{
			name:    "an added observer runs after those given at construction, which still run",
			observe: recordingObservers,
			add:     func(f *observedFixture) []session.EndObserver { return []session.EndObserver{addedRecorder(f)} },
			assert: func(t *testing.T, f *observedFixture, errs []error) {
				require.Equal(t, []error{nil}, errs)

				require.NoError(t, f.m.DeleteByUser(t.Context(), endUser))
				assert.Equal(t, []string{"first", "second", "added"}, order(f))
				assert.Equal(t, f.calls[0].report, f.calls[2].report)
			},
		},
		{
			name:    "an observer added to a manager built with none is told",
			observe: func(*observedFixture) []session.EndObserver { return nil },
			add:     func(f *observedFixture) []session.EndObserver { return []session.EndObserver{addedRecorder(f)} },
			assert: func(t *testing.T, f *observedFixture, errs []error) {
				require.Equal(t, []error{nil}, errs)

				require.NoError(t, f.m.DeleteByUser(t.Context(), endUser))
				assert.Equal(t, []string{"added"}, order(f))
			},
		},
		{
			name:    "several additions run in the order added",
			observe: recordingObservers,
			add: func(f *observedFixture) []session.EndObserver {
				a, b := addedRecorder(f), addedRecorder(f)
				a.name, b.name = "added-1", "added-2"

				return []session.EndObserver{a, b}
			},
			assert: func(t *testing.T, f *observedFixture, errs []error) {
				require.Equal(t, []error{nil, nil}, errs)

				require.NoError(t, f.m.DeleteByUser(t.Context(), endUser))
				assert.Equal(t, []string{"first", "second", "added-1", "added-2"}, order(f))
			},
		},
		{
			name: "the first of two observers panicking still calls the second, an added one",
			observe: func(*observedFixture) []session.EndObserver {
				return []session.EndObserver{panicking}
			},
			add: func(f *observedFixture) []session.EndObserver { return []session.EndObserver{addedRecorder(f)} },
			assert: func(t *testing.T, f *observedFixture, errs []error) {
				require.Equal(t, []error{nil}, errs)

				require.NotPanics(t, func() { require.NoError(t, f.m.DeleteByUser(t.Context(), endUser)) })
				require.Equal(t, []string{"added"}, order(f))
				assertPanicLoggedWithoutContents(t, f.logs.String(), f.calls[0].report)
			},
		},
		{
			name: "an added observer that panics does not stop the one added after it",
			observe: func(*observedFixture) []session.EndObserver {
				return nil
			},
			add: func(f *observedFixture) []session.EndObserver {
				return []session.EndObserver{panicking, addedRecorder(f)}
			},
			assert: func(t *testing.T, f *observedFixture, errs []error) {
				require.Equal(t, []error{nil, nil}, errs)

				require.NotPanics(t, func() { require.NoError(t, f.m.DeleteByUser(t.Context(), endUser)) })
				assert.Equal(t, []string{"added"}, order(f))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, _ := newObservedFixture(t, tc.observe)
			f.calls = nil

			var errs []error
			for _, o := range tc.add(f) {
				errs = append(errs, f.m.AddEndObserver(o))
			}

			tc.assert(t, f, errs)
		})
	}
}

// TestSessions_AddEndObserver_Concurrent runs under -race. The barriers make
// the additions and the reports overlap without a sleep.
func TestSessions_AddEndObserver_Concurrent(t *testing.T) {
	t.Parallel()

	const (
		adders   = 4
		perAdder = 25
	)

	type testCase struct {
		name   string
		reader bool
	}

	cases := []testCase{
		{name: "two or more goroutines adding at once lose no addition"},
		{name: "adding while reports run is clean", reader: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := managerFor(t)
			observers := make([]*countingObserver, adders*perAdder)
			for i := range observers {
				observers[i] = &countingObserver{}
			}

			start := make(chan struct{})
			stop := make(chan struct{})
			var adding, reporting sync.WaitGroup

			if tc.reader {
				reporting.Add(2)
				for range 2 {
					go func() {
						defer reporting.Done()
						<-start
						for {
							select {
							case <-stop:
								return
							default:
								assert.NoError(t, m.DeleteByUser(t.Context(), endUser))
							}
						}
					}()
				}
			}

			adding.Add(adders)
			for g := range adders {
				go func() {
					defer adding.Done()
					<-start
					for i := range perAdder {
						assert.NoError(t, m.AddEndObserver(observers[g*perAdder+i]))
					}
				}()
			}

			close(start)
			adding.Wait()
			close(stop)
			reporting.Wait()

			for i, o := range observers {
				assert.True(t, m.ReportsEndsTo(o), "addition %d was lost", i)
			}

			before := make([]int64, len(observers))
			for i, o := range observers {
				before[i] = o.told.Load()
			}
			require.NoError(t, m.DeleteByUser(t.Context(), endUser))
			for i, o := range observers {
				assert.Equal(t, before[i]+1, o.told.Load(), fmt.Sprintf("addition %d not told once by a later end", i))
			}
		})
	}
}

func TestSessions_EndObserver_NotOnExpiry(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(ctx context.Context, f *observedFixture) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the expiry sweep reports nothing",
			act: func(ctx context.Context, f *observedFixture) error {
				f.clk.Advance(13 * time.Hour)
				n, err := f.m.DeleteExpired(ctx)
				if n != 2 {
					return fmt.Errorf("the sweep removed %d sessions, not 2", n)
				}

				return err
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "loading a session past its deadline reports nothing",
			act: func(ctx context.Context, f *observedFixture) error {
				f.clk.Advance(13 * time.Hour)
				_, err := f.m.Load(ctx, f.a.ID)

				return err
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, session.ErrExpired) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Both the observers given at construction and one added are told
			// nothing.
			f, _ := newObservedFixture(t, recordingObservers)
			added := &endRecorder{name: "added", calls: &f.calls, written: &f.written}
			require.NoError(t, f.m.AddEndObserver(added))
			f.calls = nil

			err := tc.act(t.Context(), f)

			tc.assert(t, err)
			assert.Empty(t, f.calls, "an observer was told")
		})
	}
}
