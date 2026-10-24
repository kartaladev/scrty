package storetest

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// settleDeadline is the context deadline a user-wide delete gets while
// sessions are created under it, and settleWithin the time it must return
// within. An unbounded delete runs until the deadline; the gap between the two
// leaves room for 64 bounded passes on a loaded CI host running the backends'
// suites in parallel under the race detector.
const (
	settleDeadline = 10 * time.Second
	settleWithin   = 8 * time.Second
	// settleCreators is how many callers create the user's sessions at once.
	settleCreators = 16
)

// RunSessionDeleteSettles holds a durable session store's user-wide deletes
// (DeleteByUser, DeleteByUserExcept, DeleteByExternalSession and
// DeleteByUserAndExternalIssuer) to ending in a bounded number of passes
// while sessions they match are created concurrently: each returns well
// before its context deadline, either having settled or with an error
// matching session.ErrDeleteDidNotSettle.
//
// newStore returns a store on the database, which a creator and the delete
// share.
func RunSessionDeleteSettles(t *testing.T, newStore func(t *testing.T) session.Store) {
	t.Helper()

	failMissing(t, missingInputs(
		input{"newStore", newStore != nil},
	))

	const issuer, sid = "https://idp.example", "settle-sid"

	type testCase struct {
		name   string
		create func(i int, user identity.UserID) *session.Session
		delete func(ctx context.Context, s session.Store, user identity.UserID) error
	}

	cases := []testCase{
		{
			name:   "deleting a user's sessions settles under concurrent creates",
			create: func(i int, user identity.UserID) *session.Session { return settleSession(i, user) },
			delete: func(ctx context.Context, s session.Store, user identity.UserID) error {
				return s.DeleteByUser(ctx, user)
			},
		},
		{
			name:   "deleting a user's other sessions settles under concurrent creates",
			create: func(i int, user identity.UserID) *session.Session { return settleSession(i, user) },
			delete: func(ctx context.Context, s session.Store, user identity.UserID) error {
				_, err := s.DeleteByUserExcept(ctx, user, settleSessionID(user, -1))
				return err
			},
		},
		{
			name: "deleting a provider session's sessions settles under concurrent creates",
			create: func(i int, user identity.UserID) *session.Session {
				return federatedSession(settleSessionID(user, i), user, issuer, sid+"-"+string(user))
			},
			delete: func(ctx context.Context, s session.Store, user identity.UserID) error {
				_, err := s.DeleteByExternalSession(ctx, issuer, sid+"-"+string(user))
				return err
			},
		},
		{
			name: "deleting a user's sessions from an issuer settles under concurrent creates",
			create: func(i int, user identity.UserID) *session.Session {
				return federatedSession(settleSessionID(user, i), user, issuer, sid)
			},
			delete: func(ctx context.Context, s session.Store, user identity.UserID) error {
				_, err := s.DeleteByUserAndExternalIssuer(ctx, user, issuer)
				return err
			},
		},
	}

	for n, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			user := identity.UserID("settle-" + strconv.Itoa(n))

			// The creators keep adding the user's sessions, each one matching
			// the delete, until the delete returns.
			stop := make(chan struct{})
			var started, creators sync.WaitGroup
			started.Add(settleCreators)
			failures := make(chan error, settleCreators)
			for c := range settleCreators {
				creators.Go(func() {
					first := true
					defer func() {
						if first {
							started.Done()
						}
					}()
					for i := 0; ; i++ {
						select {
						case <-stop:
							return
						default:
						}
						err := s.Create(t.Context(), tc.create(i*settleCreators+c, user))
						if first {
							first = false
							started.Done()
						}
						if err != nil {
							failures <- err
							return
						}
					}
				})
			}
			started.Wait()

			ctx, cancel := context.WithTimeout(t.Context(), settleDeadline)
			defer cancel()
			began := time.Now()
			err := tc.delete(ctx, s, user)
			took := time.Since(began)
			close(stop)
			creators.Wait()
			close(failures)
			for cerr := range failures {
				t.Fatalf("a concurrent create failed: %v", cerr)
			}

			assert.Less(t, took, settleWithin, "the delete ran until near its context deadline")
			if err != nil {
				assert.ErrorIs(t, err, session.ErrDeleteDidNotSettle, "the delete failed for another reason")
			}
			assert.False(t, errors.Is(err, context.DeadlineExceeded), "the delete ended at its context deadline")
		})
	}
}

// settleSessionID is the identifier of the i-th session the settle cases
// create for user.
func settleSessionID(user identity.UserID, i int) string {
	return string(user) + "-session-" + strconv.Itoa(i)
}

// settleSession is the i-th first-party session the settle cases create for
// user.
func settleSession(i int, user identity.UserID) *session.Session {
	return sessionRecord(settleSessionID(user, i), user)
}
