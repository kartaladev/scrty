package httpsecconformance

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// The values the failing store's error quotes, which no refusal may carry
// whichever framework reports it.
const (
	quotedAddress = "alice@example.com"
	quotedUserRef = "u-123"
)

// errStoreQuotesARow is what the failing session store answers with: the kind
// of text a database driver writes, quoting the row it could not write.
var errStoreQuotesARow = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// failingCreateStore is a session store whose Create always fails with
// errStoreQuotesARow. Everything else is the in-memory store's, which the
// scenario never reaches.
type failingCreateStore struct {
	*session.MemoryStore
}

func (failingCreateStore) Create(context.Context, *session.Session) error { return errStoreQuotesARow }

// storeFailureTextStaysOutOfTheRefusal pins that a refusal caused by a
// consumer's dependency carries the library's own text on every framework: on
// net/http the error handler's error, on gin the error channel, on fiber the
// error its handler is given. The status is the one a store failure has always
// mapped to, and the store's error is still reachable for a consumer who
// matches it deliberately.
func storeFailureTextStaysOutOfTheRefusal() Scenario {
	return Scenario{
		Name: "a store failure's text stays out of the refusal",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			manager, err := session.NewManager(session.WithStore(failingCreateStore{MemoryStore: effects.Store}))
			require.NoError(t, err)

			effects.Sessions = manager

			return ChainSpec{Options: formLoginOptions(effects), Effects: effects}
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusInternalServerError, res.Status)
			assert.False(t, res.RouteRan)

			require.Error(t, res.Refusal, "the adapter's error channel carried no refusal")
			assert.ErrorIs(t, res.Refusal, errStoreQuotesARow, "the store's error is no longer reachable")
			assert.NotContains(t, res.Refusal.Error(), quotedAddress, "the refusal quotes the store")
			assert.NotContains(t, res.Refusal.Error(), quotedUserRef, "the refusal quotes the store")
			assert.NotContains(t, res.Body, quotedAddress, "the response quotes the store")

			// An adapter may carry the refusal in an error of its own whose
			// text is only the status (fiber does), which would hide a raw
			// store error from the check above. What must hold on every
			// framework is that the store's error sits beneath the library's
			// own text, not directly beneath the adapter's carrier.
			parent := wrapping(res.Refusal, errStoreQuotesARow)
			require.Error(t, parent, "the store's error is the refusal itself, not wrapped by the library")
			assert.NotEqual(t, http.StatusText(res.Status), parent.Error(),
				"the store's error sits directly beneath the adapter's carrier, not the library's text")
			assert.NotContains(t, parent.Error(), quotedAddress, "the library's text quotes the store")
			assert.NotContains(t, parent.Error(), quotedUserRef, "the library's text quotes the store")

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "no session was opened")
		},
	}
}

// wrapping returns the error in err's tree that directly wraps target, or nil
// when there is none. err itself being target has no parent.
func wrapping(err, target error) error {
	var children []error

	switch e := err.(type) { //nolint:errorlint // walking the tree node by node, not matching
	case interface{ Unwrap() []error }:
		children = e.Unwrap()
	case interface{ Unwrap() error }:
		children = []error{e.Unwrap()}
	}

	for _, child := range children {
		if child == target { //nolint:errorlint // identity: the node that wraps target itself
			return err
		}

		if child == nil {
			continue
		}

		if parent := wrapping(child, target); parent != nil {
			return parent
		}
	}

	return nil
}
