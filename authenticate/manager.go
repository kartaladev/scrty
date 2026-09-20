package authenticate

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Manager resolves credentials by offering them to ordered providers.
//
// It is safe for concurrent use: the provider list is fixed at construction and
// never written afterwards.
type Manager struct {
	delegates []Authenticator
}

// NewManager returns a Manager that offers credentials to delegates in the
// order given.
//
// There is no default list. Which methods a deployment accepts, and in which
// order, is the consumer's decision, and a manager that invented one would
// accept a credential the consumer never meant to accept.
//
// No delegates is a configuration error rather than a manager that refuses
// everything, because the two are indistinguishable at the first request while
// only one of them is what anyone meant.
//
// An absent delegate is refused rather than skipped, and that includes a
// non-nil interface holding a nil pointer — what an unchecked constructor error
// hands over. Skipping it would run fewer providers than the consumer wrote,
// silently; keeping it would panic on the first request, where the mistake
// looks like a runtime fault rather than a line of wiring.
func NewManager(delegates ...Authenticator) (*Manager, error) {
	if len(delegates) == 0 {
		return nil, fmt.Errorf("%w: a manager with no delegates authenticates nobody", ErrConfig)
	}
	for i, d := range delegates {
		if nilcheck.IsNil(d) {
			return nil, fmt.Errorf("%w: delegate %d is nil", ErrConfig, i)
		}
	}

	// Cloned so a caller that keeps and rewrites the slice it passed cannot
	// change which providers run, or in which order, after construction.
	return &Manager{delegates: slices.Clone(delegates)}, nil
}

// Authenticate offers c to each delegate in turn and returns the first answer
// that is not a refusal to handle the credentials.
//
// A delegate reporting ErrUnsupportedCredentials is skipped. Any other error
// ends the walk and is returned unchanged, so an outage inside one provider
// reaches the caller as itself rather than being retried by the next provider
// or collapsed into a refusal. When every delegate skips,
// ErrNoEligibleAuthenticator says so.
//
// A deciding delegate that reports no error but no result, or a result with no
// principal, is turned into ErrAuthenticationFailed here. This is the single
// choke point that lets every caller read Principal after a nil error without
// checking it; leaving the check to each provider would let the next provider
// written reopen it for everyone.
func (m *Manager) Authenticate(ctx context.Context, c identity.Credentials) (*Authentication, error) {
	for _, d := range m.delegates {
		a, err := d.Authenticate(ctx, c)
		if errors.Is(err, ErrUnsupportedCredentials) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if a == nil || a.Principal == nil {
			return nil, ErrAuthenticationFailed
		}

		return a, nil
	}

	return nil, ErrNoEligibleAuthenticator
}

var _ Authenticator = (*Manager)(nil)
