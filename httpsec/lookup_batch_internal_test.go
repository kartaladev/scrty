package httpsec

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// lookupPerTarget is the classification lookup makes, written as one
// errwalk.Is per sentinel, in each list's order: the reference the batch scans
// must agree with.
func lookupPerTarget(err error) (status int, ok bool, abort error) {
	unrecognised := func(stop error) (int, bool, error) {
		return http.StatusInternalServerError, false, stop
	}

	chain, abort := errwalk.Flatten(err)
	if abort != nil {
		return unrecognised(abort)
	}

	if len(chain) == 0 {
		return unrecognised(nil)
	}

	if _, found, stop := errwalk.As[*issueFailure](chain); stop != nil {
		return unrecognised(stop)
	} else if found {
		return http.StatusInternalServerError, true, nil
	}

	for _, sentinel := range unavailableSentinels {
		if found, stop := errwalk.Is(chain, sentinel); stop != nil {
			return unrecognised(stop)
		} else if found {
			return http.StatusInternalServerError, true, nil
		}
	}

	if ch, found, stop := errwalk.As[*ChallengeError](chain); stop != nil {
		return unrecognised(stop)
	} else if found {
		switch ch.Kind {
		case policy.ChallengePasswordChange, policy.ChallengeMFAEnrolment, policy.ChallengeAccountRecovery:
			return http.StatusForbidden, true, nil
		default:
			return http.StatusUnauthorized, true, nil
		}
	}

	for _, row := range statusTable {
		if found, stop := errwalk.Is(chain, row.err); stop != nil {
			return unrecognised(stop)
		} else if found {
			return row.status, true, nil
		}
	}

	if _, found, stop := errwalk.As[*diag.Fault](chain); stop != nil {
		return unrecognised(stop)
	} else if found {
		return http.StatusInternalServerError, true, nil
	}

	for _, sentinel := range dependencySentinels {
		if found, stop := errwalk.Is(chain, sentinel); stop != nil {
			return unrecognised(stop)
		} else if found {
			return http.StatusInternalServerError, true, nil
		}
	}

	return unrecognised(nil)
}

// claims has an Is method that reports true for one target only.
type claims struct{ target error }

func (claims) Error() string { return "claims" }

func (e claims) Is(target error) bool { return target == e.target } //nolint:errorlint // identity of the target it was handed

// panicsOn has an Is method that panics for one target and says no to the rest.
type panicsOn struct{ target error }

func (panicsOn) Error() string { return "panics on" }

func (e panicsOn) Is(target error) bool {
	if target == e.target { //nolint:errorlint // identity of the target it was handed
		panic("is boom")
	}

	return false
}

// lookupAtoms are the errors the differential matrix is built from: every
// sentinel lookup matches, the As targets it checks, nodes that claim or panic
// on a sentinel through an Is method, and errors nothing recognises.
func lookupAtoms() []error {
	var atoms []error

	atoms = append(atoms, unavailableSentinels...)
	atoms = append(atoms, statusSentinels(statusTable)...)
	atoms = append(atoms, dependencySentinels...)

	for _, kind := range []policy.ChallengeKind{
		policy.ChallengeMFA, policy.ChallengePasswordChange, policy.ChallengeMFAEnrolment,
		policy.ChallengeAccountRecovery, policy.ChallengeKind(99),
	} {
		atoms = append(atoms, &ChallengeError{Kind: kind})
	}

	atoms = append(atoms,
		(*ChallengeError)(nil),
		&issueFailure{text: "issue failed", err: errConn},
		diag.Wrap(errConn, "fault"),
		diag.Wrap(errConn, "throttled fault", ratelimit.ErrThrottled),
		claims{target: ratelimit.ErrThrottled},
		claims{target: dependencySentinels[0]},
		claims{target: statusTable[len(statusTable)-1].err},
		panicsOn{target: authorize.ErrAccessDenied},
		panicsOn{target: dependencySentinels[len(dependencySentinels)-1]},
		errConn,
		errors.New("nothing recognises this"),
	)

	return atoms
}

// TestLookup_BatchMatchesPerTarget pins that lookup, which matches each list
// of sentinels with one errwalk.Index scan, classifies exactly as one
// errwalk.Is per sentinel in table order does: the same status, the same
// claim, and the same abort reason, over a generated matrix of sentinels,
// joins and wraps in every order.
func TestLookup_BatchMatchesPerTarget(t *testing.T) {
	t.Parallel()

	atoms := lookupAtoms()

	var errs []error

	errs = append(errs, nil)
	for _, a := range atoms {
		errs = append(errs, a, fmt.Errorf("wrapped: %w", a), fmt.Errorf("twice: %w", fmt.Errorf("once: %w", a)))

		for _, b := range atoms {
			errs = append(errs, errors.Join(a, b))
		}
	}

	// Deterministic triples, nested so a later sentinel can sit ahead of an
	// earlier one in walk order.
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a fixed, reproducible test matrix
	for range 4000 {
		a, b, c := atoms[r.IntN(len(atoms))], atoms[r.IntN(len(atoms))], atoms[r.IntN(len(atoms))]
		errs = append(errs,
			errors.Join(a, fmt.Errorf("w: %w", errors.Join(b, c))),
			fmt.Errorf("w: %w", errors.Join(errors.Join(a, b), c)),
		)
	}

	aborts := 0

	for _, err := range errs {
		wantStatus, wantOK, wantAbort := lookupPerTarget(err)
		gotStatus, gotOK, gotAbort := lookup(err)

		require.Equal(t, wantStatus, gotStatus, "status of %v", err)
		require.Equal(t, wantOK, gotOK, "claim of %v", err)
		require.Equal(t, errwalk.Reason(wantAbort), errwalk.Reason(gotAbort), "abort of %v", err)

		if gotAbort != nil {
			aborts++
		}
	}

	t.Logf("compared %d errors from %d atoms; %d aborted in both", len(errs), len(atoms), aborts)
}
