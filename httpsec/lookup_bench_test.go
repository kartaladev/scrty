package httpsec_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// lookupSink keeps the results of the measured calls alive, so the compiler
// cannot drop them.
var (
	lookupSinkStatus int
	lookupSinkOK     bool
)

// wrapN returns err wrapped n times with fmt.Errorf and %w.
func wrapN(err error, n int) error {
	for range n {
		err = fmt.Errorf("w: %w", err)
	}
	return err
}

// BenchmarkLookupStatus measures classifying an error into an HTTP status, for
// the error shapes a request can raise: a bare sentinel, a short wrap chain, a
// joined challenge, an error nothing recognises, and a long chain.
func BenchmarkLookupStatus(b *testing.B) {
	rows := []struct {
		name string
		err  error
	}{
		{"bare-sentinel", authorize.ErrAccessDenied},
		{"wrap-5", wrapN(authorize.ErrAccessDenied, 5)},
		{"join-3-challenge", errors.Join(
			&httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			authorize.ErrAccessDenied,
			errors.New("second sentinel"),
		)},
		{"unknown", errors.New("nothing recognises this")},
		{"chain-50", wrapN(authorize.ErrAccessDenied, 50)},
	}
	for _, row := range rows {
		b.Run(row.name, func(b *testing.B) {
			b.ReportAllocs()
			var (
				status int
				ok     bool
			)
			for range b.N {
				status, ok = httpsec.LookupStatus(row.err)
			}
			lookupSinkStatus, lookupSinkOK = status, ok
		})
	}
}
