package prblmsec_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kartaladev/prblm"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/policy"
)

// mapperSink keeps the results of the measured calls alive, so the compiler
// cannot drop them.
var mapperSink *prblm.Problem

// benchWrapN returns err wrapped n times with fmt.Errorf and %w.
func benchWrapN(err error, n int) error {
	for range n {
		err = fmt.Errorf("w: %w", err)
	}
	return err
}

// BenchmarkMapError measures the mapper turning an error into a problem, for
// the error shapes a request can raise: a bare sentinel, a short wrap chain, a
// joined challenge, an error nothing recognises, and a long chain.
func BenchmarkMapError(b *testing.B) {
	p, err := prblmsec.New()
	if err != nil {
		b.Fatalf("prblmsec.New: %v", err)
	}
	mapper := p.Mapper()

	rows := []struct {
		name string
		err  error
	}{
		{"bare-sentinel", authorize.ErrAccessDenied},
		{"wrap-5", benchWrapN(authorize.ErrAccessDenied, 5)},
		{"join-3-challenge", errors.Join(
			&httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			authorize.ErrAccessDenied,
			errors.New("second sentinel"),
		)},
		{"unknown", errors.New("nothing recognises this")},
		{"chain-50", benchWrapN(authorize.ErrAccessDenied, 50)},
	}
	for _, row := range rows {
		b.Run(row.name, func(b *testing.B) {
			ctx := b.Context()
			b.ReportAllocs()
			var got *prblm.Problem
			for range b.N {
				got = mapper.MapError(ctx, row.err)
			}
			mapperSink = got
		})
	}
}
