package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// spendChallenge checks the challenge a challenge method's response presents
// against those issued to session s through mgr, and spends it. Only a nil
// return lets the method verify the response. The second-factor and the
// re-proof endpoints both spend their challenges here, so the two cannot
// drift apart.
//
// Every attempt that presents a live challenge spends it, whether the method
// then accepts the response or not. That departs from check-then-consume as
// the one-time package frames it — where a refusal between the two leaves the
// token redeemable — on purpose: a pending challenge is not a credential the
// user holds and would lose, only the server's nonce for one attempt, and one
// try per challenge is the simpler guarantee to state and to keep. It also
// settles a race: of several attempts presenting one challenge, the store's
// compare-and-set lets exactly one through to Verify.
//
// Every failure is mfa.ErrInvalidCode, the refusal the method itself gives a
// wrong response, so a caller learns only that the answer was not good. That
// includes a store that could not answer: the one-time manager reports its
// store's failures as an invalid token too, and logs them, so this fails
// closed rather than letting an attempt reach the method unspent.
func spendChallenge(
	ctx context.Context,
	mgr *onetime.Tokens,
	cm mfa.ChallengeMethod,
	s *session.Session,
	response []byte,
) error {
	presented, err := cm.PresentedChallenge(response)
	if err != nil || presented == "" {
		return mfa.ErrInvalidCode
	}

	checked, err := mgr.Check(ctx, presented, s.ID)
	if err != nil {
		return mfa.ErrInvalidCode
	}

	if err := mgr.Consume(ctx, checked); err != nil {
		return mfa.ErrInvalidCode
	}

	return nil
}

// sweepExpired purges method's expired challenges from mgr's store, when
// clock says a sweep is due. A sweep that fails is logged through the chain's
// sampler, under flow and msg, and otherwise ignored.
//
// It runs under the request's own context, so a store that stops answering
// holds the begin no longer than the request allows. A sweep that fails, or is
// cut short, gives its turn back, so a later begin sweeps again rather than
// waiting out the window; the exception is a store that cannot purge at all,
// which no retry would change, so its turn is kept and it is logged once per
// window.
func sweepExpired(
	ctx context.Context,
	mgr *onetime.Tokens,
	clock *sweepClock,
	now func() time.Time,
	flow, msg, method string,
	sampler *logsample.Sampler,
	log *slog.Logger,
) {
	claimed, due := clock.claim(now(), mgr.IssuanceWindow())
	if !due {
		return
	}

	_, err := mgr.PurgeExpired(ctx)
	if err == nil {
		return
	}

	reason := reasonStoreUnavailable
	if errors.Is(err, onetime.ErrReapUnsupported) {
		reason = reasonPurgeUnsupported
	} else {
		clock.release(claimed)
	}

	logSampled(ctx, sampler, log, slog.LevelWarn, now(),
		flow+sampleKeySeparator+method+sampleKeySeparator+reason, msg,
		slog.String("method", method), slog.String("reason", reason))
}
