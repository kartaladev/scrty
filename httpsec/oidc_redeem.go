package httpsec

import (
	"net/url"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/session"
)

// redeem answers a POST to the handoff path: it spends the handoff code a
// callback conveyed and completes the login it stands for.
//
// It follows the magic-link consume endpoint step for step, because the two
// guard the same thing, a single-use credential that opens a session. The
// source is checked before the code is read, so a throttled guesser costs one
// bucket read rather than a store round trip, and its refusal is the same
// uniform error every other refusal gives: a client must not be able to tell a
// throttled source from a wrong code.
func (i *oidcInterceptor) redeem(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, i.guard, ex.Request.ClientIP(), oidcHandoffFlow, i.sampler, i.log, i.now())
	if err != nil {
		return oidc.ErrInvalidHandoff
	}

	code := i.readHandoff(ex.Request)
	if code == "" {
		// Nothing to redeem, which is a failed attempt like any wrong code:
		// it is counted, and never reaches the redeemer.
		recordSourceFailure(ctx, i.guard, src)

		return oidc.ErrInvalidHandoff
	}

	check, out := redemptionPolicyCheck(i.engine, i.enforced, factor.OIDC, i.now)

	res, err := i.redeemer.Redeem(ctx, code, oidc.RedeemCheck(check))
	if err != nil {
		if countsAgainstSource(i.countRefusals, err, out) {
			recordSourceFailure(ctx, i.guard, src)
		}

		// The redeemer's error, unchanged: oidc already answers every cause
		// with one uniform refusal, and a policy refusal is the policy's own
		// reason for the consumer to read.
		return err
	}

	// Checked before anything is created. A HandoffRedeemer is an interface,
	// and an implementation that skipped or discarded the check has not shown
	// this login is permitted.
	if err := guardRedemption(out); err != nil {
		return err
	}

	// Set before the tail runs, so a challenge response carries it too: the
	// page the browser posted from held the code in its URL either way.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	// The provider session travels in the write that creates the session, so
	// no request ever sees a federated session without it, and back-channel
	// logout can find it from its first moment.
	tok, err := completeLogin(ex, loginTailDeps{
		engine:            i.engine,
		sessions:          i.sessions,
		tokens:            i.tokens,
		enrolmentLifetime: i.enrolmentLifetime,
		enforced:          i.enforced,
	}, postAuthenticationInput(&res.Principal, factor.OIDC, "", res.PasswordChangedAt, i.now()),
		session.WithExternalSession(res.Provider, res.Issuer, res.SessionID, res.IDToken))
	if err != nil {
		return err
	}

	// The response carries a credential, so no cache may keep it.
	ex.Writer.SetHeader("Cache-Control", "no-store")

	// next is re-resolved here rather than trusted: the handoff recorded the
	// destination the client asked for when the login started, before any
	// allowlist looked at it.
	return writeSuccessDocument(ex, oidcHandoffDocument{
		loginDocument: loginDocument{AccessToken: tok, ValidUntil: ex.Session.IdleExpiresAt},
		Next:          i.redirects.Resolve(res.Next),
	})
}

// oidcHandoffDocument is the default success body of a redemption. It embeds a
// login's document rather than restating it, so a client that reads a form
// login's answer reads this one, and the two cannot drift apart; next is the
// destination the redirect allowlist settled on, "/" when it held none.
type oidcHandoffDocument struct {
	loginDocument

	Next string `json:"next"`
}

// readHandoff reads the handoff code out of a form body, and only out of it.
//
// A handoff code is a credential, and one accepted from a query string is one
// already written into every access log, proxy log and browser history that saw
// the URL. A body over the bound, or one that is not a form, reads as no code.
func (i *oidcInterceptor) readHandoff(r Request) string {
	body, err := r.Body(i.bodyLimit)
	if err != nil || !declaresForm(r.Header("Content-Type")) {
		return ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}

	return values.Get(DefaultOIDCHandoffParam)
}
