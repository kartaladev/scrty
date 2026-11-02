package httpsec

import (
	"context"
	"net/url"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/policy"
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

	// The proof is judged before the code is redeemed, so a bad one leaves
	// the code unspent. An invalid proof is counted against the source as a
	// request carrying no code is; the nonce round trip and a failure of the
	// replay store or nonce cipher are not.
	binding, err := issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request)
	if err != nil {
		if chargesProofRefusal(err) {
			recordSourceFailure(ctx, i.guard, src)
		}

		return err
	}

	// The check mints the assurance evidence from the candidate the redeemer
	// hands it, which carries the record the callback wrote from the verified
	// ID token. Nothing in this request reaches it.
	check, out := oidcRedemptionCheck(i.engine, i.enforced, i.challengeMethods, i.now)

	// Built and issued inside the check, after the refusal check has passed
	// and before the redeemer consumes the code, so a credential that cannot
	// be issued leaves the code redeemable. The session is stored only once
	// the code is spent, below.
	login := newRedemptionLogin(loginTailDeps{
		engine:            i.engine,
		sessions:          i.sessions,
		tokens:            i.tokens,
		issue:             i.issue,
		enrolmentLifetime: i.enrolmentLifetime,
		enforced:          i.enforced,
		challengeMethods:  i.challengeMethods,
		cancelHeld:        i.cancelHeld,
		csrfToken:         i.csrfToken,
		binding:           binding,
	}, out)

	// One check, as the redeemer has always been handed: the refusal check,
	// then, only once it has passed, the issuing step.
	checkThenIssue := func(ctx context.Context, c oidc.RedeemCandidate) error {
		if err := check(ctx, c); err != nil {
			return err
		}

		// The assurance the session records must be the assurance the
		// policy check decided on, so a candidate carrying any other is
		// refused before anything is issued for it.
		if err := guardFederatedAssurance(out, c.Provider, c.Issuer, c.AMR, c.ACR); err != nil {
			return err
		}

		in := postAuthenticationInput(&c.Principal, factor.OIDC, "", c.PasswordChangedAt, i.now())
		in.FederatedAssurance = out.federated

		return login.issue(ctx, in)
	}

	res, err := i.redeemer.Redeem(ctx, code, checkThenIssue)
	if err != nil {
		if countsAgainstSource(i.countRefusals, err, out) {
			recordSourceFailure(ctx, i.guard, src)
		}

		// The redeemer's error, unchanged: oidc already answers every cause
		// with one uniform refusal, a policy refusal is the policy's own
		// reason for the consumer to read, and a credential that could not be
		// issued is a dependency failure. Whatever the issuing step built is
		// dropped: it was never stored, so it names nothing.
		return err
	}

	// Checked before anything is stored. A HandoffRedeemer is an interface,
	// and an implementation that skipped or discarded the checks has not shown
	// this login is permitted, nor that the login issued for is the one
	// returned.
	if err := guardRedemption(out, res.Principal, res.PasswordChangedAt); err != nil {
		return err
	}

	// The returned assurance is what the session records and every later
	// request matches, so it must be the assurance the check decided on.
	if err := guardFederatedAssurance(out, res.Provider, res.Issuer, res.AMR, res.ACR); err != nil {
		return err
	}

	issued, err := login.redeemed()
	if err != nil {
		return err
	}

	// Set before the session is stored, so a challenge response carries it
	// too: the page the browser posted from held the code in its URL either
	// way.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	// The provider session is known only from the redeemer's result, after
	// the consume, and the credential issued inside the checks does not
	// depend on it. It is recorded on the session before the one write that
	// creates it, so no request ever sees a federated session without it, and
	// back-channel logout can find it from its first moment. The asserted
	// assurance was recorded when the session was built, from the evidence
	// the guards above have just shown is what the check decided on.
	session.WithExternalSession(res.Provider, res.Issuer, res.SessionID, res.IDToken)(issued.session())

	// The code is spent, so the first factor is proved: the user's held
	// recoveries are cancelled before the session is stored, as completeLogin
	// cancels them for every login. A cancellation that cannot be recorded
	// refuses the login, with the code already spent.
	if err := login.deps.cancelHeldRecoveries(ctx, res.Principal.ID); err != nil {
		return err
	}

	tok, err := issued.commit(ex)
	if err != nil {
		return err
	}

	// The response carries a credential, so no cache may keep it.
	ex.Writer.SetHeader("Cache-Control", "no-store")

	// next is re-resolved here rather than trusted: the handoff recorded the
	// destination the client asked for when the login started, before any
	// allowlist looked at it.
	return writeSuccessDocument(ex, oidcHandoffDocument{
		loginDocument: loginDocument{
			AccessToken: tok, ValidUntil: ex.Session.IdleExpiresAt, TokenType: tokenTypeOf(ex.Session),
		},
		Next: i.redirects.Resolve(res.Next),
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

//go:generate mockgen -destination=federatedassurancesource_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy FederatedAssuranceSource
//go:generate mockgen -destination=assuranceevaluator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/oidc AssuranceEvaluator

// mintFederated is the evidence of the assurance provider asserted for a
// login: the only place in this package that mints it.
//
// It is called with values the library itself wrote, and with nothing else:
// the handoff record a redemption check is handed (oidc.RedeemCandidate),
// which the callback wrote from the verified ID token, and a session's
// library-owned fields (session.Session.FederatedAMR and FederatedACR, beside
// its ExternalProvider and ExternalIssuer) on every request. Never a value
// read from a request, a header, a claim or consumer data. An empty provider
// mints the zero evidence, which asserts nothing.
func mintFederated(provider, issuer string, amr []string, acr string) policy.FederatedAssurance {
	return assurance.NewFederated(provider, issuer, amr, acr)
}
