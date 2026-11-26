package httpsec

import (
	"errors"
	"slices"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// completeCookieSignIn is a cookie chain's conveyance of a federated login,
// used when the consumer gave no WithOIDCCallbackSuccess: the callback
// completes the sign-in itself, as a handoff redemption would, and no
// handoff code is issued.
//
//  1. The user is loaded afresh through the cookie session's user loader by
//     the reference the broker resolved, and an unknown, missing, inactive or
//     mismatched one is refused with oidc.ErrInvalidHandoff, as a redemption
//     refuses each; a loader that fails is a dependency failure behind fixed
//     text (loadCompleting).
//  2. The post-authentication policy decides the login, with the assurance
//     the verified ID token asserted, and a denial or an unenforced challenge
//     is refused with nothing stored (oidcRedemptionCheck, guardRedemption,
//     guardFederatedAssurance).
//  3. The session is created in one write with the federated first factor,
//     the provider's session and ID token and the asserted assurance, after
//     the user's held recoveries are cancelled (commitFederatedLogin), and its
//     cookie is delivered through the chain's delivery step. A delivery that
//     fails ends the sign-in, and the failure is returned: no redirect is
//     sent.
//  4. The browser is sent 303 See Other to next, the destination the redirect
//     allowlist resolved, on a no-store response sending no referrer. A
//     challenge the policy raised has already set the pending session's
//     cookie, and is answered with the same redirect: the pending-challenge
//     refusals of the requests that follow are what the page answers.
func (i *oidcInterceptor) completeCookieSignIn(ex *Exchange, provider string, res oidc.CallbackResult, next string) error {
	ctx := ex.Context()

	if res.Principal == nil || res.Principal.ID == "" {
		// The relying party never answers so; a broker that did names no one
		// to load.
		return oidc.ErrInvalidHandoff
	}

	details, err := i.loadCompleting(ex, provider, i.deliver.cookie.users, res.Principal.ID)
	if err != nil {
		return err
	}

	principal := *identity.PrincipalFromDetailsAt(details, i.now())

	check, out := oidcRedemptionCheck(i.engine, i.enforced, i.challengeMethods, i.now, i.log)

	if err := check(ctx, oidc.RedeemCandidate{
		Principal:         principal,
		PasswordChangedAt: details.PasswordChangedAt,
		Provider:          res.Provider,
		Issuer:            res.Issuer,
		AMR:               slices.Clone(res.AMR),
		ACR:               res.ACR,
	}); err != nil {
		return err
	}

	if err := guardRedemption(out, principal, details.PasswordChangedAt); err != nil {
		return err
	}

	if err := guardFederatedAssurance(out, res.Provider, res.Issuer, res.AMR, res.ACR); err != nil {
		return err
	}

	// A browser returning from its provider carries no proof of a key, so the
	// sign-in is bound to none.
	login := newRedemptionLogin(i.loginTail(session.KeyBinding{}), out)

	in := postAuthenticationInput(&principal, factor.OIDC, "", details.PasswordChangedAt, i.now())
	in.FederatedAssurance = out.federated

	if err := login.issue(ctx, in); err != nil {
		return err
	}

	issued, err := login.redeemed()
	if err != nil {
		return err
	}

	// The provider's page sent the browser here with a code in the URL: the
	// next page must not learn it, whatever this answers.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")

	_, err = commitFederatedLogin(ex, login, issued, federatedSession{
		provider: res.Provider, issuer: res.Issuer, sessionID: res.SessionID, idToken: res.IDToken,
	}, principal.ID)

	var challenge *ChallengeError
	if err != nil && !errors.As(err, &challenge) {
		return err
	}

	redirectSignIn(ex, next)

	return nil
}
