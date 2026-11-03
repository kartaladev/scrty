package httpsec

import (
	"context"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/security"
)

// reprove answers a password re-proof at POST <prefix>/password.
//
// The order is the requirement:
//
//  1. Admission: only a full session (admit).
//  2. The factor policy (passwordOffered), before the body is read: a user it
//     does not offer the password to, because they hold a second factor or
//     second-factor re-proof is required, is ErrReauthenticationMethodNotUsable,
//     and a lookup that fails refuses. The methods are looked up in order and
//     the first enrolled one settles it, so the ones after it are not asked.
//     Neither reads the body, checks a password or records anything.
//  3. The password, and nothing else, from the form field form login reads it
//     from or else a JSON body, under form login's body limit: a missing one is
//     ErrCredentialsMissing, an oversized body ErrRequestTooLarge.
//  4. The username is the resolved caller's, never the request's: a username
//     the request names is ignored, so a session cannot check, or lock, another
//     user's password. A resolved caller who is not the session's own user (a
//     consumer interceptor past the gates published another) or who has no
//     username is refused as authenticate.ErrAuthenticationFailed, before the
//     password is checked or anything is recorded.
//  5. Form login's own password order (attemptPassword), the one a login
//     runs: the password-login source guard, the pre-authentication phase, a
//     lock refused as a login refuses it, the password check, and a refused
//     password recorded against the user. The source is charged what a login
//     charges: a lock and a refused password check, an unavailable user
//     store included. Any other pre-authentication refusal, a policy deny or
//     an unenforced challenge, is not. The account the password proved must
//     be the session's own user.
//  6. The user's held account recoveries are cancelled, as a login cancels
//     them once its first factor is proved: the password shows the user
//     still holds the account. A cancellation the recovery store cannot
//     record refuses the re-proof with its error, as it refuses a login,
//     and leaves the session as it was. A re-proof the phase then refuses
//     has still cancelled, as a refused login has.
//  7. The post-authentication policy phase, with the input a login builds
//     for the same principal, first factor, username and password-change
//     time, read at the chain's time, and marked as the re-authentication
//     of an existing session (policy.Input.Reauthenticating), so a policy
//     counting sessions knows none is added (postAuthenticate). A deny
//     refuses with the policy's reason; a challenge refuses with a
//     *ChallengeError of its kind carrying no session, or as a configuration
//     error when nothing on the chain enforces it. Neither clears failures,
//     charges the source, rotates or refreshes anything.
//  8. Success clears the user's recorded failures, as a login does, and
//     resolves the re-proof. A login clears them before its phase, so one a
//     policy denies has still cleared them; a re-proof clears them only here.
func (i *reauthInterceptor) reprove(ex *Exchange) error {
	s, err := i.admit(ex)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	if password, err := i.passwordOffered(ctx, s); err != nil {
		return err
	} else if !password {
		return ErrReauthenticationMethodNotUsable
	}

	l := i.login

	password, err := readPassword(l, ex.Request)
	if err != nil {
		return err
	}

	// Before the password is checked, so a bad proof is never a failed
	// password and spends nothing.
	binding, err := reauthBinding(ex, s)
	if err != nil {
		return err
	}

	principal := ex.Authentication.Principal
	if principal.ID != s.UserID {
		return authenticate.ErrAuthenticationFailed
	}

	username := principal.Username
	if username == "" {
		return authenticate.ErrAuthenticationFailed
	}

	now := i.now()

	verifyCtx, upgrade := requestRehash(ctx, i.rehash)

	// Ends the handle on every outcome, after any Result, so the presented
	// password does not outlive the request.
	defer upgrade.Discard()

	// A re-proof is made from a signed-in session, so no automation challenge
	// stands in front of it.
	auth, err := l.attemptPassword(verifyCtx, ex.Request.ClientIP(), username, password, now,
		func(ctx context.Context) {
			emitEvent(ctx, sessionEvent(security.ReauthenticationFail, security.OutcomeFailure, s))
		}, nil)
	if err != nil {
		return err
	}

	// The username is the caller's as published, so the account it proved is
	// confirmed to be the session's own before anything is reset or refreshed.
	if auth == nil || auth.Principal == nil || auth.Principal.ID != s.UserID {
		return authenticate.ErrAuthenticationFailed
	}

	// The proved password shows the user still holds the account, so their
	// held recoveries are cancelled as a login cancels them, before the phase.
	if l.cancelHeld != nil {
		if err := l.cancelHeld(ctx, s.UserID); err != nil {
			return err
		}
	}

	in := postAuthenticationInput(auth.Principal, factor.Password, username, auth.PasswordChangedAt, now)
	in.Reauthenticating = true

	err = postAuthenticate(ctx, l, in)

	// As at login, a re-proof that is accepted, or challenged for a second
	// factor, upgrades an outdated hash; any other refusal does not.
	if err == nil || isChallenge(err) {
		runRehash(ctx, i.log, i.rehash, upgrade)
	}

	if err != nil {
		return err
	}

	l.resetFailures(ctx, username)

	return i.resolve(ex, s, nil, binding)
}

// postAuthenticate applies the post-authentication phase to a proved
// password re-proof, on form login's engine and with the input a login builds,
// and refuses as a login refuses: a deny with the policy's reason, and a
// challenge nothing on the chain enforces (or one only a built-in gate raises)
// with a configuration error.
//
// Any other challenge refuses with a *ChallengeError of its kind carrying no
// session and no token. A re-proof never marks or rotates a session into a
// pending state; the user meets the challenge by signing in, where a login
// marks it. A refusal here charges nothing to the source and records nothing
// against the user, as at login, where the phase runs after the password has
// been accepted.
func postAuthenticate(ctx context.Context, l *formLogin, in *policy.Input) error {
	d := evaluatePhase(ctx, l.engine, policy.PostAuthentication, in)

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		return refuseReproofChallenge(l.enforced, d.Challenge)
	case policy.Allow:
	}

	return nil
}

// refuseReproofChallenge is the refusal of a re-proof whose post-authentication
// phase challenged for kind, the same at the password and second-factor
// endpoints: a kind nothing on the chain enforces (enforced), or one only a
// built-in gate raises, is a configuration error, and any other kind a
// *ChallengeError of that kind carrying no session and no token.
func refuseReproofChallenge(enforced map[policy.ChallengeKind]bool, kind policy.ChallengeKind) error {
	if err := refuseUnenforced(enforced, kind); err != nil {
		return err
	}

	return &ChallengeError{Kind: kind}
}

// readPassword reads only the password out of a re-proof request, the way
// form login binds a login: the body under form login's limit, then the form
// field form login reads the password from, or the JSON member of that name
// when the form yields none. Every other field, a username included, is
// ignored.
func readPassword(l *formLogin, r Request) ([]byte, error) {
	body, err := r.Body(l.bodyLimit)
	if err != nil {
		return nil, err
	}

	password, _ := l.bindForm(r, body)[l.passwordParam].(string)

	if password == "" {
		fields, err := l.bindJSON(r, body)
		if err != nil {
			return nil, err
		}

		password, _ = fields[l.passwordParam].(string)
	}

	if password == "" {
		return nil, ErrCredentialsMissing
	}

	return []byte(password), nil
}
