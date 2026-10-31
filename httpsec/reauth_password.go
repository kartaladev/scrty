package httpsec

import (
	"github.com/kartaladev/scrty/authenticate"
)

// reprove answers a password re-proof at POST <prefix>/password.
//
// The order is the requirement:
//
//  1. Admission: only a full session (admit).
//  2. The factor policy (offered), before the body is read: a user it does not
//     offer the password to, because they hold a second factor or second-factor
//     re-proof is required, is ErrReauthenticationMethodNotUsable, and a lookup
//     that fails refuses. Neither reads the body, checks a password or records
//     anything.
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
//     an unenforced challenge, is not.
//  6. Success clears the user's recorded failures, as a login does, and
//     resolves the re-proof.
func (i *reauthInterceptor) reprove(ex *Exchange) error {
	s, err := i.admit(ex)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	if _, password, err := i.offered(ctx, s); err != nil {
		return err
	} else if !password {
		return ErrReauthenticationMethodNotUsable
	}

	l := i.login

	password, err := readPassword(l, ex.Request)
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

	auth, err := l.attemptPassword(ctx, ex.Request.ClientIP(), username, password, i.now())
	if err != nil {
		return err
	}

	// The username is the caller's as published, so the account it proved is
	// confirmed to be the session's own before anything is reset or refreshed.
	if auth == nil || auth.Principal == nil || auth.Principal.ID != s.UserID {
		return authenticate.ErrAuthenticationFailed
	}

	l.resetFailures(ctx, username)

	return i.resolve(ex, s, nil)
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
