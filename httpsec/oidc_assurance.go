package httpsec

import (
	"slices"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/session"
)

// RFC 8176 values the default states.
const (
	amrPassword = "pwd"
	amrMFA      = "mfa"
)

// defaultOIDCSignInAssurance is the amr and acr a sign-in's session states, by the
// mapping WithOIDCSignInAssurance documents. A value is stated only when the session
// can truthfully assert it.
func defaultOIDCSignInAssurance(s *session.Session) (amr []string, acr string) {
	switch s.FirstFactor {
	case factor.Password, factor.Basic:
		amr = []string{amrPassword}
	case factor.OIDC:
		assured := sessionFederatedAssurance(s)
		amr, acr = slices.Clone(assured.AMR()), assured.ACR()
	}

	if s.MFA == session.MFASatisfied && !slices.Contains(amr, amrMFA) {
		amr = append(amr, amrMFA)
	}

	return amr, acr
}

// WithOIDCSignInAssurance replaces how a sign-in's session states its authentication
// methods (amr) and class (acr) to the provider, and so what the ID tokens it issues
// assert. The function is called once per resumed sign-in with a session that passed
// the chain's gates, and its results are used as given.
//
// Default, which asserts a value only when the session can truthfully assert it:
//
//   - amr is "pwd" for factor.Password and factor.Basic;
//   - for factor.OIDC it is the upstream's own amr;
//   - factor.Passkey, factor.MagicLink, factor.Recovery, a consumer's own kind and an
//     unset kind state no method, because no value in RFC 8176 describes them
//     truthfully: a passkey cannot be told apart as "hwk" or "swk", and a magic link is
//     not an "otp";
//   - when the session's second factor is satisfied (session.MFASatisfied), "mfa" is
//     added whatever the first factor, once. The session does not record which second
//     factor was used, so nothing more specific is asserted;
//   - acr is the upstream's for a federated sign-in and empty otherwise, because scrty
//     defines no assurance levels.
//
// So a password and a second factor is ["pwd","mfa"], a password alone is ["pwd"], a
// passkey that met the second factor at login is ["mfa"], and a passkey alone states
// nothing.
//
// A nil function is refused with ErrConfig, because it would read as the default while
// the consumer believed they had replaced it. Given twice is refused too.
func WithOIDCSignInAssurance(assurance func(*session.Session) (amr []string, acr string)) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if assurance == nil {
			return newConfigError("WithOIDCSignInAssurance needs a function")
		}

		if op.resume.assuranceSet {
			return newConfigError("WithOIDCSignInAssurance was given twice")
		}

		op.resume.assurance = assurance
		op.resume.assuranceSet = true

		return nil
	}
}
