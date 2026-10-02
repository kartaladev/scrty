package httpsec

import (
	"encoding/json"

	"github.com/kartaladev/scrty/passkey"
)

// PasskeyBeginResponder writes a ceremony begin's answer: options are the
// creation or request options for the browser, as the verifier rendered them
// (the members of navigator.credentials' publicKey argument).
//
// It is called instead of the downstream handler. An error it returns leaves
// the chain as the request's refusal; the challenge in the options has
// already been issued and will expire unused.
type PasskeyBeginResponder func(ex *Exchange, options json.RawMessage) error

// PasskeyRegistrationResponder writes a finished registration. res carries
// the stored passkey, whether it is active, and the saved recovery codes when
// it awaits their confirmation, which is the only time they are readable: a
// responder that drops them leaves the user unable to confirm.
//
// It is called instead of the downstream handler, after the passkey is
// stored and, when it became active, after a confined session has been moved
// on to its second factor.
type PasskeyRegistrationResponder func(ex *Exchange, res *passkey.RegistrationResult) error

// WithPasskeyRegistrationPrefix answers the registration endpoints under
// prefix instead: POST "<prefix>/begin", "<prefix>/finish", "<prefix>/confirm"
// and "<prefix>/confirm-email".
//
// Default: DefaultPasskeyRegistrationPrefix. A trailing slash is dropped. An
// empty prefix, one that does not start with "/", and the root "/" are
// refused; New also refuses a prefix whose paths collide with another
// endpoint's (see EnablePasskeys). The recovery and enrolment gates exempt
// the moved paths, not the defaults.
func WithPasskeyRegistrationPrefix(prefix string) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		trimmed, err := passkeyPrefix("WithPasskeyRegistrationPrefix", prefix)
		if err != nil {
			return err
		}

		p.regPrefix = trimmed

		return nil
	}
}

// WithPasskeyCredentialsPrefix answers the management endpoints under prefix
// instead: GET "<prefix>" lists, POST "<prefix>/rename" renames and POST
// "<prefix>/remove" removes.
//
// Default: DefaultPasskeyCredentialsPrefix. It is validated as
// WithPasskeyRegistrationPrefix's is.
func WithPasskeyCredentialsPrefix(prefix string) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		trimmed, err := passkeyPrefix("WithPasskeyCredentialsPrefix", prefix)
		if err != nil {
			return err
		}

		p.credPrefix = trimmed

		return nil
	}
}

// WithPasskeyBeginResponder replaces how a registration begin is answered.
//
// Default: 200 with {"publicKey":<options>} as JSON, and Cache-Control:
// no-store. A nil function is refused; omit the option to keep the default.
func WithPasskeyBeginResponder(fn PasskeyBeginResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyBeginResponder was given no function; omit the " +
				"option to keep the default document")
		}

		p.respondBegin = fn

		return nil
	}
}

// WithPasskeyRegistrationResponder replaces how a finished registration is
// answered.
//
// Default: 200 with {"id","name","state","pending","recovery_codes",
// "backup_eligible","no_synced_passkey","recovery_not_set_up"} as JSON, and
// Cache-Control: no-store (see EnablePasskeys). A nil function is refused;
// omit the option to keep the default.
func WithPasskeyRegistrationResponder(fn PasskeyRegistrationResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyRegistrationResponder was given no function; omit " +
				"the option to keep the default document")
		}

		p.respondRegistration = fn

		return nil
	}
}
