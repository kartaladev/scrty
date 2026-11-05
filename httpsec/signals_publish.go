package httpsec

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// CredentialKind names the kind of credential a credential_changed signal reports.
type CredentialKind string

const (
	// CredentialPassword is a changed or reset password.
	CredentialPassword CredentialKind = credentialKindPassword

	// CredentialPasskey is a passkey added or removed.
	CredentialPasskey CredentialKind = credentialKindPasskey

	// CredentialSecondFactor is a second factor enrolled or removed.
	CredentialSecondFactor CredentialKind = credentialKindSecondFactor
)

// ReportCredentialChange tells every open stream of user that a credential of the given kind
// changed, as the chain's own endpoints do for the changes they make. Use it for a change made
// outside them, such as an admin console or a reset of the consumer's own. The signal names
// only the kind and carries no detail of the credential. A stream the change ended hears
// session_ended instead, from the session manager.
//
// Call it after the change has committed: a raised signal cannot be recalled, so one raised
// ahead of a transaction that then rolls back tells the user of a change that never happened.
// A signal that is dropped is gone, and the default bus reaches only this replica's streams, so
// a consumer must not rely on it alone: the notice sent out of band stays the record.
//
// By default a chain's set lacks credential_changed (SessionSignals.Signals), and then nothing is
// raised at all: no stream of the chain can send it, so a consumer's bus is handed nothing, and nil is
// returned whether or not that bus could have taken it. Put the signal in the set to send it. Every
// replica sharing a bus is expected to run the same set, because a replica lacking the signal raises
// none, and its streams send none that another replica raised.
//
// It returns ErrSessionSignalsDisabled on a chain without EnableSessionSignals, ErrInvalidSignal
// for a kind other than the three above, and ErrSignalsBusy when a consumer's bus could not take
// the signal, or, on either bus, after CloseSessionSignals, since nil would say it was sent. A user
// with no open stream is not an error. The signal is raised on a detached context, since a bus
// outlives the request, and ctx is not used.
func (c *Chain) ReportCredentialChange(_ context.Context, user identity.UserID, kind CredentialKind) error {
	e := c.signalsEndpoint()
	if e == nil {
		return ErrSessionSignalsDisabled
	}

	switch kind {
	case CredentialPassword, CredentialPasskey, CredentialSecondFactor:
	default:
		return fmt.Errorf("%w: unknown credential kind", ErrInvalidSignal)
	}

	return e.raiseCredentialChange(user, kind) //nolint:contextcheck // detached on purpose: a bus outlives the request, and ctx is documented as unused
}

// raiseCredentialChange hands a credential_changed of a known kind to the hub, which never blocks. A
// chain whose set lacks the signal raises nothing: no stream of it could send one, and a consumer's bus
// is not to carry what it cannot, or to report busy for it. Every raise passes here, so that holds of
// the chain's endpoints and of ReportCredentialChange alike. Every replica is expected to run the same
// set, or a signal from a replica holding it reaches no stream of one that does not.
func (e *sessionSignals) raiseCredentialChange(user identity.UserID, kind CredentialKind) error {
	if !e.set[SignalCredentialChanged] {
		return nil
	}

	// The kind is one of the three constants, so it needs no escaping.
	data := json.RawMessage(`{"kind":"` + string(kind) + `"}`)

	return e.hub.raise(SignalEnvelope{User: user, Name: string(SignalCredentialChanged), Data: data}) //nolint:contextcheck // detached on purpose: a bus outlives the request
}

// credentialChanged tells the open streams of user that a credential of the given kind changed,
// for an endpoint of the chain this exchange runs through that has just written it. It is called
// after the write, never before and never on a refusal. The change has happened whatever the
// signal does, so a full or closed bus changes nothing the endpoint answers, and a chain without
// signals, or an exchange of none, does nothing.
func (ex *Exchange) credentialChanged(user identity.UserID, kind CredentialKind) {
	ph := ex.perRequest
	if ph == nil || ph.signals == nil {
		return
	}

	_ = ph.signals.raiseCredentialChange(user, kind)
}

// credentialsRemoved tells the open streams of user which kinds of credential a completed
// recovery removed, one credential_changed for each kind, in the order the recovery removed them.
// removed is recovery.Result.Removed. Only the kinds the signal names are told: recovery.MFAKind
// is a second_factor and the passkey kind is a passkey, and a consumer's own kind raises
// nothing, since the signal's set of kinds is closed. Kinds are told by name, and the name is the
// contract: a consumer's kind that takes recovery.MFAKind or passkey.RecoveryKindName, where the
// library's own is not registered, raises that signal. Nothing of the references reaches a stream.
// The recovery never removes a password: one bound afterwards is raised by the password-change
// endpoint. Like credentialChanged, it changes nothing the endpoint answers.
func (ex *Exchange) credentialsRemoved(user identity.UserID, removed []recovery.AuthenticatorRef) {
	var told [2]bool

	for _, ref := range removed {
		var kind CredentialKind

		switch ref.Kind {
		case recovery.MFAKind:
			kind = CredentialSecondFactor
			if told[0] {
				continue
			}

			told[0] = true
		case passkey.RecoveryKindName:
			kind = CredentialPasskey
			if told[1] {
				continue
			}

			told[1] = true
		default:
			continue
		}

		ex.credentialChanged(user, kind)
	}
}

// PublishSignal sends the consumer's own signal to every open stream of user, whose client hears
// it unless its narrowing leaves the name out. The name must be "app." followed by 1 to 63
// characters, the first a lowercase letter or digit and the rest lowercase letters, digits, '.',
// '_' or '-'. data is the consumer's own JSON, of at most 8 KiB, valid UTF-8, with no raw line
// break between its tokens (compact it, do not indent it), and it reaches the browser byte for
// byte. The library does not interpret either. Nothing is sent for a refused signal.
//
// A stream can follow a thief who holds the session, so put nothing in data the signed-in user
// should not hand to whoever holds that session: send a pointer to what changed, such as a
// version, and let the client fetch it through its own authorised request.
//
// Like ReportCredentialChange, a signal cannot be recalled once raised, and a dropped one is
// gone: the default bus reaches only this replica's streams, so a consumer must not rely on one
// alone. ctx is not used, as a bus outlives the request.
//
// It returns ErrSessionSignalsDisabled on a chain without EnableSessionSignals, ErrInvalidSignal
// for a name or data outside the limits above, and ErrSignalsBusy when a consumer's bus could not
// take the signal, or, on either bus, after CloseSessionSignals, since nil would say it was sent. A
// user with no open stream is not an error.
func (c *Chain) PublishSignal(_ context.Context, user identity.UserID, name string, data json.RawMessage) error {
	e := c.signalsEndpoint()
	if e == nil {
		return ErrSessionSignalsDisabled
	}

	if !validAppSignalName(name) {
		return fmt.Errorf("%w: name is not app. followed by 1 to 63 of [a-z0-9._-]", ErrInvalidSignal)
	}

	if !validSignalData(data) {
		return fmt.Errorf("%w: data is not up to 8 KiB of one-line valid JSON and UTF-8", ErrInvalidSignal)
	}

	return e.hub.raise(SignalEnvelope{User: user, Name: name, Data: data}) //nolint:contextcheck // detached on purpose: a bus outlives the request
}
