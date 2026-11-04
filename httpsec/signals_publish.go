package httpsec

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kartaladev/scrty/identity"
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
// It returns ErrSessionSignalsDisabled on a chain without EnableSessionSignals, ErrInvalidSignal
// for a kind other than the three above, and ErrSignalsBusy when a consumer's bus could not take
// the signal. A user with no open stream is not an error, and neither is a chain whose set of
// signals lacks credential_changed: no stream sends it, so nothing is sent. The signal is raised
// on a detached context, since a bus outlives the request, and ctx is not used.
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

	data, err := json.Marshal(struct {
		Kind CredentialKind `json:"kind"`
	}{kind})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignal, err)
	}

	return e.hub.raise(SignalEnvelope{User: user, Name: string(SignalCredentialChanged), Data: data}) //nolint:contextcheck // detached on purpose: a bus outlives the request
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
// take the signal. A user with no open stream is not an error.
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
