package passkey

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/id"
)

// CloneResponse is what the library does about a suspected clone when no
// consumer clone policy is set.
//
// A clone is suspected when an accepted assertion's counter does not move
// forward on a credential that is still active, and the two counters are not
// both zero. The counter write decides it, so of two concurrent assertions
// carrying one counter, exactly one is recorded and the other is a suspected
// clone. Authenticators that always report zero, as synced passkeys do, are
// never affected.
type CloneResponse uint8

const (
	// CloneSuspend refuses the login or verification with ErrCloneSuspected,
	// suspends the credential, ends every session of its user (unless
	// WithoutSessionRevocationOnClone), queues the Suspended notice and
	// writes a sampled warning. It is the default.
	CloneSuspend CloneResponse = iota + 1
	// CloneSignalOnly allows the login or verification, leaves the stored
	// counter as it is, and writes a sampled warning naming the credential's
	// library identifier.
	CloneSignalOnly
)

// CloneAction is a consumer clone policy's decision about one suspected
// clone.
type CloneAction uint8

const (
	// CloneAllow allows the login or verification, leaving the stored counter
	// as it is.
	CloneAllow CloneAction = iota + 1
	// CloneRefuse refuses with ErrCloneSuspected, leaving the credential
	// active.
	CloneRefuse
	// CloneRefuseSuspend refuses with ErrCloneSuspected, suspends the
	// credential, ends its user's sessions and queues the Suspended notice,
	// as CloneSuspend does.
	CloneRefuseSuspend
)

// CloneSignal is what a consumer clone policy is given about a suspected
// clone.
type CloneSignal struct {
	// User is the credential's user.
	User identity.UserID
	// Credential is the credential's library identifier.
	Credential id.ID
	// Stored is the counter stored for the credential, and Presented the one
	// the assertion carried.
	Stored    uint32
	Presented uint32
	// BackupEligible and BackupState are the assertion's backup flags.
	BackupEligible bool
	BackupState    bool
}

// WithCloneResponse replaces what the library does about a suspected clone.
// The default is CloneSuspend: refuse, suspend the credential, end the
// user's sessions and notify the user. CloneSignalOnly allows the login and
// only writes a warning. A consumer clone policy, when set, decides in its
// place. Any other value is a configuration error.
func WithCloneResponse(r CloneResponse) Option {
	return func(m *Manager) { m.cloneResponse = r }
}

// WithClonePolicy sets a consumer function that decides each suspected clone,
// in place of the clone response. There is none by default. It is given the
// user, the credential's identifier, both counters and the backup flags, and
// returns CloneAllow, CloneRefuse or CloneRefuseSuspend; any other value is
// taken as CloneRefuseSuspend, the safe reading. Every suspected clone is
// also written as a sampled warning. A nil function is a configuration error.
func WithClonePolicy(fn func(ctx context.Context, s CloneSignal) CloneAction) Option {
	return func(m *Manager) {
		m.clonePolicy = fn
		m.clonePolicySet = true
	}
}

// onCounterRefused handles a counter write the store refused for c. A
// credential no longer found or no longer active is refused as it now
// stands; one still active is a suspected clone, decided by the consumer's
// policy or the clone response. Only the call whose Suspend suspended c ends
// the user's sessions and queues the notice: of two racing clone assertions,
// one does.
func (m *Manager) onCounterRefused(ctx context.Context, c *Credential, res *AssertionResult) error {
	now, err := m.credentials.Find(ctx, c.User, c.ID)

	switch {
	case errors.Is(err, ErrNotFound):
		return m.refused(ctx, "counter", c.ID)
	case err != nil:
		return diag.Wrap(err, "passkey: could not read the credential back")
	case now == nil:
		return m.refused(ctx, "counter", c.ID)
	case now.State == StateSuspended:
		_ = m.refused(ctx, "suspended", c.ID)
		return ErrSuspended
	case now.State != StateActive:
		return m.refused(ctx, "counter", c.ID)
	}

	signal := CloneSignal{
		User:           c.User,
		Credential:     c.ID,
		Stored:         now.SignCount,
		Presented:      res.SignCount,
		BackupEligible: res.BackupEligible,
		BackupState:    res.BackupState,
	}

	action := m.cloneAction(ctx, signal)

	m.sampled(ctx, slog.LevelWarn, "clone|"+c.ID.String(), msgClone,
		credentialAttr(c.ID), slog.String("action", action.String()))

	switch action {
	case CloneAllow:
		return m.recordAllowedClone(ctx, c, res)
	case CloneRefuse:
		return ErrCloneSuspected
	default:
		// The suspension is detached from the request: a client that
		// disconnects must not leave a suspected clone active.
		suspended, err := m.credentials.Suspend(context.WithoutCancel(ctx), c.ID)
		if err != nil {
			return diag.Wrap(err, "passkey: could not suspend the credential", ErrCloneSuspected)
		}

		if suspended {
			ended := m.endSessionsOnClone(ctx, c)
			m.notify(ctx, noticeSuspended, now, nil, ended)
		}

		return ErrCloneSuspected
	}
}

// endSessionsOnClone ends every session of c's user after c was suspended as
// a suspected clone, unless WithoutSessionRevocationOnClone was given, and
// reports whether it did. It runs under a context the caller cannot cancel,
// so a client that disconnects does not leave the sessions alive. Its failure
// is logged at error level; the refusal stands either way.
//
// The manager holds a revoker whenever clone revocation is on: New refuses
// any other wiring.
func (m *Manager) endSessionsOnClone(ctx context.Context, c *Credential) bool {
	if m.keepOnClone {
		return false
	}

	ctx = context.WithoutCancel(ctx)

	if err := m.sessions.DeleteByUser(ctx, c.User); err != nil {
		m.sampled(ctx, slog.LevelError, "clone|sessions-not-ended", msgSessionsNotEnded,
			append(diag.Failure("clone", err), credentialAttr(c.ID))...)

		return false
	}

	return true
}

// recordAllowedClone records the backup state and last use of an assertion
// allowed despite its counter, leaving the stored counter as it is. A
// credential that is no longer active, such as one suspended meanwhile, is
// refused as it now stands.
func (m *Manager) recordAllowedClone(ctx context.Context, c *Credential, res *AssertionResult) error {
	recorded, err := m.credentials.RecordUse(ctx, c.ID, res.BackupState, m.clock.Now())
	if err != nil {
		return diag.Wrap(err, "passkey: could not record the assertion")
	}

	if recorded {
		return nil
	}

	now, err := m.credentials.Find(ctx, c.User, c.ID)
	if err == nil && now != nil && now.State == StateSuspended {
		_ = m.refused(ctx, "suspended", c.ID)
		return ErrSuspended
	}

	return m.refused(ctx, "counter", c.ID)
}

// cloneAction is the decision about signal: the consumer's policy when set,
// otherwise the clone response.
func (m *Manager) cloneAction(ctx context.Context, signal CloneSignal) CloneAction {
	if m.clonePolicy != nil {
		switch a := m.clonePolicy(ctx, signal); a {
		case CloneAllow, CloneRefuse, CloneRefuseSuspend:
			return a
		default:
			return CloneRefuseSuspend
		}
	}

	if m.cloneResponse == CloneSignalOnly {
		return CloneAllow
	}

	return CloneRefuseSuspend
}

// String names the action in a warning record.
func (a CloneAction) String() string {
	switch a {
	case CloneAllow:
		return "allow"
	case CloneRefuse:
		return "refuse"
	case CloneRefuseSuspend:
		return "refuse-suspend"
	default:
		return "unknown"
	}
}
