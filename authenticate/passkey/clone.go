package passkey

//go:generate mockgen -source=clone.go -destination=clone_mock_test.go -package=passkey_test -typed

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/pkg/id"
)

// cloneGrantCause is the cause a suspended clone revokes the user's grants with.
const cloneGrantCause = "passkey_clone"

// GrantRevoker revokes every grant an application holds for a user, those with
// offline access included. *oidcprovider.Provider satisfies it.
type GrantRevoker interface {
	// RevokeUserGrants revokes every grant of user, recording cause. Revoking
	// what is already revoked is not an error.
	RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error
}

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
	// WithoutSessionRevocationOnClone), revokes the user's application grants
	// (WithGrantRevoker), queues the Suspended notice and writes a sampled
	// warning. It is the default.
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
	return func(m *Passkeys) { m.cloneResponse = r }
}

// WithClonePolicy sets a consumer function that decides each suspected clone,
// in place of the clone response. There is none by default. It is given the
// user, the credential's identifier, both counters and the backup flags, and
// returns CloneAllow, CloneRefuse or CloneRefuseSuspend; any other value is
// taken as CloneRefuseSuspend, the safe reading. Every suspected clone is
// also written as a sampled warning. A nil function is a configuration error.
func WithClonePolicy(fn func(ctx context.Context, s CloneSignal) CloneAction) Option {
	return func(m *Passkeys) {
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
func (m *Passkeys) onCounterRefused(ctx context.Context, c *Credential, res *AssertionResult) error {
	// The read-back and the suspension are detached from the request: a client
	// that disconnects once the write was refused must not leave a suspected
	// clone active.
	detached := context.WithoutCancel(ctx)

	now, err := m.credentials.Find(detached, c.User, c.ID)

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
		suspended, err := m.credentials.Suspend(detached, c.ID)
		if err != nil {
			return diag.Wrap(err, "passkey: could not suspend the credential", ErrCloneSuspected)
		}

		if suspended {
			ended := m.endSessionsOnClone(ctx, c)
			m.revokeGrantsOnClone(ctx, c)
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
func (m *Passkeys) endSessionsOnClone(ctx context.Context, c *Credential) bool {
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

// revokeGrantsOnClone revokes every application grant of c's user after c was
// suspended as a suspected clone, unless WithoutCloneGrantRevocation was given
// or there is no revoker. It runs under a context the caller cannot cancel, so a
// client that disconnects does not leave the grants alive.
//
// A credential suspends once, so nothing will ask again, and what is written here
// is all an operator gets to know the grants are still live by. A failure is
// therefore logged every time at error level, with no sampling, as one key would
// hide another user's, and reported as event.GrantRevokeFailed on a request a chain
// watches. The refusal stands either way.
func (m *Passkeys) revokeGrantsOnClone(ctx context.Context, c *Credential) {
	if m.grants == nil || m.keepGrantsOnClone {
		return
	}

	ctx = context.WithoutCancel(ctx)

	err := m.grants.RevokeUserGrants(ctx, c.User, cloneGrantCause)
	if err == nil {
		return
	}

	m.logger.LogAttrs(ctx, slog.LevelError, msgGrantsNotRevoked, append(diag.Failure("clone", err), credentialAttr(c.ID))...)
	eventsink.Send(ctx, event.Event{
		Name: event.GrantRevokeFailed, At: m.clock.Now(), Outcome: event.OutcomeFailure, User: c.User,
	})
}

// recordAllowedClone records the backup state and last use of an assertion
// allowed despite its counter, leaving the stored counter as it is. A
// credential that is no longer active, such as one suspended meanwhile, is
// refused as it now stands.
func (m *Passkeys) recordAllowedClone(ctx context.Context, c *Credential, res *AssertionResult) error {
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
func (m *Passkeys) cloneAction(ctx context.Context, signal CloneSignal) CloneAction {
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

// WithoutSessionRevocationOnClone keeps the user's sessions when a suspected
// clone suspends a passkey, replacing the default of ending every one of them,
// the session that presented the clone included.
func WithoutSessionRevocationOnClone() Option {
	return func(m *Passkeys) { m.keepOnClone = true }
}

// WithGrantRevoker revokes every application grant of the credential's user,
// those with offline access included, when a suspected clone suspends a passkey.
// It is how a provider learns of the clone: a session manager given as
// Deps.Sessions that was not built with the provider as its end observer ends
// sessions with no report a provider could see.
//
// The default is no revoker, and no grant is revoked, since this package alone
// has no provider. A chain with EnableOIDCProvider and EnablePasskeys refuses a
// manager with neither this option nor WithoutCloneGrantRevocation, so the default
// cannot silently leave grants alive there. A chain that uses the manager only
// through MFAMethod, without EnablePasskeys, cannot be seen by that check, and a
// consumer there must pass this option themselves.
//
// The revocation runs only when this call's suspension is the one that suspended
// the credential: never for CloneSignalOnly, CloneAllow or CloneRefuse, and once
// for racing assertions. Its failure is logged every time, reported as
// event.GrantRevokeFailed on a request a chain watches (the manager has no sink of
// its own, so off a chain the log is all there is), and the refusal stands.
// Removing a passkey by the user's own request revokes nothing.
//
// A nil revoker, typed nil included, is a configuration error from New.
func WithGrantRevoker(r GrantRevoker) Option {
	return func(m *Passkeys) { m.grants, m.grantsSet = r, true }
}

// WithoutCloneGrantRevocation keeps the user's application grants when a
// suspected clone suspends a passkey, replacing the revocation WithGrantRevoker
// sets up. Given with WithGrantRevoker, in either order, it wins and the grants
// are kept. It also tells a chain with a provider that keeping them was meant.
// The user's sessions end as usual (WithoutSessionRevocationOnClone).
//
// What it gives up: a suspected clone means someone else may hold the
// authenticator, and a grant kept is what they would keep, for as long as its
// refresh token lives.
func WithoutCloneGrantRevocation() Option {
	return func(m *Passkeys) { m.keepGrantsOnClone = true }
}

// CloneGrantsDecided reports whether the manager was told what a suspended clone
// does to the user's application grants: WithGrantRevoker or
// WithoutCloneGrantRevocation was given. A chain with a provider reads it to
// refuse a manager that was told neither.
func (m *Passkeys) CloneGrantsDecided() bool {
	return m.grants != nil || m.keepGrantsOnClone
}
