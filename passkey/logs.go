package passkey

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate"

	"github.com/kartaladev/scrty/pkg/id"
)

// The messages of the records the manager writes. None carries a challenge,
// a code, a user handle, a public key, an attestation statement, a WebAuthn
// credential ID or a contact address: a credential is named only by its
// library identifier, and a dependency's failure only by a fixed reason and
// its Go type.
const (
	msgNoticeNotQueued  = "passkey: a notice was not queued"
	msgSuppressed       = "passkey: records suppressed"
	msgSyncedUnknown    = "passkey: could not tell whether the user has a synced passkey"
	msgPurgeFailed      = "passkey: expired login challenges were not purged"
	msgRefused          = "passkey: assertion refused"
	msgClone            = "passkey: suspected clone"
	msgSessionsNotEnded = "passkey: the user's sessions could not all be ended"
)

// sampled writes the record msg at level under key when the manager's sampler
// lets it through, with the count of records suppressed for key since its
// last one. attrs never carry a secret.
func (m *Manager) sampled(ctx context.Context, level slog.Level, key, msg string, attrs ...slog.Attr) {
	write, suppressed := m.sampler.Allow(key, m.clock.Now())
	if !write {
		return
	}

	attrs = append(attrs, slog.String("key", key))
	if suppressed > 0 {
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}

	m.logger.LogAttrs(ctx, level, msg, attrs...)
}

// reportSuppressed is the sampler's reporter: it writes how many records
// under key the sampler held back.
func (m *Manager) reportSuppressed(key string, suppressed int) {
	m.logger.LogAttrs(context.Background(), slog.LevelInfo, msgSuppressed,
		slog.String("key", key), slog.Int("suppressed", suppressed))
}

// credentialAttr names a credential in a record by its library identifier.
func credentialAttr(cid id.ID) slog.Attr {
	return slog.String("credential", cid.String())
}

// refused writes the sampled record of an assertion refused for reason, keyed
// by the reason, naming credential cid when it is known, and returns
// authenticate.ErrAuthenticationFailed, the one refusal a client sees.
func (m *Manager) refused(ctx context.Context, reason string, cid id.ID, attrs ...slog.Attr) error {
	attrs = append(attrs, slog.String("refusal", reason))
	if !cid.IsZero() {
		attrs = append(attrs, credentialAttr(cid))
	}

	m.sampled(ctx, slog.LevelInfo, "refused|"+reason, msgRefused, attrs...)

	return authenticate.ErrAuthenticationFailed
}

// WithLogInterval replaces the window of the manager's log sampler: refused
// assertions, suspected clones and notices that could not be queued are each
// written at most once per key per window, keyed by reason, and the counts
// held back are reported. The default is one minute. An interval of zero or
// less writes every record. It governs the passkey manager's records only.
func WithLogInterval(d time.Duration) Option {
	return func(m *Manager) { m.logInterval = d }
}

// FlushRefusalLogs reports every count of records the manager's sampler has
// held back but not yet reported, then forgets every key, so counts held for
// a window that will never close are not lost — for example at shutdown. It
// is safe to call more than once and while ceremonies are in flight, and it
// never fails: its reporter only logs.
func (m *Manager) FlushRefusalLogs() error {
	m.sampler.Flush()

	return nil
}

// LogInterval is the window of the manager's log sampler: the one
// WithLogInterval set, or one minute when none was given. An interval of zero
// or less means every record is written. It is for an integration that
// samples records about passkeys of its own and wants the same window the
// consumer chose for the manager's, so one option governs both.
func (m *Manager) LogInterval() time.Duration { return m.logInterval }
