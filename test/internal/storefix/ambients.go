package storefix

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// AmbientSID is the identifier of the session record i of the ambient suite.
func AmbientSID(i int) string { return fmt.Sprintf("ambient-sid-%d", i) }

// SessionAmbient is the ambient suite's view of the session store: record i
// is a session, and the refusal a save of a session that is not stored.
func SessionAmbient() storetest.Ambient[session.Store] {
	return storetest.Ambient[session.Store]{
		Write: func(ctx context.Context, s session.Store, i int) error {
			return s.Create(ctx, DurableSession(AmbientSID(i), time.Now()))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id_digest = $1)`, Digest(AmbientSID(i)))
		},
		Refuse: func(ctx context.Context, s session.Store) error {
			return s.Save(ctx, DurableSession("ambient-sid-never-created", time.Now()))
		},
		Refusal: session.ErrSessionNotFound,
	}
}

// AmbientToken is the one-time token record i of the ambient suite.
func AmbientToken(i int) onetime.Token {
	tok := RaceToken(0x10000 + i)
	tok.Purpose = "ambient"

	return tok
}

// OneTimeAmbient is the ambient suite's view of the one-time token store:
// record i is a token, and the refusal a consumption of a token that does
// not exist.
func OneTimeAmbient[S onetime.Store]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			return s.Insert(ctx, AmbientToken(i))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM one_time_tokens WHERE id = $1)`, AmbientToken(i).ID)
		},
		Refuse: func(ctx context.Context, s S) error {
			return s.Consume(ctx, AmbientToken(999).ID, time.Now())
		},
		Refusal: onetime.ErrTokenNotFound,
	}
}

// AttemptAmbient is the ambient suite's view of the login-attempt store:
// record i is a failure of its own user. The contract refuses nothing by a
// write, so the refusal is the reaper's refusal of a zero cutoff.
func AttemptAmbient[S interface {
	policy.AttemptStore
	policy.AttemptReaper
}]() storetest.Ambient[S] {
	user := func(i int) string { return fmt.Sprintf("ambient-user-%d", i) }

	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			return s.RecordFailure(ctx, user(i), time.Now())
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM login_attempts WHERE username = $1)`, user(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			// Refused before any statement runs, so this case cannot fail for this store;
			// the signing-key refusal is the one that runs a statement inside the transaction.
			_, err := s.DeleteAttemptsBefore(ctx, time.Time{})
			return err
		},
		Refusal: policy.ErrRetainSinceRequired,
	}
}

// SigningKeyAmbient is the ambient suite's view of the signing-key store:
// record i is a key. The contract refuses nothing by a write, so the refusal
// is a load that fails closed: foreign builds a store over the same database
// whose cipher seals under a key the store under test does not hold, a key it
// seals is stored through the same context, and the load refuses the whole
// set with seal.ErrUnknownKeyID. It is read-side only, so it runs no failing
// statement either.
func SigningKeyAmbient(foreign func() (signingkey.KeyStore, error)) storetest.Ambient[signingkey.KeyStore] {
	kid := func(i int) string { return fmt.Sprintf("ambient-kid-%d", i) }

	return storetest.Ambient[signingkey.KeyStore]{
		Write: func(ctx context.Context, s signingkey.KeyStore, i int) error {
			return s.Store(ctx, SigningKey(kid(i), []byte("PKCS8-"+kid(i))))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM signing_keys WHERE kid = $1)`, kid(i))
		},
		Refuse: func(ctx context.Context, s signingkey.KeyStore) error {
			other, err := foreign()
			if err != nil {
				return err
			}
			if err := other.Store(ctx, SigningKey("ambient-kid-foreign", []byte("PKCS8-FOREIGN"))); err != nil {
				return err
			}
			_, err = s.LoadAll(ctx)
			return err
		},
		Refusal: seal.ErrUnknownKeyID,
	}
}

// EnrolmentAmbient is the ambient suite's view of the MFA store: record i is
// a pending enrolment, and the refusal a begin over a confirmed one.
func EnrolmentAmbient() storetest.Ambient[mfa.EnrolmentStore] {
	user := func(i int) identity.UserID { return identity.UserID(fmt.Sprintf("ambient-user-%d", i)) }

	return storetest.Ambient[mfa.EnrolmentStore]{
		Write: func(ctx context.Context, s mfa.EnrolmentStore, i int) error {
			return s.PutPending(ctx, Pending(user(i), "TOTP-SECRET"))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM mfa_enrolments WHERE user_id = $1)`, string(user(i)))
		},
		Refuse: func(ctx context.Context, s mfa.EnrolmentStore) error {
			if err := s.PutPending(ctx, Pending("ambient-confirmed", "TOTP-SECRET")); err != nil {
				return err
			}
			if _, err := s.Confirm(ctx, "ambient-confirmed", 1000, EnrolmentBegun); err != nil {
				return err
			}
			return s.PutPending(ctx, Pending("ambient-confirmed", "TOTP-OTHER"))
		},
		Refusal: mfa.ErrAlreadyEnrolled,
	}
}

// APIKeyAmbient is the ambient suite's view of the API key store: record i
// is a key, and the refusal a revocation of a key that does not exist.
func APIKeyAmbient[S apikey.Store]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			return s.Put(ctx, APIKey(i, "ambient-svc"))
		},
		Present: APIKeyPresent,
		Refuse: func(ctx context.Context, s S) error {
			return s.Revoke(ctx, APIKey(999, "").ID, time.Now())
		},
		Refusal: apikey.ErrKeyNotFound,
	}
}

// LinkAmbient is the ambient suite's view of the link store: record i is a
// link of its own subject, and the refusal a second insert of one link.
func LinkAmbient[S oidc.LinkStore]() storetest.Ambient[S] {
	gen := id.NewV7Generator()
	subject := func(i int) string { return fmt.Sprintf("ambient-subject-%d", i) }
	insert := func(ctx context.Context, s S, subject string) error {
		linkID, err := gen.NewID()
		if err != nil {
			return err
		}
		return s.Insert(ctx, oidc.Link{
			ID: linkID, Provider: "corp", Issuer: "https://ambient.example", Subject: subject,
			UserID: "ambient-user", CreatedAt: OIDCStart,
		})
	}

	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error { return insert(ctx, s, subject(i)) },
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_links WHERE subject = $1)`, subject(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			if err := insert(ctx, s, "ambient-subject-twice"); err != nil {
				return err
			}
			return insert(ctx, s, "ambient-subject-twice")
		},
		Refusal: oidc.ErrLinkExists,
	}
}

// FlowAmbient is the ambient suite's view of the flow store: record i is a
// flow of its own state, and the refusal a completion of an unknown handle.
func FlowAmbient[S oidc.FlowStore]() storetest.Ambient[S] {
	state := func(i int) string { return fmt.Sprintf("ambient-state-%d", i) }

	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			_, err := s.Begin(ctx, Flow("ambient", state(i)))
			return err
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_flows WHERE state = $1)`, state(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			_, err := s.Complete(ctx, "no-such-handle", "ambient", state(1))
			return err
		},
		Refusal: oidc.ErrInvalidState,
	}
}

// HandoffAmbient is the ambient suite's view of the handoff store: record i
// is a record of its own token id, and the refusal a consumption of a token
// id that does not exist.
func HandoffAmbient[S oidc.HandoffStore]() storetest.Ambient[S] {
	gen := id.NewV7Generator()
	token := func(i int) string { return fmt.Sprintf("ambient-token-%d", i) }

	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			recID, err := gen.NewID()
			if err != nil {
				return err
			}
			return s.Insert(ctx, oidc.HandoffRecord{
				ID: recID, TokenID: token(i), SecretHash: []byte("digest"), UserID: "ambient-user",
				CreatedAt: OIDCStart, ExpiresAt: OIDCStart.Add(time.Minute),
			})
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_handoffs WHERE token_id = $1)`, token(i))
		},
		Refuse: func(ctx context.Context, s S) error {
			return s.Consume(ctx, "ambient-token-never-issued", time.Now())
		},
		Refusal: oidc.ErrHandoffNotFound,
	}
}
