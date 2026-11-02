package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

// Cipher seals and opens the session fields that are credentials in their own
// right, the provider ID token and the CSRF token, binding each value to the
// session it belongs to.
//
// It is declared here, in the package that consumes it, rather than imported
// from a package that owns encryption. A cipher shipped by another capability
// satisfies this interface structurally, so neither package imports the other,
// and a consumer wires one implementation into every place that seals. A later
// capability needing to seal something else declares the narrow port it needs
// rather than inheriting this one.
//
// An implementation must be safe for concurrent use, and must bind the
// additional authenticated data to the ciphertext: Open has to fail when it is
// given the same ciphertext with different additional data. That is what stops
// a sealed value being moved from one session to another.
//
// Both methods take the context of the save or load the sealing store
// serves; the store never substitutes a context of its own or imposes a
// deadline. An implementation over a remote service, such as a key management
// service, should honour it, so a request's deadline and cancellation reach
// the service.
//
// The sealing store reads an Open failure in one of two ways. An outage —
// an error matching context.Canceled or context.DeadlineExceeded, or one the
// implementation marks by wrapping it with ErrCipherUnavailable, for example
// errors.Join(ErrCipherUnavailable, err) — says nothing about the value, and
// fails the load as a store failure wrapping it. Every other error, the
// default for anything left unmarked, means the value does not open, and the
// load fails with ErrUnreadable, which ends the session. An implementation
// over a remote service marks its retryable failures (timeouts, throttling,
// a key that is temporarily unavailable) and leaves a value it judged invalid
// unmarked.
//
//go:generate mockgen -source=store_encrypted.go -package=session_test -destination=store_encrypted_mock_test.go -typed
type Cipher interface {
	// Seal encrypts plaintext, authenticating additionalData alongside it
	// without storing it.
	Seal(ctx context.Context, plaintext, additionalData []byte) ([]byte, error)

	// Open decrypts ciphertext, and fails unless additionalData is exactly
	// what Seal was given.
	Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error)
}

// aadPrefix prefixes the additional authenticated data every sealed provider
// ID token is bound to. The session identifier follows it, so an envelope
// lifted from one row and written into another will not open: the additional
// data names the session it was sealed for.
//
// It is a documented constant rather than an option. Changing it makes every
// stored envelope unreadable, which is a key rotation with none of a key
// rotation's machinery, so it is not something a consumer configures.
const aadPrefix = "scrty/session:external-id-token:"

// csrfAADPrefix prefixes the additional authenticated data every sealed CSRF
// token is bound to, as aadPrefix does for the ID token. It differs from
// aadPrefix, so one field's envelope will not open as the other's, even within
// one session. It is a documented constant for the same reason aadPrefix is.
const csrfAADPrefix = "scrty/session:csrf-token:"

// textSessionUnreadableCSRFTokenNotOpened is ErrUnreadable's own words for a
// CSRF token that would not open, kept as a constant for the reason
// textSessionUnreadableIDTokenNotOpened is.
const textSessionUnreadableCSRFTokenNotOpened = "session: session cannot be read: the CSRF token would not open"

// textSessionUnreadableIDTokenNotOpened is ErrUnreadable's own words,
// kept as a constant (never ErrUnreadable.Error(), which forbidigo
// forbids outside a stated exception) so this fixed text is never a
// dependency's error rendered at runtime. It must read exactly as
// ErrUnreadable.Error() does, followed by what additionally failed.
const textSessionUnreadableIDTokenNotOpened = "session: session cannot be read: the provider ID token would not open"

// encryptedStore seals Session.ExternalIDToken and Session.CSRFToken on the
// way to inner and opens them on the way back.
type encryptedStore struct {
	inner  Store
	cipher Cipher
}

// NewEncryptedStore wraps inner so a session's provider ID token and CSRF
// token are sealed before they reach storage and opened when they are loaded.
//
// Only ExternalIDToken and CSRFToken are sealed: they are the fields of the
// record that are credentials in their own right, and a store that sealed more
// would hand back rows no query could filter. Every other field, and every
// other operation, passes straight through. Each is sealed under additional
// data of its own (the field and the session identifier), so neither opens as
// the other.
//
// The CSRF token is written by Create and by a supersession's successor only
// (see Store.Save): Create and Supersede seal it, the successor's copy sealed
// again for the successor's own identifier, and Save hands inner a copy with no
// token at all, so a save neither pays for a seal inner ignores nor could put a
// token in the clear into a store that disregarded the contract.
//
// ListByUser opens nothing: a listing needs no sealed field, so it lists with
// the cipher's keys unreachable or retired, and the sessions it returns carry
// neither token, never an envelope in a token's place.
//
// A failure of inner or of the cipher is returned behind fixed text of this
// package — never naming the session identifier, which is the bearer
// credential — and still matches the original error through errors.Is and
// errors.As. A cipher that will not open a value is also ErrUnreadable,
// unless its failure is an outage: a context error, or an error marked with
// ErrCipherUnavailable, which comes back as a store failure and never as
// ErrUnreadable (see Cipher). A sentinel of this package that inner returns
// bare comes back as itself.
//
// Every seal and open runs under the context of the Create, Save, Supersede
// or Load it serves.
//
// The sealed value is bound to the session identifier, so an envelope moved to
// another session's row will not open. An empty token, either one, is stored unsealed,
// because there is nothing to hide and an envelope over nothing still says a
// federated session was here.
//
// A nil inner store or a nil cipher is a configuration error. Falling back to
// storing tokens in the clear, or to no store at all, would be a security
// decision made on the consumer's behalf at the moment they most clearly asked
// for the opposite.
func NewEncryptedStore(inner Store, c Cipher) (Store, error) {
	if nilcheck.IsNil(inner) {
		return nil, fmt.Errorf("%w: the inner store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c) {
		return nil, fmt.Errorf("%w: the cipher must not be nil", ErrConfig)
	}

	return &encryptedStore{inner: inner, cipher: c}, nil
}

// additionalData is what a session's ID token is sealed against.
func additionalData(id string) []byte {
	return []byte(aadPrefix + id)
}

// csrfAdditionalData is what a session's CSRF token is sealed against.
func csrfAdditionalData(id string) []byte {
	return []byte(csrfAADPrefix + id)
}

// sealed returns a copy of sess whose ID token and, with csrf, CSRF token are
// envelopes, leaving the caller's own record holding plaintext. Without csrf,
// the copy carries no CSRF token at all: Save is the caller that passes it,
// and a save never writes the token.
//
// Sealing a copy is what keeps a create or a save from reaching back into the
// caller's struct. A caller that handed over a session and then read its token
// would otherwise find ciphertext there, and a retry of the same write would
// seal the envelope a second time.
func (s *encryptedStore) sealed(ctx context.Context, sess *Session, csrf bool) (*Session, error) {
	if sess.ExternalIDToken == "" && sess.CSRFToken == "" {
		return sess, nil
	}

	out := sess.clone()
	if sess.ExternalIDToken != "" {
		envelope, err := s.cipher.Seal(ctx, []byte(sess.ExternalIDToken), additionalData(sess.ID))
		if err != nil {
			return nil, diag.Wrap(err, "session: the provider ID token of the session could not be sealed")
		}
		out.ExternalIDToken = base64.RawURLEncoding.EncodeToString(envelope)
	}

	out.CSRFToken = ""
	if csrf && sess.CSRFToken != "" {
		envelope, err := s.cipher.Seal(ctx, []byte(sess.CSRFToken), csrfAdditionalData(sess.ID))
		if err != nil {
			return nil, diag.Wrap(err, "session: the CSRF token of the session could not be sealed")
		}
		out.CSRFToken = base64.RawURLEncoding.EncodeToString(envelope)
	}

	return out, nil
}

func (s *encryptedStore) Create(ctx context.Context, sess *Session) error {
	out, err := s.sealed(ctx, sess, true)
	if err != nil {
		return err
	}

	return storeFailed(s.inner.Create(ctx, out), "session: the inner store could not create the session")
}

func (s *encryptedStore) Save(ctx context.Context, sess *Session) error {
	out, err := s.sealed(ctx, sess, false)
	if err != nil {
		return err
	}

	return storeFailed(s.inner.Save(ctx, out), "session: the inner store could not save the session")
}

// Load opens the stored ID token and CSRF token and returns the session with
// plaintext in them.
//
// A value that will not open is ErrUnreadable, and the session is not
// returned at all. Returning it with the token blanked would turn a retired
// key — an operational mistake affecting every federated session at once —
// into a session that works until something reaches for the token, and by then
// nothing points at the key.
//
// An open that the context abandoned, by cancellation or a deadline, or that
// the cipher marked with ErrCipherUnavailable, is not that: the value was
// never judged, so the load fails with a store failure wrapping the cause.
//
// Nothing is written here. Re-sealing what was just opened would make every
// read a write, and a write on read is how a session another request has just
// revoked comes back.
func (s *encryptedStore) Load(ctx context.Context, id string) (*Session, error) {
	sess, err := s.inner.Load(ctx, id)
	if err != nil {
		return nil, storeFailed(err, "session: the inner store could not load the session")
	}
	if sess == nil {
		return nil, ErrNotFound
	}

	idToken, err := s.open(ctx, sess.ExternalIDToken, additionalData(sess.ID),
		textSessionUnreadableIDTokenNotOpened, "session: the provider ID token of the session could not be opened")
	if err != nil {
		return nil, err
	}
	csrfToken, err := s.open(ctx, sess.CSRFToken, csrfAdditionalData(sess.ID),
		textSessionUnreadableCSRFTokenNotOpened, "session: the CSRF token of the session could not be opened")
	if err != nil {
		return nil, err
	}

	sess.ExternalIDToken, sess.CSRFToken = idToken, csrfToken

	return sess, nil
}

// open opens one stored sealed value against aad; an empty one is returned as
// it is. A value that is not an envelope, or that the cipher judges not to
// open, is ErrUnreadable under unreadable; an outage is a store failure under
// outage (see openFailed).
func (s *encryptedStore) open(ctx context.Context, stored string, aad []byte, unreadable, outage string) (string, error) {
	if stored == "" {
		return "", nil
	}

	envelope, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		return "", diag.Wrap(err, unreadable, ErrUnreadable)
	}

	plaintext, err := s.cipher.Open(ctx, envelope, aad)
	if err != nil {
		return "", openFailed(err, unreadable, outage)
	}

	return string(plaintext), nil
}

// openFailed classifies a cipher's failure to open a stored sealed value,
// under the fixed texts of the field it was opening.
//
// A failure that is an outage — the context ended, or the cipher marked it
// with ErrCipherUnavailable — says nothing about the value, so it comes back
// as a store failure wrapping the cause, never as ErrUnreadable, which ends
// the session. An outage — a context error or the marker — wins over anything
// joined with it. Every other failure is ErrUnreadable, the safe default: a
// value that truly does not open lets the user log in again instead of
// failing every request until it expires.
func openFailed(err error, unreadable, outage string) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrCipherUnavailable):
		return diag.Wrap(err, outage)
	default:
		return diag.Wrap(err, unreadable, ErrUnreadable)
	}
}

func (s *encryptedStore) Delete(ctx context.Context, id string) error {
	return storeFailed(s.inner.Delete(ctx, id), "session: the inner store could not delete the session")
}

func (s *encryptedStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	return storeFailed(s.inner.DeleteByUser(ctx, user), "session: the inner store could not delete the user's sessions")
}

func (s *encryptedStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	n, err := s.inner.DeleteByUserExcept(ctx, user, keep)

	return n, storeFailed(err, "session: the inner store could not delete the user's other sessions")
}

func (s *encryptedStore) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.inner.CountActiveByUser(ctx, user)

	return n, storeFailed(err, "session: the inner store could not count the user's active sessions")
}

// ListByUser passes the listing on and opens nothing: a listing needs no
// sealed field. Each session it returns has its ID token and CSRF token
// cleared, so no envelope is ever handed back in a token's place; a caller
// needing a token loads the session.
func (s *encryptedStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*Session, error) {
	listed, err := s.inner.ListByUser(ctx, user, now)
	if err != nil {
		return nil, storeFailed(err, "session: the inner store could not list the user's sessions")
	}
	for _, sess := range listed {
		if sess != nil {
			sess.ExternalIDToken, sess.CSRFToken = "", ""
		}
	}

	return listed, nil
}

func (s *encryptedStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.inner.DeleteExpired(ctx)

	return n, storeFailed(err, "session: the inner store could not delete expired sessions")
}

func (s *encryptedStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	n, err := s.inner.DeleteByExternalSession(ctx, issuer, sessionID)

	return n, storeFailed(err, "session: the inner store could not delete the provider session's sessions")
}

func (s *encryptedStore) DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error) {
	n, err := s.inner.DeleteByUserAndExternalIssuer(ctx, user, issuer)

	return n, storeFailed(err, "session: the inner store could not delete the user's sessions from the issuer")
}

func (s *encryptedStore) RecordActivity(ctx context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
	return storeFailed(s.inner.RecordActivity(ctx, id, lastAccessed, idleExpires, olderThan),
		"session: the inner store could not record the session's activity")
}

// Supersede seals the successor's ID token and CSRF token, bound to the
// successor's own identifier, as Create does, and passes the supersession on.
// The caller's successor keeps its plaintext.
func (s *encryptedStore) Supersede(ctx context.Context, op Supersession) error {
	if op.Successor == nil {
		return errors.New("session: a supersession needs a successor")
	}
	successor, err := s.sealed(ctx, op.Successor, true)
	if err != nil {
		return err
	}
	op.Successor = successor

	return storeFailed(s.inner.Supersede(ctx, op), "session: the inner store could not supersede the session")
}

func (s *encryptedStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	n, err := s.inner.DeleteFamily(ctx, family)

	return n, storeFailed(err, "session: the inner store could not delete the session family")
}

// MarkPresented passes the mark on. The inner store's ErrNotFound and
// ErrSuperseded come back bare, as Supersede's refusals do.
func (s *encryptedStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	return storeFailed(s.inner.MarkPresented(ctx, id, at),
		"session: the inner store could not record the session's first presentation")
}

// SuccessorPresented passes the read on: it reads only presentation and
// supersession state, which is not sealed. The inner store's
// ErrNotFound comes back bare.
func (s *encryptedStore) SuccessorPresented(ctx context.Context, id string) (bool, error) {
	used, err := s.inner.SuccessorPresented(ctx, id)

	return used, storeFailed(err, "session: the inner store could not read whether the session's successor was used")
}

var _ Store = (*encryptedStore)(nil)
