package httpsec

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// passkeyManageBodyLimit is how many body bytes a rename or a removal reads:
// an identifier and a name of at most a few hundred bytes.
const passkeyManageBodyLimit int64 = 4 << 10

// PasskeyListResponder writes the listing of the session user's passkeys:
// list is every passkey the user holds, in every state, oldest first. A
// summary carries no public key, credential ID, user handle or attestation
// statement.
//
// It is called instead of the downstream handler. An error it returns leaves
// the chain as the request's refusal.
type PasskeyListResponder func(ex *Exchange, list []passkey.Summary) error

// PasskeyChangeResponder writes the answer to a rename or a removal of the
// session user's passkey cid, after the change was made.
//
// It is called instead of the downstream handler. An error it returns leaves
// the chain as the request's refusal; the change stands.
type PasskeyChangeResponder func(ex *Exchange, cid id.ID) error

// WithPasskeyListResponder replaces how the listing is answered.
//
// Default: 200 with {"passkeys":[{"id","name","state","created_at",
// "last_used_at","backup_eligible","backup_state","transports","aaguid"}]} as
// JSON, and Cache-Control: no-store. "last_used_at" is null for a passkey
// never used, and "aaguid" is the authenticator model as UUID text, or null
// when the authenticator reported none. A nil function is refused; omit the
// option to keep the default.
func WithPasskeyListResponder(fn PasskeyListResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyListResponder was given no function; omit the " +
				"option to keep the default document")
		}

		p.respondList = fn

		return nil
	}
}

// WithPasskeyRenameResponder replaces how a rename is answered.
//
// Default: 204 with no body. A nil function is refused; omit the option to
// keep the default.
func WithPasskeyRenameResponder(fn PasskeyChangeResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyRenameResponder was given no function; omit the " +
				"option to keep the default answer")
		}

		p.respondRename = fn

		return nil
	}
}

// WithPasskeyRemoveResponder replaces how a removal is answered.
//
// Default: 204 with no body. A nil function is refused; omit the option to
// keep the default.
func WithPasskeyRemoveResponder(fn PasskeyChangeResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyRemoveResponder was given no function; omit the " +
				"option to keep the default answer")
		}

		p.respondRemove = fn

		return nil
	}
}

// manage serves the management endpoints: GET on the credentials prefix
// lists, POST on its rename and remove paths changes. It reports false for
// any other request, which the caller passes on.
func (p *passkeyInterceptor) manage(ex *Exchange) (bool, error) {
	r := ex.Request

	var serve func(*Exchange, *session.Session) error

	switch {
	case r.Method() == http.MethodGet && r.Path() == p.credPrefix:
		serve = p.list
	case r.Method() == http.MethodPost && r.Path() == p.credPrefix+passkeyRenameSegment:
		serve = p.rename
	case r.Method() == http.MethodPost && r.Path() == p.credPrefix+passkeyRemoveSegment:
		serve = p.remove
	default:
		return false, nil
	}

	// There must be a session and a resolved caller for it: a session whose
	// first factor published no caller names nobody whose passkeys to manage.
	s := ex.Session
	if s == nil || ex.Authentication == nil || ex.Authentication.Principal == nil {
		return true, ErrAuthenticationRequired
	}

	if err := fullSessionOnly(s); err != nil {
		return true, err
	}

	return true, serve(ex, s)
}

// fullSessionOnly refuses a session that is confined or owes a challenge,
// with the challenge it owes. The gates ahead of the endpoints refuse them
// first on a chain that enables them; this holds the line for an
// interceptor a consumer placed between, and for a chain without the gate.
func fullSessionOnly(s *session.Session) error {
	var kind policy.ChallengeKind

	switch {
	case s.MFA == session.MFARecoveryPending:
		kind = policy.ChallengeAccountRecovery
	case s.MFA == session.MFAEnrolmentPending:
		kind = policy.ChallengeMFAEnrolment
	case s.MFA == session.MFAPending:
		kind = policy.ChallengeMFA
	case s.PasswordChangePending:
		kind = policy.ChallengePasswordChange
	default:
		return nil
	}

	return &ChallengeError{Kind: kind, Session: s}
}

// list answers the session user's passkeys.
func (p *passkeyInterceptor) list(ex *Exchange, s *session.Session) error {
	list, err := p.deps.Passkeys.List(ex.Context(), s.UserID)
	if err != nil {
		return err
	}

	return p.respondList(ex, list)
}

// rename names one of the session user's passkeys. The identifier is read
// from the "id" field of a URL-encoded body and the name from its "name"
// field; a missing name is the empty name, which the manager replaces with
// the default date name.
func (p *passkeyInterceptor) rename(ex *Exchange, s *session.Session) error {
	cid, values, err := postedPasskeyID(ex.Request)
	if err != nil {
		return err
	}

	if err := p.deps.Passkeys.Rename(ex.Context(), s.UserID, cid, values.Get("name")); err != nil {
		return err
	}

	return p.respondRename(ex, cid)
}

// remove removes one of the session user's passkeys, under the manager's
// assurance and freshness admission.
func (p *passkeyInterceptor) remove(ex *Exchange, s *session.Session) error {
	cid, _, err := postedPasskeyID(ex.Request)
	if err != nil {
		return err
	}

	if err := p.deps.Passkeys.Remove(ex.Context(), s, cid, p.registrationContext(s)); err != nil {
		return err
	}

	return p.respondRemove(ex, cid)
}

// postedPasskeyID reads the "id" field of a URL-encoded body, and only of the
// body, with the rest of the form. A body the endpoint cannot read, or one
// without the field, is ErrCredentialsMissing. An identifier that does not
// parse names no passkey of the user, so it is passkey.ErrNotFound, the same
// refusal as another user's identifier; its text is not repeated.
func postedPasskeyID(r Request) (id.ID, url.Values, error) {
	raw, err := postedFieldLimited(r, "id", passkeyManageBodyLimit)
	if err != nil {
		return id.Nil, nil, err
	}

	// The body has been read and parsed whole by the call above; reading it
	// again answers the same bytes.
	body, err := r.Body(passkeyManageBodyLimit)
	if err != nil {
		return id.Nil, nil, refusedAs(ErrCredentialsMissing, textCredentialsMissing, err)
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return id.Nil, nil, ErrCredentialsMissing
	}

	cid, err := id.Parse(raw)
	if err != nil {
		return id.Nil, nil, passkey.ErrNotFound
	}

	return cid, values, nil
}

// passkeyListDocument is the listing's default answer. Its member names are
// the endpoint's documented contract.
type passkeyListDocument struct {
	Passkeys []passkeySummaryDocument `json:"passkeys"`
}

// passkeySummaryDocument is one listed passkey.
type passkeySummaryDocument struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	Transports     []string   `json:"transports"`
	AAGUID         *string    `json:"aaguid"`
}

// writePasskeyList is the default list responder: 200 with every passkey's
// summary, which no cache may keep.
func writePasskeyList(ex *Exchange, list []passkey.Summary) error {
	doc := passkeyListDocument{Passkeys: make([]passkeySummaryDocument, 0, len(list))}

	for _, sum := range list {
		item := passkeySummaryDocument{
			ID:             sum.ID.String(),
			Name:           sum.Name,
			State:          passkeyStateName(sum.State),
			CreatedAt:      sum.CreatedAt,
			BackupEligible: sum.BackupEligible,
			BackupState:    sum.BackupState,
			Transports:     append([]string{}, sum.Transports...),
			AAGUID:         aaguidText(sum.AAGUID),
		}

		if !sum.LastUsedAt.IsZero() {
			used := sum.LastUsedAt
			item.LastUsedAt = &used
		}

		doc.Passkeys = append(doc.Passkeys, item)
	}

	return writePasskeyDocument(ex, doc)
}

// aaguidText writes a 16-byte authenticator model identifier as UUID text,
// and anything else as absent.
func aaguidText(b []byte) *string {
	const aaguidSize = 16
	if len(b) != aaguidSize {
		return nil
	}

	h := hex.EncodeToString(b)
	text := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]

	return &text
}

// writePasskeyChanged is the default rename and remove responder: 204.
func writePasskeyChanged(ex *Exchange, _ id.ID) error {
	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}
