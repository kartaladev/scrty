package pgschema

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// How the provider's records map to their rows, which the three adapters share, so
// they store the same rows and refuse alike. An Args function judges a record and
// returns the values its statement binds. They are plain driver values: a uuid is its
// text, a time is UTC at the microsecond PostgreSQL keeps, a list or map is the JSON text
// of its jsonb column, and an absent nullable value is nil. A Row type holds what one row
// scans into, through database/sql's scanners, which pgx honours too.
//
// No refusal here repeats a value. Text PostgreSQL cannot hold is refused by naming the
// field. The caller wraps each error with its adapter's prefix and operation's name.

// opField is one text value a write stores, and the name its refusal gives it.
type opField struct{ name, value string }

// storableText reports whether PostgreSQL text can hold v.
func storableText(v string) bool {
	return strings.IndexByte(v, 0) < 0 && utf8.ValidString(v)
}

// checkFields refuses the first field PostgreSQL text cannot hold.
func checkFields(fields ...opField) error {
	for _, f := range fields {
		if !storableText(f.value) {
			return unstorableField(f.name)
		}
	}

	return nil
}

func unstorableField(name string) error {
	return fmt.Errorf("the %s holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store", name)
}

// opTime is t as stored.
func opTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// opNullTime is t as a nullable column stores it: NULL for the zero time.
func opNullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return opTime(t)
}

// fromNullTime is a nullable column's time: zero for NULL.
func fromNullTime(t sql.NullTime) time.Time {
	if !t.Valid {
		return time.Time{}
	}

	return t.Time.UTC()
}

// opNullID is v as a nullable column stores it: NULL for the nil identifier.
func opNullID(v id.ID) any {
	if v.IsZero() {
		return nil
	}

	return v.String()
}

// bytesOrEmpty is b for a NOT NULL bytea column.
func bytesOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}

	return b
}

// encodeList is values as a jsonb column holds them, "[]" for none, or the refusal of
// a value json.Marshal would alter or jsonb refuse.
func encodeList[S ~string](name string, values []S) (string, error) {
	plain := make([]string, len(values))
	for i, v := range values {
		if !storableText(string(v)) {
			return "", unstorableField(name)
		}
		plain[i] = string(v)
	}
	b, err := json.Marshal(plain)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// decodeList is what a jsonb column holds, and nil for an empty list, the "none" the
// in-memory stores return.
func decodeList[S ~string](name string, raw []byte) ([]S, error) {
	var plain []string
	if err := json.Unmarshal(raw, &plain); err != nil {
		return nil, fmt.Errorf("the stored %s is not a JSON array of strings", name)
	}
	if len(plain) == 0 {
		return nil, nil
	}
	values := make([]S, len(plain))
	for i, v := range plain {
		values[i] = S(v)
	}

	return values, nil
}

// encodeMap is values as a jsonb column holds them, "{}" for none.
func encodeMap(name string, values map[string]string) (string, error) {
	for k, v := range values {
		if !storableText(k) || !storableText(v) {
			return "", unstorableField(name)
		}
	}
	if len(values) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// decodeMap is what a jsonb column holds, and nil for an empty object.
func decodeMap(name string, raw []byte) (map[string]string, error) {
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("the stored %s is not a JSON object of strings", name)
	}
	if len(values) == 0 {
		return nil, nil
	}

	return values, nil
}

// StageMoveAllowed reports whether a request may move between these stages, by the
// order oidcprovider.Stage documents. An adapter checks it before its conditional write.
func StageMoveAllowed(from, to oidcprovider.Stage) bool {
	switch from {
	case oidcprovider.StageLogin:
		return to == oidcprovider.StageConsent || to == oidcprovider.StageDone
	case oidcprovider.StageConsent, oidcprovider.StageLogout:
		return to == oidcprovider.StageDone
	default:
		return false
	}
}

// RequireTime refuses a zero time, which could not be told from no time at all, with
// an error matching oidcprovider.ErrConfig. operation names the port's method.
func RequireTime(operation string, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("%w: %s: the time must not be zero", oidcprovider.ErrConfig, operation)
	}

	return nil
}

// CheckSelector refuses a selector of no valid shape, with an error matching
// oidcprovider.ErrConfig, and one holding text no row could hold.
func CheckSelector(sel oidcprovider.SignInSelector) error {
	if err := sel.Validate(); err != nil {
		return err
	}

	return checkFields(
		opField{"user reference", string(sel.User)},
		opField{"upstream issuer", sel.ExternalIssuer},
		opField{"upstream session", sel.ExternalSessionID},
	)
}

// signInWhere is the condition selecting what a valid selector names, over the columns
// the grants, codes and browser sessions share, with its arguments numbered from first.
// Each shape has a condition of its own, so a prepared plan can use its index.
//
// "Every family but one" reads a NULL family as different, since a grant may have none.
func signInWhere(sel oidcprovider.SignInSelector, first int) (string, []any) {
	param := func(i int) string { return fmt.Sprintf("$%d", first+i) }

	switch {
	case sel.Family != id.Nil:
		return "sign_in_family = " + param(0), []any{sel.Family.String()}
	case sel.ExceptFamily != id.Nil:
		return "user_ref = " + param(0) + " AND sign_in_family IS DISTINCT FROM " + param(1),
			[]any{string(sel.User), sel.ExceptFamily.String()}
	case sel.User != "" && sel.ExternalIssuer != "":
		return "user_ref = " + param(0) + " AND external_issuer = " + param(1),
			[]any{string(sel.User), sel.ExternalIssuer}
	case sel.User != "":
		return "user_ref = " + param(0), []any{string(sel.User)}
	default:
		return "external_issuer = " + param(0) + " AND external_session_id = " + param(1),
			[]any{sel.ExternalIssuer, sel.ExternalSessionID}
	}
}

// CodeUnspentBySignIn is the statement listing the grant family of each code record sel
// selects, and its arguments. Records holding offline_access are left out unless
// includeOffline is true, or the record ends with its sign-in. sel must be valid.
func CodeUnspentBySignIn(sel oidcprovider.SignInSelector, includeOffline bool) (string, []any) {
	where, args := signInWhere(sel, 2)

	return "SELECT grant_family FROM op_authorization_codes WHERE " + where +
		" AND ($1::boolean OR NOT offline OR ends_with_sign_in)", append([]any{includeOffline}, args...)
}

// BrowserSessionDeleteBySignIn is the statement removing every browser session sel
// selects, expired ones included, and its arguments. sel must be valid.
func BrowserSessionDeleteBySignIn(sel oidcprovider.SignInSelector) (string, []any) {
	where, args := signInWhere(sel, 1)

	return "DELETE FROM op_browser_sessions WHERE " + where, args
}

// GrantBulkWrite is the two steps of an operation writing many grants, which an adapter
// runs in order as one unit, at READ COMMITTED unless a caller's transaction decides
// otherwise.
//
// # One lock order
//
// Every statement taking more than one op_grants row takes them in ascending family
// order, whichever of them are stored grants and whichever are only named by an
// outstanding code, and whichever write they will get. Two such statements then wait for
// each other and cannot deadlock. A row's lock and a new key's insert are one order, not
// two: an insert of a key another transaction has inserted waits for that transaction as
// a lock would, so an operation recording its revocations first and writing its grants
// after, or the other way round, can deadlock with any other, even one doing the same in
// the same phases, when a family is one's stored grant and the other's outstanding code.
//
// So Hold takes everything in one statement: one ascending stream of both sets, each row
// inserted as a revocation recorded first, or locked if it is already there, and written
// to no further. ON CONFLICT DO UPDATE locks a row its WHERE then declines to update, so
// a stored grant is locked and left as it was. Hold returns the set it took, as $1 of
// Write, which writes only those rows and so takes no lock Hold has not. A grant stored
// after Hold's snapshot, which Write's own could see, is left out, as if it had been
// stored after the operation; were it not, Write would lock it out of order. A revocation
// recorded first, or one Hold recorded, already holds the grant's revocation if its code
// was outstanding.
//
// That leaves one limit: a grant with no held code, stored while an end waits on a lock,
// is not among the rows Hold took, so that end does not mark it, and the next end does.
// The provider never stores such a grant, as each comes from an exchange of a code the end
// holds.
//
// Hold reads the grants it selects with no lock, so a row may have been changed or deleted
// by the time it gets there. A change waits on the row's lock, and Write, on a later
// snapshot, sees it. A delete, by the sweep, leaves the row inserted as a revocation
// recorded first: it says only what is true, that the family is revoked, and is swept like
// any other.
//
// A single Create or Revoke holds one row, and so cannot close a cycle on its own, nor
// can GrantOrphanDelete, which takes its candidates in family order. The order is held
// within one call: a caller's transaction that has already written a later family holds
// that row out of order when it calls one of these, and can deadlock. PostgreSQL then ends
// a statement with 40P01, which the caller retries, as it must any such failure.
type GrantBulkWrite struct {
	// Hold is the first step's statement. It returns one row: the set held, as JSON
	// text, which WriteArgs takes.
	Hold     string
	HoldArgs []any

	// Write is the second step's statement. It returns each grant the operation
	// reports, in family order.
	Write     string
	writeArgs []any
}

// WriteArgs are Write's arguments, given what Hold returned.
func (w GrantBulkWrite) WriteArgs(held string) []any {
	return append([]any{held}, w.writeArgs...)
}

// grantHold is the statement holding families and the stored grants selected by where,
// whose placeholders start at $5. mark is the sign-in-ended mark a record this creates
// carries, and nil for none.
func grantHold(families []id.ID, cause oidcprovider.RevocationCause, at time.Time, mark any, where string, args ...any) (string, []any) {
	set, ok := FamilySet(families)
	if !ok {
		set = "[]"
	}

	return `WITH wanted AS (
  SELECT named.family::uuid AS family FROM jsonb_array_elements_text($1::jsonb) AS named(family)
  UNION
  SELECT family FROM op_grants WHERE ` + where + `),
inserted AS (
  INSERT INTO op_grants (family, revoked, revoked_at, revoke_cause, sign_in_ended_at)
  SELECT family, true, $2::timestamptz, $3::text, $4::timestamptz FROM wanted ORDER BY family
  ON CONFLICT (family) DO UPDATE SET revoked = op_grants.revoked WHERE false)
SELECT COALESCE(jsonb_agg(family), '[]'::jsonb)::text FROM wanted`,
		append([]any{set, opTime(at), string(cause), mark}, args...)
}

// grantRevokeWrite is the statement revoking every held family not yet revoked, and
// returning each stored grant among them that report selects, whose placeholders start at
// $4. Revoking changes nothing it selects by, and the stored grants a hold takes either
// match report or are named by a code, so it decides nothing else.
const grantRevokeWrite = `WITH written AS (
  UPDATE op_grants SET revoked = true, revoked_at = $2::timestamptz, revoke_cause = $3::text
  WHERE NOT revoked AND family IN (` + heldFamilies + `)
  RETURNING ` + grantColumns + `)
SELECT ` + grantColumns + ` FROM written WHERE created_at IS NOT NULL AND `

// GrantRevokeByUser is the unit revoking every stored grant of user not yet revoked, with
// a revocation recorded for each of families, and reporting each of those grants that
// this revoked. A family's grant is revoked with the rest, and reported if it is the
// user's.
func GrantRevokeByUser(
	user identity.UserID, families []id.ID, cause oidcprovider.RevocationCause, at time.Time,
) GrantBulkWrite {
	hold, holdArgs := grantHold(families, cause, at, nil,
		`user_ref = $5 AND created_at IS NOT NULL AND NOT revoked`, string(user))

	return GrantBulkWrite{
		Hold:      hold,
		HoldArgs:  holdArgs,
		Write:     grantRevokeWrite + `user_ref = $4 ORDER BY family`,
		writeArgs: []any{opTime(at), string(cause), string(user)},
	}
}

// GrantRevokeByUserAndClient is GrantRevokeByUser for one client alone.
func GrantRevokeByUserAndClient(
	user identity.UserID, clientID string, families []id.ID, cause oidcprovider.RevocationCause, at time.Time,
) GrantBulkWrite {
	hold, holdArgs := grantHold(families, cause, at, nil,
		`user_ref = $5 AND client_id = $6 AND created_at IS NOT NULL AND NOT revoked`, string(user), clientID)

	return GrantBulkWrite{
		Hold:      hold,
		HoldArgs:  holdArgs,
		Write:     grantRevokeWrite + `user_ref = $4 AND client_id = $5 ORDER BY family`,
		writeArgs: []any{opTime(at), string(cause), string(user), clientID},
	}
}

// GrantEndSignIns is the unit ending what sel selects, sel being valid. Each stored grant
// it selects and no end has marked is marked, and revoked if it has no offline_access or
// is tied to its sign-in, and is reported. Each of families is revoked if it is not yet,
// and a record this creates for one carries the mark; a stored grant is only marked if
// sel selects it, and a revocation already recorded was not this end's. Of any number of
// concurrent ends exactly one reports a grant: a second waits on the row's lock in Hold,
// and Write's later snapshot sees it marked.
func GrantEndSignIns(sel oidcprovider.SignInSelector, families []id.ID, at time.Time) GrantBulkWrite {
	cause := oidcprovider.CauseSignInEnded
	holdWhere, holdArgs := signInWhere(sel, 5)
	hold, args := grantHold(families, cause, at, opTime(at),
		holdWhere+` AND created_at IS NOT NULL AND sign_in_ended_at IS NULL`, holdArgs...)

	set, ok := FamilySet(families)
	if !ok {
		set = "[]"
	}
	writeWhere, writeArgs := signInWhere(sel, 5)

	// What the row held decides, and is read before it is written: Hold has locked it, so
	// no other call can change it after this statement's snapshot.
	return GrantBulkWrite{
		Hold:     hold,
		HoldArgs: args,
		Write: `WITH chosen AS (
  SELECT family AS chosen_family,
    created_at IS NOT NULL AND sign_in_ended_at IS NULL AND ` + writeWhere + ` AS newly_ended,
    family IN (SELECT named.family::uuid FROM jsonb_array_elements_text($4::jsonb) AS named(family)) AS outstanding
  FROM op_grants WHERE family IN (` + heldFamilies + `)),
written AS (
  UPDATE op_grants SET
    sign_in_ended_at = CASE WHEN newly_ended THEN $2::timestamptz ELSE sign_in_ended_at END,
    revoked = revoked OR outstanding OR (newly_ended AND (NOT offline OR ends_with_sign_in)),
    revoked_at = CASE WHEN NOT revoked AND (outstanding OR (newly_ended AND (NOT offline OR ends_with_sign_in)))
      THEN $2::timestamptz ELSE revoked_at END,
    revoke_cause = CASE WHEN NOT revoked AND (outstanding OR (newly_ended AND (NOT offline OR ends_with_sign_in)))
      THEN $3::text ELSE revoke_cause END
  FROM chosen WHERE family = chosen_family AND (newly_ended OR (outstanding AND NOT revoked))
  RETURNING ` + grantColumns + `, newly_ended)
SELECT ` + grantColumns + ` FROM written WHERE newly_ended ORDER BY family`,
		writeArgs: append([]any{opTime(at), string(cause), set}, writeArgs...),
	}
}

// FamilySet is families as a GrantBulkWrite's statements take them: without repeats, and
// in order. ok is false when there are none.
func FamilySet(families []id.ID) (set string, ok bool) {
	if len(families) == 0 {
		return "", false
	}
	texts := make([]string, len(families))
	for i, family := range families {
		texts[i] = family.String()
	}
	slices.Sort(texts)
	// Marshalling a []string of uuid text cannot fail.
	b, _ := json.Marshal(slices.Compact(texts))

	return string(b), true
}

// CodeSource is where a grant store reads the outstanding codes from, as
// GrantStore.UseCodes joins it, with the rules that port states. Its zero value has
// none. It is safe for concurrent use.
type CodeSource struct {
	mu    sync.Mutex
	codes oidcprovider.UnspentCodes
}

// Join implements GrantStore.UseCodes.
func (s *CodeSource) Join(codes oidcprovider.UnspentCodes) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.codes != nil && !sameCodes(s.codes, codes) {
		return fmt.Errorf("%w: GrantStore: UseCodes: this store already reads another code store, "+
			"so two providers sharing a grant store must share their code store too", oidcprovider.ErrConfig)
	}
	s.codes = codes

	return nil
}

// Read returns the source joined, or the refusal of a store nothing told where the
// outstanding codes are.
func (s *CodeSource) Read() (oidcprovider.UnspentCodes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.codes == nil {
		return nil, fmt.Errorf("%w: GrantStore: UseCodes was never called, so a code could outlive this operation",
			oidcprovider.ErrConfig)
	}

	return s.codes, nil
}

// sameCodes reports whether a and b are one source. Values that cannot be compared are
// not known to be one, and == on them would panic.
func sameCodes(a, b oidcprovider.UnspentCodes) bool {
	return reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

// storedSignIn is the sign_in column's JSON object. It spells each field out, so
// renaming a field of oidcprovider.SignIn cannot change what is stored.
type storedSignIn struct {
	User              string    `json:"user"`
	Family            id.ID     `json:"family"`
	AuthenticatedAt   time.Time `json:"authenticated_at"`
	AMR               []string  `json:"amr"`
	ACR               string    `json:"acr"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	ExternalIssuer    string    `json:"external_issuer"`
	ExternalSessionID string    `json:"external_session_id"`
}

// checkSignIn refuses a sign-in holding text PostgreSQL cannot store.
func checkSignIn(s *oidcprovider.SignIn) error {
	if err := checkFields(
		opField{"sign-in's user reference", string(s.User)},
		opField{"sign-in's acr", s.ACR},
		opField{"sign-in's upstream issuer", s.ExternalIssuer},
		opField{"sign-in's upstream session", s.ExternalSessionID},
	); err != nil {
		return err
	}
	for _, v := range s.AMR {
		if !storableText(v) {
			return unstorableField("sign-in's amr")
		}
	}

	return nil
}

// EncodeSignIn is PendingRequestAdvance's $4: s as the sign_in column holds it, and nil
// (NULL) when s is nil.
func EncodeSignIn(s *oidcprovider.SignIn) (any, error) {
	if s == nil {
		return nil, nil
	}
	if err := checkSignIn(s); err != nil {
		return nil, err
	}
	amr := s.AMR
	if amr == nil {
		amr = []string{}
	}
	b, err := json.Marshal(storedSignIn{
		User: string(s.User), Family: s.Family, AuthenticatedAt: opTime(s.AuthenticatedAt), AMR: amr, ACR: s.ACR,
		AbsoluteExpiresAt: opTime(s.AbsoluteExpiresAt), ExternalIssuer: s.ExternalIssuer,
		ExternalSessionID: s.ExternalSessionID,
	})
	if err != nil {
		return nil, err
	}

	return string(b), nil
}

func decodeSignIn(raw []byte) (*oidcprovider.SignIn, error) {
	if raw == nil {
		return nil, nil
	}
	var stored storedSignIn
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errors.New("the stored sign-in is not a JSON object of its fields")
	}
	s := &oidcprovider.SignIn{
		User: identity.UserID(stored.User), Family: stored.Family, AuthenticatedAt: stored.AuthenticatedAt.UTC(),
		ACR: stored.ACR, AbsoluteExpiresAt: stored.AbsoluteExpiresAt.UTC(), ExternalIssuer: stored.ExternalIssuer,
		ExternalSessionID: stored.ExternalSessionID,
	}
	if len(stored.AMR) > 0 {
		s.AMR = stored.AMR
	}

	return s, nil
}

// storedClientSecret is one element of the secrets column. SecretBytes marshals as
// a redacted constant, so the digest is converted to plain bytes here and encoded by
// hand. A stored form that marshalled a ClientSecret would hold no digest at all.
type storedClientSecret struct {
	// Digest is the SHA-256 digest, base64url without padding.
	Digest string `json:"digest"`
	// ExpiresAt is absent when the secret never expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// EncodeClientSecrets is secrets as the secrets column holds them: a JSON array of
// digests and deadlines, "[]" for none.
func EncodeClientSecrets(secrets []oidcprovider.ClientSecret) (string, error) {
	stored := make([]storedClientSecret, len(secrets))
	for i, s := range secrets {
		stored[i].Digest = base64.RawURLEncoding.EncodeToString([]byte(s.Digest))
		if !s.ExpiresAt.IsZero() {
			at := opTime(s.ExpiresAt)
			stored[i].ExpiresAt = &at
		}
	}
	b, err := json.Marshal(stored)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// DecodeClientSecrets reads the secrets column, and nil for none. A digest that does
// not decode, as a redacted value written by mistake would not, is an error, never a
// secret that matches nothing.
func DecodeClientSecrets(raw []byte) ([]oidcprovider.ClientSecret, error) {
	var stored []storedClientSecret
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errors.New("the stored client secrets are not a JSON array of digests")
	}
	if len(stored) == 0 {
		return nil, nil
	}
	secrets := make([]oidcprovider.ClientSecret, len(stored))
	for i, s := range stored {
		digest, err := base64.RawURLEncoding.DecodeString(s.Digest)
		if err != nil || len(digest) == 0 {
			return nil, errors.New("a stored client secret's digest is not base64url")
		}
		secrets[i].Digest = digest
		if s.ExpiresAt != nil {
			secrets[i].ExpiresAt = s.ExpiresAt.UTC()
		}
	}

	return secrets, nil
}

// PendingRequestArgs is PendingRequestInsert's arguments for r.
func PendingRequestArgs(r *oidcprovider.PendingRequest) ([]any, error) {
	if err := checkFields(
		opField{"client identifier", r.ClientID}, opField{"redirect URI", r.RedirectURI},
		opField{"state", r.State}, opField{"nonce", r.Nonce}, opField{"code challenge", r.Challenge},
		opField{"hint's subject", r.IDTokenHintSubject}, opField{"dpop_jkt", r.DPoPJKT}, opField{"login hint", r.LoginHint},
	); err != nil {
		return nil, err
	}
	lists := make([]any, 0, 6)
	for _, l := range []struct {
		name   string
		values []string
	}{
		{"scopes", r.Scopes}, {"resources", r.Resources}, {"prompt", r.Prompt},
		{"UI locales", r.UILocales}, {"claims locales", r.ClaimsLocales}, {"ACR values", r.ACRValues},
	} {
		encoded, err := encodeList(l.name, l.values)
		if err != nil {
			return nil, err
		}
		lists = append(lists, encoded)
	}
	signIn, err := EncodeSignIn(r.SignIn)
	if err != nil {
		return nil, err
	}
	var maxAge any
	if r.MaxAge != nil {
		maxAge = int64(*r.MaxAge)
	}

	return []any{
		r.ID.String(), bytesOrEmpty(r.HandleDigest), bytesOrEmpty(r.FlowDigest), r.ClientID, r.RedirectURI,
		lists[0], lists[1], r.State, r.Nonce, r.Challenge, lists[2], maxAge, r.IDTokenHintSubject, r.DPoPJKT,
		r.LoginHint, lists[3], lists[4], lists[5], opTime(r.ParkedAt), opTime(r.ExpiresAt), int16(r.Stage), signIn,
	}, nil
}

// PendingRequestRow holds a scanned op_pending_requests row.
type PendingRequestRow struct {
	rec                                        oidcprovider.PendingRequest
	scopes, resources, prompt, ui, claims, acr []byte
	maxAge                                     sql.NullInt64
	parked, expires                            time.Time
	stage                                      int16
	signIn                                     []byte
}

// Dest is what a row scans into.
func (r *PendingRequestRow) Dest() []any {
	return []any{
		&r.rec.ID, &r.rec.HandleDigest, &r.rec.FlowDigest, &r.rec.ClientID, &r.rec.RedirectURI, &r.scopes, &r.resources,
		&r.rec.State, &r.rec.Nonce, &r.rec.Challenge, &r.prompt, &r.maxAge, &r.rec.IDTokenHintSubject, &r.rec.DPoPJKT,
		&r.rec.LoginHint, &r.ui, &r.claims, &r.acr, &r.parked, &r.expires, &r.stage, &r.signIn,
	}
}

// Record is the row as the port returns it.
func (r *PendingRequestRow) Record() (*oidcprovider.PendingRequest, error) {
	out := r.rec
	var err error
	for _, l := range []struct {
		name string
		raw  []byte
		dst  *[]string
	}{
		{"scopes", r.scopes, &out.Scopes}, {"resources", r.resources, &out.Resources}, {"prompt", r.prompt, &out.Prompt},
		{"UI locales", r.ui, &out.UILocales}, {"claims locales", r.claims, &out.ClaimsLocales}, {"ACR values", r.acr, &out.ACRValues},
	} {
		if *l.dst, err = decodeList[string](l.name, l.raw); err != nil {
			return nil, err
		}
	}
	if out.SignIn, err = decodeSignIn(r.signIn); err != nil {
		return nil, err
	}
	if r.maxAge.Valid {
		maxAge := int(r.maxAge.Int64)
		out.MaxAge = &maxAge
	}
	out.ParkedAt, out.ExpiresAt = r.parked.UTC(), r.expires.UTC()
	out.Stage = oidcprovider.Stage(r.stage) //nolint:gosec // written from a Stage, a uint8

	return &out, nil
}

// CodeArgs is CodeInsert's arguments for r.
func CodeArgs(r *oidcprovider.CodeRecord) ([]any, error) {
	if err := checkFields(
		opField{"client identifier", r.ClientID}, opField{"redirect URI", r.RedirectURI},
		opField{"code challenge", r.Challenge}, opField{"nonce", r.Nonce}, opField{"dpop_jkt", r.DPoPJKT},
	); err != nil {
		return nil, err
	}
	if err := checkSignIn(&r.SignIn); err != nil {
		return nil, err
	}
	scopes, err := encodeList("scopes", r.Scopes)
	if err != nil {
		return nil, err
	}
	resources, err := encodeList("resources", r.Resources)
	if err != nil {
		return nil, err
	}
	amr, err := encodeList("amr", r.SignIn.AMR)
	if err != nil {
		return nil, err
	}

	return []any{
		r.TokenID.String(), r.ClientID, r.RedirectURI, r.Challenge, r.Nonce, r.DPoPJKT, scopes, resources,
		string(r.SignIn.User), r.SignIn.Family.String(), opTime(r.SignIn.AuthenticatedAt), amr, r.SignIn.ACR,
		opTime(r.SignIn.AbsoluteExpiresAt), r.SignIn.ExternalIssuer, r.SignIn.ExternalSessionID,
		r.GrantFamily.String(), r.Offline, r.EndsWithSignIn, opTime(r.ExpiresAt),
	}, nil
}

// signInRow holds the sign-in columns a code and a browser session share.
type signInRow struct {
	user                  string
	family                id.ID
	authenticated, signIn time.Time
	amr                   []byte
	acr, issuer, session  string
}

func (r *signInRow) record() (oidcprovider.SignIn, error) {
	amr, err := decodeList[string]("amr", r.amr)
	if err != nil {
		return oidcprovider.SignIn{}, err
	}

	return oidcprovider.SignIn{
		User: identity.UserID(r.user), Family: r.family, AuthenticatedAt: r.authenticated.UTC(), AMR: amr, ACR: r.acr,
		AbsoluteExpiresAt: r.signIn.UTC(), ExternalIssuer: r.issuer, ExternalSessionID: r.session,
	}, nil
}

// CodeRow holds a scanned op_authorization_codes row.
type CodeRow struct {
	rec               oidcprovider.CodeRecord
	scopes, resources []byte
	signIn            signInRow
	expires           time.Time
}

// Dest is what a row scans into.
func (r *CodeRow) Dest() []any {
	return []any{
		&r.rec.TokenID, &r.rec.ClientID, &r.rec.RedirectURI, &r.rec.Challenge, &r.rec.Nonce, &r.rec.DPoPJKT, &r.scopes,
		&r.resources, &r.signIn.user, &r.signIn.family, &r.signIn.authenticated, &r.signIn.amr, &r.signIn.acr,
		&r.signIn.signIn, &r.signIn.issuer, &r.signIn.session, &r.rec.GrantFamily, &r.rec.Offline, &r.rec.EndsWithSignIn,
		&r.expires,
	}
}

// Record is the row as the port returns it.
func (r *CodeRow) Record() (*oidcprovider.CodeRecord, error) {
	out := r.rec
	var err error
	if out.Scopes, err = decodeList[string]("scopes", r.scopes); err != nil {
		return nil, err
	}
	if out.Resources, err = decodeList[string]("resources", r.resources); err != nil {
		return nil, err
	}
	if out.SignIn, err = r.signIn.record(); err != nil {
		return nil, err
	}
	out.ExpiresAt = r.expires.UTC()

	return &out, nil
}

// ConsentGiveArgs is ConsentGive's arguments, with rowID the uuid of a row it creates.
// A scope given twice is given once.
func ConsentGiveArgs(
	rowID id.ID, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time,
) ([]any, error) {
	if err := CheckConsentKey(user, clientID); err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(unique, scope) {
			unique = append(unique, scope)
		}
	}
	encoded, err := encodeList("scopes", unique)
	if err != nil {
		return nil, err
	}

	return []any{rowID.String(), string(user), clientID, encoded, offline, opTime(at)}, nil
}

// CheckConsentKey refuses a user or client no row could hold.
func CheckConsentKey(user identity.UserID, clientID string) error {
	return checkFields(opField{"user reference", string(user)}, opField{"client identifier", clientID})
}

// CheckText refuses a value no row could hold, naming it name.
func CheckText(name, value string) error { return checkFields(opField{name, value}) }

// Storable reports whether PostgreSQL text can hold every one of values, so a lookup
// by one that cannot is answered as absent, without a statement.
func Storable(values ...string) bool {
	for _, v := range values {
		if !storableText(v) {
			return false
		}
	}

	return true
}

// ConsentRow holds a scanned op_consents row.
type ConsentRow struct {
	rec    oidcprovider.Consent
	user   string
	scopes []byte
	given  time.Time
}

// Dest is what a row scans into.
func (r *ConsentRow) Dest() []any {
	return []any{&r.user, &r.rec.ClientID, &r.scopes, &r.rec.Offline, &r.given}
}

// Record is the row as the port returns it.
func (r *ConsentRow) Record() (*oidcprovider.Consent, error) {
	out := r.rec
	var err error
	if out.Scopes, err = decodeList[string]("scopes", r.scopes); err != nil {
		return nil, err
	}
	out.User, out.LastGivenAt = identity.UserID(r.user), r.given.UTC()

	return &out, nil
}

// GrantArgs is GrantInsert's arguments for g. It writes created_at even when it is the
// zero time, because NULL would make a stored grant read as a tombstone, and holds_lineage
// as given, because the column's default says nothing about this grant. A revocation
// already on g is kept when no tombstone is there, as the in-memory store has it.
func GrantArgs(g *oidcprovider.Grant) ([]any, error) {
	if err := checkFields(
		opField{"user reference", string(g.User)}, opField{"client identifier", g.ClientID}, opField{"acr", g.ACR},
		opField{"key binding", g.KeyBinding}, opField{"upstream issuer", g.ExternalIssuer},
		opField{"upstream session", g.ExternalSessionID}, opField{"revocation cause", string(g.RevokeCause)},
	); err != nil {
		return nil, err
	}
	scopes, err := encodeList("scopes", g.Scopes)
	if err != nil {
		return nil, err
	}
	resources, err := encodeList("resources", g.Resources)
	if err != nil {
		return nil, err
	}
	amr, err := encodeList("amr", g.AMR)
	if err != nil {
		return nil, err
	}

	return []any{
		g.Family.String(), string(g.User), g.ClientID, scopes, resources, opNullTime(g.AuthTime), amr, g.ACR, g.KeyBinding,
		opNullID(g.CodeID), opNullID(g.SignInFamily), g.ExternalIssuer, g.ExternalSessionID, g.Offline, g.EndsWithSignIn,
		g.HoldsLineage, opTime(g.CreatedAt), opTime(g.ExpiresAt), g.Revoked, opNullTime(g.RevokedAt), string(g.RevokeCause),
		opNullTime(g.SignInEndedAt),
	}, nil
}

// GrantRow holds a scanned op_grants row.
type GrantRow struct {
	rec                                        oidcprovider.Grant
	user, cause                                string
	scopes, resources, amr                     []byte
	code, signIn                               sql.Null[id.ID]
	authTime, created, expires, revoked, ended sql.NullTime
}

// Dest is what a row scans into.
func (r *GrantRow) Dest() []any {
	return []any{
		&r.rec.Family, &r.user, &r.rec.ClientID, &r.scopes, &r.resources, &r.authTime, &r.amr, &r.rec.ACR, &r.rec.KeyBinding,
		&r.code, &r.signIn, &r.rec.ExternalIssuer, &r.rec.ExternalSessionID, &r.rec.Offline, &r.rec.EndsWithSignIn,
		&r.rec.HoldsLineage, &r.created, &r.expires, &r.rec.Revoked, &r.revoked, &r.cause, &r.ended,
	}
}

// Record is the row as the port returns it.
func (r *GrantRow) Record() (*oidcprovider.Grant, error) {
	out := r.rec
	var err error
	if out.Scopes, err = decodeList[string]("scopes", r.scopes); err != nil {
		return nil, err
	}
	if out.Resources, err = decodeList[string]("resources", r.resources); err != nil {
		return nil, err
	}
	if out.AMR, err = decodeList[string]("amr", r.amr); err != nil {
		return nil, err
	}
	out.User, out.RevokeCause = identity.UserID(r.user), oidcprovider.RevocationCause(r.cause)
	out.CodeID, out.SignInFamily = r.code.V, r.signIn.V
	out.AuthTime, out.CreatedAt, out.ExpiresAt = fromNullTime(r.authTime), fromNullTime(r.created), fromNullTime(r.expires)
	out.RevokedAt, out.SignInEndedAt = fromNullTime(r.revoked), fromNullTime(r.ended)

	return &out, nil
}

// AccessTokenArgs is AccessTokenInsert's arguments for r.
func AccessTokenArgs(r *oidcprovider.AccessTokenRecord) ([]any, error) {
	if err := checkFields(opField{"client identifier", r.ClientID}, opField{"user reference", string(r.User)}); err != nil {
		return nil, err
	}
	scopes, err := encodeList("scopes", r.Scopes)
	if err != nil {
		return nil, err
	}
	audience, err := encodeList("audience", r.Audience)
	if err != nil {
		return nil, err
	}
	confirmation, err := encodeMap("confirmation", r.Confirmation)
	if err != nil {
		return nil, err
	}

	return []any{
		r.ID.String(), bytesOrEmpty(r.Digest), r.GrantFamily.String(), r.ClientID, string(r.User), scopes, audience,
		confirmation, opTime(r.IssuedAt), opTime(r.ExpiresAt), r.Revoked,
	}, nil
}

// AccessTokenRow holds a scanned op_access_tokens row.
type AccessTokenRow struct {
	rec                            oidcprovider.AccessTokenRecord
	user                           string
	scopes, audience, confirmation []byte
	issued, expires                time.Time
}

// Dest is what a row scans into.
func (r *AccessTokenRow) Dest() []any {
	return []any{
		&r.rec.ID, &r.rec.Digest, &r.rec.GrantFamily, &r.rec.ClientID, &r.user, &r.scopes, &r.audience, &r.confirmation,
		&r.issued, &r.expires, &r.rec.Revoked,
	}
}

// Record is the row as the port returns it.
func (r *AccessTokenRow) Record() (*oidcprovider.AccessTokenRecord, error) {
	out := r.rec
	var err error
	if out.Scopes, err = decodeList[string]("scopes", r.scopes); err != nil {
		return nil, err
	}
	if out.Audience, err = decodeList[string]("audience", r.audience); err != nil {
		return nil, err
	}
	if out.Confirmation, err = decodeMap("confirmation", r.confirmation); err != nil {
		return nil, err
	}
	out.User, out.IssuedAt, out.ExpiresAt = identity.UserID(r.user), r.issued.UTC(), r.expires.UTC()

	return &out, nil
}

// AssertionIDArgs is AssertionIDRecord's arguments, with rowID the uuid of a row it
// creates.
func AssertionIDArgs(rowID id.ID, clientID, jti string, until time.Time) ([]any, error) {
	if err := checkFields(opField{"client identifier", clientID}, opField{"assertion identifier", jti}); err != nil {
		return nil, err
	}

	return []any{rowID.String(), clientID, jti, opTime(until)}, nil
}

// CheckBrowserSession refuses what BrowserSessionStore.Put does, with an error matching
// oidcprovider.ErrConfig: a record no load could find or judge.
func CheckBrowserSession(s *oidcprovider.BrowserSession) error {
	if len(s.Digest) == 0 {
		return fmt.Errorf("%w: BrowserSessionStore.Put: the digest must not be empty", oidcprovider.ErrConfig)
	}
	if s.IdleExpiresAt.IsZero() || s.AbsoluteExpiresAt.IsZero() {
		return fmt.Errorf("%w: BrowserSessionStore.Put: a deadline must not be zero", oidcprovider.ErrConfig)
	}

	return nil
}

// BrowserSessionArgs is BrowserSessionInsert's arguments for s, with rowID the uuid of a
// row it creates. The idle deadline is lowered to the absolute one when it is later.
func BrowserSessionArgs(rowID id.ID, s *oidcprovider.BrowserSession) ([]any, error) {
	if err := checkSignIn(&s.SignIn); err != nil {
		return nil, err
	}
	amr, err := encodeList("amr", s.SignIn.AMR)
	if err != nil {
		return nil, err
	}
	idle := s.IdleExpiresAt
	if idle.After(s.AbsoluteExpiresAt) {
		idle = s.AbsoluteExpiresAt
	}

	return []any{
		rowID.String(), s.Digest, string(s.SignIn.User), s.SignIn.Family.String(), opTime(s.SignIn.AuthenticatedAt), amr,
		s.SignIn.ACR, opTime(s.SignIn.AbsoluteExpiresAt), s.SignIn.ExternalIssuer, s.SignIn.ExternalSessionID,
		opTime(idle), opTime(s.AbsoluteExpiresAt),
	}, nil
}

// BrowserSessionRow holds a scanned op_browser_sessions row.
type BrowserSessionRow struct {
	rec           oidcprovider.BrowserSession
	signIn        signInRow
	idle, absolut time.Time
}

// Dest is what a row scans into.
func (r *BrowserSessionRow) Dest() []any {
	return []any{
		&r.rec.Digest, &r.signIn.user, &r.signIn.family, &r.signIn.authenticated, &r.signIn.amr, &r.signIn.acr,
		&r.signIn.signIn, &r.signIn.issuer, &r.signIn.session, &r.idle, &r.absolut,
	}
}

// Record is the row as the port returns it.
func (r *BrowserSessionRow) Record() (*oidcprovider.BrowserSession, error) {
	out := r.rec
	var err error
	if out.SignIn, err = r.signIn.record(); err != nil {
		return nil, err
	}
	out.IdleExpiresAt, out.AbsoluteExpiresAt = r.idle.UTC(), r.absolut.UTC()

	return &out, nil
}

// ClientUsesSecret reports whether a client authenticating by method holds secrets.
func ClientUsesSecret(method oidcprovider.AuthMethod) bool {
	return method == oidcprovider.ClientSecretBasic || method == oidcprovider.ClientSecretPost
}

// ClientArgs is ClientUpsert's arguments for rc, validated by the caller, with rowID the
// uuid of a row it creates and keepHeld saying a replacement keeps the secrets held.
func ClientArgs(rowID id.ID, rc *oidcprovider.RegisteredClient, keepHeld bool) ([]any, error) {
	if err := checkFields(
		opField{"client identifier", rc.ID}, opField{"client name", rc.Name}, opField{"authentication method", string(rc.AuthMethod)},
		opField{"key set URI", rc.JWKSURI}, opField{"back-channel logout URI", rc.BackChannelLogoutURI},
		opField{"resource identifier", rc.ResourceIdentifier}, opField{"ID token algorithm", rc.IDTokenAlg},
	); err != nil {
		return nil, err
	}
	lists := make([]any, 0, 5)
	for _, l := range []struct {
		name   string
		values []string
	}{
		{"redirect URIs", rc.RedirectURIs}, {"post-logout redirect URIs", rc.PostLogoutRedirectURIs}, {"scopes", rc.Scopes},
		{"resources", rc.Resources}, {"default audience", rc.DefaultAudience},
	} {
		encoded, err := encodeList(l.name, l.values)
		if err != nil {
			return nil, err
		}
		lists = append(lists, encoded)
	}
	grantTypes, err := encodeList("grant types", rc.GrantTypes)
	if err != nil {
		return nil, err
	}
	metadata, err := encodeMap("metadata", rc.Metadata)
	if err != nil {
		return nil, err
	}
	secrets, err := EncodeClientSecrets(rc.Secrets)
	if err != nil {
		return nil, err
	}
	var jwks any
	if rc.JWKS != nil {
		jwks = rc.JWKS
	}

	return []any{
		rowID.String(), rc.ID, rc.Name, int16(rc.Type), int16(rc.ApplicationType), string(rc.AuthMethod), int16(rc.PKCE),
		jwks, rc.JWKSURI, lists[0], lists[1], rc.BackChannelLogoutURI, lists[2], lists[3], lists[4], rc.ResourceIdentifier,
		grantTypes, rc.FirstParty, int16(rc.OfflineAccess), rc.IDTokenAlg, int64(rc.IDTokenLifetime),
		int64(rc.AccessTokenLifetime), rc.OpaqueAccessTokens, int16(rc.RequireBinding), int64(rc.RefreshGrace),
		int64(rc.GrantIdleTimeout), int64(rc.GrantAbsoluteLifetime), rc.DisableRotation, rc.EndGrantsWithSignIn,
		rc.KeepPublicWebGrantsPastSignIn, metadata, secrets, keepHeld,
	}, nil
}

// ClientRow holds a scanned op_clients row.
type ClientRow struct {
	rec                                      oidcprovider.RegisteredClient
	clientType, appType, pkce, offline, bind int16
	method                                   string
	redirects, logouts, scopes, resources    []byte
	audience, grantTypes, metadata, secrets  []byte
	idToken, access, grace, idle, absolute   int64
}

// Dest is what a row scans into.
func (r *ClientRow) Dest() []any {
	return []any{
		&r.rec.ID, &r.rec.Name, &r.clientType, &r.appType, &r.method, &r.pkce, &r.rec.JWKS, &r.rec.JWKSURI, &r.redirects,
		&r.logouts, &r.rec.BackChannelLogoutURI, &r.scopes, &r.resources, &r.audience, &r.rec.ResourceIdentifier,
		&r.grantTypes, &r.rec.FirstParty, &r.offline, &r.rec.IDTokenAlg, &r.idToken, &r.access, &r.rec.OpaqueAccessTokens,
		&r.bind, &r.grace, &r.idle, &r.absolute, &r.rec.DisableRotation, &r.rec.EndGrantsWithSignIn,
		&r.rec.KeepPublicWebGrantsPastSignIn, &r.metadata, &r.secrets,
	}
}

// Record is the row as the port returns it. It validates nothing: the provider
// validates a client as it reads it.
func (r *ClientRow) Record() (*oidcprovider.RegisteredClient, error) {
	out := r.rec
	var err error
	for _, l := range []struct {
		name string
		raw  []byte
		dst  *[]string
	}{
		{"redirect URIs", r.redirects, &out.RedirectURIs}, {"post-logout redirect URIs", r.logouts, &out.PostLogoutRedirectURIs},
		{"scopes", r.scopes, &out.Scopes}, {"resources", r.resources, &out.Resources}, {"default audience", r.audience, &out.DefaultAudience},
	} {
		if *l.dst, err = decodeList[string](l.name, l.raw); err != nil {
			return nil, err
		}
	}
	if out.GrantTypes, err = decodeList[oidcprovider.GrantType]("grant types", r.grantTypes); err != nil {
		return nil, err
	}
	if out.Metadata, err = decodeMap("metadata", r.metadata); err != nil {
		return nil, err
	}
	if out.Secrets, err = DecodeClientSecrets(r.secrets); err != nil {
		return nil, err
	}
	//nolint:gosec // each was written from its uint8 type
	out.Type, out.ApplicationType, out.PKCE, out.OfflineAccess, out.RequireBinding = oidcprovider.ClientType(r.clientType),
		oidcprovider.ApplicationType(r.appType), oidcprovider.PKCERequirement(r.pkce),
		oidcprovider.OfflineAccess(r.offline), oidcprovider.BindingRequirement(r.bind)
	out.AuthMethod = oidcprovider.AuthMethod(r.method)
	out.IDTokenLifetime, out.AccessTokenLifetime = time.Duration(r.idToken), time.Duration(r.access)
	out.RefreshGrace, out.GrantIdleTimeout, out.GrantAbsoluteLifetime = time.Duration(r.grace), time.Duration(r.idle), time.Duration(r.absolute)

	return &out, nil
}
