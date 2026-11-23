package pgschema

import (
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// The device authorization store's statements and their arguments, which the three
// adapters share. Every transition is one UPDATE whose WHERE holds the record's ID, the
// state it leaves and, but for a poll, its expiry against the time the provider passes,
// never the database's clock: no row affected is the port's ErrNotFound. A poll compares
// poll_count, never a time, since a time read back has lost its nanoseconds.
//
// Create is three statements an adapter runs as one unit (a transaction of its own at READ
// COMMITTED, or a savepoint inside a caller's): DeviceRelease, then DeviceInsert, then,
// only when the insert wrote no row, DeviceHeld to say why. The unique index on
// user_code_digest decides two creates of one code: the second insert waits for the
// first's transaction, and then writes nothing. DeviceHeld runs on a later snapshot, so it
// sees the row that won. A refusal must roll the unit back, so a release is never left
// without its insert.
const (
	// DeviceRelease clears user-code digest $1 from every record holding it that has
	// expired at $2, the time the provider passes.
	DeviceRelease = `UPDATE op_device_authorizations SET user_code_digest = NULL
WHERE user_code_digest = $1 AND expires_at <= $2`

	// DeviceInsert stores a record, with the arguments DeviceArgs returns. No row affected
	// means a unique key of it is held: its ID, its device-code digest or its user-code
	// digest, which DeviceHeld tells apart.
	DeviceInsert = `INSERT INTO op_device_authorizations (` + deviceColumns + `)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
ON CONFLICT DO NOTHING`

	// DeviceHeld reports, for a refused DeviceInsert, whether ID $1 or device-code digest
	// $2 is held, and whether user-code digest $3 is.
	DeviceHeld = `SELECT
  EXISTS (SELECT 1 FROM op_device_authorizations WHERE id = $1 OR device_code_digest = $2),
  EXISTS (SELECT 1 FROM op_device_authorizations WHERE user_code_digest = $3)`

	// DeviceSelectByDeviceCode reads the record of device-code digest $1, whatever its
	// state and expiry.
	DeviceSelectByDeviceCode = `SELECT ` + deviceColumns + ` FROM op_device_authorizations WHERE device_code_digest = $1`

	// DeviceSelectByUserCode reads the record holding user-code digest $1 while $2 is
	// before its expiry.
	DeviceSelectByUserCode = `SELECT ` + deviceColumns + ` FROM op_device_authorizations
WHERE user_code_digest = $1 AND $2 < expires_at`

	// DeviceClaim moves record $1 from issued to claimed, storing flow digest $2, while $3
	// is before its expiry.
	DeviceClaim = `UPDATE op_device_authorizations SET state = 1, claim_flow_digest = $2
WHERE id = $1 AND state = 0 AND $3 < expires_at`

	// DeviceDecide moves record $1 from claimed to state $2, writing the approval's
	// columns $3 to $12, while $13 is before its expiry. DeviceDecideArgs binds it.
	DeviceDecide = `UPDATE op_device_authorizations SET state = $2, user_ref = $3, granted_scopes = $4, sign_in = $5,
  sign_in_family = $6, external_issuer = $7, external_session_id = $8, grant_family = $9, offline = $10,
  ends_with_sign_in = $11, survives_sign_in_end = $12
WHERE id = $1 AND state = 1 AND $13 < expires_at`

	// DeviceRecordPoll records a poll of record $1, issued or claimed, whose poll count is
	// still $2: the count goes up by one, the last poll is $3 and the interval $4
	// nanoseconds. It judges no expiry, as the provider records a poll only of a record it
	// found unexpired.
	DeviceRecordPoll = `UPDATE op_device_authorizations SET poll_count = poll_count + 1, last_polled_at = $3,
  interval_ns = $4
WHERE id = $1 AND state IN (0, 1) AND poll_count = $2`

	// DeviceSpend moves record $1 from approved to spent while $2 is before its expiry.
	DeviceSpend = `UPDATE op_device_authorizations SET state = 4 WHERE id = $1 AND state = 2 AND $2 < expires_at`

	// DeviceDeleteExpired removes every record expired at $1, but a spent one only once it
	// expired at $2 too, which DeviceDeleteExpiredArgs sets a minute before $1: the window
	// in which a replay of its device code is still detected.
	DeviceDeleteExpired = `DELETE FROM op_device_authorizations WHERE expires_at <= $1 AND (state <> 4 OR expires_at <= $2)`

	// DeviceUnspentByClient lists the grant family of each approved or spent record of
	// user $1 and client $2, whatever its expiry. A record holding no approving sign-in
	// has no approval, as DeviceRow.Record decides, so it names no grant family to list.
	DeviceUnspentByClient = `SELECT grant_family FROM op_device_authorizations
WHERE user_ref = $1 AND client_id = $2 AND state IN (2, 4) AND sign_in IS NOT NULL`
)

// deviceKeptPastExpiry is how long past its expiry a spent device authorization is kept,
// as the in-memory store keeps one: the window in which a replay of its code is detected.
const deviceKeptPastExpiry = time.Minute

// deviceColumns are op_device_authorizations' columns, in the order DeviceArgs binds and
// DeviceRow scans.
const deviceColumns = `id, device_code_digest, user_code_digest, claim_flow_digest, client_id, scopes, resources,
  issued_at, expires_at, last_polled_at, interval_ns, poll_count, state, user_ref, granted_scopes, sign_in,
  sign_in_family, external_issuer, external_session_id, grant_family, offline, ends_with_sign_in,
  survives_sign_in_end`

// The refusals of a record no row could hold. Their text is fixed, and carries no value.
var (
	errDeviceNil        = errors.New("a device authorization must not be nil")
	errDeviceIncomplete = errors.New("a device authorization needs an identifier, a device-code digest and a user-code digest")
	errDeviceState      = errors.New("the device authorization's state is not one DeviceState names")
	errDevicePollCount  = errors.New("the device authorization's poll count is negative or too large to store")
	errDeviceInterval   = errors.New("the device authorization's interval is negative")
	errDeviceNoClient   = errors.New("a device authorization must name the client that asked")
	errDeviceNoFamily   = errors.New("a device approval must name its grant family")

	// The refusals of a stored row no write could have made, which a read reports as a failure.
	errDeviceRowState    = errors.New("a stored device authorization holds a state DeviceState does not name")
	errDeviceRowPolls    = errors.New("a stored device authorization holds a negative poll count")
	errDeviceRowInterval = errors.New("a stored device authorization holds a negative interval")
)

// CheckDevice refuses what DeviceAuthorizationStore.Create refuses before any statement: a
// nil record, or one with a zero ID or an empty device-code or user-code digest.
func CheckDevice(r *oidcprovider.DeviceAuthorization) error {
	if r == nil {
		return errDeviceNil
	}
	if r.ID.IsZero() || len(r.DeviceCodeDigest) == 0 || len(r.UserCodeDigest) == 0 {
		return errDeviceIncomplete
	}

	return nil
}

// DeviceArgs is DeviceInsert's arguments for r, which CheckDevice has passed. Its times
// are stored at the microsecond, and a zero LastPolledAt, an empty ClaimFlowDigest and a
// nil Approval as NULL.
func DeviceArgs(r *oidcprovider.DeviceAuthorization) ([]any, error) {
	if r.ClientID == "" {
		return nil, errDeviceNoClient
	}
	if err := checkFields(opField{"client identifier", r.ClientID}); err != nil {
		return nil, err
	}
	if r.State > oidcprovider.DeviceSpent {
		return nil, errDeviceState
	}
	if r.PollCount < 0 || r.PollCount > math.MaxInt32 {
		return nil, errDevicePollCount
	}
	if r.Interval < 0 {
		return nil, errDeviceInterval
	}
	scopes, err := encodeList("scopes", r.Scopes)
	if err != nil {
		return nil, err
	}
	resources, err := encodeList("resources", r.Resources)
	if err != nil {
		return nil, err
	}
	approval, err := deviceApprovalValues(r.Approval)
	if err != nil {
		return nil, err
	}
	var flow any
	if len(r.ClaimFlowDigest) > 0 {
		flow = r.ClaimFlowDigest
	}

	return append([]any{
		r.ID.String(), r.DeviceCodeDigest, r.UserCodeDigest, flow, r.ClientID, scopes, resources,
		opTime(r.IssuedAt), opTime(r.ExpiresAt), opNullTime(r.LastPolledAt), int64(r.Interval), int64(r.PollCount),
		int16(r.State),
	}, approval...), nil
}

// DeviceDecideArgs is DeviceDecide's arguments: an approval of record deviceID when
// approval is not nil, and a denial, which clears the approval's columns, when it is.
func DeviceDecideArgs(deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time) ([]any, error) {
	values, err := deviceApprovalValues(approval)
	if err != nil {
		return nil, err
	}
	state := oidcprovider.DeviceDenied
	if approval != nil {
		state = oidcprovider.DeviceApproved
	}
	args := append([]any{deviceID.String(), int16(state)}, values...)

	return append(args, opTime(now)), nil
}

// deviceApprovalValues are the ten approval columns, from user_ref to
// survives_sign_in_end, for a, and each column's unset value for a nil a.
func deviceApprovalValues(a *oidcprovider.DeviceApproval) ([]any, error) {
	if a == nil {
		return []any{"", "[]", nil, nil, "", "", nil, false, false, false}, nil
	}
	if a.GrantFamily.IsZero() {
		return nil, errDeviceNoFamily
	}
	if err := checkFields(opField{"approving user", string(a.User)}); err != nil {
		return nil, err
	}
	granted, err := encodeList("granted scopes", a.GrantedScopes)
	if err != nil {
		return nil, err
	}
	signIn, err := EncodeSignIn(&a.SignIn)
	if err != nil {
		return nil, err
	}

	return []any{
		string(a.User), granted, signIn, opNullID(a.SignIn.Family), a.SignIn.ExternalIssuer, a.SignIn.ExternalSessionID,
		a.GrantFamily.String(), a.Offline, a.EndsWithSignIn, a.SurvivesSignInEnd,
	}, nil
}

// DeviceRecordPollArgs is DeviceRecordPoll's arguments. A negative interval is refused with
// an error, as no row could hold it and the poll is no lost compare. ok is false, with no
// error, when no stored count could be seenPolls: the poll is then a lost compare, which
// writes nothing.
func DeviceRecordPollArgs(
	deviceID id.ID, seenPolls int, at time.Time, interval time.Duration,
) (args []any, ok bool, err error) {
	if interval < 0 {
		return nil, false, errDeviceInterval
	}
	if seenPolls < 0 || seenPolls >= math.MaxInt32 {
		return nil, false, nil
	}

	return []any{deviceID.String(), int64(seenPolls), opTime(at), int64(interval)}, true, nil
}

// DeviceDeleteExpiredArgs is DeviceDeleteExpired's arguments for a sweep at now.
func DeviceDeleteExpiredArgs(now time.Time) []any {
	return []any{opTime(now), opTime(now.Add(-deviceKeptPastExpiry))}
}

// DeviceUnspentBySignIn is the statement listing the grant family of each approved or
// spent record whose approval sel selects, whatever its expiry, and its arguments. A
// record that does not end with its sign-in (endsWithSignIn) is left out unless
// includeOffline is true. sel must be valid.
func DeviceUnspentBySignIn(sel oidcprovider.SignInSelector, includeOffline bool) (string, []any) {
	where, args := signInWhere(sel, 2)

	return "SELECT grant_family FROM op_device_authorizations WHERE " + where +
		" AND state IN (2, 4) AND sign_in IS NOT NULL AND ($1::boolean OR " + endsWithSignIn + ")", append([]any{includeOffline}, args...)
}

// DeviceUnspentByClientArgs is DeviceUnspentByClient's arguments.
func DeviceUnspentByClientArgs(user identity.UserID, clientID string) []any {
	return []any{string(user), clientID}
}

// DeviceRow holds a scanned op_device_authorizations row.
type DeviceRow struct {
	rec                       oidcprovider.DeviceAuthorization
	user                      string
	scopes, resources, grants []byte
	signIn                    []byte
	issued, expires           time.Time
	polled                    sql.NullTime
	interval, polls           int64
	state                     int16
	family, signInFamily      sql.Null[id.ID]
	issuer, session           string
	offline, tied, survives   bool
}

// Dest is what a row scans into.
func (r *DeviceRow) Dest() []any {
	return []any{
		&r.rec.ID, &r.rec.DeviceCodeDigest, &r.rec.UserCodeDigest, &r.rec.ClaimFlowDigest, &r.rec.ClientID, &r.scopes,
		&r.resources, &r.issued, &r.expires, &r.polled, &r.interval, &r.polls, &r.state, &r.user, &r.grants, &r.signIn,
		&r.signInFamily, &r.issuer, &r.session, &r.family, &r.offline, &r.tied, &r.survives,
	}
}

// Record is the row as the port returns it: an empty digest is nil, and the approval is
// nil unless the row holds an approving sign-in. A row holding what no write stores, a state
// beyond the last DeviceState names or a negative poll count or interval, is refused with an
// error that repeats none of it.
func (r *DeviceRow) Record() (*oidcprovider.DeviceAuthorization, error) {
	switch {
	case r.state < 0 || r.state > int16(oidcprovider.DeviceSpent):
		return nil, errDeviceRowState
	case r.polls < 0:
		return nil, errDeviceRowPolls
	case r.interval < 0:
		return nil, errDeviceRowInterval
	}

	out := r.rec
	var err error
	if out.Scopes, err = decodeList[string]("scopes", r.scopes); err != nil {
		return nil, err
	}
	if out.Resources, err = decodeList[string]("resources", r.resources); err != nil {
		return nil, err
	}
	out.DeviceCodeDigest, out.UserCodeDigest = nilIfEmpty(out.DeviceCodeDigest), nilIfEmpty(out.UserCodeDigest)
	out.ClaimFlowDigest = nilIfEmpty(out.ClaimFlowDigest)
	out.IssuedAt, out.ExpiresAt, out.LastPolledAt = r.issued.UTC(), r.expires.UTC(), fromNullTime(r.polled)
	out.Interval, out.PollCount = time.Duration(r.interval), int(r.polls)
	out.State = oidcprovider.DeviceState(r.state) //nolint:gosec // written from a DeviceState, a uint8

	signIn, err := decodeSignIn(r.signIn)
	if err != nil {
		return nil, err
	}
	if signIn == nil {
		return &out, nil
	}
	granted, err := decodeList[string]("granted scopes", r.grants)
	if err != nil {
		return nil, err
	}
	out.Approval = &oidcprovider.DeviceApproval{
		User: identity.UserID(r.user), GrantedScopes: granted, SignIn: *signIn, GrantFamily: r.family.V,
		Offline: r.offline, EndsWithSignIn: r.tied, SurvivesSignInEnd: r.survives,
	}

	return &out, nil
}

// nilIfEmpty is b, or nil when it holds nothing, as the in-memory store returns an unset
// digest.
func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}
