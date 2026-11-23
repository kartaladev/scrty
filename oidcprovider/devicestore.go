package oidcprovider

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -destination=devicestore_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider DeviceAuthorizationStore

// DeviceState is how far a device authorization has come. It moves only forward, each
// move one conditional write: from DeviceIssued to DeviceClaimed when a browser enters
// the user code, from DeviceClaimed to DeviceApproved or DeviceDenied when the user
// answers the consent page, and from DeviceApproved to DeviceSpent when the device
// exchanges its code. Expiry is no state: the provider judges it from ExpiresAt.
type DeviceState uint8

const (
	// DeviceIssued has been handed to the device, and no browser has entered its code.
	DeviceIssued DeviceState = iota

	// DeviceClaimed has had its user code entered by one browser, which alone may go on.
	DeviceClaimed

	// DeviceApproved has been approved by the user, and waits for the device to poll.
	DeviceApproved

	// DeviceDenied has been denied by the user.
	DeviceDenied

	// DeviceSpent has been exchanged for tokens, and is kept only to detect a replay.
	DeviceSpent
)

// DeviceApproval is what the user's approval of a device authorization recorded: who
// approved it, what they granted, the sign-in they approved it under, and the grant it
// will create.
type DeviceApproval struct {
	// User is the user who approved.
	User identity.UserID
	// GrantedScopes are the scopes the user granted, which may be fewer than were asked.
	GrantedScopes []string
	// SignIn is the sign-in the approval was given under.
	SignIn SignIn
	// GrantFamily is the family of the grant the exchange creates, chosen at approval so
	// that an end of the sign-in or a revocation reaches an approval not yet exchanged.
	GrantFamily id.ID
	// Offline reports that the grant holds offline_access.
	Offline bool
	// EndsWithSignIn ties the grant to its sign-in even when Offline is true.
	EndsWithSignIn bool
	// SurvivesSignInEnd keeps the grant past the end of its sign-in even when Offline is
	// false, as the client's DeviceGrantsOutliveSignIn asks. EndsWithSignIn wins over it.
	SurvivesSignInEnd bool
}

// DeviceAuthorization is one device authorization (RFC 8628): what a device asked for,
// how far the user has come in answering it, and how the device has polled. It holds
// the digests of the device code, the user code and the claiming browser's flow secret,
// never any of them.
type DeviceAuthorization struct {
	// ID is the record's identifier, by which every transition names it.
	ID id.ID
	// DeviceCodeDigest is the digest of the device code, and the record's key.
	DeviceCodeDigest []byte
	// UserCodeDigest is the keyed digest of the user code, unique among unexpired records.
	UserCodeDigest []byte
	// ClaimFlowDigest is the digest of the flow secret of the browser that claimed the
	// record, and empty until one has.
	ClaimFlowDigest []byte

	// ClientID is the client that asked.
	ClientID string
	// Scopes and Resources are the scopes and resource indicators asked for.
	Scopes, Resources []string

	// IssuedAt is when the record was issued, and ExpiresAt when it stops being valid.
	IssuedAt, ExpiresAt time.Time
	// LastPolledAt is when the device last polled, and zero until it has.
	LastPolledAt time.Time
	// Interval is how long the device must wait between polls.
	Interval time.Duration
	// PollCount is how many polls have been recorded. It is the version a poll's
	// compare-and-set reads, so that no write compares timestamps a store may truncate.
	PollCount int

	// State is how far the record has come.
	State DeviceState
	// Approval is what the user's approval recorded, and nil until the user approves.
	Approval *DeviceApproval
}

// ErrUserCodeTaken reports that DeviceAuthorizationStore.Create found the user code's
// digest held by an unexpired record. The provider draws another code. Its text is fixed,
// and carries no digest.
var ErrUserCodeTaken = errors.New("oidcprovider: user code taken")

// DeviceAuthorizationStore keeps device authorizations. WithDeviceAuthorizationStore
// supplies one; with none, a provider that enables the device grant keeps them in a
// MemoryDeviceAuthorizationStore. The conformance suite in the test module's storetest
// package holds a store to this contract.
//
// The provider supplies every secret as a digest, and a store never receives a device
// code, a user code or a flow secret. No method's error may carry a digest.
//
// A store reads no clock of its own. Every time it judges by is one the provider passes:
// a record is expired at now when now is not before its ExpiresAt. LoadByDeviceCode
// returns a record whatever its expiry, and the provider judges it.
//
// Every transition (Claim, Decide, RecordPoll and Spend) names the record by its ID and
// is one conditional write: it changes the record only when the record's State, its
// expiry against the time given and, for RecordPoll, its PollCount still hold. A
// transition whose condition does not hold, including one of an unknown ID, answers
// ErrNotFound and writes nothing. An input no record could hold is refused instead, with an
// error that is neither ErrNotFound nor ErrUserCodeTaken, before any condition is judged. So of any number of concurrent attempts at one
// transition of one record, at most one succeeds, and exactly one when the condition held.
//
// Retention is the store's to keep. A replay of a spent device code is detected, and
// revokes the grant it created, only while the record is held, so a spent record is kept
// until a minute past its ExpiresAt, as DeleteExpired does.
//
// Every DeviceAuthorizationStore is an UnspentCodes over the records the user approved,
// DeviceApproved and DeviceSpent alike, whatever their expiry, and lists the GrantFamily
// of each one's Approval. A record's user is its Approval.User, and its sign-in its
// Approval.SignIn. A record is listed by UnspentBySignIn when includeOffline is true, or
// when it ends with its sign-in: it is tied to it (EndsWithSignIn), which wins over
// everything else, or it neither holds offline_access (Offline) nor survives the
// sign-in's end (SurvivesSignInEnd).
type DeviceAuthorizationStore interface {
	UnspentCodes

	// Create stores record. It first releases the user-code digest of any record already
	// holding it that has expired at now, then stores record. A record that holds the digest
	// and has not expired at now makes it answer ErrUserCodeTaken. A record whose ID or
	// DeviceCodeDigest is already held is refused with an error, as is a nil record, one
	// with a zero ID or an empty digest, and one whose PollCount is negative or past
	// math.MaxInt32, and one whose Interval is negative, and every refusal leaves what is stored unchanged.
	// A released record keeps everything else, its device-code digest included, so a
	// replay of it is still detected.
	Create(ctx context.Context, record *DeviceAuthorization, now time.Time) error

	// LoadByDeviceCode returns a copy of the record for digest, whatever its state and
	// expiry, or ErrNotFound.
	LoadByDeviceCode(ctx context.Context, digest []byte) (*DeviceAuthorization, error)

	// LoadByUserCode returns a copy of the record holding the user-code digest, whatever its
	// state, when it has not expired at now. It answers ErrNotFound for an expired record,
	// judged by now and never by a clock of the store's.
	LoadByUserCode(ctx context.Context, digest []byte, now time.Time) (*DeviceAuthorization, error)

	// Claim moves the record from DeviceIssued to DeviceClaimed, and stores flowDigest as
	// its ClaimFlowDigest, when it has not expired at now. An empty flowDigest is refused
	// with an error, and writes nothing.
	Claim(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error

	// Decide moves the record from DeviceClaimed, when it has not expired at now: to
	// DeviceApproved, storing a copy of approval, when approval is not nil, and to
	// DeviceDenied when it is nil. An approval whose GrantFamily is zero is refused with an
	// error, whatever the record's state, and writes nothing.
	Decide(ctx context.Context, deviceID id.ID, approval *DeviceApproval, now time.Time) error

	// RecordPoll records a poll of a record in DeviceIssued or DeviceClaimed whose
	// PollCount is still seenPolls: PollCount becomes seenPolls+1, LastPolledAt at and
	// Interval interval. A negative interval is refused with an error, and writes nothing.
	// It does not judge expiry, as the provider records a poll only of a record it has
	// found unexpired.
	RecordPoll(ctx context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration) error

	// Spend moves the record from DeviceApproved to DeviceSpent, when it has not expired
	// at now.
	Spend(ctx context.Context, deviceID id.ID, now time.Time) error

	// DeleteExpired removes every record expired at now, but a spent one only once now is
	// not before a minute past its ExpiresAt, and returns how many it removed. It judges
	// only by now, never by a clock of its own.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
