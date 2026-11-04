package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrNotFound reports that a store holds no such record, or, from
// PendingRequestStore.Advance, none at the stage the caller expected, or a move the
// order of the stages does not allow.
var ErrNotFound = errors.New("oidcprovider: not found")

// Stage is how far a pending request has come. A stage is spent by moving past
// it, through one conditional write. An authorization request moves strictly forward
// through StageLogin, StageConsent and StageDone, and may skip StageConsent. An
// end-session request is parked at StageLogout, and moves only to StageDone.
type Stage uint8

const (
	// StageLogin waits for the user to sign in.
	StageLogin Stage = iota

	// StageConsent waits for the user to answer the consent page.
	StageConsent

	// StageLogout parks an end-session request that must ask the user.
	StageLogout

	// StageDone has been answered, and can no longer be resumed: no move leaves it.
	StageDone
)

// advancesTo reports whether a request at this stage may move to stage to.
func (s Stage) advancesTo(to Stage) bool {
	switch s {
	case StageLogin:
		return to == StageConsent || to == StageDone
	case StageConsent, StageLogout:
		return to == StageDone
	default:
		return false
	}
}

// SignIn is what a pending request and a code record keep of the sign-in that
// answered them. Its authentication facts are copied from the sign-in, never
// taken from the current time.
type SignIn struct {
	// User is the signed-in user.
	User identity.UserID
	// Family is the sign-in's session family.
	Family id.ID
	// AuthenticatedAt is when the user last authenticated.
	AuthenticatedAt time.Time
	// AMR lists the authentication methods used.
	AMR []string
	// ACR is the authentication context reached.
	ACR string
	// AbsoluteExpiresAt is the sign-in's absolute deadline.
	AbsoluteExpiresAt time.Time
	// ExternalIssuer and ExternalSessionID name the upstream sign-in of a federated
	// one, as the session recorded them. Both are empty for a local sign-in.
	ExternalIssuer, ExternalSessionID string
}

// PendingRequest is an authorization or end-session request parked while the
// user signs in or answers a page. It holds the digests of the handle and of the
// flow secret, never either secret.
type PendingRequest struct {
	// ID is the record's identifier, which the handle carries in the clear.
	ID id.ID
	// HandleDigest is the digest of the handle's secret, and the record's key.
	HandleDigest []byte
	// FlowDigest is the digest of the browser's flow secret.
	FlowDigest []byte

	// ClientID and RedirectURI name who asked, and where the answer goes.
	ClientID, RedirectURI string
	// Scopes and Resources are the scopes and resource indicators asked for.
	Scopes, Resources []string
	// State, Nonce and Challenge are the client's values, returned or checked unchanged.
	State, Nonce, Challenge string
	// Prompt lists the request's prompt values.
	Prompt []string
	// MaxAge is the request's max_age in seconds, and nil when it had none.
	MaxAge *int
	// IDTokenHintSubject is the subject of a valid id_token_hint.
	IDTokenHintSubject string
	// DPoPJKT is the request's dpop_jkt.
	DPoPJKT string
	// LoginHint is the request's login_hint.
	LoginHint string
	// UILocales, ClaimsLocales and ACRValues are the request's space-separated lists.
	UILocales, ClaimsLocales, ACRValues []string

	// ParkedAt is when the request was parked, and ExpiresAt when it stops being valid.
	ParkedAt, ExpiresAt time.Time
	// Stage is how far the request has come.
	Stage Stage
	// SignIn is the sign-in that answered the login stage, and nil before that.
	SignIn *SignIn
}

// PendingRequestStore keeps parked requests. The provider supplies its secrets as
// digests, and a store never receives the secrets. No method's error may carry a
// digest. WithPendingRequestStore supplies one; with none, the provider keeps them in
// a MemoryPendingRequestStore.
//
// A store does not judge expiry: Load returns an expired record, and the provider
// compares ExpiresAt with its own clock.
type PendingRequestStore interface {
	// Create stores r, keyed by its HandleDigest. A digest already held is refused
	// with an error, and the stored record is left unchanged.
	Create(ctx context.Context, r *PendingRequest) error

	// Load returns a copy of the record for handleDigest, or ErrNotFound.
	Load(ctx context.Context, handleDigest []byte) (*PendingRequest, error)

	// Advance moves the record from stage from to stage to, and, when s is not nil,
	// stores s as its sign-in. Nothing else changes. It answers ErrNotFound and writes
	// nothing unless the stored stage equals from and the move is one Stage's order
	// allows, so moving out of StageDone, backwards, or to the same stage is refused. It
	// must decide with one conditional write, so that of any number of concurrent calls
	// with one from, at most one succeeds, and exactly one when the move is allowed.
	Advance(ctx context.Context, handleDigest []byte, from, to Stage, s *SignIn) error

	// DeleteExpired removes the records whose ExpiresAt is strictly before before, and
	// returns how many it removed. It judges only by before, never by a clock of its own.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// CodeRecord is the request data of one authorization code. The code's secret and
// its single spend live in token/onetime, and this record is keyed by that token's
// identifier.
type CodeRecord struct {
	// TokenID is the identifier of the code's token/onetime token.
	TokenID id.ID
	// ClientID, RedirectURI, Challenge, Nonce and DPoPJKT are the bindings the exchange checks.
	ClientID, RedirectURI, Challenge, Nonce, DPoPJKT string
	// Scopes and Resources are what was granted.
	Scopes, Resources []string
	// SignIn is the sign-in the code came from, including its upstream issuer and session.
	SignIn SignIn
	// GrantFamily is the family of the grant this code creates, chosen at issue so
	// that a replay or an end of the sign-in can revoke a grant not yet stored.
	GrantFamily id.ID
	// Offline reports that the code holds offline_access.
	Offline bool
	// EndsWithSignIn ties the code to its sign-in even when Offline is true. It is
	// recorded from the client when the code is issued, as the grant's is.
	EndsWithSignIn bool
	// ExpiresAt is when the code stops being valid.
	ExpiresAt time.Time
}

// UnspentCodes is what a GrantStore asks of the code records, so that a revocation
// reaches a grant whose code is still outstanding. Every CodeStore is one.
//
// A record's spend is decided in token/onetime, which this port cannot see, so
// each method answers for every record still held: all that are unspent, and any
// spent or expired one not yet deleted. Revoking the family of a spent one changes
// nothing, because its grant matches the same operation.
type UnspentCodes interface {
	// UnspentBySignIn returns the GrantFamily of each record whose sign-in sel selects.
	// Records holding offline_access are left out unless includeOffline is true, or the
	// record has EndsWithSignIn set, as such a code ends with its sign-in like the grant
	// it creates. A selector of no valid shape is refused with an error matching ErrConfig.
	UnspentBySignIn(ctx context.Context, sel SignInSelector, includeOffline bool) ([]id.ID, error)

	// UnspentByClient returns the GrantFamily of each record of user and clientID,
	// offline_access or not.
	UnspentByClient(ctx context.Context, user identity.UserID, clientID string) ([]id.ID, error)
}

// CodeStore keeps code records. WithCodeStore supplies one; with none, the provider
// keeps them in a MemoryCodeStore.
//
// A store does not judge expiry: Load returns an expired record, and the provider
// compares ExpiresAt with its own clock.
//
// Retention is the store's to keep. A valid replay of a spent code is detected, and revokes
// what the code issued, only while the record is held, and an end of the sign-in reaches an
// exchange in flight only while it is too. Both need the code kept until a minute past its
// expiry, as the default stores do. A store swept sooner gives that up: a replay after the sweep
// is refused with nothing revoked. The code-token store given through WithCodeTokenStore must
// retain the same window, so for a longer one both stores must retain together.
type CodeStore interface {
	UnspentCodes

	// Create stores r, keyed by its TokenID. An identifier already held is refused
	// with an error, and the stored record is left unchanged.
	Create(ctx context.Context, r *CodeRecord) error

	// Load returns a copy of the record for tokenID, or ErrNotFound.
	Load(ctx context.Context, tokenID id.ID) (*CodeRecord, error)

	// DeleteExpired removes the records whose ExpiresAt is strictly before before, and
	// returns how many it removed. It judges only by before, never by a clock of its own.
	//
	// The caller chooses before, and with it how long a spent code is remembered. A valid
	// replay's detection and an end's reach to an exchange in flight need a record kept until
	// a minute past its expiry, so a before later than that minute behind now gives both up
	// for the records between. The default stores sweep on their own at that mark.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// Consent is what a user has allowed a client.
type Consent struct {
	// User and ClientID are who allowed whom.
	User identity.UserID
	// ClientID is the client allowed.
	ClientID string
	// Scopes is every scope given so far.
	Scopes []string
	// Offline reports that offline access was given explicitly.
	Offline bool
	// LastGivenAt is when consent was last given.
	LastGivenAt time.Time
}

// ConsentStore keeps consents, one per user and client. WithConsentStore supplies
// one; with none, the provider keeps them in a MemoryConsentStore.
type ConsentStore interface {
	// Give adds scopes to what user has allowed clientID, and records at as when
	// consent was last given. Scopes accumulate, also under concurrent calls. Offline
	// becomes true when offline is true, and no later call clears it. A scope named
	// offline_access does not set it, because the store does not interpret scopes.
	Give(ctx context.Context, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time) error

	// Load returns a copy of the consent, or ErrNotFound.
	Load(ctx context.Context, user identity.UserID, clientID string) (*Consent, error)

	// Revoke forgets the consent, reporting whether there was one. Giving consent
	// afterwards starts again from nothing.
	Revoke(ctx context.Context, user identity.UserID, clientID string) (bool, error)

	// ListByUser returns copies of user's consents, and of no other user's.
	ListByUser(ctx context.Context, user identity.UserID) ([]Consent, error)
}

// RevocationCause says why a grant was revoked.
type RevocationCause string

// The causes the provider records.
const (
	// CauseReuse is a refresh token presented after its grace window.
	CauseReuse RevocationCause = "reuse"
	// CauseCodeReplay is an authorization code presented twice.
	CauseCodeReplay RevocationCause = "code_replay"
	// CauseSignInEnded is the end of the sign-in the grant came from.
	CauseSignInEnded RevocationCause = "sign_in_ended"
	// CauseConsentRevoked is the user withdrawing their consent.
	CauseConsentRevoked RevocationCause = "consent_revoked"
	// CauseRevokedByClient is the client revoking its own token.
	CauseRevokedByClient RevocationCause = "revoked_by_client"
	// CauseUserDisabled is the account being disabled.
	CauseUserDisabled RevocationCause = "user_disabled"
	// CauseRecovery is an account recovery.
	CauseRecovery RevocationCause = "recovery"
	// CauseMFAReset is a reset of the user's second factors.
	CauseMFAReset RevocationCause = "mfa_reset"
	// CausePasskeyClone is a passkey's clone detection.
	CausePasskeyClone RevocationCause = "passkey_clone"
	// CausePasswordChange is a password change whose option revokes grants.
	CausePasswordChange RevocationCause = "password_change"
	// CauseUserRequest is the user ending their own access.
	CauseUserRequest RevocationCause = "user_request"
)

// Grant is the authoritative record of what one code exchange granted. It is read
// before anything changes state, and it carries the revocation a refresh-token
// lineage cannot.
//
// A revocation recorded before the exchange stores its grant leaves a record holding
// only Family, the revocation's fields and, when an end of the sign-in recorded it,
// SignInEndedAt. Load returns it as it does any other.
type Grant struct {
	// Family is the grant's identifier: the refresh token's family, and the access
	// token's gid. It is not a credential.
	Family id.ID
	// User and ClientID are whom the grant is for.
	User identity.UserID
	// ClientID is the client holding the grant.
	ClientID string
	// Scopes and Resources are what was granted.
	Scopes, Resources []string

	// AuthTime, AMR and ACR are copied from the sign-in, never taken from the exchange.
	AuthTime time.Time
	// AMR lists the authentication methods used.
	AMR []string
	// ACR is the authentication context reached.
	ACR string
	// KeyBinding is the thumbprint of the key the grant is bound to, if any.
	KeyBinding string
	// CodeID is the identifier of the code that created the grant.
	CodeID id.ID

	// SignInFamily is the session family of the sign-in the grant came from, which
	// the ID token's sid names. A SignInSelector's Family is compared with this, and
	// never with the grant's own Family.
	SignInFamily id.ID
	// ExternalIssuer and ExternalSessionID name a federated sign-in's upstream, unchanged.
	ExternalIssuer, ExternalSessionID string
	// Offline reports that the grant holds offline_access, and so outlives its sign-in.
	Offline bool
	// EndsWithSignIn ties the grant to its sign-in even when Offline is true.
	EndsWithSignIn bool
	// HoldsLineage reports that the grant has a refresh-token lineage. A refresh reads
	// it, to know whether a lineage is to be looked for at all.
	HoldsLineage bool

	// CreatedAt and ExpiresAt bound the grant's life.
	CreatedAt, ExpiresAt time.Time

	// Revoked is the mark no later write clears.
	Revoked bool
	// RevokedAt is when the first revocation happened.
	RevokedAt time.Time
	// RevokeCause is the first revocation's cause.
	RevokeCause RevocationCause
	// SignInEndedAt is when the grant was first marked as outliving its sign-in, and
	// zero until then.
	SignInEndedAt time.Time
}

// SignInSelector names the sign-ins an operation applies to. Exactly five shapes
// are valid, and Validate refuses every other, above all the empty selector, so a
// selector can never mean everyone:
//
//	Family                             one sign-in
//	User                               every sign-in of the user
//	User, ExceptFamily                 every sign-in of the user but one
//	ExternalIssuer, ExternalSessionID  one upstream session
//	User, ExternalIssuer               every sign-in of the user through that issuer
type SignInSelector struct {
	// Family selects by the sign-in's session family.
	Family id.ID
	// User selects by the signed-in user.
	User identity.UserID
	// ExceptFamily leaves out one family of User's.
	ExceptFamily id.ID
	// ExternalIssuer and ExternalSessionID select by upstream, compared exactly.
	ExternalIssuer, ExternalSessionID string
}

// Validate reports a selector of no valid shape, with an error matching ErrConfig.
// Its text names the shapes, and repeats no value. Every store calls it before
// reading or writing anything.
func (s SignInSelector) Validate() error {
	family, user, except := s.Family != id.Nil, s.User != "", s.ExceptFamily != id.Nil
	issuer, session := s.ExternalIssuer != "", s.ExternalSessionID != ""

	switch {
	case family && !user && !except && !issuer && !session,
		!family && user && !issuer && !session,
		!family && !user && !except && issuer && session,
		!family && user && !except && issuer && !session:
		return nil
	default:
		return fmt.Errorf("%w: SignInSelector: must be a family, a user, a user and an excepted family, "+
			"an upstream issuer and session, or a user and an upstream issuer", ErrConfig)
	}
}

// matches reports whether a sign-in with these facts is selected. It assumes a
// selector Validate accepted, in which a field left empty selects nothing.
func (s SignInSelector) matches(user identity.UserID, family id.ID, issuer, session string) bool {
	switch {
	case s.Family != id.Nil && s.Family != family,
		s.User != "" && s.User != user,
		s.ExceptFamily != id.Nil && s.ExceptFamily == family,
		s.ExternalIssuer != "" && s.ExternalIssuer != issuer,
		s.ExternalSessionID != "" && s.ExternalSessionID != session:
		return false
	default:
		return true
	}
}

// GrantStore keeps grants. WithGrantStore supplies one; with none, the provider keeps
// them in a MemoryGrantStore. No write ever clears Revoked, and the first revocation's
// time and cause are the ones kept.
//
// A store does not judge expiry: Load returns an expired or revoked record, and the
// provider decides. A time a method judges by, or records, is always the caller's.
type GrantStore interface {
	// UseCodes names where the outstanding codes are read from. New calls it, before
	// any traffic, with the provider's CodeStore, and returns its error. A store that was
	// never given one refuses EndSignIns, RevokeByUser and RevokeByUserAndClient with an
	// error matching ErrConfig, rather than leave a code able to outlive them.
	//
	// Calling it again with the same value, as a second provider sharing both stores
	// does, changes nothing. Any other value is refused with an error matching ErrConfig,
	// and the first stays, because replacing it would silently stop revocations reaching
	// the first provider's codes. Values that cannot be compared count as different, and
	// must not panic.
	UseCodes(codes UnspentCodes) error

	// Create stores g. Over a revocation recorded first for g.Family it fills in the
	// record and answers nil, and the grant is stored revoked with that revocation's
	// time and cause, and with the sign-in-ended mark EndSignIns left on it, if any.
	// Over another grant it is refused with an error, and the stored record is left
	// unchanged.
	Create(ctx context.Context, g *Grant) error

	// Load returns a copy of the record for family, or ErrNotFound.
	Load(ctx context.Context, family id.ID) (*Grant, error)

	// Revoke marks the grant revoked, recording the revocation first when no record
	// exists. A second revocation changes nothing. A zero at is refused with an error
	// matching ErrConfig.
	Revoke(ctx context.Context, family id.ID, cause RevocationCause, at time.Time) error

	// RevokeByUser revokes every grant of user, offline_access included, and records a
	// revocation for the family of each of user's outstanding codes, offline_access
	// included. It returns copies of the grants this call newly revoked. An empty user
	// or a zero at is refused with an error matching ErrConfig. A failure to read the
	// codes fails the call before anything is written.
	RevokeByUser(ctx context.Context, user identity.UserID, cause RevocationCause, at time.Time) ([]Grant, error)

	// RevokeByUserAndClient is RevokeByUser for one client alone: another client's
	// grants and outstanding codes are left as they were. An empty clientID is refused too.
	RevokeByUserAndClient(ctx context.Context, user identity.UserID, clientID string, cause RevocationCause, at time.Time) ([]Grant, error)

	// EndSignIns records that the sign-ins sel selects have ended. Every selected grant
	// not yet marked gets SignInEndedAt, and those without Offline, or with EndsWithSignIn,
	// are also revoked with CauseSignInEnded. An Offline grant keeps working. It returns
	// copies of the grants this call newly marked, so the same end reported twice returns
	// nothing the second time.
	//
	// It first records a revocation for the family of each selected outstanding code
	// without offline_access, or with EndsWithSignIn, so a failure there marks no stored
	// grant and the end can be reported again. A record this creates carries the mark as
	// well, so the grant an exchange later stores over it is not returned by a later end,
	// and a client is not told twice of one end. A revocation already recorded by any
	// other write stays unmarked, whatever its cause. A selector of no valid shape, or a
	// zero at, is refused with an error matching ErrConfig before anything is read or
	// written.
	//
	// A grant with no held code, stored while an end waits, is left for the next end. The
	// provider never stores such a grant, as each comes from an exchange whose code the
	// end holds.
	//
	// It deletes no browser session, as those are not this store's: the provider does
	// that itself, through its browser-session store's DeleteBySignIn.
	EndSignIns(ctx context.Context, sel SignInSelector, at time.Time) ([]Grant, error)

	// DeleteExpired removes each unrevoked grant whose ExpiresAt is strictly before now,
	// and each revoked one, recorded first or not, whose RevokedAt plus keepRevoked is
	// strictly before now, whatever its ExpiresAt. It returns how many it removed. It
	// judges only by now, never by a clock of its own.
	//
	// keepRevoked must cover every code that could still name the grant, and one of
	// zero or less is refused with an error matching ErrConfig.
	DeleteExpired(ctx context.Context, now time.Time, keepRevoked time.Duration) (int, error)
}

// AccessTokenRecord is one opaque access token. The token's secret is held only as a
// digest. Its authorization is its grant's, so a revoked grant ends it without this
// record changing.
type AccessTokenRecord struct {
	// ID is the record's identifier, which the token carries in the clear.
	ID id.ID
	// Digest is the digest of the token's secret, compared by the provider.
	Digest []byte
	// GrantFamily is the grant the token was issued from.
	GrantFamily id.ID
	// ClientID is the client the token was issued to.
	ClientID string
	// User is the user the token speaks for.
	User identity.UserID
	// Scopes and Audience are what the token allows, and where.
	Scopes, Audience []string
	// Confirmation is the token's cnf claim: the key it is bound to, if any.
	Confirmation map[string]string
	// IssuedAt and ExpiresAt bound the token's life.
	IssuedAt, ExpiresAt time.Time
	// Revoked is the mark no later write clears.
	Revoked bool
}

// AccessTokenStore keeps opaque access tokens. WithAccessTokenStore supplies one; with
// none, the provider keeps them in a MemoryAccessTokenStore. No method's error may
// carry a digest.
//
// A store does not judge expiry or revocation: Load returns an expired or revoked
// record, and the provider decides.
type AccessTokenStore interface {
	// Create stores r, keyed by its ID, with its Digest unchanged. An identifier already
	// held is refused with an error, and the stored record is left unchanged.
	Create(ctx context.Context, r *AccessTokenRecord) error

	// Load returns a copy of the record for id, or ErrNotFound.
	Load(ctx context.Context, id id.ID) (*AccessTokenRecord, error)

	// Revoke marks this one token revoked, and no other of its grant. A second call
	// changes nothing. A token not held is ErrNotFound, and nothing is inserted.
	Revoke(ctx context.Context, id id.ID) error

	// DeleteExpired removes the records whose ExpiresAt is strictly before before,
	// revoked or not, and returns how many it removed. It judges only by before, never
	// by a clock of its own.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// BrowserSession is what the provider remembers of a browser that signed in, so it can
// answer later requests from it (R2). It holds the digest of the cookie's secret, and
// never the secret. It is read only by the provider, and no sign-in path reads it. It
// does not see a marker placed on the sign-in afterwards, such as a required password
// change: an administrator's change that matters ends the sign-in, which reaches it.
type BrowserSession struct {
	// Digest is the digest of the cookie's secret, and the record's key.
	Digest []byte
	// SignIn is the sign-in the browser holds, with its authentication facts.
	SignIn SignIn
	// IdleExpiresAt is when the session ends without use.
	IdleExpiresAt time.Time
	// AbsoluteExpiresAt is when it ends regardless, and no later than its sign-in.
	AbsoluteExpiresAt time.Time
}

// BrowserSessionStore keeps browser sessions. WithBrowserSessionStore supplies one;
// with none, the provider keeps them in a MemoryBrowserSessionStore. No method's error
// may carry a digest.
//
// To replace a session, Put the new digest and then Delete the old, so a failure
// between the two leaves the browser signed in rather than not.
type BrowserSessionStore interface {
	// Put stores s, keyed by its Digest, with the idle deadline at most the absolute
	// one. A digest already held is refused with an error, and the stored record is left
	// unchanged. An empty digest or a zero deadline is refused with an error matching
	// ErrConfig, as a record no load could find or judge.
	Put(ctx context.Context, s *BrowserSession) error

	// Load returns a copy of the record for digest while now is before both of its
	// deadlines, and ErrNotFound otherwise, also for an empty digest. It judges by now
	// alone, never by a clock of its own. A zero now, which would keep every session
	// alive, is refused with an error matching ErrConfig.
	Load(ctx context.Context, digest []byte, now time.Time) (*BrowserSession, error)

	// Touch moves the idle deadline to idleUntil, or to the absolute deadline if that
	// is sooner. It only ever extends it, so a slower request cannot shorten what a
	// later one wrote, and it writes nothing else. It must decide with one conditional
	// write. A digest not held is ErrNotFound, and nothing is inserted. A zero idleUntil
	// is refused with an error matching ErrConfig. It takes no current time, so a caller
	// touches only what its Load has just returned.
	Touch(ctx context.Context, digest []byte, idleUntil time.Time) error

	// Delete removes the record for digest. One not held is not an error.
	Delete(ctx context.Context, digest []byte) error

	// DeleteBySignIn removes every record whose sign-in sel selects, expired ones
	// included, and returns how many it removed. A selector of no valid shape is refused
	// with an error matching ErrConfig before anything is read or written.
	DeleteBySignIn(ctx context.Context, sel SignInSelector) (int, error)

	// DeleteExpired removes the records with either deadline strictly before before, and
	// returns how many it removed. It judges only by before, never by a clock of its own.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
