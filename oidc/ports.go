package oidc

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -source=ports.go -package=oidc_test -destination=ports_mock_test.go -typed

// Flow is one authorization attempt, from Authorize to Callback.
//
// Every field but ExpiresAt is secret or untrusted: State, Nonce and Verifier
// bind the attempt, and Next is the destination the client asked for, not yet
// allowlisted. None of them is ever logged.
type Flow struct {
	Provider, State, Nonce, Verifier, Next string
	ExpiresAt                              time.Time
}

// FlowStore holds login flows between Authorize and Callback.
//
// When a consumer supplies none, the Manager uses an in-memory store, which
// holds flows for one process only.
type FlowStore interface {
	// Begin stores f and returns the opaque handle that later names it.
	Begin(ctx context.Context, f Flow) (handle string, err error)

	// Complete decides existence, the provider and state bindings, single
	// completion and expiry in one indivisible operation. Every refusal is
	// ErrInvalidState and leaves the flow as it was.
	//
	// A flow is expired from its ExpiresAt instant on. A durable store may
	// judge that instant at its own storage precision rather than to the
	// nanosecond; the conformance suite in test/oidc pins the boundary to
	// within one second either side of ExpiresAt so such a store still
	// conforms.
	Complete(ctx context.Context, handle, provider, state string) (Flow, error)

	// DeleteExpired removes flows that expired before the cutoff and returns
	// how many it removed. A zero cutoff is refused with
	// ErrRetainSinceRequired.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// ExternalIdentity is a verified identity as the provider asserted it.
//
// Claims holds every claim of the verified ID token, unchanged. Their meaning
// belongs to the consumer; the library reads only the ones it documents.
type ExternalIdentity struct {
	Provider, Issuer, Subject, Email string
	EmailVerified                    bool
	Claims                           map[string]any
}

// IdentityBroker resolves a verified external identity to one of the
// application's own users.
//
// It is required: NewManager refuses a nil broker. The library's own broker
// resolves through a LinkStore; a consumer may supply any other.
//
// A broker that also has a method Links() LinkStore exposes the store it
// resolves through, and a back-channel logout token naming only a subject is
// resolved to a user through that store. A consumer broker without one leaves
// such a token unresolved: it ends no session, and the endpoint logs a
// warning.
type IdentityBroker interface {
	// Broker returns the principal ext resolves to, or an error:
	// ErrNoLinkedAccount or ErrProvisioningRefused for a refusal, anything
	// else for a failure.
	Broker(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error)
}

// Link binds one provider's subject to one of the application's users.
//
// The key is Provider, Issuer and Subject together. Username and Email are a
// record of what they were when the link was made, never used to resolve it.
type Link struct {
	// ID identifies this link, never its external identity or user
	// reference. It is minted by the caller, not the store: the library's
	// own Broker mints one (WithBrokerIDGenerator names its source, default
	// id.NewV7Generator) before every Insert. It must be unique and
	// non-zero; a store may refuse a zero ID rather than mint one of its
	// own, since a store cannot tell a zero value that was never meant as
	// an identifier from a genuine one.
	ID                        id.ID
	Provider, Issuer, Subject string
	UserID                    identity.UserID
	Username, Email           string
	CreatedAt                 time.Time
}

// LinkStore holds the links between external identities and users.
//
// NewBroker requires one and refuses a nil store as a missing port. The
// library's own implementation is NewMemoryLinkStore, which holds links for
// one process only.
type LinkStore interface {
	// FindByExternal returns the link for the external identity, or
	// ErrLinkNotFound. It returns a pointer so a nil from a non-conforming
	// store can be refused rather than dereferenced.
	FindByExternal(ctx context.Context, provider, issuer, subject string) (*Link, error)

	// Insert stores l, or returns ErrLinkExists when its external identity is
	// already linked. l.ID must be unique and non-zero (see Link.ID); a
	// store may refuse a zero ID.
	Insert(ctx context.Context, l Link) error

	// DeleteByUser removes every link to user and returns how many it removed.
	DeleteByUser(ctx context.Context, user identity.UserID) (int, error)
}

// HandoffRecord is one issued handoff code, as its store holds it.
//
// The code itself is never stored: TokenID finds the record and SecretHash
// verifies the secret half. IDToken is kept for RP-initiated logout.
type HandoffRecord struct {
	// ID identifies this record, never TokenID or the secret it hashes. It
	// is minted by the caller, not the store: the library's own
	// HandoffManager mints one (WithHandoffIDGenerator names its source,
	// default id.NewV7Generator) before every Insert. It must be unique and
	// non-zero; a store may refuse a zero ID rather than mint one of its
	// own, since a store cannot tell a zero value that was never meant as
	// an identifier from a genuine one.
	ID                                         id.ID
	TokenID                                    string
	SecretHash                                 []byte
	UserID                                     identity.UserID
	Provider, Issuer, SessionID, IDToken, Next string
	ExpiresAt, CreatedAt                       time.Time
	ConsumedAt                                 *time.Time
}

// HandoffStore holds issued handoff codes until they are redeemed or expire.
//
// NewHandoffManager requires one and refuses a nil store as a missing port. The
// library's own implementation is NewMemoryHandoffStore, which holds codes for
// one process only.
type HandoffStore interface {
	// Insert stores rec. rec.ID must be unique and non-zero (see
	// HandoffRecord.ID); a store may refuse a zero ID.
	Insert(ctx context.Context, rec HandoffRecord) error

	// FindByTokenID returns the record, or ErrHandoffNotFound. It returns a
	// pointer so a nil from a non-conforming store can be refused rather than
	// dereferenced.
	FindByTokenID(ctx context.Context, tokenID string) (*HandoffRecord, error)

	// Consume marks an unconsumed record consumed at the given time; a
	// consumed or missing one is ErrHandoffNotFound. Exactly one of racing
	// calls succeeds.
	Consume(ctx context.Context, tokenID string, at time.Time) error

	// DeleteExpired removes records that expired before the cutoff and returns
	// how many it removed. A zero cutoff is refused with
	// ErrRetainSinceRequired.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// CallbackResult is a completed, verified and brokered login.
//
// Next is the destination the client requested at Authorize, untrusted until
// the caller allowlists it. IDToken is kept for RP-initiated logout and is
// never logged.
type CallbackResult struct {
	Principal                            *identity.Principal
	Provider, Issuer, SessionID, IDToken string
	Next                                 string
}
