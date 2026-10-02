package passkey_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/token"
)

// The examples in this file mirror the passkeys section of the README. The
// core module has no WebAuthn dependency, so exampleVerifier stands in for the
// passkey.Verifier that github.com/kartaladev/scrty/passkey/webauthn supplies;
// the adapter's own examples show webauthn.New.

// exampleVerifier answers for its relying party and nothing else.
type exampleVerifier struct {
	passkey.Verifier
	rp passkey.RelyingParty
}

func (v exampleVerifier) RelyingParty() passkey.RelyingParty { return v.rp }

// exampleUsers is an identity.UserLoader over one user.
type exampleUsers struct{ details *identity.Details }

func (u exampleUsers) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	if username != u.details.Username {
		return nil, identity.ErrUserNotFound
	}

	return u.details, nil
}

func (u exampleUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != u.details.ID {
		return nil, identity.ErrUserNotFound
	}

	return u.details, nil
}

// exampleSender is a notify.Sender that reports it does not block, as the
// passkey manager requires; use notify.NewQueuedSender over a real sender.
type exampleSender struct{}

func (exampleSender) Send(context.Context, notify.Message) error { return nil }
func (exampleSender) NonBlocking() bool                          { return true }

// exampleTokens is a token.Generator that issues nothing.
type exampleTokens struct{}

func (exampleTokens) Generate(context.Context, string, *identity.Principal) (string, error) {
	return "token", nil
}

func (exampleTokens) Verify(context.Context, string) (*token.Claims, error) {
	return nil, token.ErrTokenInvalid
}

func exampleUser() exampleUsers {
	return exampleUsers{details: &identity.Details{ID: "u-1", Username: "grace@example.com", Active: true}}
}

// ExampleRelyingParty names the relying party. It has no default: the ID is a
// bare host, the origins are https origins on that host or a subdomain of it
// (http only on localhost), and a malformed one is an error wrapping
// passkey.ErrConfig. Changing the ID later orphans every registered passkey.
func ExampleRelyingParty() {
	rp := passkey.RelyingParty{
		ID:      "example.com",
		Name:    "Example Co",
		Origins: []string{"https://example.com", "https://app.example.com"},
	}

	fmt.Println(rp.Validate())

	rp.ID = "https://example.com" // a scheme is not a host

	fmt.Println(errors.Is(rp.Validate(), passkey.ErrConfig))

	// Output:
	// <nil>
	// true
}

// exampleSessions returns the session manager an example wires as the
// revoker; a real application passes the one its chain uses.
func exampleSessions() *session.Manager {
	sessions, err := session.NewManager()
	if err != nil {
		panic(err)
	}

	return sessions
}

// ExampleNew builds the manager over the verifier, the user loader and a
// non-blocking sender. The credential, handle and challenge stores are left
// at their defaults, which are in memory and hold one process's records only.
func ExampleNew() {
	verifier := exampleVerifier{rp: passkey.RelyingParty{
		ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
	}}

	manager, err := passkey.New(passkey.Deps{
		Verifier: verifier, // webauthn.New(rp) in the adapter module
		Users:    exampleUser(),
		Sender:   exampleSender{},   // a non-blocking notify.Sender, e.g. notify.NewQueuedSender
		Sessions: exampleSessions(), // the session manager the chain uses
	},
		passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// Output: true
}

// ExampleNew_durableStores replaces the in-memory stores with the SQL ones. A
// deployment with more than one replica needs them: the credential store seals
// the emailed code at rest with a seal.Cipher. The pgx and gorm modules carry
// the same constructors for their handles. It is compiled, not run, as it
// needs a database.
func ExampleNew_durableStores() {
	var db *sql.DB // opened by the application

	var cipher seal.Cipher // seal.NewAEADCipher over a seal.Keyring

	credentials, err := sqlstore.NewPasskeyCredentialStore(db, cipher)
	if err != nil {
		panic(err)
	}

	handles, err := sqlstore.NewPasskeyHandleStore(db)
	if err != nil {
		panic(err)
	}

	manager, err := passkey.New(passkey.Deps{
		Verifier:    exampleVerifier{},
		Credentials: credentials,
		Handles:     handles,
		Users:       exampleUser(),
		Sender:      exampleSender{},
		Sessions:    exampleSessions(),
	},
		passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
	)
	if err != nil {
		panic(err)
	}

	_ = manager
}

// ExampleWithCloneResponse overrides what the manager does about a suspected
// clone. By default it refuses, suspends the credential and notifies the user;
// CloneSignalOnly allows the login and only writes a warning. WithClonePolicy
// hands each decision to the consumer instead and wins over the response.
func ExampleWithCloneResponse() {
	deps := passkey.Deps{
		Verifier: exampleVerifier{rp: passkey.RelyingParty{
			ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
		}},
		Users:    exampleUser(),
		Sender:   exampleSender{},
		Sessions: exampleSessions(),
	}
	contact := passkey.WithRepudiationContact("Contact support@example.com if you did not do this.")

	signalOnly, err := passkey.New(deps, contact, passkey.WithCloneResponse(passkey.CloneSignalOnly))
	if err != nil {
		panic(err)
	}

	decided, err := passkey.New(deps, contact,
		passkey.WithClonePolicy(func(_ context.Context, s passkey.CloneSignal) passkey.CloneAction {
			if s.BackupState { // a synced passkey's counter is unreliable: allow it
				return passkey.CloneAllow
			}

			return passkey.CloneRefuseSuspend
		}),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(signalOnly != nil, decided != nil)

	// Output: true true
}

// ExampleWithoutSessionRevocationOnRemoval turns the two session revocations
// off, each with its own option. By default a removal ends the user's other
// sessions (the removing one stays) and a suspected clone ends every session
// of the user; the first option keeps the removal default at "keep", the
// second leaves sessions alone when a credential is suspended. With both off
// Deps.Sessions may be left out.
func ExampleWithoutSessionRevocationOnRemoval() {
	manager, err := passkey.New(passkey.Deps{
		Verifier: exampleVerifier{rp: passkey.RelyingParty{
			ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
		}},
		Users:  exampleUser(),
		Sender: exampleSender{},
	},
		passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
		passkey.WithoutSessionRevocationOnRemoval(),
		passkey.WithoutSessionRevocationOnClone(),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// Output: true
}

// ExampleKeepOtherSessions chooses, for one removal, whether the user's other
// sessions end with the passkey; the choice wins over the manager's default.
// The HTTP endpoint offers the same choice as the posted "other_sessions"
// field ("keep" or "end"). It is compiled, not run, as it needs a stored
// passkey and the session that removes it.
func ExampleKeepOtherSessions() {
	var (
		manager *passkey.Manager // built as in ExampleNew
		current *session.Session // the session removing the passkey
		cid     id.ID            // the passkey to remove
		rc      passkey.RegistrationContext
	)

	ctx := context.Background()

	// Keep the other sessions, though the manager ends them by default.
	_ = manager.Remove(ctx, current, cid, rc, passkey.KeepOtherSessions())

	// End them, though the manager was built with WithoutSessionRevocationOnRemoval.
	_ = manager.Remove(ctx, current, cid, rc, passkey.EndOtherSessions())
}

// ExampleWithoutSecondFactorAtLogin stops a passwordless login from proving
// the second factor. By default a user-verified passkey login meets it, so no
// MFA challenge follows; with this option a user the policies require to use
// MFA completes a second factor on another channel, as after any other login.
func ExampleWithoutSecondFactorAtLogin() {
	manager, err := passkey.New(passkey.Deps{
		Verifier: exampleVerifier{rp: passkey.RelyingParty{
			ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
		}},
		Users:    exampleUser(),
		Sender:   exampleSender{},
		Sessions: exampleSessions(),
	},
		passkey.WithRepudiationContact("Contact support@example.com if you did not do this."),
		passkey.WithoutSecondFactorAtLogin(),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager != nil)

	// Output: true
}

// Example_recovery wires saved recovery codes. The way-back check counts
// passkeys through the passkey kind, and a manager's recovery dependencies need
// the check, so the kind is built first with NewRecoveryKind over the same
// credential store the manager will use. Without WithOptionalRecoveryCodes a
// passkey waits pending until its user has confirmed a set of saved codes when
// they have no other way back in.
func Example_recovery() {
	verifier := exampleVerifier{rp: passkey.RelyingParty{
		ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
	}}
	users := exampleUser()
	credentials := passkey.NewMemoryCredentialStore()
	handles := passkey.NewMemoryHandleStore()

	contact := passkey.WithRepudiationContact("Contact support@example.com if you did not do this.")

	deps := passkey.Deps{
		Verifier: verifier, Credentials: credentials, Handles: handles,
		Users: users, Sender: exampleSender{}, Sessions: exampleSessions(),
	}

	codes, err := recovery.NewCodes()
	if err != nil {
		panic(err)
	}

	wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
		Users:       users,
		Codes:       codes,
		Kinds:       []recovery.AuthenticatorKind{passkey.NewRecoveryKind(credentials)},
		IssuedCodes: true, // recovery.ProofIssued is enabled
	})
	if err != nil {
		panic(err)
	}

	deps.Recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack}

	manager, err := passkey.New(deps, contact)
	if err != nil {
		panic(err)
	}

	fmt.Println(manager.RecoveryKind().Kind(), manager.RequiresRecoveryCodes())

	// A deployment whose passkey-only accounts are recovered by its operator
	// alone asks for the optional mode, with no saved codes wired.
	deps.Recovery = nil

	optional, err := passkey.New(deps, contact, passkey.WithOptionalRecoveryCodes())
	if err != nil {
		panic(err)
	}

	fmt.Println(optional.RequiresRecoveryCodes())

	// Output:
	// passkey false
	// false
}

// Example_chain serves passkeys on a chain: registration and management at
// their default paths (/passkey/register, /passkey/credentials), passwordless
// login at /passkey/login, and the passkey as a second factor beside TOTP.
func Example_chain() {
	verifier := exampleVerifier{rp: passkey.RelyingParty{
		ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
	}}
	users := exampleUser()

	sessions, err := session.NewManager()
	if err != nil {
		panic(err)
	}

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lookups, err := mfa.LookupsFor(totp)
	if err != nil {
		panic(err)
	}

	codes, err := recovery.NewCodes()
	if err != nil {
		panic(err)
	}

	contact := passkey.WithRepudiationContact("Contact support@example.com if you did not do this.")

	credentials := passkey.NewMemoryCredentialStore() // the one store, shared with the way-back check

	deps := passkey.Deps{
		Verifier:    verifier,
		Credentials: credentials,
		Users:       users,
		Sender:      exampleSender{},
		Sessions:    sessions, // the manager given to httpsec.PasskeyDeps.Sessions
		MFAMethods:  lookups,  // for direct calls; inside a chain the MFA slot's methods decide
	}

	wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{
		Users: users, Codes: codes, Kinds: []recovery.AuthenticatorKind{passkey.NewRecoveryKind(credentials)},
	})
	if err != nil {
		panic(err)
	}

	deps.Recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack}

	passkeys, err := passkey.New(deps, contact)
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.EnableMFA([]mfa.Method{totp, passkeys.MFAMethod()}, // each verified at /mfa/verify/<name>
			httpsec.WithMFATokens(exampleTokens{}),
		),
		httpsec.EnablePasskeys(
			httpsec.PasskeyDeps{Passkeys: passkeys, Sessions: sessions, Users: users},
			httpsec.WithPasswordlessLogin(httpsec.PasswordlessTokens(exampleTokens{})),
		),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(chain != nil)

	// Output: true
}
