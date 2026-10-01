package httpsec_test

import (
	"fmt"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// ExampleEnableAccountRecovery wires account recovery onto a chain: two
// recovery-code proofs (recovery.WithProofs), the MFA reset kind
// (recovery.WithAuthenticatorKinds over recovery.MFAEnrolments), and a binding
// route the recovered session can reach. Here that route is the
// password-change resolve endpoint (httpsec.EnablePasswordChangeGate); the MFA
// enrolment path (httpsec.EnableMFAEnrolment) is the other one
// EnableAccountRecovery accepts.
func ExampleEnableAccountRecovery() {
	users := exampleUserLoader{details: &identity.Details{
		ID: "u-1", Username: "grace@example.com", Active: true,
	}}

	sessions, err := session.NewManager()
	if err != nil {
		panic(err)
	}

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	mfaReset, err := recovery.MFAEnrolments(totp)
	if err != nil {
		panic(err)
	}

	codes, err := recovery.NewCodes()
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.EnablePasswordChangeGate(sessions,
			httpsec.WithChangePasswordEndpoint("/account/password", func(ex *httpsec.Exchange) error {
				return nil // the consumer's own password-change logic
			}),
		),
		httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
			Users:    users,
			Sessions: sessions,
			Sender:   exampleSender{},
			Codes:    codes,
		},
			httpsec.WithRecoveryTokens(exampleTokens{}),
			httpsec.WithRecoveryCore(
				recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithRepudiationContact("Contact support@example.com if you did not request this."),
				recovery.WithAuthenticatorKinds(mfaReset),
			),
		),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(chain != nil)

	// Output: true
}
