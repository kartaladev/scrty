package httpsec_test

import (
	"context"
	"log"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// ExampleChain_ExpiryTasks sweeps the expired state of a chain with account
// recovery, together with the sessions it serves, in one manual run, as a
// CronJob's main would. The chain contributes the recovery core's issued-code
// task; the session store, which the consumer built, contributes its own
// through session.ExpiryTask. No task carries an interval or a cutoff: each
// owner deletes only what its own rules call expired.
func ExampleChain_ExpiryTasks() {
	sessionStore := session.NewMemoryStore()

	sessions, err := session.NewManager(session.WithStore(sessionStore))
	if err != nil {
		log.Fatal(err)
	}

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		log.Fatal(err)
	}

	mfaReset, err := recovery.MFAEnrolments(totp)
	if err != nil {
		log.Fatal(err)
	}

	codes, err := recovery.NewCodes()
	if err != nil {
		log.Fatal(err)
	}

	chain, err := httpsec.New(
		httpsec.EnablePasswordChangeGate(sessions,
			httpsec.WithChangePasswordEndpoint("/account/password", func(*httpsec.Exchange) error { return nil }),
		),
		httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
			Users: exampleUserLoader{details: &identity.Details{
				ID: "u-1", Username: "grace@example.com", Active: true,
			}},
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
		log.Fatal(err)
	}

	tasks := append(chain.ExpiryTasks(), session.ExpiryTask(sessionStore))

	runner, err := expiry.NewRunner(tasks)
	if err != nil {
		log.Fatal(err)
	}

	// RunOnce runs every task, isolating each failure in the report, and
	// returns the failures joined, so a manual run can exit non-zero.
	report, err := runner.RunOnce(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, res := range report.Results {
		log.Printf("%s removed %d", res.Task, res.Removed)
	}
}
