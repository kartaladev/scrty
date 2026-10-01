package recovery

//go:generate mockgen -source=messages.go -destination=messages_mock_test.go -package=recovery_test -typed

import (
	"fmt"
	"strings"
	"time"
)

// Notice is what a recovery notice reports.
type Notice struct {
	// At is when the recovery completed, was held or was cancelled.
	At time.Time
	// Removed is the authenticators the recovery removed or will remove.
	//
	// On the Held notice it is the plan made when the hold started. Finish
	// plans again over what the user holds then, so the Recovered notice, not
	// this one, names what was actually removed.
	Removed []AuthenticatorRef
	// CodesReplaced reports that the user's saved codes were replaced by a new
	// set, which happens when a completed recovery spent one of them.
	CodesReplaced bool
	// CodesVoided reports that the user's saved set was voided because the
	// recovery spent one of its codes, whoever holds the rest. It is set on the
	// Held notice, since the set is voided when the hold starts, and on the
	// Cancelled notice of such a recovery, whose user has no saved code left
	// and must generate a new set.
	CodesVoided bool
	// Repudiation is the text WithRepudiationContact configured.
	Repudiation string
}

// Messages builds every message a recovery sends. Each method returns a
// subject and a plain-text body; the library always sets the recipient itself,
// so a builder cannot redirect a code.
//
// The default is DefaultMessages. A consumer replaces it with WithMessages to
// change the wording, the language or the branding.
type Messages interface {
	// IssuedCode carries an issued recovery code, valid once until until.
	IssuedCode(code string, until time.Time) (subject, body string)
	// Recovered is the notice sent when a recovery completes.
	Recovered(n Notice) (subject, body string)
	// Held is the notice sent when a recovery is held, carrying the link that
	// cancels it before until. Its Notice.Removed is the plan made when the
	// hold started, which Finish computes again.
	Held(n Notice, cancelLink string, until time.Time) (subject, body string)
	// Cancelled is the notice sent when a held recovery is cancelled.
	Cancelled(n Notice) (subject, body string)
	// Regenerated is the notice sent when a user's saved codes are replaced.
	Regenerated(at time.Time) (subject, body string)
}

// DefaultMessages returns the default message builder: plain text naming no
// product or organisation, with every time in UTC.
func DefaultMessages() Messages { return defaultMessages{} }

type defaultMessages struct{}

// timeLayout writes an instant for a person, in UTC.
const timeLayout = "2 January 2006 15:04 MST"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func (defaultMessages) IssuedCode(code string, until time.Time) (string, string) {
	return "Your account recovery code", fmt.Sprintf(
		"Someone asked to recover your account. If it was you, enter this code to continue:\n\n"+
			"%s\n\n"+
			"The code can be used once, and it expires at %s.\n\n"+
			"If it was not you, you can ignore this message: this code alone does not open your account.\n",
		code, formatTime(until))
}

func (defaultMessages) Recovered(n Notice) (string, string) {
	var b strings.Builder

	fmt.Fprintf(&b, "Your account was recovered at %s.\n", formatTime(n.At))
	writeRemoved(&b, n.Removed, "These sign-in methods were removed")

	if n.CodesReplaced {
		b.WriteString("\nYour saved recovery codes were replaced; the previous codes no longer work.\n")
	}

	fmt.Fprintf(&b, "\nIf this was not you, %s\n", n.Repudiation)

	return "Your account was recovered", b.String()
}

func (defaultMessages) Held(n Notice, cancelLink string, until time.Time) (string, string) {
	var b strings.Builder

	fmt.Fprintf(&b, "A recovery of your account was started at %s. It can complete at %s.\n",
		formatTime(n.At), formatTime(until))
	writeRemoved(&b, n.Removed, "When it completes, these sign-in methods will be removed")

	if n.CodesVoided {
		b.WriteString("\nOne of your saved recovery codes was used, so your saved recovery codes no longer work.\n")
	}

	fmt.Fprintf(&b, "\nIf this was not you, cancel it here:\n\n%s\n\nand then %s\n", cancelLink, n.Repudiation)

	return "A recovery of your account is pending", b.String()
}

func (defaultMessages) Cancelled(n Notice) (string, string) {
	var b strings.Builder

	fmt.Fprintf(&b, "A pending recovery of your account was cancelled at %s. Nothing was removed.\n", formatTime(n.At))

	if n.CodesVoided {
		b.WriteString("\nOne of your saved recovery codes was used, so your saved recovery codes no longer work; " +
			"generate a new set.\n")
	}

	fmt.Fprintf(&b, "\nIf you did not cancel it, %s\n", n.Repudiation)

	return "A recovery of your account was cancelled", b.String()
}

func (defaultMessages) Regenerated(at time.Time) (string, string) {
	return "Your recovery codes were replaced", fmt.Sprintf(
		"New saved recovery codes were generated for your account at %s. The previous codes no longer work.\n\n"+
			"If this was not you, secure your account now.\n",
		formatTime(at))
}

func writeRemoved(b *strings.Builder, removed []AuthenticatorRef, lead string) {
	if len(removed) == 0 {
		return
	}

	fmt.Fprintf(b, "\n%s:\n", lead)

	for _, r := range removed {
		fmt.Fprintf(b, "  - %s\n", r)
	}
}
