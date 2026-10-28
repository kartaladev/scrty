package mfa

import (
	"context"
	"errors"

	"github.com/kartaladev/scrty/identity"
)

// ContactResolver returns the address the enrolment path and an operator reset
// send a user's messages to — the emailed code and the notifications — from
// the user's loaded details.
//
// The default is UsernameAsAddress: where usernames are email addresses, which
// is the convention magic links already rely on, nothing needs configuring. A
// consumer whose usernames are not addresses supplies their own, reading
// whatever field of their own records holds the address. The library does not
// interpret the details beyond the default.
//
// An error refuses the step that needed the address. The address is never
// written to a log.
type ContactResolver func(ctx context.Context, d *identity.Details) (string, error)

// LabelResolver returns the account label a provisioning URI carries, which an
// authenticator app shows beside the issuer, from the user's loaded details.
// It is never taken from the request.
//
// The default is UsernameAsAddress. A consumer replaces it, for instance with
// one returning the display email held elsewhere in their records.
type LabelResolver func(ctx context.Context, d *identity.Details) (string, error)

// UsernameAsAddress is the default ContactResolver and LabelResolver: the
// user's username, unchanged — never trimmed, case-folded or parsed.
//
// An empty username, or no details at all, is an error rather than an empty
// address. A username containing ':' is returned as it is, and TOTP then
// refuses it as an account label when an enrolment begins, storing nothing; a
// deployment whose usernames may contain ':' supplies its own LabelResolver.
func UsernameAsAddress(_ context.Context, d *identity.Details) (string, error) {
	if d == nil || d.Username == "" {
		return "", errors.New("mfa: the user has no username to use as an address")
	}

	return d.Username, nil
}

var (
	_ ContactResolver = UsernameAsAddress
	_ LabelResolver   = UsernameAsAddress
)
