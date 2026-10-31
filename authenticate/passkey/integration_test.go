package passkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// nilPadded is a credential store whose lists carry a nil element, as a
// consumer's store with a bug might return.
type nilPadded struct {
	*passkey.MemoryCredentialStore
}

func (s nilPadded) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	held, err := s.MemoryCredentialStore.List(ctx, user)
	if err != nil {
		return nil, err
	}

	return append([]*passkey.Credential{nil}, held...), nil
}

// TestCredentialList_NilElementIsMissing pins that a nil element in a stored
// credential list is skipped wherever the manager reads the list, instead of
// panicking.
func TestCredentialList_NilElementIsMissing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		codes bool
		run   func(t *testing.T, f *fixture, m *passkey.Passkeys)
	}

	cases := []testCase{
		{
			name: "beginning a registration",
			run: func(t *testing.T, f *fixture, m *passkey.Passkeys) {
				f.begin(t, m, fullSession("sess-a", "u-1"))
			},
		},
		{
			name:  "finishing, then abandoning a pending passkey for a new registration",
			codes: true,
			run: func(t *testing.T, f *fixture, m *passkey.Passkeys) {
				s := fullSession("sess-a", "u-1")

				res, err := m.FinishRegistration(t.Context(), s, regBody(f.begin(t, m, s), "cred-a", ""),
					passkey.RegistrationContext{})
				require.NoError(t, err)
				assert.False(t, res.Activated)

				f.clock.Advance(time.Minute)

				res, err = m.FinishRegistration(t.Context(), s, regBody(f.begin(t, m, s), "cred-b", ""),
					passkey.RegistrationContext{})
				require.NoError(t, err)
				assert.False(t, res.Activated)

				// ConfirmSavedCode finds the passkey awaiting its codes.
				c, err := m.ConfirmSavedCode(t.Context(), s, res.RecoveryCodes[0], passkey.RegistrationContext{})
				require.NoError(t, err)
				assert.Equal(t, passkey.StateActive, c.State)
			},
		},
		{
			name: "confirming an emailed code",
			run: func(t *testing.T, f *fixture, m *passkey.Passkeys) {
				s := enrolmentSession("sess-a", "u-1")
				rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: permissive(t)}

				res, err := m.FinishRegistration(t.Context(), s, regBody(f.begin(t, m, s), "cred-a", ""), rc)
				require.NoError(t, err)
				assert.False(t, res.Activated)

				c, err := m.ConfirmEmailCode(t.Context(), s, emailedCode(t, f), rc)
				require.NoError(t, err)
				assert.Equal(t, passkey.StateActive, c.State)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.deps.Credentials = nilPadded{passkey.NewMemoryCredentialStore()}

			if tc.codes {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			}

			m := f.manager(t)

			require.NotPanics(t, func() { tc.run(t, f, m) })
		})
	}
}
