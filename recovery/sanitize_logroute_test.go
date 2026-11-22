package recovery_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/recovery"
)

// TestLogRoute_Sanitizers pins that the abort record of a port error whose
// chain cannot be walked, sanitized in a component that holds no logger (the
// reset planner, the MFA kind, the way-back check), reaches the logger of the
// chain handling the request, and none reaches the default. A request with no
// chain still writes to slog.Default() as it is when the record is written. It
// swaps the default logger, so it does not run in parallel.
func TestLogRoute_Sanitizers(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		run  func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error
	}

	oneKind := func(ctrl *gomock.Controller) *MockAuthenticatorKind { return namedKind(ctrl, "passkey") }
	planned := []recovery.AuthenticatorRef{{Kind: "passkey", ID: "k-1"}}

	cases := []testCase{
		{
			name: "the planner's listing of a kind",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				k := oneKind(ctrl)
				k.EXPECT().Held(gomock.Any(), anaID).Return(nil, portErr)

				p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{k}, recovery.ResetAll, nil)
				require.NoError(t, err)

				_, err = p.Plan(ctx, anaID, nil, nil)

				return err
			},
		},
		{
			name: "the planner's custom policy",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				k := oneKind(ctrl)
				k.EXPECT().Held(gomock.Any(), anaID).Return(planned, nil)

				policy := func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return nil, portErr }
				p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{k}, recovery.ResetCustom, policy)
				require.NoError(t, err)

				_, err = p.Plan(ctx, anaID, nil, nil)

				return err
			},
		},
		{
			name: "the planner's removal by a kind",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				k := oneKind(ctrl)
				k.EXPECT().Remove(gomock.Any(), anaID, planned).Return(portErr)

				p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{k}, recovery.ResetAll, nil)
				require.NoError(t, err)

				return p.Execute(ctx, anaID, planned)
			},
		},
		{
			name: "an MFA method's Enrolled",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				set, methods := removableMethods(ctrl)
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), anaID).Return(false, portErr)

				kind, err := recovery.MFAEnrolments(methods...)
				require.NoError(t, err)

				_, err = kind.Held(ctx, anaID)

				return err
			},
		},
		{
			name: "an MFA method's RemoveEnrolment",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				set, methods := removableMethods(ctrl)
				set.removers["totp"].EXPECT().RemoveEnrolment(gomock.Any(), anaID).Return(portErr)

				kind, err := recovery.MFAEnrolments(methods...)
				require.NoError(t, err)

				return kind.Remove(ctx, anaID, []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}})
			},
		},
		{
			name: "the way-back linked-login lookup",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				c := wbCheck(t, recovery.WayBackDeps{
					Users: NewMockUserLoader(ctrl),
					LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
						return nil, portErr
					},
				})

				_, err := c.HasWayBack(ctx, anaID)

				return err
			},
		},
		{
			name: "the way-back admission lookup",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				c := wbCheck(t, recovery.WayBackDeps{
					Users: NewMockUserLoader(ctrl),
					LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
						return []factor.Kind{factor.OIDC}, nil
					},
					Admits: func(context.Context, identity.UserID, factor.Kind) (bool, error) { return false, portErr },
				})

				_, err := c.HasWayBack(ctx, anaID)

				return err
			},
		},
		{
			name: "the way-back user loader",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(nil, portErr)

				_, err := wbCheck(t, recovery.WayBackDeps{Users: users, IssuedCodes: true}).HasWayBack(ctx, anaID)

				return err
			},
		},
		{
			name: "a kind's Usable",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(&identity.Details{ID: anaID, Active: true}, nil)

				u := usableKind{MockAuthenticatorKind: namedKind(ctrl, "passkey"), MockUsableLister: NewMockUsableLister(ctrl)}
				u.MockUsableLister.EXPECT().Usable(gomock.Any(), anaID).Return(nil, portErr)

				c := wbCheck(t, recovery.WayBackDeps{Users: users, IssuedCodes: true, Kinds: []recovery.AuthenticatorKind{u}})
				_, err := c.HasWayBack(ctx, anaID)

				return err
			},
		},
		{
			name: "a kind's Held, read for a kind with no Usable",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, portErr error) error {
				t.Helper()

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(&identity.Details{ID: anaID, Active: true}, nil)

				k := oneKind(ctrl)
				k.EXPECT().Held(gomock.Any(), anaID).Return(nil, portErr)

				c := wbCheck(t, recovery.WayBackDeps{Users: users, IssuedCodes: true, Kinds: []recovery.AuthenticatorKind{k}})
				_, err := c.HasWayBack(ctx, anaID)

				return err
			},
		},
	}

	for _, tc := range cases {
		for _, chain := range []bool{true, false} {
			name := tc.name + ", no chain"
			if chain {
				name = tc.name + ", inside a configured chain"
			}

			t.Run(name, func(t *testing.T) {
				def, onChain := &syncBuffer{}, &syncBuffer{}

				previous := slog.Default()
				t.Cleanup(func() { slog.SetDefault(previous) })
				slog.SetDefault(lrJSON(def))

				ctx := t.Context()
				if chain {
					ctx = ctxlog.With(ctx, lrJSON(onChain))
				}

				err := tc.run(t, ctx, gomock.NewController(t), &limCycleOne{})
				require.ErrorIs(t, err, porterr.ErrUnwalkable)

				if chain {
					assert.Contains(t, onChain.String(), porterr.MsgClassificationAborted, "the chain's logger takes the record")
					assert.Empty(t, def.String(), "the default logger must see nothing")

					return
				}

				assert.Contains(t, def.String(), porterr.MsgClassificationAborted, "the default as swapped at record time")
			})
		}
	}
}
