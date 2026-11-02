package guardauth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/guardauth"
)

// headers is a HeaderWriter over an http.Header.
type headers http.Header

func (h headers) SetHeader(name, value string) { http.Header(h).Set(name, value) }
func (h headers) AddHeader(name, value string) { http.Header(h).Add(name, value) }

func TestChallenge(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refused")
	errReplaced := errors.New("the challenge could not be set")

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, h http.Header, err error)
	}

	cases := []testCase{
		{
			name: "nothing published: the refusal unchanged, no header",
			assert: func(t *testing.T, h http.Header, err error) {
				require.ErrorIs(t, err, errRefused)
				assert.Empty(t, h)
			},
		},
		{
			name: "the published challenger sets its challenge",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx,
					func(_ context.Context, w guardauth.HeaderWriter, err error) error {
						w.AddHeader("WWW-Authenticate", "DPoP")

						return err
					})
			},
			assert: func(t *testing.T, h http.Header, err error) {
				require.ErrorIs(t, err, errRefused)
				assert.Equal(t, []string{"DPoP"}, h.Values("WWW-Authenticate"))
			},
		},
		{
			name: "the challenger's error replaces the refusal",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx,
					func(context.Context, guardauth.HeaderWriter, error) error { return errReplaced })
			},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, errReplaced)
			},
		},
		{
			name: "a nil challenger is nothing published",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx, nil)
			},
			assert: func(t *testing.T, h http.Header, err error) {
				require.ErrorIs(t, err, errRefused)
				assert.Empty(t, h)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			h := http.Header{}
			err := guardauth.Challenge(ctx, headers(h), errRefused)
			tc.assert(t, h, err)
		})
	}
}
