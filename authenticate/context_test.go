package authenticate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
)

func TestAuthenticationContext(t *testing.T) {
	t.Parallel()

	t.Run("round trips", func(t *testing.T) {
		t.Parallel()

		want := &authenticate.Authentication{Principal: principal(t)}

		got, ok := authenticate.AuthenticationFromContext(
			authenticate.WithAuthentication(t.Context(), want))
		require.True(t, ok)
		assert.Same(t, want, got)
	})

	t.Run("reports absence rather than a zero value", func(t *testing.T) {
		t.Parallel()

		got, ok := authenticate.AuthenticationFromContext(t.Context())
		assert.False(t, ok)
		assert.Nil(t, got, "a caller that ignores ok must not get a usable empty principal")
	})

	t.Run("an attached nil reports absence rather than handing over a nil to dereference", func(t *testing.T) {
		t.Parallel()

		got, ok := authenticate.AuthenticationFromContext(
			authenticate.WithAuthentication(t.Context(), nil))
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}
