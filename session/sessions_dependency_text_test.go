package session_test

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessions_DependencyErrorTextIsFixed pins that an error from the
// consumer's random reader or family generator reaches the caller behind the
// library's own text, the dependency's error still reachable by identity. It
// runs every site of randomSites.
func TestSessions_DependencyErrorTextIsFixed(t *testing.T) {
	cause := errors.New("hsm slot u-123 offline")

	for _, site := range randomSites() {
		t.Run(site.name, func(t *testing.T) {
			got := site.run(t, t.Context(), slog.New(slog.DiscardHandler), cause)

			require.Error(t, got)
			assert.False(t, strings.Contains(got.Error(), "u-123"), "text leaks the dependency: %q", got.Error())
			assert.ErrorIs(t, got, cause)
		})
	}
}
