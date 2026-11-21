package password_test

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/outbound"
)

// hostileTransport fails every round trip with a chain that cannot be walked.
type hostileTransport struct{}

func (hostileTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &hostileCycleOne{}
}

func transportAborts(h *recordingHandler) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := 0

	for _, r := range h.records {
		if r.message == porterr.MsgClassificationAborted {
			n++
		}
	}

	return n
}

// TestPwnedPasswords_HostileTransportRecordsOnThePolicyLogger pins that the abort
// record of a hostile transport error under PwnedPasswords goes to the policy's
// logger, exactly once, and not to slog.Default(). It replaces the default
// logger, so it does not run in parallel.
func TestPwnedPasswords_HostileTransportRecordsOnThePolicyLogger(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	def := &recordingHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(def))
	t.Cleanup(func() { slog.SetDefault(previous) })

	client, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: hostileTransport{}}))
	require.NoError(t, err)

	consumer := &recordingHandler{}
	p, err := password.NewPolicy(
		password.WithPolicyLogger(slog.New(consumer)),
		password.Breached(password.PwnedPasswords(client), password.Accept))
	require.NoError(t, err)

	require.NoError(t, p.Check(t.Context(), checkUser(), breachCandidate))

	assert.Equal(t, 1, transportAborts(consumer), "one abort record on the policy's logger")
	assert.Zero(t, transportAborts(def), "none on slog.Default()")
}
