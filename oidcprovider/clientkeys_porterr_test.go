package oidcprovider_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
)

// ckLockedBuffer is a buffer safe for a logger's concurrent writes.
type ckLockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *ckLockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *ckLockedBuffer) aborts() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return strings.Count(b.buf.String(), porterr.MsgClassificationAborted)
}

// ckHostileTransport fails every round trip with a chain that cannot be walked.
type ckHostileTransport struct{}

func (ckHostileTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &pe7bCycleOne{}
}

// TestClientKeySets_HostileTransportRecordsOnTheProviderLogger pins that the abort
// record of a hostile error from the client-keys fetch's transport lands once on
// the provider's logger and none on slog.Default(), and that the fetch is still an
// outage. It replaces the default logger, so it does not run in parallel.
func TestClientKeySets_HostileTransportRecordsOnTheProviderLogger(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	def := &ckLockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(def, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	own := &ckLockedBuffer{}
	f := newKeysFixture(t, keysOptions{
		outbound: func(*keysFixture) []outbound.Option {
			return []outbound.Option{outbound.WithHTTPClient(&http.Client{Transport: ckHostileTransport{}})}
		},
		provider: []oidcprovider.Option{oidcprovider.WithLogger(slog.New(slog.NewJSONHandler(own, nil)))},
	})

	f.mustFailDependency(keyClientID, esKid)

	assert.Equal(t, 1, own.aborts(), "one abort record on the provider's logger")
	assert.Zero(t, def.aborts(), "none on slog.Default()")
	require.NotNil(t, f.provider)
}
