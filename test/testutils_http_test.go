package test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOKServer starts a server that answers 200, closed when t ends.
func newOKServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// getReusing sends GET url with client under ctx, reads the body to its end
// and reports whether the request reused an existing connection.
func getReusing(ctx context.Context, t *testing.T, client *http.Client, url string) bool {
	t.Helper()

	var reused bool
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	return reused
}

func TestHTTPClientsKeepTheirConnectionsWhenAnotherServerCloses(t *testing.T) {
	tests := []struct {
		name   string
		client func(t *testing.T) *http.Client
	}{
		{name: "keycloak browser", client: keycloakBrowser},
		{name: "smtp message API", client: smtpAPIClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			own, other := newOKServer(t), newOKServer(t)
			client := tt.client(t)
			get := func() bool { return getReusing(t.Context(), t, client, own.URL) }

			get()
			other.Close()
			reused := get()

			assert.True(t, reused, "the second request to its own server opened a new connection after another server closed")
		})
	}
}

func TestHTTPClientsReleaseTheirConnectionsWhenTheirTestEnds(t *testing.T) {
	tests := []struct {
		name   string
		client func(t *testing.T) *http.Client
	}{
		{name: "keycloak browser", client: keycloakBrowser},
		{name: "smtp message API", client: smtpAPIClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			own := newOKServer(t)
			var client *http.Client
			t.Run("build", func(t *testing.T) {
				client = tt.client(t)
				getReusing(t.Context(), t, client, own.URL)
			})

			reused := getReusing(t.Context(), t, client, own.URL)

			assert.False(t, reused, "the client kept a connection after the test that built it ended")
		})
	}
}
