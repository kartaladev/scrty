package test_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCProvider_DeviceCodeAcrossReplicas holds two providers built with the same user-code
// key over one durable device store, as two replicas behind a load balancer are: a code issued
// by one is entered and claimed through the other, and the device then collects its tokens
// from the first.
func TestOIDCProvider_DeviceCodeAcrossReplicas(t *testing.T) {
	t.Parallel()

	for _, a := range opAdapters {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()

			e := newDevE2EReplicas(t, a.name, 2)
			// Replica 0 issues the codes.
			e.active.Store(0)
			da, err := e.conf.DeviceAuth(e.oauthCtx)
			require.NoError(t, err)
			require.NotEmpty(t, da.UserCode)

			// Replica 1 receives the entry and the approval: the digest of the code it
			// computes must be the one replica 0 stored.
			e.active.Store(1)
			e.approve(t, da.UserCode)

			// Replica 0 answers the device's poll with tokens.
			e.active.Store(0)
			tokCtx, cancel := context.WithTimeout(e.oauthCtx, 30*time.Second)
			defer cancel()
			tok, err := e.conf.DeviceAccessToken(tokCtx, da)
			require.NoError(t, err)
			assert.NotEmpty(t, tok.AccessToken)

			// And the code is spent on every replica.
			e.active.Store(1)
			status, code := e.pollRaw(t, da.DeviceCode)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "invalid_grant", code)
		})
	}
}
