package storetest_test

import (
	"testing"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/test/storetest"
)

// TestMemory runs the provider's in-memory defaults through their suites.
func TestMemory(t *testing.T) {
	t.Parallel()

	t.Run("PendingRequests", func(t *testing.T) {
		t.Parallel()
		storetest.PendingRequestSuite(t, func(*testing.T) oidcprovider.PendingRequestStore {
			return must.Must(oidcprovider.NewMemoryPendingRequestStore())
		})
	})

	t.Run("CodeRecords", func(t *testing.T) {
		t.Parallel()
		storetest.CodeRecordSuite(t, func(*testing.T) oidcprovider.CodeStore {
			return must.Must(oidcprovider.NewMemoryCodeStore())
		})
	})

	t.Run("Consents", func(t *testing.T) {
		t.Parallel()
		storetest.ConsentSuite(t, func(*testing.T) oidcprovider.ConsentStore {
			return must.Must(oidcprovider.NewMemoryConsentStore())
		})
	})

	t.Run("Grants", func(t *testing.T) {
		t.Parallel()
		storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore {
			return must.Must(oidcprovider.NewMemoryGrantStore())
		})
	})
}
