package oidcprovider_test

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// markedIDs mints identifiers that carry a mark no default generator's output has, in order.
type markedIDs struct{ n atomic.Uint64 }

func (m *markedIDs) NewID() (id.ID, error) {
	return id.Parse(fmt.Sprintf("c0ffee00-0000-7000-8000-%012x", m.n.Add(1)))
}

const idMark = "c0ffee00-"

func TestProvider_NamesItsRecordsWithTheConsumersIDGenerator(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t, oidcprovider.WithIDGenerator(&markedIDs{}))
	c := issueOpaque(t, x)

	recordID, _ := handleParts(t, c.parked.handle)
	assert.True(t, strings.HasPrefix(recordID, idMark), "the handle names its record with the consumer's identifier: %s", recordID)

	res, err := x.p.Token(t.Context(), opaqueExchange(c))
	require.NoError(t, err)
	grant := grantOf(t, x, c)
	assert.True(t, strings.HasPrefix(grant.Family.String(), idMark), "the grant family: %s", grant.Family)

	tokenID, _ := opaqueParts(t, res.AccessToken)
	assert.True(t, strings.HasPrefix(tokenID.String(), idMark), "the opaque token: %s", tokenID)
}

func TestNew_RefusesANilIDGenerator(t *testing.T) {
	t.Parallel()

	for name, g := range map[string]id.Generator{"nil": nil, "typed nil": (*markedIDs)(nil)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reg, err := oidcprovider.NewMemoryRegistry(authzClients())
			require.NoError(t, err)
			_, err = oidcprovider.New(oidcprovider.Deps{
				Issuer: issuer, Registry: reg, Keys: newExchangeKeys(t), Users: NewMockUserLoader(gomock.NewController(t)),
				LoginURL: issuer + "/login", ConsentURL: issuer + "/consent",
				LogoutURL: issuer + "/logout", LoggedOutURL: issuer + "/bye",
			}, oidcprovider.WithIDGenerator(g))
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "WithIDGenerator")
		})
	}
}
