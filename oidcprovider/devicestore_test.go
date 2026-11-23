package oidcprovider_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

// The generated mock stands in for the port wherever a test needs a store's answer
// scripted, such as a refusal the memory store never gives.
func TestDeviceStoreMock_Compiles(t *testing.T) {
	t.Parallel()

	mock := NewMockDeviceAuthorizationStore(gomock.NewController(t))
	now := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	mock.EXPECT().Create(gomock.Any(), gomock.Any(), now).Return(oidcprovider.ErrUserCodeTaken)

	var store oidcprovider.DeviceAuthorizationStore = mock
	err := store.Create(t.Context(), &oidcprovider.DeviceAuthorization{}, now)
	require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken)
}

func TestWithDeviceAuthorizationStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts builds the provider's options around the mock store given.
		opts   func(mock oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option
		assert func(t *testing.T, mock oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error)
	}

	key := oidcprovider.WithUserCodeKey(bytes.Repeat([]byte{7}, oidcprovider.MinUserCodeKeyBytes))
	device := func(opts ...oidcprovider.DeviceOption) []oidcprovider.Option {
		return []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer+"/activate", opts...)}
	}
	refused := func(option string) func(*testing.T, oidcprovider.DeviceAuthorizationStore, *oidcprovider.Provider, error) {
		return func(t *testing.T, _ oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, option)
			assert.Nil(t, p)
		}
	}
	usesMock := func(t *testing.T, mock oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Same(t, mock, p.DeviceStoreForTest(), "the store given is the one used")
	}
	memory := oidcprovider.NewMemoryDeviceAuthorizationStore()

	cases := []testCase{
		{
			name: "a memory store is the default when the grant is enabled",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option { return device() },
			assert: func(t *testing.T, _ oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.IsType(t, &oidcprovider.MemoryDeviceAuthorizationStore{}, p.DeviceStoreForTest())
			},
		},
		{
			name: "no store when the grant is off",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option { return nil },
			assert: func(t *testing.T, _ oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Nil(t, p.DeviceStoreForTest())
			},
		},
		{
			name: "a consumer's store with a user-code key replaces the default",
			opts: func(mock oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(mock), key)
			},
			assert: usesMock,
		},
		{
			name: "a consumer's store without a user-code key is refused, as it is durable",
			opts: func(mock oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(mock))
			},
			assert: refused("WithUserCodeKey"),
		},
		{
			name: "a memory store given explicitly needs no key",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(memory))
			},
			assert: func(t *testing.T, _ oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, memory, p.DeviceStoreForTest())
			},
		},
		{
			name: "a nil store is refused",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(nil), key)
			},
			assert: refused("WithDeviceAuthorizationStore"),
		},
		{
			name: "a typed nil memory store is refused",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore((*oidcprovider.MemoryDeviceAuthorizationStore)(nil)))
			},
			assert: refused("WithDeviceAuthorizationStore"),
		},
		{
			name: "a typed nil consumer's store is refused",
			opts: func(oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore((*MockDeviceAuthorizationStore)(nil)), key)
			},
			assert: refused("WithDeviceAuthorizationStore"),
		},
		{
			name: "given twice, the last store wins",
			opts: func(mock oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(memory), oidcprovider.WithDeviceAuthorizationStore(mock), key)
			},
			assert: usesMock,
		},
		{
			name: "given twice, a last memory store needs no key",
			opts: func(mock oidcprovider.DeviceAuthorizationStore) []oidcprovider.Option {
				return device(oidcprovider.WithDeviceAuthorizationStore(mock), oidcprovider.WithDeviceAuthorizationStore(memory))
			},
			assert: func(t *testing.T, _ oidcprovider.DeviceAuthorizationStore, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, memory, p.DeviceStoreForTest())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The mock expects no call: New must not touch the store.
			mock := NewMockDeviceAuthorizationStore(gomock.NewController(t))
			p, err := oidcprovider.New(validDeps(t), tc.opts(mock)...)
			tc.assert(t, mock, p, err)
		})
	}
}
