package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
)

// emptyLists is a JSON array holding nothing, which every list column of a stored row holds
// at least.
var emptyLists = []byte("[]")

// scanned fills every byte-slice destination of a row with an empty JSON array, then the
// ones in doc by index, as a database would have scanned them. It requires each index to
// name a byte slice, so a column added before it fails here and not by quietly scanning
// into the wrong one.
func scanned(t *testing.T, dest []any, doc map[int]string) {
	t.Helper()

	for i, d := range dest {
		if b, ok := d.(*[]byte); ok {
			*b = emptyLists
			if raw, set := doc[i]; set {
				*b = []byte(raw)
			}
		}
	}
	for i := range doc {
		require.IsType(t, new([]byte), dest[i], "column %d is a byte slice", i)
	}
}

const (
	// A stored sign-in with every proof key, and with every proof key the wrong type, each
	// value one no log should repeat.
	provenDoc = `{"user":"u-1","second_factor_verified":true,"external_provider":"corp",
		"external_amr":["mfa","hwk"],"external_acr":"urn:corp:loa:2"}`
	hostileMarkerDoc   = `{"user":"u-1","second_factor_verified":"leak-true"}`
	hostileAMRDoc      = `{"user":"u-1","external_amr":"leak-mfa"}`
	hostileAMRItemsDoc = `{"user":"u-1","external_amr":[7654321]}`
	hostileProviderDoc = `{"user":"u-1","external_provider":{"leak":"corp"}}`
	hostileACRDoc      = `{"user":"u-1","external_acr":7654321}`
)

// requireRefusedUnrepeated requires err to be a refusal that repeats none of the stored value.
func requireRefusedUnrepeated(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "leak")
	assert.NotContains(t, err.Error(), "7654321")
}

// TestStoredSignInProof_Decode proves a pending request's and a device authorization's
// sign-in document keeps its proof, and that a document whose proof keys hold the wrong type
// is refused, returns no sign-in and repeats none of it.
func TestStoredSignInProof_Decode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		doc    string
		assert func(t *testing.T, got *oidcprovider.SignIn, err error)
	}

	kept := func(t *testing.T, got *oidcprovider.SignIn, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.SecondFactorVerified)
		assert.Equal(t, "corp", got.ExternalProvider)
		assert.Equal(t, []string{"mfa", "hwk"}, got.ExternalAMR)
		assert.Equal(t, "urn:corp:loa:2", got.ExternalACR)
	}
	refused := func(t *testing.T, got *oidcprovider.SignIn, err error) {
		t.Helper()
		requireRefusedUnrepeated(t, err)
		assert.Nil(t, got, "no sign-in is returned")
	}
	absent := func(t *testing.T, got *oidcprovider.SignIn, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.False(t, got.SecondFactorVerified)
		assert.Empty(t, got.ExternalProvider)
		assert.Nil(t, got.ExternalAMR)
		assert.Empty(t, got.ExternalACR)
	}

	cases := []testCase{
		{name: "a document with its proof keeps it", doc: provenDoc, assert: kept},
		{name: "a document from before the proof reads back with none", doc: `{"user":"u-1"}`, assert: absent},
		{name: "a marker that is text", doc: hostileMarkerDoc, assert: refused},
		{name: "an upstream amr that is text", doc: hostileAMRDoc, assert: refused},
		{name: "an upstream amr of numbers", doc: hostileAMRItemsDoc, assert: refused},
		{name: "a provider that is an object", doc: hostileProviderDoc, assert: refused},
		{name: "an upstream acr that is a number", doc: hostileACRDoc, assert: refused},
	}

	for _, tc := range cases {
		t.Run("pending request/"+tc.name, func(t *testing.T) {
			t.Parallel()

			var row pgschema.PendingRequestRow
			scanned(t, row.Dest(), map[int]string{21: tc.doc})
			rec, err := row.Record()
			if err != nil {
				assert.Nil(t, rec, "no record is returned")
				tc.assert(t, nil, err)

				return
			}
			tc.assert(t, rec.SignIn, nil)
		})

		t.Run("device authorization/"+tc.name, func(t *testing.T) {
			t.Parallel()

			var row pgschema.DeviceRow
			scanned(t, row.Dest(), map[int]string{15: tc.doc})
			rec, err := row.Record()
			if err != nil {
				assert.Nil(t, rec, "no record is returned")
				tc.assert(t, nil, err)

				return
			}
			require.NotNil(t, rec.Approval, "the approving sign-in is read")
			signIn := rec.Approval.SignIn
			tc.assert(t, &signIn, nil)
		})
	}
}

// TestGrantRow_Record_ProofColumns proves a grant row whose proof columns hold what no write
// stores is refused with an error that repeats none of it, and that the columns a write
// stores are read back.
func TestGrantRow_Record_ProofColumns(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		amr    []byte
		assert func(t *testing.T, got *oidcprovider.Grant, err error)
	}

	refused := func(t *testing.T, got *oidcprovider.Grant, err error) {
		t.Helper()
		requireRefusedUnrepeated(t, err)
		assert.Nil(t, got, "no grant is returned")
	}

	cases := []testCase{
		{
			name: "an array is read in order",
			amr:  []byte(`["mfa","hwk"]`),
			assert: func(t *testing.T, got *oidcprovider.Grant, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"mfa", "hwk"}, got.ExternalAMR)
			},
		},
		{
			name: "NULL reads as no evidence",
			amr:  nil,
			assert: func(t *testing.T, got *oidcprovider.Grant, err error) {
				require.NoError(t, err)
				assert.Nil(t, got.ExternalAMR)
			},
		},
		{name: "an object", amr: []byte(`{"leak":"mfa"}`), assert: refused},
		{name: "a number", amr: []byte(`7654321`), assert: refused},
		{name: "text", amr: []byte(`"leak-mfa"`), assert: refused},
		{name: "numbers in an array", amr: []byte(`[7654321]`), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var row pgschema.GrantRow
			dest := row.Dest()
			scanned(t, dest, map[int]string{27: string(tc.amr)})
			if tc.amr == nil {
				*(dest[27].(*[]byte)) = nil
			}
			got, err := row.Record()
			tc.assert(t, got, err)
		})
	}
}
