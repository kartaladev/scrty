package storekit_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/session"
)

func TestOptionalDigest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		digest []byte
		assert func(t *testing.T, got []byte, arg any)
	}

	cases := []testCase{
		{
			name: "nil is none",
			assert: func(t *testing.T, got []byte, arg any) {
				assert.Nil(t, got)
				assert.True(t, arg == nil, "the argument is an untyped nil, got %#v", arg)
			},
		},
		{
			name:   "empty is none",
			digest: []byte{},
			assert: func(t *testing.T, got []byte, arg any) {
				assert.Nil(t, got)
				assert.True(t, arg == nil, "the argument is an untyped nil, got %#v", arg)
			},
		},
		{
			name:   "a digest is kept as given",
			digest: []byte{1, 2, 3},
			assert: func(t *testing.T, got []byte, arg any) {
				assert.Equal(t, []byte{1, 2, 3}, got)
				assert.Equal(t, []byte{1, 2, 3}, arg)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.OptionalDigest(tc.digest), storekit.OptionalDigestArg(tc.digest))
		})
	}
}

func TestNotFoundUnless(t *testing.T) {
	t.Parallel()

	errRead := errors.New("read failed")

	type testCase struct {
		name   string
		exists bool
		err    error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "stored",
			exists: true,
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "not stored",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Same(t, session.ErrNotFound, err, "returned bare")
			},
		},
		{
			name: "the read failed",
			err:  errRead,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errRead)
				assert.Same(t, errRead, err, "returned bare")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.NotFoundUnless(tc.exists, tc.err))
		})
	}
}

func TestSupersedeRefusal(t *testing.T) {
	t.Parallel()

	errNoFamily := errors.New("adapter: supersede session: no family")

	type testCase struct {
		name   string
		cause  int
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:  "missing",
			cause: pgschema.SupersedeRefusalMissing,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Same(t, session.ErrNotFound, err, "returned bare")
			},
		},
		{
			name:  "no family",
			cause: pgschema.SupersedeRefusalNoFamily,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errNoFamily)
				assert.Same(t, errNoFamily, err, "returned bare")
			},
		},
		{
			name:  "successor or supersession",
			cause: pgschema.SupersedeRefusalOther,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrRenewalConflict)
				assert.Same(t, session.ErrRenewalConflict, err, "returned bare")
			},
		},
		{
			name:  "an unknown cause is a conflict",
			cause: 7,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrRenewalConflict)
				assert.Same(t, session.ErrRenewalConflict, err, "returned bare")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.SupersedeRefusal(tc.cause, errNoFamily))
		})
	}
}

func TestPresentationRefusal(t *testing.T) {
	t.Parallel()

	errRead := errors.New("read failed")

	type testCase struct {
		name              string
		exists, supersede bool
		err               error
		assert            func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "presented already",
			exists: true,
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name: "not stored",
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Same(t, session.ErrNotFound, err, "returned bare")
			},
		},
		{
			name:      "superseded",
			exists:    true,
			supersede: true,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrSuperseded)
				assert.Same(t, session.ErrSuperseded, err, "returned bare")
			},
		},
		{
			name:   "the read failed",
			exists: true,
			err:    errRead,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errRead)
				assert.Same(t, errRead, err, "returned bare")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.PresentationRefusal(tc.exists, tc.supersede, tc.err))
		})
	}
}

func TestEncodeSessionData(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		data   map[string]string
		assert func(t *testing.T, got string, err error)
	}

	cases := []testCase{
		{
			name: "nil is an empty object",
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "{}", got)
			},
		},
		{
			name: "empty is an empty object",
			data: map[string]string{},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "{}", got)
			},
		},
		{
			name: "values are kept",
			data: map[string]string{"b": "2", "a": "résumé"},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"a":"résumé","b":"2"}`, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := storekit.EncodeSessionData(tc.data)
			tc.assert(t, got, err)
		})
	}
}

func TestDecodeSessionData(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		raw    string
		assert func(t *testing.T, got map[string]string, err error)
	}

	cases := []testCase{
		{
			name: "an empty object is an empty map",
			raw:  "{}",
			assert: func(t *testing.T, got map[string]string, err error) {
				require.NoError(t, err)
				assert.NotNil(t, got)
				assert.Empty(t, got)
			},
		},
		{
			name: "null is an empty map",
			raw:  "null",
			assert: func(t *testing.T, got map[string]string, err error) {
				require.NoError(t, err)
				assert.NotNil(t, got)
				assert.Empty(t, got)
			},
		},
		{
			name: "values are read back",
			raw:  `{"a":"1","b":"résumé"}`,
			assert: func(t *testing.T, got map[string]string, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"a": "1", "b": "résumé"}, got)
			},
		},
		{
			name: "not an object of strings is encoding/json's error",
			raw:  `{"a":1}`,
			assert: func(t *testing.T, _ map[string]string, err error) {
				var typeErr *json.UnmarshalTypeError
				assert.ErrorAs(t, err, &typeErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := storekit.DecodeSessionData([]byte(tc.raw))
			tc.assert(t, got, err)
		})
	}
}
