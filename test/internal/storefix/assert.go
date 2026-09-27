package storefix

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cancelled is a table's ctx modifier for a case whose context is already
// cancelled.
func Cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// RefusedConfig asserts a constructor refused its configuration with
// errConfig, whose text is prefix, ": invalid configuration: " and exactly
// text, and returned no store.
func RefusedConfig[S any](errConfig error, prefix, text string) func(t *testing.T, s S, err error) {
	return func(t *testing.T, s S, err error) {
		t.Helper()
		require.ErrorIs(t, err, errConfig)
		assert.EqualError(t, err, prefix+": invalid configuration: "+text)
		assert.Nil(t, s)
	}
}

// AcceptedConfig asserts a constructor returned a store.
func AcceptedConfig[S any](t *testing.T, s S, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.NotNil(t, s)
}

// ErrorTexts is the text of err and of every error it wraps.
func ErrorTexts(err error) []string {
	if err == nil {
		return nil
	}

	texts := []string{err.Error()}
	switch u := err.(type) { //nolint:errorlint // walking the tree itself
	case interface{ Unwrap() error }:
		texts = append(texts, ErrorTexts(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			texts = append(texts, ErrorTexts(e)...)
		}
	}

	return texts
}

// AssertNamesOnly requires some error in err's tree to name field, and none
// to carry any of values.
func AssertNamesOnly(t *testing.T, err error, field string, values ...string) {
	t.Helper()

	texts := ErrorTexts(err)
	assert.True(t, slices.ContainsFunc(texts, func(text string) bool { return strings.Contains(text, field) }),
		"no error names %q: %q", field, texts)
	for _, text := range texts {
		for _, v := range values {
			assert.NotContains(t, text, v, "an error carries a value")
		}
	}
}
