package onetime_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/onetime"
)

// TestCheckedCannotBeConstructedOutsideThePackage pins the one thing that makes
// check-then-consume a rule the compiler keeps rather than one a caller has to
// remember. Every field of Checked is unexported and nothing but Check returns
// one, so there is no spelling of "spend this token" that skips the check.
func TestCheckedCannotBeConstructedOutsideThePackage(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(onetime.Checked{})
	require.Positive(t, typ.NumField(),
		"Checked carries nothing, so it proves nothing about what was checked")

	for i := range typ.NumField() {
		field := typ.Field(i)
		assert.False(t, field.IsExported(),
			"Checked.%s is exported, so a caller can build one and consume without checking", field.Name)
	}
}
