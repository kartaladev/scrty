package apikey_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/apikey"
)

// TestKeyCarriesNoSecret pins the one property of the record that no later
// change may quietly undo: a leaked store must yield nothing that
// authenticates. A field named for the secret itself is refused; a field whose
// name mentions a secret may only be a digest of one.
func TestKeyCarriesNoSecret(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeFor[apikey.Key]()

	for i := range rt.NumField() {
		name := strings.ToLower(rt.Field(i).Name)

		assert.NotEqual(t, "secret", name, "the record must never hold the secret itself")

		if strings.Contains(name, "secret") {
			assert.Contains(t, name, "digest",
				"a secret-ish field may only be a digest, got %s", rt.Field(i).Name)
		}
	}
}
