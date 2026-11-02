package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy_DefaultsBundledCommonList(t *testing.T) {
	t.Parallel()

	list := bundledCommonPasswords()
	require.GreaterOrEqual(t, len(list), 3000, "the bundled list holds at least 3,000 entries")
	assert.NotContains(t, list, "", "a blank line is no entry")

	_, ok := list["password"]
	assert.True(t, ok, "entries are kept lower-cased")
}
