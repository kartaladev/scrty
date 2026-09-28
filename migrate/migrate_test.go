package migrate_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/migrate"
)

// TestIdentitySet pins the identity set's directory, its version table and
// the shape of its embedded files: exactly one goose-annotated SQL file, and
// no foreign key anywhere (the identity migration set is independent of
// security state).
func TestIdentitySet(t *testing.T) {
	t.Parallel()

	set := migrate.Identity()

	assert.Equal(t, "identity", set.Dir)
	assert.Equal(t, "goose_identity", migrate.IdentityVersionTable)
	assert.Equal(t, "goose_identity", set.VersionTable)

	sub, err := fs.Sub(set.FS(), set.Dir)
	require.NoError(t, err)

	entries, err := fs.ReadDir(sub, ".")
	require.NoError(t, err)
	require.Len(t, entries, 1, "the identity set has exactly one migration file")

	name := entries[0].Name()
	assert.True(t, strings.HasSuffix(name, ".sql"), "file %s", name)

	data, err := fs.ReadFile(sub, name)
	require.NoError(t, err)
	content := string(data)

	assert.Contains(t, content, "-- +goose Up")
	assert.Contains(t, content, "-- +goose Down")

	upper := strings.ToUpper(content)
	assert.NotContains(t, upper, "REFERENCES", "no identity table declares a foreign key")
	assert.NotContains(t, upper, "FOREIGN KEY", "no identity table declares a foreign key")
}

// TestSecurityStateFilesAvoidNoTransactionAnnotation walks the embedded
// security-state set and fails when any file contains a line goose's
// migration parser would honour as its annotation for opting a migration out
// of its own transaction. Goose parses every comment line for annotations, so
// a failed migration in this set must never be able to leave partial changes
// behind — not even from a comment.
func TestSecurityStateFilesAvoidNoTransactionAnnotation(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	sub, err := fs.Sub(set.FS(), set.Dir)
	require.NoError(t, err)

	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(sub, path)
		require.NoError(t, err)
		assert.False(t, containsNoTransactionAnnotation(string(data)), "file %s", path)
		return nil
	})
	require.NoError(t, err)
}

// containsNoTransactionAnnotation reports whether content has a line that
// goose v3's migration parser (internal/sqlparser, ParseSQLMigration and
// extractAnnotation, github.com/pressly/goose/v3@v3.28.0) would honour as
// goose's no-transaction annotation: the one that opts a migration out of its
// own transaction.
//
// It mirrors goose's own normalisation line by line, without importing goose
// (this module must not depend on it): a line is a candidate only when its
// trimmed form starts with "--" and the raw line contains "+goose". Goose
// then rejects any candidate whose raw line has leading whitespace before the
// "--" — that line fails to parse as any annotation at all, rather than being
// silently ignored. For the remaining candidates, goose strips every "--" and
// the first "+goose", trims what is left, and compares it case-insensitively
// (strings.EqualFold) against the annotation's keyword. Trailing or leading text
// beyond that — a longer comment sharing the line — makes goose reject the
// line as an unsupported annotation instead of honouring it, so this helper
// reports false for those too.
//
// The annotation's text is built by concatenation, and never written out in
// these comments, so this test file itself never contains it.
func containsNoTransactionAnnotation(content string) bool {
	marker := "+goose"
	target := "NO" + " " + "TRANSACTION"

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") || !strings.Contains(line, marker) {
			continue
		}
		// Goose rejects a raw line with leading whitespace before the dash;
		// it never reaches annotation recognition, so it is not honoured.
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}

		cmd := strings.ReplaceAll(line, "--", "")
		cmd = strings.Replace(cmd, marker, "", 1)
		cmd = strings.TrimSpace(cmd)

		if strings.EqualFold(cmd, target) {
			return true
		}
	}
	return false
}

// TestContainsNoTransactionAnnotation pins containsNoTransactionAnnotation
// against goose's real parsing rule with the case, spacing and stray-text
// variations a migration author could plausibly write.
func TestContainsNoTransactionAnnotation(t *testing.T) {
	t.Parallel()

	dash, marker := "--", "+goose"
	noun := "NO" + " " + "TRANSACTION"

	type testCase struct {
		name    string
		content string
		assert  func(t *testing.T, got bool)
	}

	cases := []testCase{
		{
			name:    "exact uppercase annotation is honoured",
			content: dash + " " + marker + " " + noun + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "lowercase annotation is honoured",
			content: dash + " " + marker + " " + strings.ToLower(noun) + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "mixed case annotation is honoured",
			content: dash + " " + marker + " " + "No" + " " + "TransACTion" + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "extra spaces around the marker are honoured",
			content: dash + "   " + marker + "   " + noun + "   " + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "leading whitespace before the dash is not honoured",
			content: "  " + dash + " " + marker + " " + noun + "\n",
			assert: func(t *testing.T, got bool) {
				assert.False(t, got)
			},
		},
		{
			name:    "trailing text sharing the annotation line is not honoured",
			content: dash + " " + marker + " " + noun + " for the index build only" + "\n",
			assert: func(t *testing.T, got bool) {
				assert.False(t, got)
			},
		},
		{
			name:    "a CRLF-terminated annotation line is honoured",
			content: dash + " " + marker + " " + noun + "\r\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "the marker directly after the dash is honoured",
			content: dash + marker + " " + noun + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "a tab between the dash and the marker is honoured",
			content: dash + "\t" + marker + " " + noun + "\n",
			assert: func(t *testing.T, got bool) {
				assert.True(t, got)
			},
		},
		{
			name:    "a leading tab before the dash is not honoured",
			content: "\t" + dash + " " + marker + " " + noun + "\n",
			assert: func(t *testing.T, got bool) {
				assert.False(t, got)
			},
		},
		{
			name:    "plain SQL without the annotation",
			content: "CREATE TABLE example (id int);\n",
			assert: func(t *testing.T, got bool) {
				assert.False(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := containsNoTransactionAnnotation(tc.content)
			tc.assert(t, got)
		})
	}
}
