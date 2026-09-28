package sqlstore

import (
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// column is one users column an update writes, and the value it binds.
type column struct {
	name  string
	value any
}

// userColumns is the users columns an update writes for the fields u names,
// in a fixed order. Column names come only from this allow-list, never from
// input. A field is written when it was named, whatever its value, and left
// alone otherwise. The email has no column and writes nothing; the roles are
// written by the grant rebuild. The password-changed-at time is its own
// field: naming the password alone never writes it.
func userColumns(u *identity.NewUser, org any) []column {
	var set []column
	if u.IsSet(identity.FieldName) {
		set = append(set, column{"name", u.Name})
	}
	if u.IsSet(identity.FieldPassword) {
		set = append(set, column{"password", storekit.OrEmpty(u.Password)})
	}
	if u.IsSet(identity.FieldOrganization) {
		set = append(set, column{"organization_id", org})
	}
	if u.IsSet(identity.FieldPasswordChangedAt) {
		set = append(set, column{"password_changed_at", nullTs(u.PasswordChangedAt)})
	}

	return set
}

// updateUserQuery is the partial UPDATE of user userID writing set and
// updated_at, with its arguments.
func updateUserQuery(set []column, now time.Time, userID id.ID) (string, []any) {
	var b strings.Builder
	args := make([]any, 0, len(set)+2)

	b.WriteString("UPDATE users SET ")
	for _, c := range set {
		args = append(args, c.value)
		b.WriteString(c.name + " = $" + strconv.Itoa(len(args)) + ", ")
	}
	args = append(args, now)
	b.WriteString("updated_at = $" + strconv.Itoa(len(args)))
	args = append(args, userID)
	b.WriteString(" WHERE id = $" + strconv.Itoa(len(args)))

	return b.String(), args
}
