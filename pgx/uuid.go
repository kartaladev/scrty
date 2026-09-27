package pgx

import (
	"errors"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kartaladev/scrty/pkg/id"
)

// uuidArg is v as a statement argument for a uuid column: its canonical text,
// which pgx encodes for a uuid parameter, as the database/sql stores send it.
func uuidArg(v id.ID) any { return v.String() }

// scanID is the identifier a uuid column held, scanned through pgtype.UUID. A
// NULL is an error: every uuid column the stores read is NOT NULL, and the
// zero identifier must never stand in for a missing one.
func scanID(u pgtype.UUID) (id.ID, error) {
	if !u.Valid {
		return id.Nil, errors.New("pgx: a uuid column held NULL")
	}

	return id.ID(u.Bytes), nil
}
