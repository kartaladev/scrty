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

// nullableID is the identifier a nullable uuid column held: id.Nil for NULL.
func nullableID(u pgtype.UUID) id.ID {
	if !u.Valid {
		return id.Nil
	}

	return id.ID(u.Bytes)
}

// nullID is v as bound to a nullable uuid column or compared with one: NULL
// for the nil identifier, otherwise uuidArg(v). The nil identifier sent as its
// text is the all-zero UUID, which "generation = $n" would match on a row
// stored with that value; NULL matches nothing.
func nullID(v id.ID) any {
	if v.IsZero() {
		return nil
	}

	return uuidArg(v)
}
