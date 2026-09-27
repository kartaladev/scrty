// Package storefix holds the fixtures the durable-store tests of this module
// share: test ciphers and keyrings, records of every store, the races and
// ambient views the durable suites take, out-of-band row reads, the
// configuration assertions, and the re-exec guard that proves a suite catches
// a deliberately broken store.
//
// It lives under internal so only this module's tests import it; the public
// conformance API is package storetest. Everything backend-specific (opening a
// *sql.DB, a pgx pool or a *gorm.DB, attaching a backend's transaction, the
// broken variants themselves) stays in the backend's own test package.
package storefix
