// Package session keeps an authenticated caller's session between requests.
//
// A Manager mints session identifiers from crypto/rand, holds sessions in a
// Store, and enforces two deadlines: an idle one that activity extends and an
// absolute one that nothing extends. Extending the idle deadline is capped at
// the absolute deadline, so a session in constant use still ends at the hour
// it was always going to end.
//
// The Store contract separates creating a session from saving one, and saving
// only ever updates a session that is still there. A save that could also
// insert turns the ordinary load-then-save of a live request into a way to
// bring back a session another request has just revoked, and it is the
// revocation that loses that race.
//
// State the library owns — the first factor a login used, how far a
// second-factor challenge has got, whether the session came through MFA
// enrolment and which enrolment it began, and whether a password change is
// owed — is kept in fields of the record, never in the consumer's data map.
// That map belongs to the consumer: it is stored and returned unchanged, and
// nothing here reads it, so no key a consumer happens to choose can forge or
// erase a challenge state.
//
// The default store is in-memory and lasts only as long as the process. A
// sealing store wraps any other Store and encrypts the provider token a
// federated session carries, which is the one field of the record that is a
// credential in its own right.
//
// # Wiring
//
// A consumer who wires nothing gets a working manager:
//
//	m, err := session.NewManager()
//
// and a consumer who wires everything replaces each default in place:
//
//	sealing, err := session.NewEncryptedStore(myStore, myCipher)
//	m, err := session.NewManager(
//		session.WithStore(sealing),
//		session.WithIdleTimeout(15*time.Minute),
//		session.WithAbsoluteTimeout(8*time.Hour),
//	)
//
// Cipher is declared here rather than imported, so an implementation shipped
// by another capability satisfies it structurally and neither package has to
// import the other.
package session
