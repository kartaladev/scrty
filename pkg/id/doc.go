// Package id provides sortable identifiers for the records scrty owns.
//
// An ID is 16 bytes. Its text form is the lowercase RFC 9562 layout
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, and Parse accepts exactly that
// layout in either letter case. IDs encode to JSON as strings and to SQL
// as canonical text; Scan also reads 16-byte binary and rejects NULL.
//
// NewV7Generator is the default Generator. It produces RFC 9562 version 7
// identifiers that strictly increase for a given generator, including within
// one millisecond, across goroutines and when the clock moves backwards.
// Components that create records accept any Generator, so a consumer can
// replace it.
//
// Identifiers are not secrets. They embed a timestamp and a partly
// predictable counter, so never use one as a credential, session token or
// link secret. Store creation times in their own columns: a burst above
// 2^25 identifiers in one millisecond borrows future timestamps.
package id
