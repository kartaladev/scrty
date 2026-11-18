// Package prblmsec answers scrty's refusals as RFC 9457 problem details
// through github.com/kartaladev/prblm.
//
// The integration is opt-in: nothing changes until its mapper is registered
// with a prblm handler, for example with prblm.NewHandler(p.Option()) for a
// *Problems built by New. A consumer who never registers it keeps the
// responses the core and the framework adapters give today.
package prblmsec
