// Package oidcprovider makes an application embedding scrty an OpenID Provider
// for its own other applications.
//
// It holds the protocol's domain logic and has no HTTP framework dependency.
// Its endpoints live in httpsec, which imports this package and never the
// reverse.
package oidcprovider
