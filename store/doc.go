// Package store holds the errors of the store contracts that every storage
// backend shares. Each backend's own name for one of them is an alias of the
// value here, so a consumer, or an HTTP chain mapping errors to statuses,
// matches it with errors.Is whichever backend runs, without importing that
// backend's module.
package store
