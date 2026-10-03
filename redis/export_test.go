package scrtyredis

import "github.com/kartaladev/scrty/internal/unavailable"

// StorageKey exposes storageKey to the external tests.
var StorageKey = storageKey

// DecoratorConfig returns the decorator configuration opts produce.
func DecoratorConfig(opts ...Option) unavailable.Config {
	return newConfig(opts).unavailable
}

// MaxRawKeyLen is the longest key stored as given.
const MaxRawKeyLen = maxRawKeyLen

// CheckVersion exposes checkVersion, the server version floor, to the
// external tests; info is the text of INFO server.
var CheckVersion = checkVersion

// ProbeError exposes probeError, how Verify classifies a failed probe run.
var ProbeError = probeError
