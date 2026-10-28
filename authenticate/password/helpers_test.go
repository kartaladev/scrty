package password_test

import "time"

// Memory is configured in KiB, so these are the sizes the floors talk about.
const (
	mib19  = 19 * 1024
	mib46  = 46 * 1024
	mib128 = 128 * 1024
)

// fastMatch is how long a record above a ceiling may take to be refused. The
// refusal derives nothing, so anything near it means a key was derived.
const fastMatch = 100 * time.Millisecond
