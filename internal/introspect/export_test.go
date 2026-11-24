package introspect

// SetJoinHook makes c call f each time a caller has joined the shared call,
// before it waits for the answer. It must be set before c is used.
func SetJoinHook(c *Client, f func()) { c.joined = f }
