package httpsec

// ThrottledSignInsOf is how many requests for the stream a throttled sign-in was answered with only a
// retry.
func ThrottledSignInsOf(c *Chain) uint64 { return c.SessionSignalStats().Throttled }
