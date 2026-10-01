package passkey

// WithEmailCodeCompare replaces the constant-time comparison of an emailed
// code, so a test can count how many presented codes are compared.
func WithEmailCodeCompare(fn func(stored, presented string) bool) Option {
	return func(m *Manager) { m.compare = fn }
}
