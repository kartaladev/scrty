package admin_test

import "github.com/kartaladev/scrty/authenticate/password"

//go:generate mockgen -source=limitedencoder_test.go -destination=limitedencoder_mock_test.go -package=admin_test -typed

// limitedEncoder is a password encoder that states its input limit, as the
// bcrypt encoder does; its mock lets a test see whether Encode is reached.
//
// The interface itself is referenced only by the generated mock's source.
type limitedEncoder interface { //nolint:unused // the mockgen source of MocklimitedEncoder
	password.Encoder
	password.InputLimiter
}
