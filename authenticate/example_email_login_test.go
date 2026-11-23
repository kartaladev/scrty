package authenticate_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// directory is a consumer's user store that loads by username and by verified
// email, as identity.EmailLoader asks: ignoring case, verified emails only.
type directory map[string]*identity.Details

func (d directory) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	if u, ok := d[username]; ok {
		return u, nil
	}

	return nil, identity.ErrUserNotFound
}

func (d directory) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	for _, u := range d {
		if u.ID == id {
			return u, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (d directory) LoadByEmail(_ context.Context, email string) (*identity.Details, error) {
	for _, u := range d {
		if u.EmailVerified() && strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

// ExampleWithEmailLogin lets ada log in with her verified email. Without the
// option, which is off by default, the same email is an unknown username.
func ExampleWithEmailLogin() {
	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idMemory(19*1024),
		password.WithArgon2idIterations(2),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	hash, err := enc.Encode("correct-horse-battery-staple")
	if err != nil {
		fmt.Println(err)

		return
	}

	users := directory{"ada": {
		ID:              "u1",
		Username:        "ada",
		Password:        hash,
		Active:          true,
		Email:           "ada@example.com",
		EmailVerifiedAt: time.Date(2024, time.May, 2, 10, 0, 0, 0, time.UTC),
	}}

	login := func(opts ...authenticate.PasswordOption) {
		auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
			append([]authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}, opts...)...)
		if err != nil {
			fmt.Println(err)

			return
		}

		result, err := auth.Authenticate(context.Background(),
			identity.NewUsernamePassword("ADA@example.com", []byte("correct-horse-battery-staple")))
		if err != nil {
			fmt.Println(err)

			return
		}

		fmt.Println("logged in as", result.Principal.Username)
	}

	login()
	login(authenticate.WithEmailLogin())

	// Output:
	// authenticate: authentication failed
	// logged in as ada
}
