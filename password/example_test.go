package password_test

import (
	"fmt"
	"log"

	"github.com/kartaladev/scrty/password"
)

// The default encoder takes no configuration: Argon2id at the parameters scrty
// considers safe today.
func Example() {
	enc, err := password.NewArgon2idEncoder()
	if err != nil {
		log.Fatal(err)
	}

	stored, err := enc.Encode("correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(enc.Match("correct horse battery staple", stored))
	fmt.Println(enc.Match("Correct horse battery staple", stored))

	// Output:
	// true
	// false
}

// Example_unknownUser shows the decoy pattern. Returning early when the username
// is unknown makes that path faster than a real failed login, and the difference
// is measurable from outside: it tells an attacker which usernames exist. So the
// miss path matches against a decoy instead, and costs the same.
func Example_unknownUser() {
	enc, err := password.NewArgon2idEncoder()
	if err != nil {
		log.Fatal(err)
	}

	// Encoded once at start-up, from a password no user is given.
	decoy, err := enc.Encode("decoy")
	if err != nil {
		log.Fatal(err)
	}

	alice, err := enc.Encode("hunter2")
	if err != nil {
		log.Fatal(err)
	}

	stored := map[string][]byte{"alice": alice}

	authenticate := func(username, presented string) bool {
		hash, found := stored[username]
		if !found {
			// The result is discarded, but the derivation is not skipped.
			_ = enc.Match(presented, decoy)

			return false
		}

		return enc.Match(presented, hash)
	}

	fmt.Println(authenticate("alice", "hunter2"))
	fmt.Println(authenticate("alice", "wrong-password"))
	fmt.Println(authenticate("nobody", "hunter2"))

	// Output:
	// true
	// false
	// false
}
