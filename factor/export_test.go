package factor

// AllKinds is every kind the const block names, in declaration order.
//
// Go cannot enumerate a string-const type, so this list is the enumeration the
// tests walk: TestKind asserts its table has a row for every entry, and
// TestSecondFactorChannels checks the authenticator-app property against the
// same list rather than restating the vocabulary a third time.
//
// It lives here, in an _test.go file of the package itself, rather than in
// factor.go: a production var read only by tests is an unused variable, and
// rather than suppress that, the list sits where its only readers are. Being in
// package factor, it still names the constants directly, and it reaches no
// consumer's build.
var AllKinds = []Kind{Password, MagicLink, OIDC, Basic, APIKey, Recovery}
