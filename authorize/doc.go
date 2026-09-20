// Package authorize decides whether a caller may do what they are asking to do.
//
// A Manager runs ordered authorizers and lets the first one that does not
// decline the attributes decide; when every one declines, the answer is a
// denial rather than an allow by default. Authorizers for the privileges of a
// caller's active role and for ownership of the record being acted on ship
// here, and a consumer adds their own by implementing Authorizer.
//
// Declining to judge and refusing are kept apart, because the manager skips one
// and stops on the other. An authorizer handed a shape of attributes it does
// not handle says so and is passed over; one that recognises the shape but
// cannot use its content refuses, and the chain ends there. Collapsing the two
// would let attributes that are merely malformed fall through to an authorizer
// that was never meant to judge them.
//
// Rules is a rule set generic over the consumer's own request type, for the
// decisions that belong in one place rather than at each operation. A non-empty
// set denies whatever no rule matched, so an operation added without a rule is
// closed rather than open; an empty set makes no central decision at all and
// leaves every operation to the Requirement guarding it. A trailing rule that
// matches everything and permits it is how a consumer opts out of the deny
// default deliberately, in a line that is visible when the set is read.
package authorize
