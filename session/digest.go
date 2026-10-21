package session

import "crypto/sha256"

// sessionDigest is the digest a store keeps of a session identifier in place
// of the identifier itself: its SHA-256. A superseded session's
// SuccessorDigest is this digest of its successor's identifier. It is the same
// digest the durable stores key their rows by, which a test pins, so a
// successor digest means the same thing whichever store wrote it.
func sessionDigest(id string) []byte {
	sum := sha256.Sum256([]byte(id))

	return sum[:]
}
