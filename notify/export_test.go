package notify

// Build and NormalizeCRLF expose the message encoder to the external test
// package, so what reaches DATA can be pinned without a server in between.
var (
	Build         = build
	NormalizeCRLF = normalizeCRLF
)
