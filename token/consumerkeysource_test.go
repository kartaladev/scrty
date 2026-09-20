package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// consumerKeySourceFile is this file, and josePath is the import prefix every
// part of the JOSE stack shares, so one check covers jwk, jws, jwa and jwt at
// whatever major version this module happens to be on.
const (
	consumerKeySourceFile = "consumerkeysource_test.go"
	josePath              = "lestrrat-go/jwx"
)

// externalKeySource is the shape a consumer's own key source takes: one key,
// no KeyManager anywhere, and deliberately no LifetimeReporter, so a source
// that cannot report its lifetimes gets no lifetime cap.
//
// It is hand-written rather than generated because the tests need it to sign
// real tokens, which a mock cannot do. It sits in a file of its own for what
// that file does not import — see TestConsumerKeySourceNeedsNoJOSEImport — so
// nothing else's need for the JOSE stack can be mistaken for this one's.
type externalKeySource struct {
	kid    string
	signer crypto.Signer
	public crypto.PublicKey
}

// externalKeySource is a complete implementation of the port, asserted here so
// that a change to KeySource fails at this line rather than somewhere in the
// tests that use it.
var _ signingkey.KeySource = (*externalKeySource)(nil)

func (s *externalKeySource) GetSigner(alg signingkey.Alg) (string, crypto.Signer, bool) {
	if alg != signingkey.RS256 {
		return "", nil, false
	}

	return s.kid, s.signer, true
}

func (s *externalKeySource) VerificationKeys() ([]signingkey.PublicKey, error) {
	return []signingkey.PublicKey{{
		Kid: s.kid,
		Alg: signingkey.RS256,
		Key: s.public,
	}}, nil
}

func newExternalKeySource(t *testing.T) *externalKeySource {
	t.Helper()

	// 2048 is the smallest size the JOSE stack accepts for RS256.
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return &externalKeySource{
		kid:    "consumer-owned-key-1",
		signer: private,
		public: private.Public(),
	}
}

// TestConsumerKeySourceNeedsNoJOSEImport pins the promise that makes
// signingkey.KeySource implementable by anyone: a key travels as its
// identifier, this capability's own algorithm name and a crypto.PublicKey, so
// nothing obliges a consumer to import the JOSE stack — at the major version
// this module happens to be pinned to — into a key service that has no use for
// it, and a major bump here never reaches their code.
//
// Running the source cannot show that. TestConsumerSuppliedKeySource issues
// and verifies real tokens with externalKeySource, and would go on passing if
// implementing it had taken a JWK or a jwa.SignatureAlgorithm. So the claim is
// read off the source instead: this file carries the whole implementation and
// nothing else, which is what makes an import it gains an import the
// implementation needed.
//
// The other half of the promise — that the port itself names no JOSE type — is
// pinned in signingkey by TestNoExportedSymbolExposesAJOSEType. A port that
// regained one would stop this file compiling, and a build failure names
// nothing, so the check that reports the breach belongs where the surface is.
func TestConsumerKeySourceNeedsNoJOSEImport(t *testing.T) {
	t.Parallel()

	fset := gotoken.NewFileSet()

	file, err := parser.ParseFile(fset, consumerKeySourceFile, nil, parser.SkipObjectResolution)
	require.NoError(t, err, "parsing %s", consumerKeySourceFile)

	// The implementation has to still be here. Were it moved out, every import
	// below would be someone else's and the check would pass over a file that
	// proves nothing.
	require.True(t, declaresExternalKeySource(file),
		"%s no longer declares externalKeySource, so its imports say nothing "+
			"about what implementing the port takes", consumerKeySourceFile)

	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.Contains(path, josePath) {
			continue
		}

		t.Errorf(
			"%s:%d: imports %s; a consumer's key source describes its keys with "+
				"crypto types and signingkey.Alg, so implementing the port must "+
				"never require the JOSE stack — move whatever needs it to a file "+
				"that is not the implementation",
			consumerKeySourceFile, fset.Position(spec.Pos()).Line, path)
	}
}

// declaresExternalKeySource reports whether file still declares the consumer
// implementation the guard above is written about.
func declaresExternalKeySource(file *ast.File) bool {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != gotoken.TYPE {
			continue
		}

		for _, spec := range gen.Specs {
			if typ, isType := spec.(*ast.TypeSpec); isType && typ.Name.Name == "externalKeySource" {
				return true
			}
		}
	}

	return false
}
