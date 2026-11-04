package oidcprovider

import "github.com/kartaladev/scrty/token/onetime"

// CodeManagerForTest builds the manager of the provider's code tokens, as issuing a code
// does.
func (p *Provider) CodeManagerForTest() (*onetime.Tokens, error) { return p.codeTokens() }
