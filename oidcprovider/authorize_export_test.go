package oidcprovider

import (
	"context"
	"errors"
	"net/url"
)

// ConsentNeededForTest decides as the login stage's resume does.
func ConsentNeededForTest(c *RegisteredClient, req *PendingRequest, remembered *Consent) bool {
	return consentNeeded(c, req, remembered)
}

// ValidateForTest answers with the protocol code of validation's refusal, if any, and
// the subject of the hint it accepted. It calls nothing a row could have failing.
func (p *Provider) ValidateForTest(ctx context.Context, params url.Values) (code, subject string) {
	req, _, err := p.validate(ctx, params)
	if err != nil {
		var refusal *redirectRefusal
		if errors.As(err, &refusal) {
			return refusal.code, ""
		}

		return "unexpected: " + err.Error(), ""
	}

	return "", req.IDTokenHintSubject
}
