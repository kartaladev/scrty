package httpsec

import (
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/policy"
)

//go:generate mockgen -destination=federatedassurancesource_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy FederatedAssuranceSource
//go:generate mockgen -destination=assuranceevaluator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidc AssuranceEvaluator

// mintFederated is the evidence of the assurance provider asserted for a
// login: the only place in this package that mints it.
//
// It is called with values the library itself wrote, and with nothing else:
// the handoff record a redemption check is handed (oidc.RedeemCandidate),
// which the callback wrote from the verified ID token, and a session's
// library-owned fields (session.Session.FederatedAMR and FederatedACR, beside
// its ExternalProvider and ExternalIssuer) on every request. Never a value
// read from a request, a header, a claim or consumer data. An empty provider
// mints the zero evidence, which asserts nothing.
func mintFederated(provider, issuer string, amr []string, acr string) policy.FederatedAssurance {
	return assurance.NewFederated(provider, issuer, amr, acr)
}
