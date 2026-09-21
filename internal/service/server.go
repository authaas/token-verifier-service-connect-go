//revive:disable:package-comments
package service

import (
	"github.com/authaas/token-verifier-service-bindings-connect-go/token/verifier/verifierconnect"
	"github.com/authaas/token-verifier-service-connect-go/internal/verifying"
)

// Server serves token.verifier.Service.
//
// It holds no signing key and produces no tokens. It reads and writes no store
// and keeps no state between requests: an answer depends on the token
// presented, the key it is configured with, and the clock.
type Server struct {
	verifierconnect.UnimplementedServiceHandler

	verifying verifying.Configuration
}

// New returns a Server verifying with verifying.
func New(verifying verifying.Configuration) *Server {
	return &Server{verifying: verifying}
}
