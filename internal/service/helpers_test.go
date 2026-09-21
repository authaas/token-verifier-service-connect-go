//revive:disable:package-comments
package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"

	"github.com/authaas/token-verifier-service-connect-go/internal/verifying"
)

const algorithm = "EdDSA"

// keyPair generates a signing key and the public half to verify it with.
func keyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return private, public
}

// configuration is the verification material for public under algorithm.
func configuration(public ed25519.PublicKey, algorithm string) verifying.Configuration {
	return verifying.Configuration{PublicKey: verifying.Key{PublicKey: public}, Algorithm: algorithm}
}

// newServer builds a server verifying against public.
func newServer(public ed25519.PublicKey) *Server {
	return New(configuration(public, algorithm))
}

// sign mints a token carrying claims, signed with private.
func sign(t *testing.T, private ed25519.PrivateKey, claims *token.JWT) string {
	t.Helper()

	unsigned := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, (*tokenjwt.Claims)(claims))

	signed, err := unsigned.SignedString(private)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	return signed
}

// claims answers with a token valid right now, which a test then adjusts.
func claims() *token.JWT {
	now := time.Now()

	return &token.JWT{
		Sub: "01234567-89ab-cdef-0123-456789abcdef",
		Iss: "issuer-under-test",
		Aud: []string{"audience-under-test"},
		Iat: now.Unix(),
		Nbf: at(now.Add(-time.Minute)),
		Exp: at(now.Add(time.Hour)),
	}
}

// at answers with a timestamp claim. exp and nbf are optional, so they are
// pointers: absent exp means the token does not expire.
func at(moment time.Time) *int64 {
	seconds := moment.Unix()

	return &seconds
}

// assertCode fails the test unless err is a *connect.Error carrying want.
func assertCode(t *testing.T, err error, want connect.Code) *connect.Error {
	t.Helper()

	if err == nil {
		t.Fatalf("expected %v, got no error", want)
	}

	if got := connect.CodeOf(err); got != want {
		t.Errorf("expected %v, got %v", want, got)
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected a *connect.Error, got %v", err)
	}

	return connectErr
}
