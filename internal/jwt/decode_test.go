//revive:disable:package-comments
package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"
)

const algorithm = "EdDSA"

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

func TestDecode(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	expires := time.Now().Add(time.Hour).Unix()

	t.Run("answers with the claims a valid token carries", func(t *testing.T) {
		want := &token.JWT{Sub: "subject", Iss: "issuer", Exp: &expires}

		got, err := Decode(sign(t, private, want), public, algorithm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got.GetSub() != want.GetSub() {
			t.Errorf("expected sub %q, got %q", want.GetSub(), got.GetSub())
		}
	})

	t.Run("refuses a token signed with another key", func(t *testing.T) {
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		signed := sign(t, other, &token.JWT{Sub: "subject", Exp: &expires})

		if _, err := Decode(signed, public, algorithm); err == nil {
			t.Fatal("expected a signature failure")
		}
	})

	t.Run("refuses a token whose header names another algorithm", func(t *testing.T) {
		claims := (*tokenjwt.Claims)(&token.JWT{Sub: "subject", Exp: &expires})

		signed, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString([]byte("shared secret"))
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		if _, err := Decode(signed, public, algorithm); err == nil {
			t.Fatal("expected the configured algorithm to be the only one accepted")
		}
	})
}
