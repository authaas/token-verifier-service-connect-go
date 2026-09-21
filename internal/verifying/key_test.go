//revive:disable:package-comments
package verifying

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/caarlos0/env/v11"
)

// publicKeyPEM generates a key and answers with the public half's PEM
// encoding.
func publicKeyPEM(t *testing.T) string {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestKey(t *testing.T) {
	t.Run("parses the configured key", func(t *testing.T) {
		t.Setenv("TOKEN_PUBLIC_KEY", publicKeyPEM(t))
		t.Setenv("TOKEN_SIGNING_ALG", "EdDSA")

		cfg, err := env.ParseAs[Configuration]()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := cfg.PublicKey.PublicKey.(ed25519.PublicKey); !ok {
			t.Errorf("key = %T, want ed25519.PublicKey", cfg.PublicKey.PublicKey)
		}
	})

	t.Run("refuses a key that is not PEM", func(t *testing.T) {
		var key Key

		if err := key.UnmarshalText([]byte("not a pem block")); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("refuses a PEM block that is not a public key", func(t *testing.T) {
		var key Key

		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nonsense")})

		if err := key.UnmarshalText(block); err == nil {
			t.Error("expected an error")
		}
	})
}
