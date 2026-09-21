//revive:disable:package-comments
package verifying

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key is a verification key, parsed from PEM-encoded PKIX.
type Key struct {
	crypto.PublicKey
}

// UnmarshalText parses the key from its PEM encoding.
func (k *Key) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	if block == nil {
		return errors.New("no PEM block found")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	k.PublicKey = parsed

	return nil
}
