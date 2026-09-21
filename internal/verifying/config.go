//revive:disable:package-comments
package verifying

// Configuration is the material a token is verified with.
type Configuration struct {
	// PublicKey matches the issuer's signing key. This service holds no
	// private key and mints nothing.
	PublicKey Key `env:"TOKEN_PUBLIC_KEY,required"`

	// Algorithm names the method to verify with. The token header's own alg is
	// never read: the header is covered by the signature, so a token whose
	// header was altered fails against this value.
	Algorithm string `env:"TOKEN_SIGNING_ALG,required"`
}
