//revive:disable:package-comments
package jwt

import (
	"crypto"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"
)

// Decode verifies a token against publicKey using algorithm, and answers with
// the claims it carries.
//
// Only algorithm is accepted. The token header's own alg is never consulted,
// so a token whose header was altered fails here rather than being verified
// with whatever it asked for.
//
// exp and nbf are checked against the clock. A token carrying no exp does not
// expire, which is what a JWT with the claim absent means. No leeway is
// allowed: the answer depends on the token, the key, and the clock.
func Decode(
	tokenString string,
	publicKey crypto.PublicKey,
	algorithm string,
) (*token.JWT, error) {
	claims := &tokenjwt.Claims{}

	_, err := jwtv5.ParseWithClaims(
		tokenString,
		claims,
		func(*jwtv5.Token) (any, error) { return publicKey, nil },
		jwtv5.WithValidMethods([]string{algorithm}),
	)
	if err != nil {
		return nil, err
	}

	return (*token.JWT)(claims), nil
}
