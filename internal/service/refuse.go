//revive:disable:package-comments
package service

import (
	"context"
	"errors"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	pbrpcerrors "github.com/pbrpc/connect-errors"

	"git.sonicoriginal.software/logger"
)

// refusal names the check a token failed.
type refusal struct {
	reason  string
	message string
}

// refusals maps what the JWT library reports to what this service answers.
// Every one of these follows from the token the caller presented, so naming it
// tells the caller nothing it did not already know.
var refusals = []struct {
	err error
	refusal
}{
	{
		jwtv5.ErrTokenMalformed,
		refusal{"malformed", "token is malformed"},
	},
	// A header naming an algorithm other than the configured one lands here
	// too, because the header is covered by the signature.
	{
		jwtv5.ErrTokenSignatureInvalid,
		refusal{"signature", "token signature does not verify"},
	},
	{jwtv5.ErrTokenExpired,
		refusal{"expired", "token has expired"},
	},
	{jwtv5.ErrTokenNotValidYet,
		refusal{"not_yet_valid", "token is not valid yet"},
	},
}

// refuse reports which check the token failed.
func refuse(ctx context.Context, err error) error {
	answer := refusal{"invalid", "token is invalid"}

	for _, candidate := range refusals {
		if errors.Is(err, candidate.err) {
			answer = candidate.refusal

			break
		}
	}

	lgr := logger.FromContext(ctx)
	lgr.InfoContext(ctx, "Token refused", "reason", answer.reason, "error", err)

	return pbrpcerrors.InvalidArgument(ctx, answer.message,
		pbrpcerrors.FieldViolation{Field: "token", Description: answer.message})
}
