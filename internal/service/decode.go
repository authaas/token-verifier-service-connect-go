//revive:disable:package-comments
package service

import (
	"context"

	pbrpcerrors "github.com/pbrpc/connect-errors"

	"buf.build/gen/go/authaas/token-verifier-service/protocolbuffers/go/token/verifier"
	"git.sonicoriginal.software/logger"

	"github.com/authaas/token-verifier-service-connect-go/internal/jwt"
)

// Decode verifies a token and answers with the claims it carries.
//
// Nothing about aud is enforced. A consumer knows which audience names it and
// this service does not, so the value is answered as carried and the consumer
// compares.
func (s *Server) Decode(
	ctx context.Context,
	req *verifier.DecodeRequest,
) (*verifier.DecodeResponse, error) {
	log := logger.FromContext(ctx)

	if req.GetToken() == "" {
		return nil, pbrpcerrors.InvalidArgument(ctx, "validation failed",
			pbrpcerrors.FieldViolation{Field: "token", Description: "is required"})
	}

	claims, err := jwt.Decode(
		req.GetToken(),
		s.verifying.PublicKey.PublicKey,
		s.verifying.Algorithm,
	)
	if err != nil {
		return nil, refuse(ctx, err)
	}

	log.InfoContext(ctx, "Token decoded",
		"iss", claims.GetIss(), "sub", claims.GetSub(), "aud", claims.GetAud(),
		"iat", claims.GetIat(), "exp", claims.GetExp(), "nbf", claims.GetNbf(),
	)

	return verifier.DecodeResponse_builder{Token: claims}.Build(), nil
}
