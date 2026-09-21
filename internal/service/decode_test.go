//revive:disable:package-comments
package service

import (
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token-verifier-service/protocolbuffers/go/token/verifier"
	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"
)

// request builds a DecodeRequest presenting signed.
func request(signed string) *verifier.DecodeRequest {
	return verifier.DecodeRequest_builder{Token: signed}.Build()
}

func TestDecode(t *testing.T) {
	t.Run("answers with the claims the token carries", func(t *testing.T) {
		private, public := keyPair(t)

		want := claims()

		response, err := newServer(public).Decode(t.Context(), request(sign(t, private, want)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		got := response.GetToken()

		if got.GetSub() != want.GetSub() {
			t.Errorf("expected sub %q, got %q", want.GetSub(), got.GetSub())
		}

		if got.GetIss() != want.GetIss() {
			t.Errorf("expected iss %q, got %q", want.GetIss(), got.GetIss())
		}

		if got.GetExp() != want.GetExp() {
			t.Errorf("expected exp %d, got %d", want.GetExp(), got.GetExp())
		}
	})

	t.Run("answers with aud as carried and compares nothing", func(t *testing.T) {
		private, public := keyPair(t)

		want := claims()
		want.Aud = []string{"someone-else", "and-another"}

		response, err := newServer(public).Decode(t.Context(), request(sign(t, private, want)))
		if err != nil {
			t.Fatalf("expected an audience this service does not name to verify, got %v", err)
		}

		if got := response.GetToken().GetAud(); !slices.Equal(got, want.GetAud()) {
			t.Errorf("expected %v, got %v", want.GetAud(), got)
		}
	})

	t.Run("verifies a token carrying no exp", func(t *testing.T) {
		private, public := keyPair(t)

		want := claims()
		want.Exp = nil

		response, err := newServer(public).Decode(t.Context(), request(sign(t, private, want)))
		if err != nil {
			t.Fatalf("expected a token with no exp to verify, got %v", err)
		}

		if response.GetToken().HasExp() {
			t.Errorf("expected no exp, got %d", response.GetToken().GetExp())
		}
	})

	t.Run("refuses an expired token", func(t *testing.T) {
		private, public := keyPair(t)

		expired := claims()
		expired.Exp = at(time.Now().Add(-time.Second))

		_, err := newServer(public).Decode(t.Context(), request(sign(t, private, expired)))

		if got := assertCode(t, err, connect.CodeInvalidArgument); got.Message() != "token has expired" {
			t.Errorf("expected the refusal to name expiry, got %q", got.Message())
		}
	})

	t.Run("refuses a token whose nbf has not arrived", func(t *testing.T) {
		private, public := keyPair(t)

		early := claims()
		early.Nbf = at(time.Now().Add(time.Hour))

		_, err := newServer(public).Decode(t.Context(), request(sign(t, private, early)))

		got := assertCode(t, err, connect.CodeInvalidArgument)
		if got.Message() != "token is not valid yet" {
			t.Errorf("expected the refusal to name nbf, got %q", got.Message())
		}
	})

	t.Run("refuses a token signed with another key", func(t *testing.T) {
		private, _ := keyPair(t)
		_, public := keyPair(t)

		_, err := newServer(public).Decode(t.Context(), request(sign(t, private, claims())))

		got := assertCode(t, err, connect.CodeInvalidArgument)
		if got.Message() != "token signature does not verify" {
			t.Errorf("expected the refusal to name the signature, got %q", got.Message())
		}
	})

	t.Run("refuses a token whose header names another algorithm", func(t *testing.T) {
		_, public := keyPair(t)

		// Configured for EdDSA while the token says HS256, which is the
		// substitution that reading the header's alg would allow.
		unsigned := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, (*tokenjwt.Claims)(claims()))

		signed, err := unsigned.SignedString([]byte("shared secret"))
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		_, err = newServer(public).Decode(t.Context(), request(signed))

		got := assertCode(t, err, connect.CodeInvalidArgument)
		if got.Message() != "token signature does not verify" {
			t.Errorf("expected the refusal to name the signature, got %q", got.Message())
		}
	})

	t.Run("refuses a malformed token", func(t *testing.T) {
		_, public := keyPair(t)

		_, err := newServer(public).Decode(t.Context(), request("not-a-token"))

		got := assertCode(t, err, connect.CodeInvalidArgument)
		if got.Message() != "token is malformed" {
			t.Errorf("expected the refusal to name malformation, got %q", got.Message())
		}
	})

	t.Run("refuses an empty token", func(t *testing.T) {
		_, public := keyPair(t)

		_, err := newServer(public).Decode(t.Context(), request(""))

		assertCode(t, err, connect.CodeInvalidArgument)
	})

	t.Run("refuses a token the library rejects for another reason", func(t *testing.T) {
		private, public := keyPair(t)

		// An algorithm the configured key cannot verify makes the library
		// report an unverifiable token rather than any of the named checks.
		server := New(configuration(public, "RS256"))

		_, err := server.Decode(t.Context(), request(sign(t, private, &token.JWT{Sub: "subject"})))

		assertCode(t, err, connect.CodeInvalidArgument)
	})
}
