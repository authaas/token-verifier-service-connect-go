// The token verifier service: token.verifier.Service served with connect-go.
package main

import (
	"os"

	"github.com/authaas/token-verifier-service-connect-go/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
