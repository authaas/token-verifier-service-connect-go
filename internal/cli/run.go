//revive:disable:package-comments
package cli

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/caarlos0/env/v11"

	grpcdclient "github.com/grpcd/connect-client/client"
	connectserver "github.com/pbrpc/connect-server"
	"github.com/pbrpc/connect-service/diagnostics"
	"github.com/pbrpc/connect-service/health"
	service_lib "github.com/pbrpc/connect-service/service"
	transport "github.com/pbrpc/http-transport"
	"github.com/pbrpc/lifecycle"
	pbrpcotel "github.com/pbrpc/otel"
	svc "github.com/pbrpc/service"

	"github.com/authaas/token-verifier-service-bindings-connect-go/token/verifier/verifierconnect"
	"github.com/authaas/token-verifier-service-connect-go/internal/service"
	"github.com/authaas/token-verifier-service-connect-go/internal/verifying"
)

// cleanupTimeout bounds stopping the server and flushing telemetry, together
const cleanupTimeout = 5 * time.Second

// Run serves until a signal arrives or serving fails, and answers with the
// process exit code.
func Run() int {
	ctx := context.Background()

	serveCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	svcCfg := svc.Configuration{Name: "token-verifier"}
	if err := env.Parse(&svcCfg); err != nil {
		slog.Default().Error("Failed to read configuration", slog.Any("error", err))
		return 1
	}

	stack := lifecycle.Stack{}

	log, flush, err := pbrpcotel.Init(ctx, svcCfg.Name, svcCfg.Version)
	if err != nil {
		slog.Default().Error("Failed to initialize telemetry", slog.Any("error", err))
		return 1
	}
	stack.Push(lifecycle.Logged(log, "telemetry", flush))

	host, err := connectserver.FromEnv(log)
	if err != nil {
		log.Error("Failed to create connect server", slog.Any("error", err))
		return 1
	}
	stack.Push(lifecycle.Logged(log, "server", host.HTTPHost.Server.Shutdown))

	defer lifecycle.HandleGracefulShutdown(ctx, log, &stack, cleanupTimeout)

	// Nothing is verified without the key, so a verification configuration
	// that does not parse is a startup failure.
	verifyingCfg, err := env.ParseAs[verifying.Configuration]()
	if err != nil {
		log.Error("Could not read verification configuration", slog.Any("error", err))
		return 1
	}

	server := service.New(verifyingCfg)

	configured, err := env.ParseAsWithOptions[grpcdclient.Configuration](
		env.Options{RequiredIfNoDef: true})
	if err != nil {
		log.Error("Could not read configuration", slog.Any("error", err))
		return 1
	}

	base, err := transport.From(nil)
	if err != nil {
		log.Error("Could not build transport", slog.Any("error", err))
		return 1
	}
	conn := grpcdclient.Connect(configured.GRPCDAddress, base)

	checks := diagnostics.Checks{grpcdclient.CheckName: grpcdclient.Check(conn)}

	methodList, err := service_lib.Register(
		host.Server,
		host.HTTPHost.Mux,
		health.NewServer(),
		checks,
		func(rpc *connect.Server) {
			verifierconnect.RegisterServiceHandler(rpc, server)
		},
	)
	if err != nil {
		log.Error("Failed to register services", slog.Any("error", err))
		return 1
	}

	lis, err := net.Listen("tcp", svcCfg.Address)
	if err != nil {
		log.Error("Failed to create listener", slog.Any("error", err))
		return 1
	}

	log = log.With(slog.String("address", lis.Addr().String()))

	// Register holds the stream open; its ending is what removes the rows, so
	// there is no deregistration to wait for here.
	go grpcdclient.New(log, svcCfg.Name, lis.Addr(), methodList, conn).Register(serveCtx)

	serveErr := make(chan error, 1)
	go func() { serveErr <- host.Serve(lis) }()

	log.Info("Connect server listening")

	select {
	case err := <-serveErr:
		if err != nil {
			log.Error("Failed to serve", slog.Any("error", err))
			return 1
		}
	case <-serveCtx.Done():
	}

	return 0
}
