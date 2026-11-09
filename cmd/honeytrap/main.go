package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/config"
	"github.com/k-wa-wa/nuage-honeytrap/internal/honeypot"
	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func main() {
	cfg := config.Load()
	log := logger.DefaultLogger

	log.Info("starting nuage-honeytrap", map[string]interface{}{
		"ssh_port":      cfg.SSHPort,
		"http_port":     cfg.HTTPPort,
		"postgres_port": cfg.PostgresPort,
	})

	mgr, err := honeypot.NewManager(cfg, log)
	if err != nil {
		log.Error("failed to initialize honeypot manager", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	if err := mgr.Start(); err != nil {
		log.Error("failed to start honeypot manager", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Info("received termination signal", map[string]interface{}{
		"signal": sig.String(),
	})

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := mgr.Stop(shutdownCtx); err != nil {
		log.Error("error during graceful shutdown", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	log.Info("nuage-honeytrap shutdown complete", nil)
}
