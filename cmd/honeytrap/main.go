package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/config"
	"github.com/k-wa-wa/nuage-honeytrap/internal/enricher"
	"github.com/k-wa-wa/nuage-honeytrap/internal/honeypot"
	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func main() {
	log := logger.DefaultLogger

	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration loading failed", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	// Initialize ASN Enricher if MMDB path is provided
	if cfg.ASNMMDBPath != "" {
		asnEnricher, err := enricher.New(cfg.ASNMMDBPath)
		if err != nil {
			log.Info("ASN enrichment disabled", map[string]interface{}{
				"reason": err.Error(),
				"path":   cfg.ASNMMDBPath,
			})
		} else if asnEnricher != nil {
			log.SetEnricher(asnEnricher)
			defer asnEnricher.Close()
			log.Info("ASN enrichment enabled", map[string]interface{}{
				"path": cfg.ASNMMDBPath,
			})
		}
	}

	log.Info("starting nuage-honeytrap", map[string]interface{}{
		"ssh_bind_port":        cfg.SSHPort,
		"http_bind_port":       cfg.HTTPPort,
		"postgres_bind_port":   cfg.PostgresPort,
		"ssh_public_port":      cfg.SSHPublicPort,
		"http_public_port":     cfg.HTTPPublicPort,
		"postgres_public_port": cfg.PostgresPublicPort,
		"max_connections":      cfg.MaxConnections,
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
