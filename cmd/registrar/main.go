// Command registrar submits the honeypot domains to urlscan.io as public scans.
// It runs as a Kubernetes CronJob and exits non-zero when any submission fails.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
	"github.com/k-wa-wa/nuage-honeytrap/internal/registrar"
)

func main() {
	log := logger.DefaultLogger

	if err := run(log); err != nil {
		log.Error("registrar failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
}

func run(log *logger.Logger) error {
	domains, err := registrar.ParseDomains(os.Getenv("REGISTRAR_DOMAINS"))
	if err != nil {
		return fmt.Errorf("REGISTRAR_DOMAINS: %w", err)
	}
	urlscanKey, err := requireEnv("URLSCAN_API_KEY")
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := &http.Client{Timeout: 60 * time.Second}
	runner := &registrar.Runner{
		Submitters: []registrar.Submitter{
			&registrar.URLScan{APIKey: urlscanKey, HTTPClient: client},
		},
		Logger:   log,
		Interval: 10 * time.Second,
	}

	log.Info("registration started", map[string]interface{}{"domains": domains})
	if failures := runner.Run(ctx, domains); failures > 0 {
		return fmt.Errorf("%d submission(s) failed", failures)
	}
	log.Info("registration completed", map[string]interface{}{"domains": domains})
	return nil
}

func requireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is not set", key)
	}
	return v, nil
}
