package honeypot

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/config"
	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func TestManagerLifecycle(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(&buf)

	cfg := &config.Config{
		SSHPort:             0,
		HTTPPort:            0,
		PostgresPort:        0,
		SSHServiceName:      "ssh-test",
		HTTPServiceName:     "http-test",
		PostgresServiceName: "pg-test",
	}

	mgr, err := NewManager(cfg, log)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := mgr.Stop(ctx); err != nil {
		t.Fatalf("failed to stop manager: %v", err)
	}
}
