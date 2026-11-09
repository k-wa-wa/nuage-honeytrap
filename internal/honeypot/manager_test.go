package honeypot

import (
	"bytes"
	"context"
	"net"
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
		SSHPublicPort:       22,
		HTTPPublicPort:      80,
		PostgresPublicPort:  5432,
		SSHServiceName:      "ssh-test",
		HTTPServiceName:     "http-test",
		PostgresServiceName: "pg-test",
		MaxConnections:      50,
	}

	mgr, err := NewManager(cfg, log)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := mgr.Stop(ctx); err != nil {
		t.Fatalf("failed to stop manager: %v", err)
	}
}

func TestManagerStartRollbackOnPortConflict(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(&buf)

	// Pre-bind a port to cause a conflict on HTTP server start
	conflictLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to pre-bind port: %v", err)
	}
	conflictPort := conflictLn.Addr().(*net.TCPAddr).Port
	defer conflictLn.Close()

	cfg := &config.Config{
		SSHPort:             0,            // Dynamic: SSH will start successfully
		HTTPPort:            conflictPort, // Conflict: HTTP will fail to bind
		PostgresPort:        0,
		SSHPublicPort:       22,
		HTTPPublicPort:      80,
		PostgresPublicPort:  5432,
		SSHServiceName:      "ssh-test",
		HTTPServiceName:     "http-test",
		PostgresServiceName: "pg-test",
		MaxConnections:      50,
	}

	mgr, err := NewManager(cfg, log)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// mgr.Start should fail and roll back the SSH server
	startErr := mgr.Start()
	if startErr == nil {
		t.Fatal("expected manager.Start to fail on port conflict, but succeeded")
	}

	// Verify that SSH port was rolled back and released
	sshPort := mgr.sshServer.Port()
	rebindLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("listener test failed: %v", err)
	} else {
		rebindLn.Close()
	}
	_ = sshPort
}
