package honeypot

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/config"
	"github.com/k-wa-wa/nuage-honeytrap/internal/honeypot/http"
	"github.com/k-wa-wa/nuage-honeytrap/internal/honeypot/postgres"
	"github.com/k-wa-wa/nuage-honeytrap/internal/honeypot/ssh"
	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

// Manager coordinates all protocol honeypot servers.
type Manager struct {
	cfg            *config.Config
	logger         *logger.Logger
	sshServer      *ssh.Server
	httpServer     *http.Server
	postgresServer *postgres.Server
}

// NewManager creates a Manager instance with configured protocol servers.
func NewManager(cfg *config.Config, log *logger.Logger) (*Manager, error) {
	if log == nil {
		log = logger.DefaultLogger
	}

	sshSrv, err := ssh.NewServer(ssh.Config{
		Port:           cfg.SSHPort,
		PublicPort:     cfg.SSHPublicPort,
		ServiceName:    cfg.SSHServiceName,
		Logger:         log,
		MaxConnections: cfg.MaxConnections,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ssh honeypot: %w", err)
	}

	httpSrv := http.NewServer(http.Config{
		Port:           cfg.HTTPPort,
		PublicPort:     cfg.HTTPPublicPort,
		ServiceName:    cfg.HTTPServiceName,
		Logger:         log,
		MaxConnections: cfg.MaxConnections,
	})

	pgSrv := postgres.NewServer(postgres.Config{
		Port:           cfg.PostgresPort,
		PublicPort:     cfg.PostgresPublicPort,
		ServiceName:    cfg.PostgresServiceName,
		Logger:         log,
		MaxConnections: cfg.MaxConnections,
	})

	return &Manager{
		cfg:            cfg,
		logger:         log,
		sshServer:      sshSrv,
		httpServer:     httpSrv,
		postgresServer: pgSrv,
	}, nil
}

// Start starts all honeypot protocol servers. If any server fails to start,
// previously started servers are stopped to prevent leaked listeners.
func (m *Manager) Start() error {
	if err := m.sshServer.Start(); err != nil {
		return fmt.Errorf("failed to start ssh server: %w", err)
	}

	if err := m.httpServer.Start(); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = m.sshServer.Stop(ctx)
		return fmt.Errorf("failed to start http server: %w", err)
	}

	if err := m.postgresServer.Start(); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = m.httpServer.Stop(ctx)
		_ = m.sshServer.Stop(ctx)
		return fmt.Errorf("failed to start postgres server: %w", err)
	}

	m.logger.Info("nuage-honeytrap initialized and running", map[string]interface{}{
		"ssh_bind_port":        m.sshServer.Port(),
		"http_bind_port":       m.httpServer.Port(),
		"postgres_bind_port":   m.postgresServer.Port(),
		"ssh_public_port":      m.cfg.SSHPublicPort,
		"http_public_port":     m.cfg.HTTPPublicPort,
		"postgres_public_port": m.cfg.PostgresPublicPort,
	})
	return nil
}

// Stop shuts down all honeypot protocol servers concurrently.
func (m *Manager) Stop(ctx context.Context) error {
	m.logger.Info("shutting down nuage-honeytrap", nil)

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := m.sshServer.Stop(ctx); err != nil {
			errCh <- fmt.Errorf("ssh shutdown error: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := m.httpServer.Stop(ctx); err != nil {
			errCh <- fmt.Errorf("http shutdown error: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := m.postgresServer.Stop(ctx); err != nil {
			errCh <- fmt.Errorf("postgres shutdown error: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
