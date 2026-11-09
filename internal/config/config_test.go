package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	cfg := Load()

	if cfg.SSHPort != 2222 {
		t.Errorf("expected default SSHPort 2222, got %d", cfg.SSHPort)
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("expected default HTTPPort 8080, got %d", cfg.HTTPPort)
	}
	if cfg.PostgresPort != 5432 {
		t.Errorf("expected default PostgresPort 5432, got %d", cfg.PostgresPort)
	}
	if cfg.SSHServiceName != "bastion-dev" {
		t.Errorf("expected default SSHServiceName bastion-dev, got %s", cfg.SSHServiceName)
	}
	if cfg.HTTPServiceName != "portal-staging" {
		t.Errorf("expected default HTTPServiceName portal-staging, got %s", cfg.HTTPServiceName)
	}
	if cfg.PostgresServiceName != "postgres-staging" {
		t.Errorf("expected default PostgresServiceName postgres-staging, got %s", cfg.PostgresServiceName)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	os.Setenv("SSH_PORT", "22")
	os.Setenv("HONEYTRAP_HTTP_PORT", "80")
	os.Setenv("HONEYTRAP_SSH_SERVICE", "custom-bastion")
	defer os.Clearenv()

	cfg := Load()
	if cfg.SSHPort != 22 {
		t.Errorf("expected SSHPort 22, got %d", cfg.SSHPort)
	}
	if cfg.HTTPPort != 80 {
		t.Errorf("expected HTTPPort 80, got %d", cfg.HTTPPort)
	}
	if cfg.SSHServiceName != "custom-bastion" {
		t.Errorf("expected SSHServiceName custom-bastion, got %s", cfg.SSHServiceName)
	}
}
