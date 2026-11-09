package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SSHPort != 2222 {
		t.Errorf("expected default SSHPort 2222, got %d", cfg.SSHPort)
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("expected default HTTPPort 8080, got %d", cfg.HTTPPort)
	}
	if cfg.PostgresPort != 5432 {
		t.Errorf("expected default PostgresPort 5432, got %d", cfg.PostgresPort)
	}
	if cfg.SSHPublicPort != 22 {
		t.Errorf("expected default SSHPublicPort 22, got %d", cfg.SSHPublicPort)
	}
	if cfg.HTTPPublicPort != 80 {
		t.Errorf("expected default HTTPPublicPort 80, got %d", cfg.HTTPPublicPort)
	}
	if cfg.PostgresPublicPort != 5432 {
		t.Errorf("expected default PostgresPublicPort 5432, got %d", cfg.PostgresPublicPort)
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
	if cfg.MaxConnections != 100 {
		t.Errorf("expected default MaxConnections 100, got %d", cfg.MaxConnections)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	os.Clearenv()
	os.Setenv("HONEYTRAP_SSH_PORT", "22222")
	os.Setenv("HONEYTRAP_HTTP_PORT", "8000")
	os.Setenv("HONEYTRAP_SSH_PUBLIC_PORT", "2200")
	os.Setenv("HONEYTRAP_SSH_SERVICE", "custom-bastion")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SSHPort != 22222 {
		t.Errorf("expected SSHPort 22222, got %d", cfg.SSHPort)
	}
	if cfg.HTTPPort != 8000 {
		t.Errorf("expected HTTPPort 8000, got %d", cfg.HTTPPort)
	}
	if cfg.SSHPublicPort != 2200 {
		t.Errorf("expected SSHPublicPort 2200, got %d", cfg.SSHPublicPort)
	}
	if cfg.SSHServiceName != "custom-bastion" {
		t.Errorf("expected SSHServiceName custom-bastion, got %s", cfg.SSHServiceName)
	}
}

func TestLoadInvalidEnvErrors(t *testing.T) {
	tests := []struct {
		key string
		val string
	}{
		{"HONEYTRAP_SSH_PORT", "abc"},
		{"HONEYTRAP_HTTP_PORT", "0"},
		{"HONEYTRAP_POSTGRES_PORT", "70000"},
		{"HONEYTRAP_SSH_PUBLIC_PORT", "-1"},
		{"HONEYTRAP_MAX_CONNECTIONS", "invalid"},
		{"HONEYTRAP_MAX_CONNECTIONS", "0"},
	}

	for _, tt := range tests {
		os.Clearenv()
		os.Setenv(tt.key, tt.val)
		_, err := Load()
		if err == nil {
			t.Errorf("expected error when %s=%q, but got nil", tt.key, tt.val)
		}
	}
	os.Clearenv()
}

func TestIgnoresK8sServiceEnvVars(t *testing.T) {
	os.Clearenv()
	// In k8s, services create environment variables like SSH_PORT="tcp://10.96.0.1:22"
	os.Setenv("SSH_PORT", "tcp://10.96.0.1:22")
	os.Setenv("HTTP_PORT", "tcp://10.96.0.1:80")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected k8s service env vars to be ignored, got error: %v", err)
	}
	if cfg.SSHPort != 2222 {
		t.Errorf("expected SSHPort 2222, got %d", cfg.SSHPort)
	}
}
