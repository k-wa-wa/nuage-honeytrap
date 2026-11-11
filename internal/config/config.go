package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the configuration parameters for nuage-honeytrap.
type Config struct {
	SSHPort             int
	HTTPPort            int
	PostgresPort        int
	SSHPublicPort       int
	HTTPPublicPort      int
	PostgresPublicPort  int
	SSHServiceName      string
	HTTPServiceName     string
	PostgresServiceName string
	MaxConnections      int
	ASNMMDBPath         string
}

// Load loads and validates configuration from environment variables.
func Load() (*Config, error) {
	sshPort, err := parsePortEnv("HONEYTRAP_SSH_PORT", 2222)
	if err != nil {
		return nil, err
	}
	httpPort, err := parsePortEnv("HONEYTRAP_HTTP_PORT", 8080)
	if err != nil {
		return nil, err
	}
	pgPort, err := parsePortEnv("HONEYTRAP_POSTGRES_PORT", 5432)
	if err != nil {
		return nil, err
	}

	sshPubPort, err := parsePortEnv("HONEYTRAP_SSH_PUBLIC_PORT", 22)
	if err != nil {
		return nil, err
	}
	httpPubPort, err := parsePortEnv("HONEYTRAP_HTTP_PUBLIC_PORT", 80)
	if err != nil {
		return nil, err
	}
	pgPubPort, err := parsePortEnv("HONEYTRAP_POSTGRES_PUBLIC_PORT", 5432)
	if err != nil {
		return nil, err
	}

	maxConns, err := parseIntEnv("HONEYTRAP_MAX_CONNECTIONS", 100, 1, 10000)
	if err != nil {
		return nil, err
	}

	return &Config{
		SSHPort:             sshPort,
		HTTPPort:            httpPort,
		PostgresPort:        pgPort,
		SSHPublicPort:       sshPubPort,
		HTTPPublicPort:      httpPubPort,
		PostgresPublicPort:  pgPubPort,
		SSHServiceName:      getEnvString("HONEYTRAP_SSH_SERVICE", "bastion-dev"),
		HTTPServiceName:     getEnvString("HONEYTRAP_HTTP_SERVICE", "portal-staging"),
		PostgresServiceName: getEnvString("HONEYTRAP_POSTGRES_SERVICE", "postgres-staging"),
		MaxConnections:      maxConns,
		ASNMMDBPath:         getEnvString("HONEYTRAP_ASN_MMDB_PATH", "/etc/GeoLite2-ASN.mmdb"),
	}, nil
}

func getEnvString(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func parsePortEnv(key string, fallback int) (int, error) {
	return parseIntEnv(key, fallback, 1, 65535)
}

func parseIntEnv(key string, fallback, minVal, maxVal int) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %q must be an integer: %w", key, val, err)
	}
	if n < minVal || n > maxVal {
		return 0, fmt.Errorf("invalid value for %s: %d is out of range [%d, %d]", key, n, minVal, maxVal)
	}
	return n, nil
}
