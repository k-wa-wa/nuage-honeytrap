package config

import (
	"os"
	"strconv"
)

// Config holds the configuration parameters for nuage-honeytrap.
type Config struct {
	SSHPort             int
	HTTPPort            int
	PostgresPort        int
	SSHServiceName      string
	HTTPServiceName     string
	PostgresServiceName string
}

// Load loads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		SSHPort:             getEnvInt("HONEYTRAP_SSH_PORT", "SSH_PORT", 2222),
		HTTPPort:            getEnvInt("HONEYTRAP_HTTP_PORT", "HTTP_PORT", 8080),
		PostgresPort:        getEnvInt("HONEYTRAP_POSTGRES_PORT", "POSTGRES_PORT", 5432),
		SSHServiceName:      getEnvString("HONEYTRAP_SSH_SERVICE", "bastion-dev"),
		HTTPServiceName:     getEnvString("HONEYTRAP_HTTP_SERVICE", "portal-staging"),
		PostgresServiceName: getEnvString("HONEYTRAP_POSTGRES_SERVICE", "postgres-staging"),
	}
}

func getEnvString(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(primaryKey, fallbackKey string, fallback int) int {
	if val := os.Getenv(primaryKey); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	if fallbackKey != "" {
		if val := os.Getenv(fallbackKey); val != "" {
			if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 65535 {
				return n
			}
		}
	}
	return fallback
}
