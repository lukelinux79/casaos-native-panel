package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds runtime and HTTP settings.
type Config struct {
	Mode string
	Host string
	Port int
	// WebDir is the directory with the static UI files.
	WebDir string
}

func Load() (Config, error) {
	cfg := Config{
		Mode: getenvDefault("CASAOS_MODE", "system"),
		Host: getenvDefault("CASAOS_HOST", "0.0.0.0"),
		Port: getenvIntDefault("CASAOS_PORT", 8080),

		WebDir: getenvDefault("CASAOS_WEB_DIR", "web"),
	}

	if cfg.Mode != "system" && cfg.Mode != "docker" {
		return Config{}, fmt.Errorf("unsupported mode %q: choose %q or %q", cfg.Mode, "system", "docker")
	}

	return cfg, nil
}

func getenvDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getenvIntDefault(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
