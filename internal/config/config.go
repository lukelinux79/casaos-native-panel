package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds runtime and HTTP settings.
type Config struct {
	Mode string
	Host string
	Port int
	// WebDir is the directory with the static UI files.
	WebDir string
	// DataDir holds panel accounts and the audit log.
	DataDir string
	// Integration is "auto" (use CasaOS when it runs on this host) or "off".
	Integration string
	// GatewayPath is where the panel is mounted in the CasaOS gateway.
	GatewayPath string
	// CasaOSRuntimeDir is where CasaOS services publish their addresses.
	CasaOSRuntimeDir string
}

func Load() (Config, error) {
	cfg := Config{
		Mode: getenvDefault("CASAOS_MODE", "system"),
		Host: getenvDefault("CASAOS_HOST", "0.0.0.0"),
		Port: getenvIntDefault("CASAOS_PORT", 8080),

		WebDir:  getenvDefault("CASAOS_WEB_DIR", "web"),
		DataDir: getenvDefault("CASAOS_DATA_DIR", "/var/lib/casaos-native-panel"),

		Integration:      getenvDefault("CASAOS_INTEGRATION", "auto"),
		GatewayPath:      strings.TrimRight(getenvDefault("CASAOS_GATEWAY_PATH", "/panel"), "/"),
		CasaOSRuntimeDir: getenvDefault("CASAOS_RUNTIME_DIR", "/var/run/casaos"),
	}

	if cfg.Integration != "auto" && cfg.Integration != "off" {
		return Config{}, fmt.Errorf("CASAOS_INTEGRATION must be %q or %q", "auto", "off")
	}
	if !strings.HasPrefix(cfg.GatewayPath, "/") || strings.Count(cfg.GatewayPath, "/") != 1 || len(cfg.GatewayPath) < 2 {
		return Config{}, fmt.Errorf("CASAOS_GATEWAY_PATH must look like /panel")
	}
	// The gateway forwards by path prefix; these belong to CasaOS itself.
	for _, reserved := range []string{"/v1", "/v2", "/doc", "/.well-known", "/ping"} {
		if cfg.GatewayPath == reserved {
			return Config{}, fmt.Errorf("CASAOS_GATEWAY_PATH %s is used by CasaOS", reserved)
		}
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
