package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"os"
)

type Config struct {
	Enabled  bool
	Username string
	Password string
}

// LoadFromEnv requires both CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD.
// The panel runs as root and can create users or rewrite smb.conf, so running
// without login must be requested explicitly with CASAOS_AUTH_DISABLED=true.
func LoadFromEnv() (Config, error) {
	username := os.Getenv("CASAOS_ADMIN_USER")
	password := os.Getenv("CASAOS_ADMIN_PASSWORD")

	if username == "" && password == "" {
		if os.Getenv("CASAOS_AUTH_DISABLED") == "true" {
			return Config{Enabled: false}, nil
		}
		return Config{}, errors.New("set CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD (or CASAOS_AUTH_DISABLED=true for local testing only)")
	}
	if username == "" || password == "" {
		return Config{}, errors.New("both CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD must be set")
	}
	if len(password) < 8 {
		return Config{}, errors.New("CASAOS_ADMIN_PASSWORD must be at least 8 characters")
	}
	return Config{Enabled: true, Username: username, Password: password}, nil
}

// Check compares credentials in constant time.
func (c Config) Check(username, password string) bool {
	u1, u2 := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(c.Username))
	p1, p2 := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(c.Password))
	userOK := subtle.ConstantTimeCompare(u1[:], u2[:])
	passOK := subtle.ConstantTimeCompare(p1[:], p2[:])
	return userOK&passOK == 1
}
