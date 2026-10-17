package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ReloadError means smb.conf was written successfully but smbd could not be
// reloaded, so the change is not active yet.
type ReloadError struct{ Err error }

func (e *ReloadError) Error() string {
	return "smb.conf saved, but smbd could not be reloaded: " + e.Err.Error()
}

func (e *ReloadError) Unwrap() error { return e.Err }

// SaveSambaConfig safely writes a new smb.conf with validation and backup.
func SaveSambaConfig(content string) error {
	confDir := "/etc/samba"
	confPath := filepath.Join(confDir, "smb.conf")

	if err := os.MkdirAll(confDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", confDir, err)
	}

	if _, err := exec.LookPath("testparm"); err != nil {
		return fmt.Errorf("testparm validation failed: testparm not found; install samba-common-bin")
	}

	tmpFile := filepath.Join(confDir, fmt.Sprintf("smb.conf.tmp.%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write temp samba config: %w", err)
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("testparm", "-s", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("testparm validation failed: %w\noutput:\n%s", err, string(out))
	}

	if _, err := os.Stat(confPath); err == nil {
		bakPath := filepath.Join(confDir, fmt.Sprintf("smb.conf.bak.%d", time.Now().Unix()))
		if copyErr := os.Rename(confPath, bakPath); copyErr != nil {
			return fmt.Errorf("failed to backup existing smb.conf: %w", copyErr)
		}
	}

	if err := os.Rename(tmpFile, confPath); err != nil {
		return fmt.Errorf("failed to place new smb.conf: %w", err)
	}

	reloadCmd := exec.Command("systemctl", "reload", "smbd")
	if err := reloadCmd.Run(); err != nil {
		restartCmd := exec.Command("systemctl", "restart", "smbd")
		if restartErr := restartCmd.Run(); restartErr != nil {
			return &ReloadError{Err: fmt.Errorf("reload error: %v, restart error: %v", err, restartErr)}
		}
	}

	return nil
}
