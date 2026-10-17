package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	if unknown := unknownParameters(string(out)); len(unknown) > 0 {
		// testparm only warns about these, but they are almost always typos.
		return fmt.Errorf("testparm validation failed: unknown parameter(s): %s", strings.Join(unknown, ", "))
	}

	if old, err := os.ReadFile(confPath); err == nil {
		bakPath := filepath.Join(confDir, fmt.Sprintf("smb.conf.bak.%d", time.Now().UnixNano()))
		if err := os.WriteFile(bakPath, old, 0o644); err != nil {
			return fmt.Errorf("failed to backup existing smb.conf: %w", err)
		}
		pruneBackups(confDir, keepBackups)
	}

	// Rename replaces smb.conf atomically, so smbd never sees a missing file.
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

const keepBackups = 10

// pruneBackups keeps only the newest n smb.conf.bak.<time> files written by the panel.
func pruneBackups(dir string, n int) {
	type backup struct {
		path string
		ns   int64
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "smb.conf.bak.*"))
	var panel []backup
	for _, m := range matches {
		ts, err := strconv.ParseInt(strings.TrimPrefix(filepath.Base(m), "smb.conf.bak."), 10, 64)
		if err != nil {
			continue // e.g. CasaOS' own smb.conf.bak
		}
		if ts < 1e12 { // older versions used seconds
			ts *= 1e9
		}
		panel = append(panel, backup{m, ts})
	}
	sort.Slice(panel, func(i, j int) bool { return panel[i].ns < panel[j].ns })
	for len(panel) > n {
		_ = os.Remove(panel[0].path)
		panel = panel[1:]
	}
}

// unknownParameters extracts names from testparm lines like
// `Unknown parameter encountered: "pathh"`.
func unknownParameters(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		_, after, ok := strings.Cut(line, "Unknown parameter encountered:")
		if ok {
			names = append(names, strings.TrimSpace(after))
		}
	}
	return names
}
