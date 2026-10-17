package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	sys "github.com/lukelinux79/casaos-native-panel/internal/system"
	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

// SystemRuntime implements native Debian system operations.
// User, group and Samba operations live in system_accounts.go and system_samba.go.
type SystemRuntime struct {
	// sambaMu serializes read-modify-write cycles on smb.conf.
	sambaMu sync.Mutex
}

func NewSystemRuntime() Runtime {
	return &SystemRuntime{}
}

func (s *SystemRuntime) Name() string { return "system" }

func (s *SystemRuntime) GetOverview() (Overview, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	kernel, _ := shellOut("uname", "-r")
	osName := detectOSName()
	debianInfo, _ := shellOut("cat", "/etc/debian_version")

	return Overview{
		Hostname:   hostname,
		OS:         osName,
		Mode:       "system",
		Kernel:     kernel,
		DebianInfo: debianInfo,
	}, nil
}

// GetMetrics collects native system metrics.
func (s *SystemRuntime) GetMetrics() (Metrics, error) {
	return sys.GetMetrics()
}

func (s *SystemRuntime) GetNetwork() (Network, error) {
	return sys.GetNetwork()
}

var logPriorities = map[string]bool{
	"emerg": true, "alert": true, "crit": true, "err": true,
	"warning": true, "notice": true, "info": true, "debug": true,
}

const maxLogLines = 2000

// GetLogs reads the systemd journal, optionally for one unit and up to a priority.
func (s *SystemRuntime) GetLogs(q LogQuery) ([]string, error) {
	if q.Lines <= 0 {
		q.Lines = 200
	}
	if q.Lines > maxLogLines {
		return nil, validate.Errorf("lines must be at most %d", maxLogLines)
	}
	args := []string{"--no-pager", "--quiet", "-o", "short-iso", "-n", strconv.Itoa(q.Lines)}
	if q.Unit != "" {
		if err := validate.ServiceName(q.Unit); err != nil {
			return nil, err
		}
		args = append(args, "-u", q.Unit)
	}
	if q.Priority != "" {
		if !logPriorities[q.Priority] {
			return nil, validate.Errorf("invalid priority %q", q.Priority)
		}
		args = append(args, "-p", q.Priority)
	}
	out, err := exec.Command("journalctl", args...).Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("journalctl not available: %w", ErrUnsupported)
		}
		return nil, fmt.Errorf("journalctl failed: %w", err)
	}
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

func (s *SystemRuntime) GetServices() ([]Service, error) {
	out, err := shellOut("systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		return []Service{}, nil
	}

	active := activeStates()
	lines := strings.Split(out, "\n")
	result := make([]Service, 0, len(lines))
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 || !strings.HasSuffix(parts[0], ".service") || strings.Contains(parts[0], "@.") {
			continue
		}
		state, ok := active[parts[0]]
		if !ok {
			state = "inactive"
		}
		result = append(result, Service{
			Name:    strings.TrimSuffix(parts[0], ".service"),
			State:   parts[1],
			Enabled: parts[1] == "enabled",
			Active:  state,
		})
	}
	return result, nil
}

// activeStates maps loaded service units to their ACTIVE column (active, failed, ...).
// Units that are not loaded are missing and therefore inactive.
func activeStates() map[string]string {
	states := map[string]string{}
	out, err := shellOut("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		return states
	}
	for _, line := range strings.Split(out, "\n") {
		// UNIT LOAD ACTIVE SUB DESCRIPTION
		if f := strings.Fields(line); len(f) >= 3 {
			states[f[0]] = f[2]
		}
	}
	return states
}

func (s *SystemRuntime) StartService(name string) error   { return s.serviceAction("start", name) }
func (s *SystemRuntime) StopService(name string) error    { return s.serviceAction("stop", name) }
func (s *SystemRuntime) RestartService(name string) error { return s.serviceAction("restart", name) }

func (s *SystemRuntime) serviceAction(action, name string) error {
	if err := validate.ServiceName(name); err != nil {
		return err
	}
	return run("", "systemctl", action, "--", name)
}

func (s *SystemRuntime) GetPackages() ([]Package, error) {
	out, err := shellOut("dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	result := make([]Package, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		result = append(result, Package{
			Name:    fields[0],
			Version: fields[1],
			State:   strings.TrimSpace(fields[2]),
		})
	}
	return result, nil
}

func (s *SystemRuntime) InstallPackage(name string) error {
	if err := validate.PackageName(name); err != nil {
		return err
	}
	if err := run("", "apt-get", "update"); err != nil {
		return err
	}
	return run("", "apt-get", "install", "-y", "--", name)
}

func (s *SystemRuntime) RemovePackage(name string) error {
	if err := validate.PackageName(name); err != nil {
		return err
	}
	return run("", "apt-get", "remove", "-y", "--", name)
}
