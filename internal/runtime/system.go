package runtime

import (
	"os"
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

func (s *SystemRuntime) GetServices() ([]Service, error) {
	out, err := shellOut("systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		return []Service{}, nil
	}

	lines := strings.Split(out, "\n")
	result := make([]Service, 0, len(lines))
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 || !strings.HasSuffix(parts[0], ".service") || strings.Contains(parts[0], "@.") {
			continue
		}
		result = append(result, Service{
			Name:    strings.TrimSuffix(parts[0], ".service"),
			State:   parts[1],
			Enabled: parts[1] == "enabled",
		})
	}
	return result, nil
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
