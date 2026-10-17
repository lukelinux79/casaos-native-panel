package runtime

import (
	"fmt"

	sys "github.com/lukelinux79/casaos-native-panel/internal/system"
)

// DockerRuntime is a compatibility layer for Docker mode.
type DockerRuntime struct{}

func NewDockerRuntime() Runtime {
	return &DockerRuntime{}
}

func (d *DockerRuntime) Name() string { return "docker" }

func (d *DockerRuntime) GetOverview() (Overview, error) {
	return Overview{Mode: "docker", OS: detectOSName()}, nil
}

func (d *DockerRuntime) GetMetrics() (Metrics, error)       { return Metrics{}, nil }
func (d *DockerRuntime) GetNetwork() (Network, error)       { return sys.GetNetwork() }
func (d *DockerRuntime) GetLogs(LogQuery) ([]string, error) { return nil, ErrUnsupported }

func (d *DockerRuntime) GetServices() ([]Service, error)  { return nil, nil }
func (d *DockerRuntime) StartService(name string) error   { return nil }
func (d *DockerRuntime) StopService(name string) error    { return nil }
func (d *DockerRuntime) RestartService(name string) error { return nil }
func (d *DockerRuntime) GetPackages() ([]Package, error)  { return nil, nil }
func (d *DockerRuntime) InstallPackage(name string) error {
	return fmt.Errorf("docker mode does not install apt packages directly; use container image workflow")
}
func (d *DockerRuntime) RemovePackage(name string) error {
	return fmt.Errorf("docker mode does not manage apt packages directly")
}

func (d *DockerRuntime) GetUsers() ([]User, error)              { return nil, nil }
func (d *DockerRuntime) CreateUser(u NewUser) error             { return ErrUnsupported }
func (d *DockerRuntime) DeleteUser(string, bool) error          { return ErrUnsupported }
func (d *DockerRuntime) SetPassword(string, string) error       { return ErrUnsupported }
func (d *DockerRuntime) GetGroups() ([]Group, error)            { return nil, nil }
func (d *DockerRuntime) CreateGroup(string) error               { return ErrUnsupported }
func (d *DockerRuntime) DeleteGroup(string) error               { return ErrUnsupported }
func (d *DockerRuntime) AddGroupMember(string, string) error    { return ErrUnsupported }
func (d *DockerRuntime) RemoveGroupMember(string, string) error { return ErrUnsupported }
func (d *DockerRuntime) GetShares() ([]Share, error)            { return nil, nil }
func (d *DockerRuntime) SaveShare(Share) error                  { return ErrUnsupported }
func (d *DockerRuntime) DeleteShare(string) error               { return ErrUnsupported }
func (d *DockerRuntime) GetSambaUsers() ([]string, error)       { return nil, nil }
func (d *DockerRuntime) SetSambaPassword(string, string) error  { return ErrUnsupported }
func (d *DockerRuntime) DeleteSambaUser(string) error           { return ErrUnsupported }

func (d *DockerRuntime) GetSambaConfig() (string, error) {
	return "# Docker mode has no direct Samba config in this compatibility layer.\n", nil
}
func (d *DockerRuntime) SaveSambaConfig(content string) error {
	return fmt.Errorf("docker mode does not persist Samba config directly")
}
