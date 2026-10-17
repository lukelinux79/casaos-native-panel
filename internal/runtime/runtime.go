package runtime

import (
	"errors"
	"fmt"

	model "github.com/lukelinux79/casaos-native-panel/internal/model"
)

// Expose model types under the runtime package as aliases to avoid duplication.
// This lets other runtime files use Overview, Service, etc. while keeping
// the concrete definitions in internal/model.

type Overview = model.Overview
type Service = model.Service
type Package = model.Package
type User = model.User
type NewUser = model.NewUser
type Group = model.Group
type Share = model.Share
type Metrics = model.Metrics
type Network = model.Network

// LogQuery selects journal entries. Empty Unit means the whole system journal.
type LogQuery struct {
	Unit     string
	Priority string
	Lines    int
}

var (
	ErrUnsupported  = errors.New("not supported in this runtime mode")
	ErrNotFound     = errors.New("not found")
	ErrForbidden    = errors.New("forbidden")
	ErrSambaMissing = errors.New("samba is not installed (install the samba package)")
)

// Runtime is the core abstraction used by the API layer.
type Runtime interface {
	Name() string
	GetOverview() (Overview, error)
	GetMetrics() (Metrics, error)
	GetNetwork() (Network, error)
	GetLogs(q LogQuery) ([]string, error)

	GetServices() ([]Service, error)
	StartService(name string) error
	StopService(name string) error
	RestartService(name string) error

	GetPackages() ([]Package, error)
	InstallPackage(name string) error
	RemovePackage(name string) error

	GetUsers() ([]User, error)
	CreateUser(u NewUser) error
	DeleteUser(name string, removeHome bool) error
	SetPassword(name, password string) error

	GetGroups() ([]Group, error)
	CreateGroup(name string) error
	DeleteGroup(name string) error
	AddGroupMember(group, user string) error
	RemoveGroupMember(group, user string) error

	GetSambaConfig() (string, error)
	SaveSambaConfig(content string) error
	GetShares() ([]Share, error)
	SaveShare(s Share) error
	DeleteShare(name string) error
	GetSambaUsers() ([]string, error)
	SetSambaPassword(name, password string) error
	DeleteSambaUser(name string) error
}

func New(mode string) (Runtime, error) {
	switch mode {
	case "system":
		return NewSystemRuntime(), nil
	case "docker":
		return NewDockerRuntime(), nil
	default:
		return nil, fmt.Errorf("unsupported runtime mode %q", mode)
	}
}
