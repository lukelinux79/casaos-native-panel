package model

// Shared data model used across runtime and system packages.

type Overview struct {
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Mode       string `json:"mode"`
	Kernel     string `json:"kernel"`
	DebianInfo string `json:"debian_info,omitempty"`
}

type Service struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
	// Active is the runtime state from systemd, e.g. active, inactive or failed.
	Active string `json:"active"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	State   string `json:"state"`
}

type User struct {
	Username string   `json:"username"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	HomeDir  string   `json:"home_dir,omitempty"`
	Shell    string   `json:"shell,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	System   bool     `json:"system"`
}

// NewUser is the payload for creating a user account.
type NewUser struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Shell    string   `json:"shell,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Samba    bool     `json:"samba"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
	System  bool     `json:"system"`
}

// Share is a single SMB share section of smb.conf.
type Share struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Comment    string   `json:"comment,omitempty"`
	ReadOnly   bool     `json:"read_only"`
	Browseable bool     `json:"browseable"`
	GuestOK    bool     `json:"guest_ok"`
	ValidUsers []string `json:"valid_users,omitempty"`
	WriteList  []string `json:"write_list,omitempty"`
	// Special marks built-in sections like [homes] or [printers].
	Special bool `json:"special,omitempty"`
}

type Metrics struct {
	Load1          float64 `json:"load1"`
	Load5          float64 `json:"load5"`
	Load15         float64 `json:"load15"`
	MemTotalKB     int64   `json:"mem_total_kb"`
	MemAvailableKB int64   `json:"mem_available_kb"`
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	DiskFreeBytes  uint64  `json:"disk_free_bytes"`
	DiskUsedPct    float64 `json:"disk_used_percent"`
	NetRxBytes     uint64  `json:"net_rx_bytes"`
	NetTxBytes     uint64  `json:"net_tx_bytes"`
	UptimeSeconds  float64 `json:"uptime_seconds"`
}

// Interface describes one network interface.
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	OperState string   `json:"oper_state,omitempty"`
	SpeedMbps int      `json:"speed_mbps,omitempty"`
	Addresses []string `json:"addresses"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
}

// Network is a read-only snapshot of the network configuration.
type Network struct {
	Interfaces     []Interface `json:"interfaces"`
	DefaultGateway string      `json:"default_gateway,omitempty"`
	DNSServers     []string    `json:"dns_servers"`
}
