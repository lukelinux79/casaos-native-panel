package system

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	model "github.com/lukelinux79/casaos-native-panel/internal/model"
)

// GetNetwork returns interfaces, default gateway and DNS servers. Details from
// /sys and /proc are only available on Linux and are left empty elsewhere.
func GetNetwork() (model.Network, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return model.Network{}, err
	}
	out := model.Network{Interfaces: make([]model.Interface, 0, len(ifaces)), DNSServers: readDNSServers("/etc/resolv.conf")}
	for _, ifc := range ifaces {
		i := model.Interface{
			Name:      ifc.Name,
			MAC:       ifc.HardwareAddr.String(),
			MTU:       ifc.MTU,
			Up:        ifc.Flags&net.FlagUp != 0,
			Loopback:  ifc.Flags&net.FlagLoopback != 0,
			Addresses: []string{},
		}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				i.Addresses = append(i.Addresses, a.String())
			}
		}
		sys := filepath.Join("/sys/class/net", ifc.Name)
		i.OperState = readTrimmed(filepath.Join(sys, "operstate"))
		i.SpeedMbps, _ = strconv.Atoi(readTrimmed(filepath.Join(sys, "speed")))
		if i.SpeedMbps < 0 {
			i.SpeedMbps = 0
		}
		i.RxBytes, _ = strconv.ParseUint(readTrimmed(filepath.Join(sys, "statistics/rx_bytes")), 10, 64)
		i.TxBytes, _ = strconv.ParseUint(readTrimmed(filepath.Join(sys, "statistics/tx_bytes")), 10, 64)
		out.Interfaces = append(out.Interfaces, i)
	}
	out.DefaultGateway = readDefaultGateway("/proc/net/route")
	return out, nil
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readDNSServers(path string) []string {
	servers := []string{}
	f, err := os.Open(path)
	if err != nil {
		return servers
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return servers
}

// readDefaultGateway parses /proc/net/route, where addresses are little-endian hex.
func readDefaultGateway(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.LittleEndian.Uint32(raw))
		return ip.String() + " (" + fields[0] + ")"
	}
	return ""
}
