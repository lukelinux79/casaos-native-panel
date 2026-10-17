//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	model "github.com/lukelinux79/casaos-native-panel/internal/model"
)

// GetMetrics reads native metrics from /proc and statfs. Missing sources are left at zero.
func GetMetrics() (model.Metrics, error) {
	var out model.Metrics

	load1, load5, load15, err := readLoadAvg()
	if err == nil {
		out.Load1 = load1
		out.Load5 = load5
		out.Load15 = load15
	}

	totalKB, availKB, err := readMemInfo()
	if err == nil {
		out.MemTotalKB = totalKB
		out.MemAvailableKB = availKB
	}

	totalBytes, freeBytes, usedPct, err := readDiskUsage()
	if err == nil {
		out.DiskTotalBytes = totalBytes
		out.DiskFreeBytes = freeBytes
		out.DiskUsedPct = usedPct
	}

	rxBytes, txBytes, err := readNetUsage()
	if err == nil {
		out.NetRxBytes = rxBytes
		out.NetTxBytes = txBytes
	}

	uptimeSec, err := readUptime()
	if err == nil {
		out.UptimeSeconds = uptimeSec
	}

	return out, nil
}

func readLoadAvg() (float64, float64, float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected /proc/loadavg format")
	}
	v1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	v5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	v15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return v1, v5, v15, nil
}

func readMemInfo() (int64, int64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var totalKB, availKB int64
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseInt(fields[1], 10, 64)
			}
		case strings.HasPrefix(line, "MemAvailable:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				availKB, _ = strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return totalKB, availKB, nil
}

func readDiskUsage() (uint64, uint64, float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	usedPct := 0.0
	if total > 0 {
		usedPct = float64(used) / float64(total) * 100.0
	}
	return total, free, usedPct, nil
}

func readNetUsage() (uint64, uint64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var rxBytes, txBytes uint64
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 10 {
			continue
		}
		rxVal, _ := strconv.ParseUint(fields[0], 10, 64)
		txVal, _ := strconv.ParseUint(fields[8], 10, 64)
		rxBytes += rxVal
		txBytes += txVal
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return rxBytes, txBytes, nil
}

func readUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("no uptime data")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}
