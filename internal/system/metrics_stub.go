//go:build !linux

package system

import model "github.com/lukelinux79/casaos-native-panel/internal/model"

// GetMetrics is a non-Linux stub so the project can build on Windows or macOS.
// The real implementation lives in metrics.go.
func GetMetrics() (model.Metrics, error) {
	return model.Metrics{}, nil
}
