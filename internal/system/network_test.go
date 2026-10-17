package system

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadDefaultGateway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	content := "Iface\tDestination\tGateway\tFlags\n" +
		"eth0\t0000A8C0\t00000000\t0001\n" +
		"eth0\t00000000\t0101A8C0\t0003\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readDefaultGateway(path); got != "192.168.1.1 (eth0)" {
		t.Fatalf("got %q", got)
	}
}

func TestReadDNSServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(path, []byte("# comment\nnameserver 1.1.1.1\nsearch lan\nnameserver 9.9.9.9\n"), 0o644)
	if got := readDNSServers(path); !reflect.DeepEqual(got, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("got %v", got)
	}
}
