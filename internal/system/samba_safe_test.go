package system

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestUnknownParameters(t *testing.T) {
	out := "Load smb config files from /tmp/x\nUnknown parameter encountered: \"pathh\"\nIgnoring unknown parameter \"pathh\"\nUnknown parameter encountered: \"wrteable\"\nLoaded services file OK.\n"
	if got := unknownParameters(out); !reflect.DeepEqual(got, []string{`"pathh"`, `"wrteable"`}) {
		t.Fatalf("got %v", got)
	}
	if got := unknownParameters("Loaded services file OK.\n"); got != nil {
		t.Fatalf("clean output reported %v", got)
	}
}

func TestPruneBackups(t *testing.T) {
	dir := t.TempDir()
	names := []string{"smb.conf.bak", "smb.conf.bak.1792265791", "smb.conf.bak.1792265855"}
	for i := 0; i < 12; i++ {
		names = append(names, "smb.conf.bak."+strconv.FormatInt(1792265900000000000+int64(i), 10))
	}
	for _, n := range names {
		_ = os.WriteFile(filepath.Join(dir, n), nil, 0o644)
	}
	pruneBackups(dir, 10)
	left, _ := filepath.Glob(filepath.Join(dir, "smb.conf.bak*"))
	if len(left) != 11 { // 10 panel backups + CasaOS' smb.conf.bak
		t.Fatalf("left %d files: %v", len(left), left)
	}
	for _, gone := range []string{"smb.conf.bak.1792265791", "smb.conf.bak.1792265855"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); err == nil {
			t.Errorf("oldest backup %s kept", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "smb.conf.bak")); err != nil {
		t.Error("CasaOS backup removed")
	}
}
