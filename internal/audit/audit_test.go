package audit

import (
	"path/filepath"
	"testing"
)

func TestLogAndRecent(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "audit.log"))
	if got, err := l.Recent(10); err != nil || len(got) != 0 {
		t.Fatalf("empty log: %v %v", got, err)
	}
	for _, a := range []string{"one", "two", "three"} {
		l.Log(Entry{User: "alice", Action: a, Status: 200})
	}
	got, err := l.Recent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Action != "three" || got[1].Action != "two" {
		t.Fatalf("unexpected entries: %+v", got)
	}
	if got[0].Time.IsZero() {
		t.Error("time not set")
	}
}
