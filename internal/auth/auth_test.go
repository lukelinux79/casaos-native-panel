package auth

import (
	"testing"
	"time"
)

func TestSessions(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSessions()
	s.now = func() time.Time { return now }

	id, err := s.Create("alice")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.Create("alice")
	if u, ok := s.Lookup(id); !ok || u != "alice" {
		t.Fatalf("lookup failed: %q %v", u, ok)
	}
	s.DeleteUser("alice", id)
	if _, ok := s.Lookup(other); ok {
		t.Fatal("other session survived DeleteUser")
	}
	if _, ok := s.Lookup(id); !ok {
		t.Fatal("kept session was deleted")
	}
	now = now.Add(SessionTTL + time.Second)
	if _, ok := s.Lookup(id); ok {
		t.Fatal("expired session accepted")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(3, time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if l.Blocked("ip") {
			t.Fatalf("blocked after %d failures", i)
		}
		l.Fail("ip")
	}
	if !l.Blocked("ip") {
		t.Fatal("not blocked after 3 failures")
	}
	now = now.Add(2 * time.Minute)
	if l.Blocked("ip") {
		t.Fatal("still blocked after window")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("CASAOS_ADMIN_USER", "admin")
	t.Setenv("CASAOS_ADMIN_PASSWORD", "")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("user without password accepted")
	}
	t.Setenv("CASAOS_ADMIN_PASSWORD", "secret123")
	t.Setenv("CASAOS_AUTH_DISABLED", "true")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("disabled auth combined with admin accepted")
	}
}
