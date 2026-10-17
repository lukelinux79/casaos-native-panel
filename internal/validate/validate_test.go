package validate

import "testing"

func TestUsername(t *testing.T) {
	for _, ok := range []string{"alice", "_svc", "bob-2", "a_b"} {
		if err := Username(ok); err != nil {
			t.Errorf("Username(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Alice", "1bob", "-rf", "a:b", "a b", "a\nb", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if Username(bad) == nil {
			t.Errorf("Username(%q) accepted", bad)
		}
	}
}

func TestPassword(t *testing.T) {
	if Password("short") == nil {
		t.Error("short password accepted")
	}
	if Password("long enough\nroot:x") == nil {
		t.Error("password with newline accepted")
	}
	if err := Password("correct horse"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
}

func TestShareName(t *testing.T) {
	for _, bad := range []string{"global", "Homes", "a]b", "x\n[global]", " lead", ""} {
		if ShareName(bad) == nil {
			t.Errorf("ShareName(%q) accepted", bad)
		}
	}
	if err := ShareName("Family Photos"); err != nil {
		t.Errorf("valid share name rejected: %v", err)
	}
}

func TestSharePath(t *testing.T) {
	for _, bad := range []string{"", "relative/dir", "/srv/../etc", "/srv/x/", "/srv/a\nb"} {
		if SharePath(bad) == nil {
			t.Errorf("SharePath(%q) accepted", bad)
		}
	}
	if err := SharePath("/srv/media"); err != nil {
		t.Errorf("valid path rejected: %v", err)
	}
}

func TestPrincipal(t *testing.T) {
	for _, ok := range []string{"alice", "@family", "+users"} {
		if err := Principal(ok); err != nil {
			t.Errorf("Principal(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "@", "@@@x", "a b", "x\ny"} {
		if Principal(bad) == nil {
			t.Errorf("Principal(%q) accepted", bad)
		}
	}
}
