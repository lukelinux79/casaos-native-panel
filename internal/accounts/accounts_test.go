package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "accounts.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestCreateAuthenticatePersist(t *testing.T) {
	s, path := newStore(t)
	if err := s.Create("alice", "secret123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("alice", "wrong-pass"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, ok := s.Authenticate("nobody", "secret123"); ok {
		t.Fatal("unknown user accepted")
	}
	info, ok := s.Authenticate("alice", "secret123")
	if !ok || info.Role != RoleAdmin {
		t.Fatalf("login failed: %+v %v", info, ok)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("accounts file mode = %v, want 0600", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "secret123") {
		t.Fatal("plain password stored")
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate("alice", "secret123"); !ok {
		t.Fatal("account not persisted")
	}
}

func TestLastAdminProtected(t *testing.T) {
	s, _ := newStore(t)
	_ = s.Create("root1", "secret123", RoleAdmin)
	_ = s.Create("op", "secret123", RoleOperator)

	if err := s.Delete("root1"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	if err := s.SetRole("root1", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := s.SetRole("op", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("root1"); err != nil {
		t.Fatalf("delete with second admin present: %v", err)
	}
}

func TestValidation(t *testing.T) {
	s, _ := newStore(t)
	if s.Create("Bad Name", "secret123", RoleAdmin) == nil {
		t.Error("invalid username accepted")
	}
	if s.Create("bob", "short", RoleAdmin) == nil {
		t.Error("short password accepted")
	}
	if s.Create("bob", "secret123", Role("root")) == nil {
		t.Error("invalid role accepted")
	}
	_ = s.Create("bob", "secret123", RoleViewer)
	if s.Create("bob", "secret123", RoleViewer) == nil {
		t.Error("duplicate accepted")
	}
}

func TestRoleAllows(t *testing.T) {
	if !RoleAdmin.Allows(RoleOperator) || RoleViewer.Allows(RoleOperator) || !RoleOperator.Allows(RoleViewer) || Role("").Allows(RoleViewer) {
		t.Fatal("role ranking wrong")
	}
}

func TestPicksUpExternalChanges(t *testing.T) {
	s, path := newStore(t)
	_ = s.Create("alice", "secret123", RoleAdmin)

	// A second process (the passwd command) changes the file.
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.SetPassword("alice", "changed123"); err != nil {
		t.Fatal(err)
	}
	// Make sure the mtime differs even on coarse filesystems.
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if _, ok := s.Authenticate("alice", "changed123"); !ok {
		t.Fatal("running store did not pick up the new password")
	}
	// A later write by the running store must not undo the external change.
	_ = s.Create("bob", "secret123", RoleViewer)
	s3, _ := Open(path)
	if _, ok := s3.Authenticate("alice", "changed123"); !ok {
		t.Fatal("external password change was overwritten")
	}
}
