// Package accounts stores the panel's own login accounts and their roles.
// These are independent of Linux users: they control who may use the panel.
package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

type Role string

const (
	// RoleViewer can see everything except logs, raw config and audit log.
	RoleViewer Role = "viewer"
	// RoleOperator can additionally manage Linux users, groups, shares and services.
	RoleOperator Role = "operator"
	// RoleAdmin can additionally edit raw smb.conf, manage panel accounts and read the audit log.
	RoleAdmin Role = "admin"
)

var rank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// Allows reports whether role r includes the permissions of min.
func (r Role) Allows(min Role) bool { return rank[r] >= rank[min] && rank[r] > 0 }

func ParseRole(s string) (Role, error) {
	r := Role(s)
	if rank[r] == 0 {
		return "", validate.Errorf("invalid role %q (use admin, operator or viewer)", s)
	}
	return r, nil
}

var (
	ErrNotFound  = errors.New("panel account not found")
	ErrLastAdmin = errors.New("the last admin account cannot be removed or demoted")
)

type account struct {
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// Info is an account without its password hash.
type Info struct {
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// Store keeps accounts in a JSON file readable only by root. Changes made to
// the file by another process (e.g. the passwd command) are picked up
// automatically before the next read or write.
type Store struct {
	mu       sync.Mutex
	path     string
	accounts map[string]*account
	modTime  time.Time
}

// dummyHash makes failed logins for unknown users take as long as for known ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

func Open(path string) (*Store, error) {
	s := &Store{path: path, accounts: map[string]*account{}}
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadLocked() error {
	st, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []*account
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	accounts := make(map[string]*account, len(list))
	for _, a := range list {
		accounts[a.Username] = a
	}
	s.accounts = accounts
	s.modTime = st.ModTime()
	return nil
}

// refreshLocked reloads the file if it changed on disk. A broken file keeps
// the last good state in memory.
func (s *Store) refreshLocked() {
	st, err := os.Stat(s.path)
	if err != nil || st.ModTime().Equal(s.modTime) {
		return
	}
	if err := s.loadLocked(); err != nil {
		log.Printf("panel accounts: keeping previous state, reload failed: %v", err)
	}
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	return len(s.accounts)
}

func (s *Store) List() []Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	out := make([]Info, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, a.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (s *Store) Get(username string) (Info, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	a, ok := s.accounts[username]
	if !ok {
		return Info{}, false
	}
	return a.info(), true
}

func (s *Store) Create(username, password string, role Role) error {
	if err := validate.Username(username); err != nil {
		return err
	}
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	if _, exists := s.accounts[username]; exists {
		return validate.Errorf("panel account %q already exists", username)
	}
	s.accounts[username] = &account{Username: username, Role: role, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	return s.saveLocked(func() { delete(s.accounts, username) })
}

func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	a, ok := s.accounts[username]
	if !ok {
		return ErrNotFound
	}
	if a.Role == RoleAdmin && s.adminCountLocked() == 1 {
		return ErrLastAdmin
	}
	delete(s.accounts, username)
	return s.saveLocked(func() { s.accounts[username] = a })
}

func (s *Store) SetRole(username string, role Role) error {
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	a, ok := s.accounts[username]
	if !ok {
		return ErrNotFound
	}
	if a.Role == RoleAdmin && role != RoleAdmin && s.adminCountLocked() == 1 {
		return ErrLastAdmin
	}
	old := a.Role
	a.Role = role
	return s.saveLocked(func() { a.Role = old })
}

func (s *Store) SetPassword(username, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	a, ok := s.accounts[username]
	if !ok {
		return ErrNotFound
	}
	old := a.PasswordHash
	a.PasswordHash = hash
	return s.saveLocked(func() { a.PasswordHash = old })
}

// Authenticate checks the password and returns the account on success.
func (s *Store) Authenticate(username, password string) (Info, bool) {
	s.mu.Lock()
	s.refreshLocked()
	a, ok := s.accounts[username]
	hash := dummyHash
	var info Info
	if ok {
		hash = []byte(a.PasswordHash)
		info = a.info()
	}
	s.mu.Unlock()
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !ok {
		return Info{}, false
	}
	return info, true
}

func (a *account) info() Info {
	return Info{Username: a.Username, Role: a.Role, CreatedAt: a.CreatedAt}
}

func (s *Store) adminCountLocked() int {
	n := 0
	for _, a := range s.accounts {
		if a.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// saveLocked writes the store atomically; on failure it calls undo so memory
// and disk stay consistent.
func (s *Store) saveLocked(undo func()) error {
	list := make([]*account, 0, len(s.accounts))
	for _, a := range s.accounts {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(s.path, data)
	}
	if err != nil {
		undo()
		return fmt.Errorf("save panel accounts: %w", err)
	}
	if st, err := os.Stat(s.path); err == nil {
		s.modTime = st.ModTime()
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".accounts-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func hashPassword(password string) (string, error) {
	if err := validate.Password(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
