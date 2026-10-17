// Package auth provides login sessions, brute-force protection and the
// environment-based bootstrap of the first admin account.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"
)

// Bootstrap holds the CASAOS_ADMIN_* settings. They only create the first
// admin account when no panel account exists yet.
type Bootstrap struct {
	Disabled bool
	Username string
	Password string
}

// LoadFromEnv requires both CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD or none.
// The panel runs as root, so running without login must be requested
// explicitly with CASAOS_AUTH_DISABLED=true.
func LoadFromEnv() (Bootstrap, error) {
	username := os.Getenv("CASAOS_ADMIN_USER")
	password := os.Getenv("CASAOS_ADMIN_PASSWORD")
	disabled := os.Getenv("CASAOS_AUTH_DISABLED") == "true"

	if (username == "") != (password == "") {
		return Bootstrap{}, errors.New("both CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD must be set")
	}
	if disabled && username != "" {
		return Bootstrap{}, errors.New("CASAOS_AUTH_DISABLED=true cannot be combined with CASAOS_ADMIN_USER")
	}
	return Bootstrap{Disabled: disabled, Username: username, Password: password}, nil
}

const SessionTTL = 12 * time.Hour

type session struct {
	username string
	expires  time.Time
}

// Sessions keeps login sessions in memory; a restart logs everyone out.
type Sessions struct {
	mu   sync.Mutex
	byID map[string]session
	now  func() time.Time
}

func NewSessions() *Sessions {
	return &Sessions{byID: map[string]session{}, now: time.Now}
}

func (s *Sessions) Create(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.byID[id] = session{username: username, expires: s.now().Add(SessionTTL)}
	return id, nil
}

// Lookup returns the username of a valid session.
func (s *Sessions) Lookup(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok || s.now().After(sess.expires) {
		delete(s.byID, id)
		return "", false
	}
	return sess.username, true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// DeleteUser ends all sessions of a user, e.g. after deletion or password change.
func (s *Sessions) DeleteUser(username string, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.byID {
		if sess.username == username && id != keep {
			delete(s.byID, id)
		}
	}
}

func (s *Sessions) pruneLocked() {
	now := s.now()
	for id, sess := range s.byID {
		if now.After(sess.expires) {
			delete(s.byID, id)
		}
	}
}

// Limiter blocks a client after too many failed logins.
type Limiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	max      int
	window   time.Duration
	now      func() time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{failures: map[string][]time.Time{}, max: max, window: window, now: time.Now}
}

// Blocked reports whether the key has reached the failure limit in the window.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recentLocked(key)) >= l.max
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recentLocked(key), l.now())
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *Limiter) recentLocked(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}
