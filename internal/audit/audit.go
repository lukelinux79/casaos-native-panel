// Package audit records who changed what through the panel.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxSize triggers a rotation to <path>.1 so the log cannot fill the disk.
const maxSize = 5 << 20

type Entry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Status int       `json:"status"`
	Remote string    `json:"remote,omitempty"`
}

// Logger appends entries as JSON lines.
type Logger struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Logger { return &Logger{path: path} }

// Log never fails the request; write errors are only reported to stderr.
func (l *Logger) Log(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.appendLocked(append(data, '\n')); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

func (l *Logger) appendLocked(line []byte) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	if st, err := os.Stat(l.path); err == nil && st.Size() > maxSize {
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// Recent returns up to limit entries, newest first.
func (l *Logger) Recent(limit int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var all []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
