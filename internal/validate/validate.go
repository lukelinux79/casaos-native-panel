// Package validate checks user input before it reaches system commands or config files.
package validate

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Error marks invalid user input. The API layer maps it to HTTP 400.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func Errorf(format string, args ...any) error {
	return &Error{msg: fmt.Sprintf(format, args...)}
}

var (
	// Debian's default NAME_REGEX for adduser, limited to 32 chars.
	accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	shareRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$`)
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)
	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)
)

var reservedShares = map[string]bool{"global": true, "homes": true, "printers": true}

func Username(s string) error {
	if !accountRe.MatchString(s) {
		return Errorf("invalid username %q: use lowercase letters, digits, '_' or '-' (max 32, must not start with a digit)", s)
	}
	return nil
}

func GroupName(s string) error {
	if !accountRe.MatchString(s) {
		return Errorf("invalid group name %q: use lowercase letters, digits, '_' or '-' (max 32, must not start with a digit)", s)
	}
	return nil
}

func Password(s string) error {
	if len(s) < 8 {
		return Errorf("password must be at least 8 characters")
	}
	if len(s) > 128 {
		return Errorf("password must be at most 128 characters")
	}
	if strings.ContainsAny(s, "\n\r\x00") {
		return Errorf("password must not contain line breaks or NUL bytes")
	}
	return nil
}

func ShareName(s string) error {
	if !shareRe.MatchString(s) {
		return Errorf("invalid share name %q: use letters, digits, space, '_', '.' or '-' (max 80)", s)
	}
	if reservedShares[strings.ToLower(s)] {
		return Errorf("share name %q is reserved by Samba", s)
	}
	return nil
}

// SharePath requires a clean absolute path without line breaks.
func SharePath(s string) error {
	if s == "" || !filepath.IsAbs(s) {
		return Errorf("share path must be an absolute path")
	}
	if filepath.Clean(s) != s {
		return Errorf("share path %q is not normalized (expected %q)", s, filepath.Clean(s))
	}
	if err := SingleLine("path", s); err != nil {
		return err
	}
	return notSystemDir(s)
}

// systemDirs must not be shared (or contain a share): they hold system
// configuration, secrets or the panel's own data.
var systemDirs = []string{"/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/run", "/usr", "/bin", "/sbin",
	"/lib", "/lib32", "/lib64", "/libx32", "/var/run", "/var/lib/samba", "/var/lib/casaos-native-panel", "/var/lib/casaos"}

// notSystemDir rejects "/" , "/var" and anything inside systemDirs. Call it again
// with the symlink-resolved path before using a directory.
func notSystemDir(p string) error {
	if p == "/" || p == "/var" {
		return Errorf("sharing %s would expose the whole system", p)
	}
	for _, d := range systemDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return Errorf("share path %q is inside the system directory %s", p, d)
		}
	}
	return nil
}

// ResolvedSharePath checks the real location of a share directory after symlinks.
func ResolvedSharePath(resolved string) error { return notSystemDir(resolved) }

// SingleLine rejects values that could inject extra lines into a config file.
func SingleLine(field, s string) error {
	if strings.ContainsAny(s, "\n\r\x00") {
		return Errorf("%s must not contain line breaks", field)
	}
	return nil
}

// Principal validates a Samba user list entry: a username or @group / +group.
func Principal(s string) error {
	name := strings.TrimLeft(s, "@+&")
	if len(s)-len(name) > 2 || !accountRe.MatchString(name) {
		return Errorf("invalid user or group %q (use name or @group)", s)
	}
	return nil
}

func ServiceName(s string) error {
	if !serviceRe.MatchString(s) {
		return Errorf("invalid service name %q", s)
	}
	return nil
}

func PackageName(s string) error {
	if !packageRe.MatchString(s) {
		return Errorf("invalid package name %q", s)
	}
	return nil
}
