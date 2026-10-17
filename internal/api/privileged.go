package api

import (
	"net/http"

	"github.com/lukelinux79/casaos-native-panel/internal/accounts"
)

// privilegedGroups grant root or root-equivalent access. Only admins may add
// or remove members, or change accounts that belong to them; otherwise an
// operator could escalate to root, e.g. via a new sudo user.
var privilegedGroups = map[string]bool{
	"root": true, "sudo": true, "wheel": true, "adm": true, "shadow": true,
	"disk": true, "docker": true, "lxd": true, "incus-admin": true, "libvirt": true,
}

// denyUnlessAdmin writes 403 and returns true if a non-admin touches privileged groups.
func denyUnlessAdmin(w http.ResponseWriter, r *http.Request, groups ...string) bool {
	if currentUser(r).Role.Allows(accounts.RoleAdmin) {
		return false
	}
	for _, g := range groups {
		if privilegedGroups[g] {
			writeJSON(w, http.StatusForbidden, response{"error": "only admins may manage members of the privileged group " + g})
			return true
		}
	}
	return false
}

// noLoginShells cannot start an interactive session.
var noLoginShells = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true}

// casaOSShellRisk explains why login shells are admin-only next to CasaOS,
// which runs as root and exposes local services to every local account.
const casaOSShellRisk = "on CasaOS hosts accounts with a login shell are a security risk"

// denyLoginShell blocks non-admins from creating accounts with a login shell when CasaOS runs.
func (s *Server) denyLoginShell(w http.ResponseWriter, r *http.Request, shell string) bool {
	if currentUser(r).Role.Allows(accounts.RoleAdmin) || noLoginShells[shell] || !s.runtime.CasaOSAvailable() {
		return false
	}
	writeJSON(w, http.StatusForbidden, response{"error": "only admins may create users with a login shell: " + casaOSShellRisk + ". Use /usr/sbin/nologin for Samba-only users."})
	return true
}

// denyPrivilegedUser blocks non-admins from changing a Linux user that is in a
// privileged group, or that has a login shell while CasaOS runs.
func (s *Server) denyPrivilegedUser(w http.ResponseWriter, r *http.Request, username string) bool {
	if currentUser(r).Role.Allows(accounts.RoleAdmin) {
		return false
	}
	users, err := s.runtime.GetUsers()
	if err != nil {
		writeError(w, err)
		return true
	}
	for _, u := range users {
		if u.Username != username {
			continue
		}
		for _, g := range u.Groups {
			if privilegedGroups[g] {
				writeJSON(w, http.StatusForbidden, response{"error": "user " + username + " is in the privileged group " + g + "; only admins may change this user"})
				return true
			}
		}
		if !noLoginShells[u.Shell] && s.runtime.CasaOSAvailable() {
			writeJSON(w, http.StatusForbidden, response{"error": "user " + username + " has a login shell; only admins may change it: " + casaOSShellRisk})
			return true
		}
	}
	return false
}
