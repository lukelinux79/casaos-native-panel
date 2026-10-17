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

// denyPrivilegedUser blocks non-admins from changing a Linux user that is in a privileged group.
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
	}
	return false
}
