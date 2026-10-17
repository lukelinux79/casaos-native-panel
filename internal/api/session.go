package api

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/lukelinux79/casaos-native-panel/internal/accounts"
	"github.com/lukelinux79/casaos-native-panel/internal/audit"
	"github.com/lukelinux79/casaos-native-panel/internal/auth"
)

const sessionCookie = "casaos_session"

type principal struct {
	Username string
	Role     accounts.Role
}

type principalKey struct{}

func currentUser(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}

// protect authenticates the request, enforces the minimum role and writes an
// audit entry for every request with a non-empty action.
func (s *Server) protect(min accounts.Role, action string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok, blocked := s.authenticate(r)
		if blocked {
			writeJSON(w, http.StatusTooManyRequests, response{"error": "too many failed logins, try again later"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, response{"error": "login required"})
			return
		}
		if !p.Role.Allows(min) {
			writeJSON(w, http.StatusForbidden, response{"error": "your role (" + string(p.Role) + ") is not allowed to do this"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		if action == "" {
			h(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		s.logAudit(r, p.Username, action, auditTarget(r), rec.status)
	})
}

// authenticate accepts a session cookie or HTTP Basic credentials (for scripts).
func (s *Server) authenticate(r *http.Request) (p principal, ok bool, blocked bool) {
	if s.authDisabled {
		return principal{Username: "local", Role: accounts.RoleAdmin}, true, false
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if name, found := s.sessions.Lookup(c.Value); found {
			if info, exists := s.accounts.Get(name); exists {
				return principal{Username: info.Username, Role: info.Role}, true, false
			}
		}
	}
	user, pass, hasBasic := r.BasicAuth()
	if !hasBasic {
		return principal{}, false, false
	}
	ip := clientIP(r)
	if s.limiter.Blocked(ip) {
		return principal{}, false, true
	}
	info, valid := s.accounts.Authenticate(user, pass)
	if !valid {
		s.limiter.Fail(ip)
		s.logAudit(r, user, "auth.basic_failed", "", http.StatusUnauthorized)
		return principal{}, false, false
	}
	return principal{Username: info.Username, Role: info.Role}, true, false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.authDisabled {
		writeJSON(w, http.StatusOK, response{"username": "local", "role": accounts.RoleAdmin, "auth_disabled": true})
		return
	}
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &p) {
		return
	}
	ip := clientIP(r)
	if s.limiter.Blocked(ip) {
		s.logAudit(r, p.Username, "auth.login_blocked", "", http.StatusTooManyRequests)
		writeJSON(w, http.StatusTooManyRequests, response{"error": "too many failed logins, try again in 15 minutes"})
		return
	}
	info, ok := s.accounts.Authenticate(p.Username, p.Password)
	if !ok {
		s.limiter.Fail(ip)
		s.logAudit(r, p.Username, "auth.login_failed", "", http.StatusUnauthorized)
		writeJSON(w, http.StatusUnauthorized, response{"error": "invalid username or password"})
		return
	}
	s.limiter.Reset(ip)
	id, err := s.sessions.Create(info.Username)
	if err != nil {
		writeError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(auth.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	s.logAudit(r, info.Username, "auth.login", "", http.StatusOK)
	writeJSON(w, http.StatusOK, response{"username": info.Username, "role": info.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, response{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := currentUser(r)
	writeJSON(w, http.StatusOK, response{"username": p.Username, "role": p.Role, "auth_disabled": s.authDisabled})
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if s.authDisabled {
		writeJSON(w, http.StatusBadRequest, response{"error": "authentication is disabled"})
		return
	}
	var p struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &p) {
		return
	}
	me := currentUser(r)
	if _, ok := s.accounts.Authenticate(me.Username, p.Current); !ok {
		writeJSON(w, http.StatusForbidden, response{"error": "current password is wrong"})
		return
	}
	if err := s.accounts.SetPassword(me.Username, p.New); err != nil {
		writeError(w, err)
		return
	}
	keep := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		keep = c.Value
	}
	s.sessions.DeleteUser(me.Username, keep)
	writeJSON(w, http.StatusOK, response{"status": "updated"})
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, response{"accounts": s.accounts.List()})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &p) {
		return
	}
	role, err := accounts.ParseRole(p.Role)
	if err == nil {
		err = s.accounts.Create(p.Username, p.Password, role)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response{"status": "created", "username": p.Username})
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Role     string `json:"role,omitempty"`
		Password string `json:"password,omitempty"`
	}
	if !decode(w, r, &p) {
		return
	}
	name := r.PathValue("name")
	if p.Role == "" && p.Password == "" {
		writeJSON(w, http.StatusBadRequest, response{"error": "role or password is required"})
		return
	}
	if p.Role != "" {
		role, err := accounts.ParseRole(p.Role)
		if err == nil {
			err = s.accounts.SetRole(name, role)
		}
		if err != nil {
			writeError(w, err)
			return
		}
	}
	if p.Password != "" {
		if err := s.accounts.SetPassword(name, p.Password); err != nil {
			writeError(w, err)
			return
		}
		s.sessions.DeleteUser(name, "")
	}
	writeJSON(w, http.StatusOK, response{"status": "updated"})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == currentUser(r).Username {
		writeJSON(w, http.StatusConflict, response{"error": "you cannot delete your own account"})
		return
	}
	if err := s.accounts.Delete(name); err != nil {
		writeError(w, err)
		return
	}
	s.sessions.DeleteUser(name, "")
	writeJSON(w, http.StatusOK, response{"status": "deleted"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		writeJSON(w, http.StatusOK, response{"entries": []audit.Entry{}})
		return
	}
	entries, err := s.audit.Recent(500)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"entries": entries})
}

func (s *Server) logAudit(r *http.Request, user, action, target string, status int) {
	if s.audit == nil {
		return
	}
	s.audit.Log(audit.Entry{User: user, Action: action, Target: target, Status: status, Remote: clientIP(r)})
}

// auditTarget describes the object of a request from its path values.
func auditTarget(r *http.Request) string {
	var parts []string
	for _, key := range []string{"name", "user", "action"} {
		if v := r.PathValue(key); v != "" {
			parts = append(parts, key+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

// clientIP trusts X-Real-IP only from a local reverse proxy (see scripts/reverse-proxy-setup.sh).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}
	return host
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
