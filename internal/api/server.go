package api

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lukelinux79/casaos-native-panel/internal/auth"
	"github.com/lukelinux79/casaos-native-panel/internal/runtime"
	"github.com/lukelinux79/casaos-native-panel/internal/system"
	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

const maxBodyBytes = 1 << 20

type Server struct {
	runtime runtime.Runtime
	authCfg auth.Config
	webDir  string
}

type response map[string]any

func NewServer(r runtime.Runtime, authCfg auth.Config, webDir string) *Server {
	return &Server{runtime: r, authCfg: authCfg, webDir: webDir}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/health", s.handleHealth)
	api.HandleFunc("GET /api/v1/system/overview", s.handleOverview)
	api.HandleFunc("GET /api/v1/system/jobs", s.handleJobs)
	api.HandleFunc("GET /api/v1/dashboard", s.handleDashboard)

	api.HandleFunc("GET /api/v1/services", s.handleServices)
	api.HandleFunc("POST /api/v1/services/{name}/{action}", s.handleServiceAction)
	api.HandleFunc("GET /api/v1/packages", s.handlePackages)

	api.HandleFunc("GET /api/v1/users", s.handleListUsers)
	api.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	api.HandleFunc("DELETE /api/v1/users/{name}", s.handleDeleteUser)
	api.HandleFunc("PUT /api/v1/users/{name}/password", s.handleSetPassword)

	api.HandleFunc("GET /api/v1/groups", s.handleListGroups)
	api.HandleFunc("POST /api/v1/groups", s.handleCreateGroup)
	api.HandleFunc("DELETE /api/v1/groups/{name}", s.handleDeleteGroup)
	api.HandleFunc("POST /api/v1/groups/{name}/members", s.handleAddMember)
	api.HandleFunc("DELETE /api/v1/groups/{name}/members/{user}", s.handleRemoveMember)

	api.HandleFunc("GET /api/v1/samba/config", s.handleGetSambaConfig)
	api.HandleFunc("PUT /api/v1/samba/config", s.handleSaveSambaConfig)
	api.HandleFunc("POST /api/v1/samba/config", s.handleSaveSambaConfig)
	api.HandleFunc("GET /api/v1/samba/shares", s.handleListShares)
	api.HandleFunc("PUT /api/v1/samba/shares/{name}", s.handleSaveShare)
	api.HandleFunc("DELETE /api/v1/samba/shares/{name}", s.handleDeleteShare)
	api.HandleFunc("GET /api/v1/samba/users", s.handleListSambaUsers)
	api.HandleFunc("PUT /api/v1/samba/users/{name}", s.handleSetSambaPassword)
	api.HandleFunc("DELETE /api/v1/samba/users/{name}", s.handleDeleteSambaUser)

	var apiHandler http.Handler = requireJSON(api)
	if s.authCfg.Enabled {
		apiHandler = withBasicAuth(apiHandler, s.authCfg)
	}
	mux.Handle("/api/", apiHandler)

	if _, err := os.Stat(s.webDir); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(s.webDir)))
	} else {
		mux.HandleFunc("/", s.handleRoot)
	}

	return mux
}

func withBasicAuth(next http.Handler, cfg auth.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !cfg.Check(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="CasaOS Native Panel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireJSON rejects POST/PUT bodies that are not JSON. Browsers cannot send
// cross-site JSON without a CORS preflight, so this blocks CSRF via HTML forms.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, response{"error": "Content-Type must be application/json"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps runtime and validation errors to HTTP status codes.
func writeError(w http.ResponseWriter, err error) {
	var verr *validate.Error
	status := http.StatusInternalServerError
	switch {
	case errors.As(err, &verr):
		status = http.StatusBadRequest
	case errors.Is(err, runtime.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, runtime.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, runtime.ErrUnsupported):
		status = http.StatusNotImplemented
	case errors.Is(err, runtime.ErrSambaMissing):
		status = http.StatusServiceUnavailable
	case strings.Contains(err.Error(), "testparm"):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, response{"error": err.Error()})
}

// writeSambaResult treats a failed smbd reload as success with a warning,
// because the config change itself was validated and written.
func writeSambaResult(w http.ResponseWriter, err error, status int, body response) {
	var rerr *system.ReloadError
	if errors.As(err, &rerr) {
		body["warning"] = rerr.Error()
	} else if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, body)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, response{"error": "invalid JSON: " + err.Error()})
		return false
	}
	return true
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "ok", "service": "CasaOS Native Panel"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, response{"status": "ok", "mode": s.runtime.Name()})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := s.runtime.GetOverview()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"data": overview})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, response{"jobs": []any{}})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	overview, err := s.runtime.GetOverview()
	if err != nil {
		writeError(w, err)
		return
	}
	services, err := s.runtime.GetServices()
	if err != nil {
		writeError(w, err)
		return
	}
	metrics, err := s.runtime.GetMetrics()
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, response{"data": response{
		"overview":  overview,
		"services":  services,
		"metrics":   metrics,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}})
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	services, err := s.runtime.GetServices()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"services": services})
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var err error
	switch r.PathValue("action") {
	case "start":
		err = s.runtime.StartService(name)
	case "stop":
		err = s.runtime.StopService(name)
	case "restart":
		err = s.runtime.RestartService(name)
	default:
		err = validate.Errorf("unknown action %q (use start, stop or restart)", r.PathValue("action"))
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "ok"})
}

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	packages, err := s.runtime.GetPackages()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"packages": packages})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.runtime.GetUsers()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var u runtime.NewUser
	if !decode(w, r, &u) {
		return
	}
	if err := s.runtime.CreateUser(u); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response{"status": "created", "username": u.Username})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	removeHome := r.URL.Query().Get("remove_home") == "true"
	if err := s.runtime.DeleteUser(r.PathValue("name"), removeHome); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "deleted"})
}

type passwordPayload struct {
	Password string `json:"password"`
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	var p passwordPayload
	if !decode(w, r, &p) {
		return
	}
	if err := s.runtime.SetPassword(r.PathValue("name"), p.Password); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "updated"})
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.runtime.GetGroups()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"groups": groups})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &p) {
		return
	}
	if err := s.runtime.CreateGroup(p.Name); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response{"status": "created", "name": p.Name})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.runtime.DeleteGroup(r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "deleted"})
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	var p struct {
		User string `json:"user"`
	}
	if !decode(w, r, &p) {
		return
	}
	if err := s.runtime.AddGroupMember(r.PathValue("name"), p.User); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "added"})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	if err := s.runtime.RemoveGroupMember(r.PathValue("name"), r.PathValue("user")); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "removed"})
}

func (s *Server) handleGetSambaConfig(w http.ResponseWriter, r *http.Request) {
	content, err := s.runtime.GetSambaConfig()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"content": content})
}

func (s *Server) handleSaveSambaConfig(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Content string `json:"content"`
	}
	if !decode(w, r, &payload) {
		return
	}
	if strings.TrimSpace(payload.Content) == "" {
		writeJSON(w, http.StatusBadRequest, response{"error": "content is required"})
		return
	}
	err := s.runtime.SaveSambaConfig(payload.Content)
	writeSambaResult(w, err, http.StatusAccepted, response{"status": "saved"})
}

func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request) {
	shares, err := s.runtime.GetShares()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"shares": shares})
}

func (s *Server) handleSaveShare(w http.ResponseWriter, r *http.Request) {
	var sh runtime.Share
	if !decode(w, r, &sh) {
		return
	}
	sh.Name = r.PathValue("name")
	err := s.runtime.SaveShare(sh)
	writeSambaResult(w, err, http.StatusOK, response{"status": "saved", "share": sh})
}

func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	err := s.runtime.DeleteShare(r.PathValue("name"))
	writeSambaResult(w, err, http.StatusOK, response{"status": "deleted"})
}

func (s *Server) handleListSambaUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.runtime.GetSambaUsers()
	if errors.Is(err, runtime.ErrSambaMissing) {
		writeJSON(w, http.StatusOK, response{"users": []string{}, "available": false})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"users": users, "available": true})
}

func (s *Server) handleSetSambaPassword(w http.ResponseWriter, r *http.Request) {
	var p passwordPayload
	if !decode(w, r, &p) {
		return
	}
	if err := s.runtime.SetSambaPassword(r.PathValue("name"), p.Password); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "updated"})
}

func (s *Server) handleDeleteSambaUser(w http.ResponseWriter, r *http.Request) {
	if err := s.runtime.DeleteSambaUser(r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response{"status": "deleted"})
}
