package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lukelinux79/casaos-native-panel/internal/accounts"
	"github.com/lukelinux79/casaos-native-panel/internal/audit"
	"github.com/lukelinux79/casaos-native-panel/internal/runtime"
	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

// fakeRuntime records calls and returns a configurable error.
type fakeRuntime struct {
	runtime.DockerRuntime
	created runtime.NewUser
	err     error
}

func (f *fakeRuntime) CreateUser(u runtime.NewUser) error {
	f.created = u
	return f.err
}

func (f *fakeRuntime) GetUsers() ([]runtime.User, error) {
	return []runtime.User{
		{Username: "mainuser", UID: 1000, Groups: []string{"mainuser", "sudo"}},
		{Username: "carla", UID: 1001, Groups: []string{"carla", "users"}},
	}, nil
}

func (f *fakeRuntime) SetPassword(string, string) error       { return nil }
func (f *fakeRuntime) AddGroupMember(string, string) error    { return nil }
func (f *fakeRuntime) RemoveGroupMember(string, string) error { return nil }

type testEnv struct {
	h     http.Handler
	rt    *fakeRuntime
	store *accounts.Store
	audit *audit.Logger
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := accounts.Open(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, role := range map[string]accounts.Role{"boss": accounts.RoleAdmin, "op": accounts.RoleOperator, "guest": accounts.RoleViewer} {
		if err := store.Create(name, "password123", role); err != nil {
			t.Fatal(err)
		}
	}
	rt := &fakeRuntime{}
	lg := audit.New(filepath.Join(dir, "audit.log"))
	srv := NewServer(Options{Runtime: rt, Accounts: store, Audit: lg, WebDir: "does-not-exist"})
	return &testEnv{h: srv.Handler(), rt: rt, store: store, audit: lg}
}

type req struct {
	method, path, body, contentType string
	cookie                          *http.Cookie
	basicUser, basicPass            string
}

func (e *testEnv) do(r req) *httptest.ResponseRecorder {
	hr := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
	if r.body != "" && r.contentType == "" {
		r.contentType = "application/json"
	}
	if r.contentType != "" {
		hr.Header.Set("Content-Type", r.contentType)
	}
	if r.cookie != nil {
		hr.AddCookie(r.cookie)
	}
	if r.basicUser != "" {
		hr.SetBasicAuth(r.basicUser, r.basicPass)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	return rec
}

func (e *testEnv) login(t *testing.T, user string) *http.Cookie {
	t.Helper()
	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"` + user + `","password":"password123"}`})
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie not hardened: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestLoginRequired(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous dashboard: %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/health"}); rec.Code != http.StatusOK {
		t.Fatalf("health should be public: %d", rec.Code)
	}
	c := e.login(t, "guest")
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard", cookie: c}); rec.Code != http.StatusOK {
		t.Fatalf("dashboard with session: %d", rec.Code)
	}
	rec := e.do(req{method: "GET", path: "/api/v1/auth/me", cookie: c})
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["username"] != "guest" || me["role"] != "viewer" {
		t.Fatalf("me: %v", me)
	}
}

func TestRoles(t *testing.T) {
	e := newEnv(t)
	guest, op, boss := e.login(t, "guest"), e.login(t, "op"), e.login(t, "boss")
	createUser := `{"username":"alice","password":"pw123456"}`

	cases := []struct {
		name   string
		r      req
		status int
	}{
		{"viewer cannot create users", req{method: "POST", path: "/api/v1/users", body: createUser, cookie: guest}, http.StatusForbidden},
		{"operator can create users", req{method: "POST", path: "/api/v1/users", body: createUser, cookie: op}, http.StatusCreated},
		{"operator cannot read raw smb.conf", req{method: "GET", path: "/api/v1/samba/config", cookie: op}, http.StatusForbidden},
		{"operator cannot list panel accounts", req{method: "GET", path: "/api/v1/accounts", cookie: op}, http.StatusForbidden},
		{"viewer cannot read logs", req{method: "GET", path: "/api/v1/logs", cookie: guest}, http.StatusForbidden},
		{"admin can list panel accounts", req{method: "GET", path: "/api/v1/accounts", cookie: boss}, http.StatusOK},
		{"admin can read audit", req{method: "GET", path: "/api/v1/audit", cookie: boss}, http.StatusOK},
	}
	for _, c := range cases {
		if rec := e.do(c.r); rec.Code != c.status {
			t.Errorf("%s: got %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body)
		}
	}
}

func TestBasicAuthAndLockout(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "GET", path: "/api/v1/users", basicUser: "op", basicPass: "password123"}); rec.Code != http.StatusOK {
		t.Fatalf("basic auth: %d", rec.Code)
	}
	for i := 0; i < 5; i++ {
		e.do(req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"boss","password":"wrong-password"}`})
	}
	rec := e.do(req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"boss","password":"password123"}`})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login after 5 failures: %d", rec.Code)
	}
}

func TestMutationsRequireJSON(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, "boss")
	rec := e.do(req{method: "POST", path: "/api/v1/users", body: "username=x", contentType: "application/x-www-form-urlencoded", cookie: c})
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: got %d", rec.Code)
	}
}

func TestCreateUserAndAudit(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, "op")
	rec := e.do(req{method: "POST", path: "/api/v1/users", body: `{"username":"alice","password":"pw123456","groups":["users"],"samba":true}`, cookie: c})
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	if e.rt.created.Username != "alice" || !e.rt.created.Samba || len(e.rt.created.Groups) != 1 {
		t.Fatalf("runtime got %+v", e.rt.created)
	}
	if strings.Contains(rec.Body.String(), "pw123456") {
		t.Fatal("password echoed in response")
	}
	entries, _ := e.audit.Recent(10)
	if len(entries) == 0 || entries[0].Action != "user.create" || entries[0].User != "op" || entries[0].Status != http.StatusCreated {
		t.Fatalf("audit entry missing: %+v", entries)
	}
}

func TestAccountManagement(t *testing.T) {
	e := newEnv(t)
	boss := e.login(t, "boss")
	guest := e.login(t, "guest")

	if rec := e.do(req{method: "DELETE", path: "/api/v1/accounts/boss", cookie: boss}); rec.Code != http.StatusConflict {
		t.Fatalf("self delete: %d", rec.Code)
	}
	if rec := e.do(req{method: "PUT", path: "/api/v1/accounts/guest", body: `{"role":"operator"}`, cookie: boss}); rec.Code != http.StatusOK {
		t.Fatalf("role change: %d %s", rec.Code, rec.Body)
	}
	// Role changes apply to existing sessions immediately.
	if rec := e.do(req{method: "GET", path: "/api/v1/logs", cookie: guest}); rec.Code == http.StatusForbidden {
		t.Fatal("promoted session still has old role")
	}
	if rec := e.do(req{method: "DELETE", path: "/api/v1/accounts/guest", cookie: boss}); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard", cookie: guest}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session of deleted account still valid: %d", rec.Code)
	}
	if rec := e.do(req{method: "PUT", path: "/api/v1/accounts/boss", body: `{"role":"viewer"}`, cookie: boss}); rec.Code != http.StatusConflict {
		t.Fatalf("demote last admin: %d", rec.Code)
	}
}

func TestChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, "guest")
	other := e.login(t, "guest")
	if rec := e.do(req{method: "PUT", path: "/api/v1/auth/password", body: `{"current_password":"nope-nope","new_password":"newpass123"}`, cookie: c}); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong current password: %d", rec.Code)
	}
	if rec := e.do(req{method: "PUT", path: "/api/v1/auth/password", body: `{"current_password":"password123","new_password":"newpass123"}`, cookie: c}); rec.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard", cookie: other}); rec.Code != http.StatusUnauthorized {
		t.Fatal("other session survived password change")
	}
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard", cookie: c}); rec.Code != http.StatusOK {
		t.Fatal("current session ended by own password change")
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, "guest")
	e.do(req{method: "POST", path: "/api/v1/auth/logout", body: `{}`, cookie: c})
	if rec := e.do(req{method: "GET", path: "/api/v1/dashboard", cookie: c}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session valid after logout: %d", rec.Code)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{validate.Errorf("bad"), http.StatusBadRequest},
		{runtime.ErrForbidden, http.StatusForbidden},
		{runtime.ErrNotFound, http.StatusNotFound},
		{runtime.ErrSambaMissing, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		e := newEnv(t)
		e.rt.err = c.err
		rec := e.do(req{method: "POST", path: "/api/v1/users", body: `{}`, basicUser: "op", basicPass: "password123"})
		if rec.Code != c.want {
			t.Errorf("%v: got %d, want %d", c.err, rec.Code, c.want)
		}
	}
}

func TestAuthDisabled(t *testing.T) {
	store, _ := accounts.Open(filepath.Join(t.TempDir(), "accounts.json"))
	srv := NewServer(Options{Runtime: &fakeRuntime{}, Accounts: store, AuthDisabled: true, WebDir: "does-not-exist"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/accounts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("auth disabled: %d", rec.Code)
	}
}

func TestOperatorCannotEscalate(t *testing.T) {
	e := newEnv(t)
	op, boss := e.login(t, "op"), e.login(t, "boss")
	cases := []struct {
		name string
		r    req
	}{
		{"create sudo user", req{method: "POST", path: "/api/v1/users", body: `{"username":"evil","password":"pw123456","groups":["sudo"]}`}},
		{"add member to sudo", req{method: "POST", path: "/api/v1/groups/sudo/members", body: `{"user":"carla"}`}},
		{"remove member from sudo", req{method: "DELETE", path: "/api/v1/groups/sudo/members/mainuser"}},
		{"reset password of sudo user", req{method: "PUT", path: "/api/v1/users/mainuser/password", body: `{"password":"pw123456"}`}},
		{"delete sudo user", req{method: "DELETE", path: "/api/v1/users/mainuser"}},
	}
	for _, c := range cases {
		r := c.r
		r.cookie = op
		if rec := e.do(r); rec.Code != http.StatusForbidden {
			t.Errorf("operator %s: got %d, want 403", c.name, rec.Code)
		}
	}
	// Normal users stay manageable for operators, privileged ones for admins.
	if rec := e.do(req{method: "PUT", path: "/api/v1/users/carla/password", body: `{"password":"pw123456"}`, cookie: op}); rec.Code != http.StatusOK {
		t.Errorf("operator on regular user: %d", rec.Code)
	}
	if rec := e.do(req{method: "PUT", path: "/api/v1/users/mainuser/password", body: `{"password":"pw123456"}`, cookie: boss}); rec.Code != http.StatusOK {
		t.Errorf("admin on sudo user: %d", rec.Code)
	}
	if rec := e.do(req{method: "POST", path: "/api/v1/groups/sudo/members", body: `{"user":"carla"}`, cookie: boss}); rec.Code != http.StatusOK {
		t.Errorf("admin add to sudo: %d", rec.Code)
	}
}

// casaRuntime pretends CasaOS runs on the host.
type casaRuntime struct{ fakeRuntime }

func (c *casaRuntime) CasaOSAvailable() bool { return true }
func (c *casaRuntime) GetUsers() ([]runtime.User, error) {
	return []runtime.User{
		{Username: "shelly", UID: 1002, Shell: "/bin/bash"},
		{Username: "nas", UID: 1003, Shell: "/usr/sbin/nologin"},
	}, nil
}

func TestLoginShellsAdminOnlyWithCasaOS(t *testing.T) {
	dir := t.TempDir()
	store, _ := accounts.Open(filepath.Join(dir, "accounts.json"))
	_ = store.Create("op", "password123", accounts.RoleOperator)
	_ = store.Create("boss", "password123", accounts.RoleAdmin)
	e := &testEnv{h: NewServer(Options{Runtime: &casaRuntime{}, Accounts: store, WebDir: "does-not-exist"}).Handler()}
	op, boss := e.login(t, "op"), e.login(t, "boss")

	cases := []struct {
		name   string
		r      req
		status int
	}{
		{"operator creates bash user", req{method: "POST", path: "/api/v1/users", body: `{"username":"x","password":"pw123456","shell":"/bin/bash"}`, cookie: op}, http.StatusForbidden},
		{"operator creates user with default shell", req{method: "POST", path: "/api/v1/users", body: `{"username":"x","password":"pw123456"}`, cookie: op}, http.StatusForbidden},
		{"operator creates nologin user", req{method: "POST", path: "/api/v1/users", body: `{"username":"x","password":"pw123456","shell":"/usr/sbin/nologin"}`, cookie: op}, http.StatusCreated},
		{"operator resets shell user password", req{method: "PUT", path: "/api/v1/users/shelly/password", body: `{"password":"pw123456"}`, cookie: op}, http.StatusForbidden},
		{"operator resets nologin user password", req{method: "PUT", path: "/api/v1/users/nas/password", body: `{"password":"pw123456"}`, cookie: op}, http.StatusOK},
		{"admin creates bash user", req{method: "POST", path: "/api/v1/users", body: `{"username":"y","password":"pw123456","shell":"/bin/bash"}`, cookie: boss}, http.StatusCreated},
	}
	for _, c := range cases {
		if rec := e.do(c.r); rec.Code != c.status {
			t.Errorf("%s: got %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body)
		}
	}
}

type shareRuntime struct{ fakeRuntime }

func (s *shareRuntime) GetShares() ([]runtime.Share, error) {
	return []runtime.Share{{Name: "Fotos", ValidUsers: []string{"@family"}}, {Name: "Misc", ValidUsers: []string{"family"}}}, nil
}
func (s *shareRuntime) DeleteGroup(string) error { return nil }

func TestDeleteGroupUsedByShare(t *testing.T) {
	store, _ := accounts.Open(filepath.Join(t.TempDir(), "accounts.json"))
	_ = store.Create("op", "password123", accounts.RoleOperator)
	e := &testEnv{h: NewServer(Options{Runtime: &shareRuntime{}, Accounts: store, WebDir: "does-not-exist"}).Handler()}
	c := e.login(t, "op")
	rec := e.do(req{method: "DELETE", path: "/api/v1/groups/family", cookie: c})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Fotos") || strings.Contains(rec.Body.String(), "Misc") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(req{method: "DELETE", path: "/api/v1/groups/family?force=true", cookie: c}); rec.Code != http.StatusOK {
		t.Fatalf("force delete: %d", rec.Code)
	}
}
