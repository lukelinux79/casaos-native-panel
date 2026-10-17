package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lukelinux79/casaos-native-panel/internal/auth"
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

func newTestServer(rt runtime.Runtime, cfg auth.Config) http.Handler {
	return NewServer(rt, cfg, "does-not-exist").Handler()
}

func do(h http.Handler, method, path, body, contentType string, setAuth func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if setAuth != nil {
		setAuth(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBasicAuth(t *testing.T) {
	h := newTestServer(&fakeRuntime{}, auth.Config{Enabled: true, Username: "admin", Password: "secret123"})

	if rec := do(h, "GET", "/api/v1/health", "", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: got %d", rec.Code)
	}
	wrong := func(r *http.Request) { r.SetBasicAuth("admin", "nope") }
	if rec := do(h, "GET", "/api/v1/health", "", "", wrong); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", rec.Code)
	}
	right := func(r *http.Request) { r.SetBasicAuth("admin", "secret123") }
	if rec := do(h, "GET", "/api/v1/health", "", "", right); rec.Code != http.StatusOK {
		t.Fatalf("valid credentials: got %d", rec.Code)
	}
}

func TestMutationsRequireJSON(t *testing.T) {
	h := newTestServer(&fakeRuntime{}, auth.Config{})
	rec := do(h, "POST", "/api/v1/users", "username=x", "application/x-www-form-urlencoded", nil)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: got %d", rec.Code)
	}
}

func TestCreateUser(t *testing.T) {
	rt := &fakeRuntime{}
	h := newTestServer(rt, auth.Config{})
	rec := do(h, "POST", "/api/v1/users", `{"username":"alice","password":"pw123456","groups":["users"],"samba":true}`, "application/json", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	if rt.created.Username != "alice" || !rt.created.Samba || len(rt.created.Groups) != 1 {
		t.Fatalf("runtime got %+v", rt.created)
	}
	if strings.Contains(rec.Body.String(), "pw123456") {
		t.Fatal("password echoed in response")
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
		h := newTestServer(&fakeRuntime{err: c.err}, auth.Config{})
		rec := do(h, "POST", "/api/v1/users", `{}`, "application/json", nil)
		if rec.Code != c.want {
			t.Errorf("%v: got %d, want %d", c.err, rec.Code, c.want)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestServer(&fakeRuntime{}, auth.Config{})
	if rec := do(h, "DELETE", "/api/v1/dashboard", "", "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}
