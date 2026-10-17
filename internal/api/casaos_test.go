package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukelinux79/casaos-native-panel/internal/accounts"
	"github.com/lukelinux79/casaos-native-panel/internal/casaos"
)

// fakeJWKS serves a CasaOS-like user service and returns a client and a token signer.
func fakeJWKS(t *testing.T) (*casaos.Client, func(user, iss string) string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		}}})
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "user-service.url"), []byte(srv.URL), 0o644)
	sign := func(user, iss string) string {
		enc := func(v any) string { d, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(d) }
		in := enc(map[string]string{"alg": "ES256"}) + "." + enc(map[string]any{"username": user, "iss": iss, "exp": time.Now().Add(time.Hour).Unix()})
		h := sha256.Sum256([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		return in + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
	}
	return casaos.New(dir), sign
}

func newCasaEnv(t *testing.T) (http.Handler, func(user, iss string) string) {
	t.Helper()
	store, _ := accounts.Open(filepath.Join(t.TempDir(), "accounts.json"))
	_ = store.Create("anna", "password123", accounts.RoleOperator)
	casa, sign := fakeJWKS(t)
	srv := NewServer(Options{Runtime: &fakeRuntime{}, Accounts: store, WebDir: "does-not-exist", CasaOS: casa, BasePath: "/panel"})
	return srv.Handler(), sign
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCasaOSLogin(t *testing.T) {
	h, sign := newCasaEnv(t)

	rec := post(h, "/panel/api/v1/auth/casaos", `{"token":"`+sign("anna", "casaos")+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"operator"`) {
		t.Fatalf("valid token: %d %s", rec.Code, rec.Body)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("no session cookie after CasaOS login")
	}
	if rec := post(h, "/api/v1/auth/casaos", `{"token":"`+sign("mallory", "casaos")+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown panel account: %d", rec.Code)
	}
	if rec := post(h, "/api/v1/auth/casaos", `{"token":"`+sign("anna", "refresh")+`"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh token accepted: %d", rec.Code)
	}
}

func TestCasaOSLoginDisabled(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "POST", path: "/api/v1/auth/casaos", body: `{"token":"x"}`}); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBasePath(t *testing.T) {
	h, _ := newCasaEnv(t)
	for path, want := range map[string]int{
		"/panel/api/v1/health":  http.StatusOK,
		"/api/v1/health":        http.StatusOK,
		"/panel":                http.StatusMovedPermanently,
		"/panelx/api/v1/health": http.StatusNotFound,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: got %d, want %d", path, rec.Code, want)
		}
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote, realIP, xff, want string
	}{
		{"192.0.2.7:1234", "", "", "192.0.2.7"},
		{"192.0.2.7:1234", "10.0.0.1", "10.0.0.2", "192.0.2.7"}, // headers from outside are ignored
		{"127.0.0.1:1234", "198.51.100.4", "", "198.51.100.4"},  // nginx
		{"127.0.0.1:1234", "", "198.51.100.5", "198.51.100.5"},  // CasaOS gateway
		{"127.0.0.1:1234", "", "1.1.1.1, 198.51.100.6", "198.51.100.6"},
		{"127.0.0.1:1234", "", "198.51.100.7, 127.0.0.1", "198.51.100.7"},          // nginx -> CasaOS gateway -> panel
		{"127.0.0.1:1234", "", "6.6.6.6, 198.51.100.8, 127.0.0.1", "198.51.100.8"}, // spoofed first hop is ignored
		{"[::1]:1234", "", "198.51.100.9", "198.51.100.9"},
		{"127.0.0.1:1234", "", "", "127.0.0.1"},
		{"127.0.0.1:1234", "", "127.0.0.1", "127.0.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.realIP != "" {
			r.Header.Set("X-Real-IP", c.realIP)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}
