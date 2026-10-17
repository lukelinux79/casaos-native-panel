package casaos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCasaOS struct {
	mu     sync.Mutex
	routes []route
	shares []Share
	key    *ecdsa.PrivateKey
}

func newFake(t *testing.T) (*Client, *fakeCasaOS) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCasaOS{key: key, shares: []Share{{ID: 1, Anonymous: true, Path: "/DATA/Media"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/gateway/routes", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.routes)
	})
	mux.HandleFunc("POST /v1/gateway/routes", func(w http.ResponseWriter, r *http.Request) {
		var rt route
		_ = json.NewDecoder(r.Body).Decode(&rt)
		f.mu.Lock()
		f.routes = append(f.routes, rt)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /v1/samba/shares", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		data, _ := json.Marshal(f.shares)
		_ = json.NewEncoder(w).Encode(result{Success: 200, Data: data})
	})
	mux.HandleFunc("DELETE /v1/samba/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.shares = nil
		_ = json.NewEncoder(w).Encode(result{Success: 200})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := f.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	for _, name := range []string{"management.url", "casaos.url", "user-service.url"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(srv.URL+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return New(dir), f
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signing := enc(map[string]string{"alg": alg, "typ": "JWT"}) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAvailable(t *testing.T) {
	c, _ := newFake(t)
	if !c.Available() {
		t.Fatal("fake CasaOS not detected")
	}
	if New(t.TempDir()).Available() {
		t.Fatal("empty runtime dir detected as CasaOS")
	}
}

func TestServiceURLRejectsRemoteHosts(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "casaos.url"), []byte("http://192.0.2.10:8080"), 0o644)
	if _, err := New(dir).serviceURL("casaos.url"); err == nil {
		t.Fatal("non-loopback CasaOS address accepted")
	}
}

func TestEnsureRouteIsIdempotent(t *testing.T) {
	c, f := newFake(t)
	for i, want := range []bool{true, false} {
		created, err := c.EnsureRoute("/panel", "http://127.0.0.1:8080")
		if err != nil || created != want {
			t.Fatalf("call %d: created=%v err=%v", i, created, err)
		}
	}
	if len(f.routes) != 1 {
		t.Fatalf("routes: %+v", f.routes)
	}
}

func TestSharesAndDelete(t *testing.T) {
	c, _ := newFake(t)
	shares, err := c.Shares()
	if err != nil || len(shares) != 1 || shares[0].Path != "/DATA/Media" || !shares[0].Anonymous {
		t.Fatalf("shares: %+v %v", shares, err)
	}
	if err := c.DeleteShare(shares[0].ID); err != nil {
		t.Fatal(err)
	}
	if shares, _ := c.Shares(); len(shares) != 0 {
		t.Fatalf("share not deleted: %+v", shares)
	}
}

func TestVerifyToken(t *testing.T) {
	c, f := newFake(t)
	now := time.Now()
	valid := map[string]any{"username": "anna", "id": 1, "iss": "casaos", "exp": now.Add(time.Hour).Unix()}

	if user, err := c.VerifyToken(signToken(t, f.key, "ES256", valid)); err != nil || user != "anna" {
		t.Fatalf("valid token: %q %v", user, err)
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	refresh := map[string]any{"username": "anna", "iss": "refresh", "exp": now.Add(time.Hour).Unix()}
	expired := map[string]any{"username": "anna", "iss": "casaos", "exp": now.Add(-time.Minute).Unix()}
	noExp := map[string]any{"username": "anna", "iss": "casaos"}
	good := signToken(t, f.key, "ES256", valid)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"username":"root","iss":"casaos","exp":9999999999}`)) + "." + parts[2]

	for name, tok := range map[string]string{
		"foreign key":     signToken(t, other, "ES256", valid),
		"refresh token":   signToken(t, f.key, "ES256", refresh),
		"expired":         signToken(t, f.key, "ES256", expired),
		"no expiry":       signToken(t, f.key, "ES256", noExp),
		"alg none":        strings.Replace(good, parts[0], base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)), 1),
		"tampered claims": tampered,
		"garbage":         "not-a-token",
	} {
		if _, err := c.VerifyToken(tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: got %v, want ErrInvalidToken", name, err)
		}
	}
}
