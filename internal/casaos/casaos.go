// Package casaos integrates the panel with a local CasaOS installation:
// it registers the panel at the CasaOS gateway, reads and removes CasaOS
// Samba shares and verifies CasaOS login tokens for single sign-on.
//
// CasaOS services publish their addresses in files under the runtime
// directory (default /var/run/casaos); the panel uses these local addresses.
package casaos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultRuntimeDir = "/var/run/casaos"

var ErrNotInstalled = errors.New("CasaOS is not running on this host")

// Client talks to the CasaOS services on this host.
type Client struct {
	runtimeDir string
	http       *http.Client
	jwks       *jwksCache
}

func New(runtimeDir string) *Client {
	if runtimeDir == "" {
		runtimeDir = DefaultRuntimeDir
	}
	c := &Client{runtimeDir: runtimeDir, http: &http.Client{Timeout: 5 * time.Second}}
	c.jwks = &jwksCache{client: c}
	return c
}

// Available reports whether the CasaOS gateway and core service are running.
func (c *Client) Available() bool {
	_, err1 := c.serviceURL("management.url")
	_, err2 := c.serviceURL("casaos.url")
	return err1 == nil && err2 == nil
}

// serviceURL reads a service address and only accepts loopback targets, so a
// tampered file cannot make the panel send requests to other hosts.
func (c *Client) serviceURL(file string) (string, error) {
	data, err := os.ReadFile(filepath.Join(c.runtimeDir, file))
	if err != nil {
		return "", ErrNotInstalled
	}
	raw := strings.TrimSpace(string(data))
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return "", fmt.Errorf("invalid CasaOS address in %s", file)
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("CasaOS address in %s is not a loopback address", file)
	}
	return strings.TrimRight(raw, "/"), nil
}

type route struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// EnsureRoute registers path at the gateway unless it already points to target.
// The gateway keeps routes only in its runtime directory, so this must be
// repeated after CasaOS restarts (see KeepRoute).
func (c *Client) EnsureRoute(path, target string) (bool, error) {
	base, err := c.serviceURL("management.url")
	if err != nil {
		return false, err
	}
	var routes []route
	if err := c.getJSON(base+"/v1/gateway/routes", &routes); err != nil {
		return false, err
	}
	for _, r := range routes {
		if r.Path == path && r.Target == target {
			return false, nil
		}
	}
	if err := c.sendJSON(http.MethodPost, base+"/v1/gateway/routes", route{Path: path, Target: target}, nil); err != nil {
		return false, fmt.Errorf("register gateway route: %w", err)
	}
	return true, nil
}

// KeepRoute re-registers the route periodically until stop is closed. While
// CasaOS is unreachable (e.g. still booting) it retries every few seconds.
func (c *Client) KeepRoute(path, target string, interval time.Duration, logf func(string, ...any), stop <-chan struct{}) {
	lastErr := ""
	for {
		created, err := c.EnsureRoute(path, target)
		wait := interval
		if err != nil && interval > 5*time.Second {
			wait = 5 * time.Second
		}
		switch {
		case err != nil && err.Error() != lastErr:
			logf("CasaOS gateway: %v", err)
			lastErr = err.Error()
		case err == nil && created:
			logf("CasaOS gateway: panel registered at %s", path)
			lastErr = ""
		case err == nil:
			lastErr = ""
		}
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}

// Share is a share managed by CasaOS (stored in its database).
type Share struct {
	ID        int    `json:"id"`
	Anonymous bool   `json:"anonymous"`
	Path      string `json:"path"`
}

type result struct {
	Success int             `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (c *Client) Shares() ([]Share, error) {
	base, err := c.serviceURL("casaos.url")
	if err != nil {
		return nil, err
	}
	var res result
	if err := c.getJSON(base+"/v1/samba/shares", &res); err != nil {
		return nil, err
	}
	var shares []Share
	if err := json.Unmarshal(res.Data, &shares); err != nil {
		return nil, fmt.Errorf("unexpected CasaOS share list: %w", err)
	}
	return shares, nil
}

// DeleteShare removes a share from CasaOS; CasaOS then rewrites
// /etc/samba/smb.casa.conf and restarts smbd.
func (c *Client) DeleteShare(id int) error {
	base, err := c.serviceURL("casaos.url")
	if err != nil {
		return err
	}
	return c.sendJSON(http.MethodDelete, fmt.Sprintf("%s/v1/samba/shares/%d", base, id), nil, nil)
}

// CreateShare is used to restore a CasaOS share if taking it over fails.
func (c *Client) CreateShare(path string, anonymous bool) error {
	base, err := c.serviceURL("casaos.url")
	if err != nil {
		return err
	}
	return c.sendJSON(http.MethodPost, base+"/v1/samba/shares", []Share{{Path: path, Anonymous: anonymous}}, nil)
}

func (c *Client) getJSON(u string, out any) error {
	return c.sendJSON(http.MethodGet, u, nil, out)
}

func (c *Client) sendJSON(method, u string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("CasaOS %s %s: HTTP %d: %s", method, u, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("CasaOS %s %s: %w", method, u, err)
		}
	}
	return nil
}
