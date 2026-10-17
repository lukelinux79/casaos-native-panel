package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lukelinux79/casaos-native-panel/internal/samba"
	sys "github.com/lukelinux79/casaos-native-panel/internal/system"
	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

const smbConfPath = "/etc/samba/smb.conf"

func (s *SystemRuntime) GetSambaConfig() (string, error) {
	content, err := os.ReadFile(smbConfPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrSambaMissing
	}
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// SaveSambaConfig validates the config with testparm, keeps a backup and reloads smbd.
func (s *SystemRuntime) SaveSambaConfig(content string) error {
	s.sambaMu.Lock()
	defer s.sambaMu.Unlock()
	return sys.SaveSambaConfig(content)
}

func (s *SystemRuntime) CasaOSAvailable() bool {
	return s.casa != nil && s.casa.Available()
}

// withCasaOS reports whether smb.conf must stay compatible with CasaOS.
func (s *SystemRuntime) withCasaOS() bool {
	if _, err := os.Stat(samba.CasaOSInclude); err == nil {
		return true
	}
	return s.CasaOSAvailable()
}

// casaOSShares returns the shares CasaOS wrote to smb.casa.conf, keyed by lowercase name.
func casaOSShares() map[string]Share {
	out := map[string]Share{}
	content, err := os.ReadFile(samba.CasaOSInclude)
	if err != nil {
		return out
	}
	for _, sh := range samba.Parse(string(content)).Shares() {
		sh.ManagedBy = "casaos"
		out[strings.ToLower(sh.Name)] = sh
	}
	return out
}

func shareWarnings(sh Share) []string {
	var w []string
	switch {
	case sh.GuestOK && !sh.ReadOnly:
		w = append(w, "anyone on the network can read and write without a password")
	case sh.GuestOK:
		w = append(w, "anyone on the network can read without a password")
	}
	if sh.ForceUser == "root" {
		w = append(w, "all file access runs as root")
	}
	return w
}

func (s *SystemRuntime) GetShares() ([]Share, error) {
	content, err := s.GetSambaConfig()
	if err != nil {
		return nil, err
	}
	shares := samba.Parse(content).Shares()
	for _, sh := range casaOSShares() {
		shares = append(shares, sh)
	}
	for i := range shares {
		shares[i].Warnings = shareWarnings(shares[i])
	}
	return shares, nil
}

func (s *SystemRuntime) SaveShare(sh Share) error {
	if err := validateShare(sh); err != nil {
		return err
	}
	if _, managed := casaOSShares()[strings.ToLower(sh.Name)]; managed {
		return validate.Errorf("share name %q is used by a CasaOS share; secure that share instead or choose another name", sh.Name)
	}
	if info, err := os.Stat(sh.Path); err != nil || !info.IsDir() {
		return validate.Errorf("share path %q does not exist or is not a directory", sh.Path)
	}
	if real, err := filepath.EvalSymlinks(sh.Path); err != nil {
		return err
	} else if err := validate.ResolvedSharePath(real); err != nil {
		return err
	}
	return s.editSambaConfig(func(c *samba.Config) error {
		c.SetShare(sh)
		return nil
	})
}

func (s *SystemRuntime) DeleteShare(name string) error {
	if err := validate.ShareName(name); err != nil {
		return err
	}
	if _, managed := casaOSShares()[strings.ToLower(name)]; managed {
		return validate.Errorf("share %q is managed by CasaOS; remove it in CasaOS or secure it here", name)
	}
	return s.editSambaConfig(func(c *samba.Config) error {
		if !c.RemoveShare(name) {
			return fmt.Errorf("share %q: %w", name, ErrNotFound)
		}
		return nil
	})
}

func (s *SystemRuntime) editSambaConfig(edit func(*samba.Config) error) error {
	s.sambaMu.Lock()
	defer s.sambaMu.Unlock()

	content, err := s.GetSambaConfig()
	if err != nil {
		return err
	}
	c := samba.Parse(content)
	if err := edit(c); err != nil {
		return err
	}
	if s.withCasaOS() {
		// Keep CasaOS from replacing smb.conf, and keep its shares included.
		c.EnsureCasaOSCompat()
		if _, err := os.Stat(samba.CasaOSInclude); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(samba.CasaOSInclude, nil, 0o644); err != nil {
				return err
			}
		}
	}
	return sys.SaveSambaConfig(c.String())
}

// AdoptShare takes a share away from CasaOS and recreates it under the same
// name and path with the given access rules. If that fails, the CasaOS share
// is restored.
func (s *SystemRuntime) AdoptShare(name string, sh Share) error {
	if !s.CasaOSAvailable() {
		return fmt.Errorf("CasaOS is not running: %w", ErrUnsupported)
	}
	old, ok := casaOSShares()[strings.ToLower(name)]
	if !ok {
		return fmt.Errorf("CasaOS share %q: %w", name, ErrNotFound)
	}
	sh.Name, sh.Path = old.Name, old.Path
	if err := validateShare(sh); err != nil {
		return err
	}
	list, err := s.casa.Shares()
	if err != nil {
		return err
	}
	id, anonymous := -1, false
	for _, c := range list {
		if c.Path == old.Path {
			id, anonymous = c.ID, c.Anonymous
		}
	}
	if id < 0 {
		return fmt.Errorf("CasaOS share for %s: %w", old.Path, ErrNotFound)
	}
	if err := s.casa.DeleteShare(id); err != nil {
		return err
	}
	err = s.SaveShare(sh)
	var reload *sys.ReloadError
	if err == nil || errors.As(err, &reload) {
		return err
	}
	if rerr := s.casa.CreateShare(old.Path, anonymous); rerr != nil {
		return fmt.Errorf("%v (restoring the CasaOS share also failed: %v)", err, rerr)
	}
	return fmt.Errorf("%w (the CasaOS share was restored)", err)
}

func (s *SystemRuntime) GetSambaUsers() ([]string, error) {
	if _, err := exec.LookPath("pdbedit"); err != nil {
		return nil, ErrSambaMissing
	}
	out, err := shellOut("pdbedit", "-L")
	if err != nil {
		return nil, err
	}
	users := []string{}
	for _, line := range strings.Split(out, "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && name != "" {
			users = append(users, name)
		}
	}
	return users, nil
}

// SetSambaPassword adds the Samba login for an existing Linux user or changes its password.
func (s *SystemRuntime) SetSambaPassword(name, password string) error {
	if err := requireRegularAccount("passwd", "user", name); err != nil {
		return err
	}
	if err := validate.Password(password); err != nil {
		return err
	}
	if _, err := exec.LookPath("smbpasswd"); err != nil {
		return ErrSambaMissing
	}
	return setSambaPassword(name, password)
}

func (s *SystemRuntime) DeleteSambaUser(name string) error {
	if err := validate.Username(name); err != nil {
		return err
	}
	if _, err := exec.LookPath("smbpasswd"); err != nil {
		return ErrSambaMissing
	}
	return run("", "smbpasswd", "-x", name)
}

func setSambaPassword(name, password string) error {
	if err := run(password+"\n"+password+"\n", "smbpasswd", "-a", "-s", name); err != nil {
		return err
	}
	return run("", "smbpasswd", "-e", name)
}

func validateShare(sh Share) error {
	if err := validate.ShareName(sh.Name); err != nil {
		return err
	}
	if err := validate.SharePath(sh.Path); err != nil {
		return err
	}
	if err := validate.SingleLine("comment", sh.Comment); err != nil {
		return err
	}
	for _, p := range append(append([]string{}, sh.ValidUsers...), sh.WriteList...) {
		if err := validate.Principal(p); err != nil {
			return err
		}
	}
	return nil
}
