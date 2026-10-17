package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func (s *SystemRuntime) GetShares() ([]Share, error) {
	content, err := s.GetSambaConfig()
	if err != nil {
		return nil, err
	}
	return samba.Parse(content).Shares(), nil
}

func (s *SystemRuntime) SaveShare(sh Share) error {
	if err := validateShare(sh); err != nil {
		return err
	}
	if info, err := os.Stat(sh.Path); err != nil || !info.IsDir() {
		return validate.Errorf("share path %q does not exist or is not a directory", sh.Path)
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
	return sys.SaveSambaConfig(c.String())
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
