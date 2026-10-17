package runtime

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/lukelinux79/casaos-native-panel/internal/validate"
)

// Debian's default UID_MIN/GID_MIN. Accounts below this (and nobody/nogroup)
// belong to the system and are protected from changes in the panel.
const firstRegularID = 1000

func isSystemID(id int) bool { return id < firstRegularID || id == 65534 }

func (s *SystemRuntime) GetUsers() ([]User, error) {
	out, err := shellOut("getent", "passwd")
	if err != nil {
		return nil, err
	}
	groups, _ := s.GetGroups()
	gidName := map[int]string{}
	memberOf := map[string][]string{}
	for _, g := range groups {
		gidName[g.GID] = g.Name
		for _, m := range g.Members {
			memberOf[m] = append(memberOf[m], g.Name)
		}
	}

	lines := strings.Split(out, "\n")
	result := make([]User, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		var userGroups []string
		if name, ok := gidName[gid]; ok {
			userGroups = append(userGroups, name)
		}
		for _, g := range memberOf[fields[0]] {
			if g != gidName[gid] {
				userGroups = append(userGroups, g)
			}
		}
		result = append(result, User{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  fields[5],
			Shell:    fields[6],
			Groups:   userGroups,
			System:   isSystemID(uid),
		})
	}
	return result, nil
}

// CreateUser adds a Linux account with password, optional groups and an
// optional Samba login. If a later step fails the account is removed again.
func (s *SystemRuntime) CreateUser(u NewUser) error {
	if err := validate.Username(u.Username); err != nil {
		return err
	}
	if err := validate.Password(u.Password); err != nil {
		return err
	}
	for _, g := range u.Groups {
		if err := validate.GroupName(g); err != nil {
			return err
		}
	}
	if u.Shell != "" && !isAllowedShell(u.Shell) {
		return validate.Errorf("shell %q is not listed in /etc/shells", u.Shell)
	}
	if u.Samba {
		if _, err := exec.LookPath("smbpasswd"); err != nil {
			return ErrSambaMissing
		}
	}
	if _, exists, err := lookupID("passwd", u.Username); err != nil {
		return err
	} else if exists {
		return validate.Errorf("user %q already exists", u.Username)
	}

	args := []string{"-m"}
	if u.Shell != "" {
		args = append(args, "-s", u.Shell)
	}
	if len(u.Groups) > 0 {
		args = append(args, "-G", strings.Join(u.Groups, ","))
	}
	if err := run("", "useradd", append(args, "--", u.Username)...); err != nil {
		return err
	}

	rollback := func(cause error) error {
		if err := run("", "userdel", "-r", "--", u.Username); err != nil {
			return fmt.Errorf("%v (rollback of user %q also failed: %v)", cause, u.Username, err)
		}
		return cause
	}
	if err := setUnixPassword(u.Username, u.Password); err != nil {
		return rollback(err)
	}
	if u.Samba {
		if err := setSambaPassword(u.Username, u.Password); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func (s *SystemRuntime) DeleteUser(name string, removeHome bool) error {
	if err := requireRegularAccount("passwd", "user", name); err != nil {
		return err
	}
	if _, err := exec.LookPath("smbpasswd"); err == nil {
		// Ignore errors: the user may simply not have a Samba login.
		_ = run("", "smbpasswd", "-x", name)
	}
	args := []string{}
	if removeHome {
		args = append(args, "-r")
	}
	return run("", "userdel", append(args, "--", name)...)
}

func (s *SystemRuntime) SetPassword(name, password string) error {
	if err := requireRegularAccount("passwd", "user", name); err != nil {
		return err
	}
	if err := validate.Password(password); err != nil {
		return err
	}
	return setUnixPassword(name, password)
}

func (s *SystemRuntime) GetGroups() ([]Group, error) {
	out, err := shellOut("getent", "group")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	result := make([]Group, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(parts[2])
		members := []string{}
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
		}
		result = append(result, Group{Name: parts[0], GID: gid, Members: members, System: isSystemID(gid)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *SystemRuntime) CreateGroup(name string) error {
	if err := validate.GroupName(name); err != nil {
		return err
	}
	if _, exists, err := lookupID("group", name); err != nil {
		return err
	} else if exists {
		return validate.Errorf("group %q already exists", name)
	}
	return run("", "groupadd", "--", name)
}

func (s *SystemRuntime) DeleteGroup(name string) error {
	if err := requireRegularAccount("group", "group", name); err != nil {
		return err
	}
	return run("", "groupdel", "--", name)
}

// AddGroupMember also allows system groups (e.g. sudo, users), since adding
// regular users to them is a normal admin task.
func (s *SystemRuntime) AddGroupMember(group, user string) error {
	if err := validate.GroupName(group); err != nil {
		return err
	}
	if err := requireRegularAccount("passwd", "user", user); err != nil {
		return err
	}
	return run("", "gpasswd", "-a", user, group)
}

func (s *SystemRuntime) RemoveGroupMember(group, user string) error {
	if err := validate.GroupName(group); err != nil {
		return err
	}
	if err := requireRegularAccount("passwd", "user", user); err != nil {
		return err
	}
	return run("", "gpasswd", "-d", user, group)
}

// lookupID resolves a user (db "passwd") or group (db "group") to its numeric id.
func lookupID(db, name string) (int, bool, error) {
	out, err := exec.Command("getent", db, name).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("getent %s failed: %w", db, err)
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 3 {
		return 0, false, fmt.Errorf("unexpected getent output for %q", name)
	}
	id, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, false, fmt.Errorf("unexpected id for %q: %w", name, err)
	}
	return id, true, nil
}

// requireRegularAccount validates the name and rejects missing or system accounts.
func requireRegularAccount(db, kind, name string) error {
	if err := validate.Username(name); err != nil {
		return err
	}
	id, exists, err := lookupID(db, name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	if isSystemID(id) {
		return fmt.Errorf("%w: %s %q is a system account and cannot be changed here", ErrForbidden, kind, name)
	}
	return nil
}

func setUnixPassword(name, password string) error {
	return run(name+":"+password+"\n", "chpasswd")
}

// isAllowedShell accepts login shells from /etc/shells plus the usual
// no-login shells for accounts that should only use Samba.
func isAllowedShell(shell string) bool {
	if shell == "/usr/sbin/nologin" || shell == "/bin/false" {
		return true
	}
	for _, l := range readLines("/etc/shells") {
		if strings.TrimSpace(l) == shell {
			return true
		}
	}
	return false
}
