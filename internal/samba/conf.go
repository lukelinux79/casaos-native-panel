// Package samba reads and edits smb.conf while keeping comments and unknown
// parameters intact, so structured share edits don't destroy manual changes.
package samba

import (
	"strings"

	model "github.com/lukelinux79/casaos-native-panel/internal/model"
)

// Section is one [name] block of smb.conf with its raw lines.
type Section struct {
	Name   string
	Header string
	Lines  []string
}

// Config is a parsed smb.conf. Lines before the first section are kept in Preamble.
type Config struct {
	Preamble []string
	Sections []*Section
}

type param struct {
	key        string // normalized
	value      string
	start, end int // line range in Section.Lines, end exclusive
}

var specialSections = map[string]bool{"homes": true, "printers": true, "print$": true}

func Parse(content string) *Config {
	c := &Config{}
	content = strings.TrimSuffix(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if content == "" {
		return c
	}
	var cur *Section
	for _, line := range strings.Split(content, "\n") {
		if name, ok := sectionName(line); ok {
			cur = &Section{Name: name, Header: line}
			c.Sections = append(c.Sections, cur)
			continue
		}
		if cur == nil {
			c.Preamble = append(c.Preamble, line)
		} else {
			cur.Lines = append(cur.Lines, line)
		}
	}
	return c
}

func (c *Config) String() string {
	var b strings.Builder
	for _, l := range c.Preamble {
		b.WriteString(l + "\n")
	}
	for _, s := range c.Sections {
		b.WriteString(s.Header + "\n")
		for _, l := range s.Lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// Section returns the section with the given name (case-insensitive) or nil.
func (c *Config) Section(name string) *Section {
	for _, s := range c.Sections {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

// Shares returns every section except [global].
func (c *Config) Shares() []model.Share {
	out := []model.Share{}
	for _, s := range c.Sections {
		if strings.EqualFold(s.Name, "global") {
			continue
		}
		out = append(out, s.share())
	}
	return out
}

// SetShare creates the share or updates its known parameters in place.
func (c *Config) SetShare(sh model.Share) {
	s := c.Section(sh.Name)
	if s == nil {
		if n := len(c.Sections); n > 0 {
			prev := c.Sections[n-1]
			if len(prev.Lines) == 0 || strings.TrimSpace(prev.Lines[len(prev.Lines)-1]) != "" {
				prev.Lines = append(prev.Lines, "")
			}
		}
		s = &Section{Name: sh.Name, Header: "[" + sh.Name + "]"}
		c.Sections = append(c.Sections, s)
	}
	s.set("path", sh.Path, "directory")
	if sh.Comment != "" {
		s.set("comment", sh.Comment)
	} else {
		s.unset("comment")
	}
	s.set("read only", yesNo(sh.ReadOnly), "readonly", "writeable", "writable", "writeok")
	s.set("browseable", yesNo(sh.Browseable), "browsable")
	s.set("guest ok", yesNo(sh.GuestOK), "public")
	if len(sh.ValidUsers) > 0 {
		s.set("valid users", strings.Join(sh.ValidUsers, " "))
	} else {
		s.unset("validusers")
	}
	if len(sh.WriteList) > 0 {
		s.set("write list", strings.Join(sh.WriteList, " "))
	} else {
		s.unset("writelist")
	}
}

// RemoveShare deletes the section and reports whether it existed.
func (c *Config) RemoveShare(name string) bool {
	for i, s := range c.Sections {
		if strings.EqualFold(s.Name, name) {
			c.Sections = append(c.Sections[:i], c.Sections[i+1:]...)
			return true
		}
	}
	return false
}

func (s *Section) share() model.Share {
	sh := model.Share{
		Name:       s.Name,
		ReadOnly:   true, // Samba defaults
		Browseable: true,
		Special:    specialSections[strings.ToLower(s.Name)],
	}
	for _, p := range s.params() {
		switch p.key {
		case "path", "directory":
			sh.Path = p.value
		case "comment":
			sh.Comment = p.value
		case "readonly":
			sh.ReadOnly = parseBool(p.value, true)
		case "writeable", "writable", "writeok":
			sh.ReadOnly = !parseBool(p.value, false)
		case "browseable", "browsable":
			sh.Browseable = parseBool(p.value, true)
		case "guestok", "public":
			sh.GuestOK = parseBool(p.value, false)
		case "validusers":
			sh.ValidUsers = splitList(p.value)
		case "writelist":
			sh.WriteList = splitList(p.value)
		}
	}
	return sh
}

func (s *Section) params() []param {
	var out []param
	for i := 0; i < len(s.Lines); i++ {
		t := strings.TrimSpace(s.Lines[i])
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		start := i
		for strings.HasSuffix(t, "\\") && i+1 < len(s.Lines) {
			i++
			t = strings.TrimSuffix(t, "\\") + strings.TrimSpace(s.Lines[i])
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		out = append(out, param{key: normKey(k), value: strings.TrimSpace(v), start: start, end: i + 1})
	}
	return out
}

// set replaces the first occurrence of key (or an alias) and removes the others.
func (s *Section) set(key, value string, aliases ...string) {
	keys := append([]string{normKey(key)}, aliases...)
	ps := s.matching(keys)
	line := "   " + key + " = " + value
	if len(ps) == 0 {
		s.insert(line)
		return
	}
	first := ps[0]
	s.removeParams(ps[1:])
	s.Lines = append(s.Lines[:first.start], append([]string{line}, s.Lines[first.end:]...)...)
}

func (s *Section) unset(keys ...string) {
	for i := range keys {
		keys[i] = normKey(keys[i])
	}
	s.removeParams(s.matching(keys))
}

func (s *Section) matching(keys []string) []param {
	var out []param
	for _, p := range s.params() {
		for _, k := range keys {
			if p.key == k {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func (s *Section) removeParams(ps []param) {
	for i := len(ps) - 1; i >= 0; i-- {
		s.Lines = append(s.Lines[:ps[i].start], s.Lines[ps[i].end:]...)
	}
}

// insert adds a line after the last non-blank line of the section.
func (s *Section) insert(line string) {
	at := len(s.Lines)
	for at > 0 && strings.TrimSpace(s.Lines[at-1]) == "" {
		at--
	}
	s.Lines = append(s.Lines[:at], append([]string{line}, s.Lines[at:]...)...)
}

func sectionName(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	end := strings.Index(t, "]")
	if end < 0 {
		return "", false
	}
	return strings.TrimSpace(t[1:end]), true
}

// normKey mirrors Samba's parameter matching: case and whitespace are ignored.
func normKey(k string) string {
	return strings.ToLower(strings.Join(strings.Fields(k), ""))
}

func parseBool(v string, def bool) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	case "no", "false", "0", "off":
		return false
	}
	return def
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}
