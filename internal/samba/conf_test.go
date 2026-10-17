package samba

import (
	"reflect"
	"strings"
	"testing"

	model "github.com/lukelinux79/casaos-native-panel/internal/model"
)

const sample = `# managed by hand
[global]
   workgroup = WORKGROUP
   server role = standalone server

[homes]
   comment = Home Directories
   browseable = no

# media share
[Media]
   path = /srv/media
   writable = yes
   create mask = 0664
   valid users = alice, @family

`

func TestRoundTripKeepsContent(t *testing.T) {
	if got := Parse(sample).String(); got != sample {
		t.Fatalf("round trip changed content:\n%q\nwant\n%q", got, sample)
	}
}

func TestSharesParsesSynonymsAndDefaults(t *testing.T) {
	shares := Parse(sample).Shares()
	if len(shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(shares))
	}
	if !shares[0].Special || shares[0].Browseable {
		t.Errorf("homes: want special and not browseable, got %+v", shares[0])
	}
	want := model.Share{Name: "Media", Path: "/srv/media", ReadOnly: false, Browseable: true, ValidUsers: []string{"alice", "@family"}}
	if !reflect.DeepEqual(shares[1], want) {
		t.Errorf("media share:\n got %+v\nwant %+v", shares[1], want)
	}
}

func TestSetShareUpdatesInPlace(t *testing.T) {
	c := Parse(sample)
	c.SetShare(model.Share{Name: "media", Path: "/srv/media2", ReadOnly: true, Browseable: true, WriteList: []string{"alice"}})
	out := c.String()

	for _, s := range []string{"create mask = 0664", "# media share", "workgroup = WORKGROUP", "path = /srv/media2", "read only = yes", "write list = alice"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q:\n%s", s, out)
		}
	}
	for _, s := range []string{"writable", "valid users", "/srv/media\n"} {
		if strings.Contains(out, s) {
			t.Errorf("output still contains %q:\n%s", s, out)
		}
	}
	if got := Parse(out).Section("Media").share(); got.Path != "/srv/media2" || !got.ReadOnly {
		t.Errorf("re-parsed share wrong: %+v", got)
	}
}

func TestSetShareAppendsNewSection(t *testing.T) {
	c := Parse(sample)
	c.SetShare(model.Share{Name: "Backup", Path: "/srv/backup", Browseable: true, GuestOK: false})
	c2 := Parse(c.String())
	s := c2.Section("backup")
	if s == nil {
		t.Fatalf("new section missing:\n%s", c.String())
	}
	if got := s.share(); got.Path != "/srv/backup" || got.ReadOnly || got.GuestOK {
		t.Errorf("unexpected share %+v", got)
	}
}

func TestContinuationLines(t *testing.T) {
	c := Parse("[x]\n   valid users = a \\\n      b\n   path = /x\n")
	sh := c.Section("x").share()
	if !reflect.DeepEqual(sh.ValidUsers, []string{"a", "b"}) {
		t.Fatalf("continuation not joined: %v", sh.ValidUsers)
	}
	c.SetShare(model.Share{Name: "x", Path: "/x", Browseable: true})
	if strings.Contains(c.String(), "b\n") {
		t.Errorf("continuation line not removed:\n%s", c.String())
	}
}

func TestRemoveShare(t *testing.T) {
	c := Parse(sample)
	if !c.RemoveShare("MEDIA") || c.Section("Media") != nil {
		t.Fatal("share not removed")
	}
	if c.RemoveShare("nope") {
		t.Fatal("removing unknown share reported success")
	}
}

func TestEnsureCasaOSCompat(t *testing.T) {
	c := Parse(sample)
	c.EnsureCasaOSCompat()
	out := c.String()
	if !strings.HasPrefix(out, CasaOSHeader+"\n") {
		t.Fatalf("header missing:\n%s", out)
	}
	if !strings.Contains(out, "include = "+CasaOSInclude) || !strings.Contains(out, "create mask = 0664") {
		t.Fatalf("include missing or content lost:\n%s", out)
	}
	// Idempotent: a second call changes nothing.
	c2 := Parse(out)
	c2.EnsureCasaOSCompat()
	if c2.String() != out {
		t.Fatalf("second call changed config:\n%s", c2.String())
	}
	// A file written by CasaOS itself keeps its own include line.
	casa := CasaOSHeader + "\n[global]\n   map to guest = bad user\n   include=/etc/samba/smb.casa.conf\n"
	c3 := Parse(casa)
	c3.EnsureCasaOSCompat()
	if c3.String() != casa {
		t.Fatalf("CasaOS file was modified:\n%s", c3.String())
	}
}

func TestForceUser(t *testing.T) {
	sh := Parse("[Media]\npath = /DATA/Media\nguest ok = Yes\nforce user = root\n").Section("Media").share()
	if sh.ForceUser != "root" || !sh.GuestOK {
		t.Fatalf("got %+v", sh)
	}
}
