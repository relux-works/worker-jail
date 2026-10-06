package jail

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The real workers-VM /proc/mounts passes; each hostile mutation fails and is named in the detail.
func TestCheckShares(t *testing.T) {
	real := fixtureMounts(t)
	if ok, d := checkShares(real, fixtureHome); !ok {
		t.Fatalf("real fixture failed: %s", d)
	}
	mut := map[string]string{
		"extra home share": real + "mount0 /Users/alexis virtiofs rw,relatime 0 0\n",
		"cache share rw":   strings.Replace(real, "/Users/alexis/Library/Caches/colima virtiofs ro,relatime", "/Users/alexis/Library/Caches/colima virtiofs rw,relatime", 1),
		"fuse.sshfs":       real + "alexis@host:/ /mnt/h fuse.sshfs ro,nosuid 0 0\n",
		"9p":               real + "mount1 /tmp/x 9p ro 0 0\n",
		"nfs":              real + "h:/e /mnt/n nfs4 ro 0 0\n",
		"other user cache": strings.Replace(real, "/Users/alexis/Library", "/Users/bob/Library", 1),
	}
	for name, m := range mut {
		if ok, d := checkShares(m, fixtureHome); ok {
			t.Errorf("%s: passed", name)
		} else if !strings.Contains(d, "unexpected host shares") {
			t.Errorf("%s: detail %q", name, d)
		}
	}
	// The allowed share with an escaped path decodes correctly.
	if ok, d := checkShares(`x /Users/a\040b/Library/Caches/colima virtiofs ro 0 0`, "/Users/a b"); !ok {
		t.Fatalf("escaped mountpoint: %s", d)
	}
}

// Doctor passes on a correct setup and fails, with ErrDoctor and every check reported, on each broken one.
func TestDoctor(t *testing.T) {
	fd := newFakeDocker()
	j := newTestJail(t, fd)
	rep, err := j.Doctor(context.Background())
	if err != nil || len(rep.Checks) != 4 {
		t.Fatalf("control: %v %+v", err, rep)
	}
	cases := map[string]func(*fakeDocker, *Jail){
		"endpoint name": func(f *fakeDocker, _ *Jail) { f.info = "colima\toverlay2\t4" },
		"driver":        func(f *fakeDocker, _ *Jail) { f.info = "colima-workers\tcontainerd\t4" },
		"image volume":  func(f *fakeDocker, _ *Jail) { f.imageOut = `{"/data":{}}` },
		"image missing": func(f *fakeDocker, _ *Jail) { f.imageExit = 1 },
		"colima error":  func(_ *fakeDocker, j *Jail) { j.colima = fakeColima{err: errors.New("ssh failed")} },
	}
	for name, br := range cases {
		fd := newFakeDocker()
		j := newTestJail(t, fd)
		br(fd, j)
		rep, err := j.Doctor(context.Background())
		if !errors.Is(err, ErrDoctor) || len(rep.Checks) != 4 {
			t.Errorf("%s: err %v checks %d", name, err, len(rep.Checks))
		}
		if name == "image missing" && !strings.Contains(err.Error(), "make image") {
			t.Errorf("missing image hint absent: %v", err)
		}
	}
}
