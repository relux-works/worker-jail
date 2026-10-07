package workplace

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This test-only transport scopes discovery and rewrites logical volume names
// to disposable fixture names. Helper/copy/verification commands execute on the
// fixed workers daemon. It cannot validate unscoped production discovery of the
// real inventory; that remains a separately reviewed operator lane.
type migrationVMTransport struct {
	real     Docker
	id       string
	names    map[string]string
	failCopy bool
}

const migrationFixtureLabel = "ai.relux.remote-workplace.migration-fixture"

func (d *migrationVMTransport) name(logical string) string {
	if n := d.names[logical]; n != "" {
		return n
	}
	n := "rwp-migration-it-" + d.id + "-" + strings.NewReplacer(".", "-", "_", "-").Replace(logical)
	d.names[logical] = n
	return n
}
func (d *migrationVMTransport) Run(ctx context.Context, a []string, in io.Reader, out, errout io.Writer) (int, error) {
	a = append([]string(nil), a...)
	if a[0] == "volume" {
		if a[1] == "ls" {
			var b bytes.Buffer
			exit, e := d.real.Run(ctx, []string{"volume", "ls", "-q", "--filter", "label=" + migrationFixtureLabel + "=" + d.id}, nil, &b, errout)
			if exit != 0 || e != nil {
				return exit, e
			}
			for _, actual := range splitLines(b.String()) {
				found := false
				for logical, n := range d.names {
					if n == actual {
						fmt.Fprintln(out, logical)
						found = true
					}
				}
				if !found {
					return 1, fmt.Errorf("unknown fixture volume")
				}
			}
			return 0, nil
		}
		logical := a[len(a)-1]
		a[len(a)-1] = d.name(logical)
		if a[1] == "create" {
			last := a[len(a)-1]
			a = append(a[:len(a)-1], "--label", migrationFixtureLabel+"="+d.id, last)
		}
		if a[1] == "inspect" {
			var b bytes.Buffer
			exit, e := d.real.Run(ctx, a, in, &b, errout)
			if exit != 0 || e != nil {
				return exit, e
			}
			labels := map[string]string{}
			if json.Unmarshal(b.Bytes(), &labels) != nil {
				return 1, fmt.Errorf("malformed fixture labels")
			}
			delete(labels, migrationFixtureLabel)
			return 0, json.NewEncoder(out).Encode(labels)
		}
	}
	if a[0] == "ps" {
		a = append(a, "--filter", "label="+migrationFixtureLabel+"="+d.id)
	}
	if a[0] == "run" {
		image := -1
		for i, v := range a {
			if v == "--mount" {
				parts := strings.Split(a[i+1], ",")
				for j, p := range parts {
					if strings.HasPrefix(p, "src=") {
						parts[j] = "src=" + d.name(strings.TrimPrefix(p, "src="))
					}
				}
				a[i+1] = strings.Join(parts, ",")
			}
			if v == DefaultImage {
				image = i
			}
			if d.failCopy && v == migrationCopyScript {
				a[i] = `set -eu; cp -a /from/. /to/; exit 79`
			}
		}
		if image < 0 {
			return 1, fmt.Errorf("unexpected fixture image")
		}
		a = append(a[:image], append([]string{"--label", migrationFixtureLabel + "=" + d.id}, a[image:]...)...)
	}
	return d.real.Run(ctx, a, in, out, errout)
}
func vmFixtureCommand(t *testing.T, d Docker, a []string, in io.Reader) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out, errout bytes.Buffer
	exit, e := d.Run(ctx, a, in, &out, &errout)
	if e != nil || exit != 0 {
		t.Fatalf("fixture command %s: exit=%d err=%v stderr=%s", a[0], exit, e, tail(errout.Bytes()))
	}
	return out.String()
}
func vmFixtureTar(t *testing.T, root string, uid int) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	links := map[[2]uint64]string{}
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(root, path)
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, e = os.Readlink(path)
			if e != nil {
				return e
			}
		}
		h, e := tar.FileInfoHeader(info, link)
		if e != nil {
			return e
		}
		h.Name = filepath.ToSlash(rel)
		h.Uid, h.Gid, h.Uname, h.Gname = uid, uid, "", ""
		if info.Mode().IsRegular() {
			st := info.Sys().(*syscall.Stat_t)
			key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if prior, ok := links[key]; ok {
				h.Typeflag = tar.TypeLink
				h.Linkname = prior
				h.Size = 0
			} else {
				links[key] = h.Name
			}
		}
		if e = w.WriteHeader(h); e != nil {
			return e
		}
		if info.Mode().IsRegular() && h.Typeflag != tar.TypeLink {
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			_, e = io.Copy(w, f)
			f.Close()
			return e
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return bytes.NewReader(b.Bytes())
}
func setupMigrationVMFixture(t *testing.T) (*migrationFixture, *migrationVMTransport) {
	return setupMigrationVMFixtureWithAuxiliary(t, nil)
}

func setupMigrationVMFixtureWithAuxiliary(t *testing.T, auxiliary func(*migrationFixture)) (*migrationFixture, *migrationVMTransport) {
	t.Helper()
	f := newMigrationFixture(t)
	// Extra workspace-root data deliberately sorts between the administration
	// directory's old/new names. Only the actual GNU tar VM lane proves its copy
	// and manifest ordering; the local orchestration fixture cannot establish it.
	writeFile(t, filepath.Join(f.paths[legacyWorkspacePrefix+"p.w"], ".vscode/settings.json"), "{\"synthetic\":true}\n")
	if auxiliary != nil {
		auxiliary(f)
	}
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	d := &migrationVMTransport{real: NewDockerCLI(home, t.TempDir()), id: strings.TrimPrefix(newCallName(), "rwp-call-"), names: map[string]string{}}
	f.spec.Docker = d
	// Cleanup touches only the exact generated fixture volumes and containers.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		var b bytes.Buffer
		exit, e := d.real.Run(ctx, []string{"ps", "-aq", "--filter", "label=" + migrationFixtureLabel + "=" + d.id}, nil, &b, io.Discard)
		if e == nil && exit == 0 {
			for _, id := range splitLines(b.String()) {
				d.real.Run(ctx, []string{"rm", "-f", id}, nil, io.Discard, io.Discard)
			}
		}
		for _, actual := range d.names {
			d.real.Run(ctx, []string{"volume", "rm", actual}, nil, io.Discard, io.Discard)
		}
	})
	for _, logical := range sortedKeys(f.labels) {
		labels := f.labels[logical]
		a := []string{"volume", "create"}
		for _, k := range sortedLabelKeys(labels) {
			a = append(a, "--label", k+"="+labels[k])
		}
		a = append(a, logical)
		vmFixtureCommand(t, d, a, nil)
		uid := 10001
		if logical == legacyEgressPrefix+"-sock" || logical == legacyEgressPrefix+"-cache" {
			uid = 10002
		}
		a = []string{"run", "--rm", "-i", "--name", newCallName(), "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges", "--user", "0:0", "--cpus", "1", "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "64", "--mount", "type=volume,src=" + logical + ",dst=/to,volume-nocopy", "--entrypoint", "/bin/bash", DefaultImage, "-c", `set -eu; tar -xpf - -C /to`}
		vmFixtureCommand(t, d, a, vmFixtureTar(t, f.paths[logical], uid))
	}
	return f, d
}

// Gated actual-VM synthetic import checks GNU tar hashes, complete HOME/ignored/
// links/cache preservation, real UID/modes and byte-identical export patches.
// Discovery is fixture-scoped; no live owned volumes are inspected or migrated.
func TestIntegrationLegacyMigrationSynthetic(t *testing.T) {
	if os.Getenv("RWP_IT") != "1" {
		t.Skip("parent lane: RWP_IT=1, canonical base image and workers VM required")
	}
	f, d := setupMigrationVMFixture(t)
	check := f.unchanged()
	defer check()
	m := migrationTransport{docker: d, imageName: DefaultImage}
	ctx := context.Background()
	rep, e := MigrateLegacy(ctx, f.spec)
	if e != nil {
		t.Fatal(e)
	}
	if rep.State != "published" {
		t.Fatal("not published")
	}
	for _, o := range rep.Objects {
		if o.Source == legacyEgressPrefix+"-sock" {
			continue
		}
		before, _, e := m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
		if e != nil || before != o.SHA256 {
			t.Fatalf("source changed: %s %v", o.Source, e)
		}
		after, _, e := m.manifest(ctx, o.Target, false)
		if e != nil || before != after {
			t.Fatalf("destination differs: %s %v", o.Target, e)
		}
		uid := "10001:10001"
		if o.Target == EgressCacheVolume {
			uid = "10002:10002"
		}
		owners, e := m.helper(ctx, o.Target, "", `set -eu; stat -c '%u:%g' /from`)
		if e != nil || strings.TrimSpace(owners) != uid {
			t.Fatalf("ownership %s: %q %v", o.Target, owners, e)
		}
		if o.Kind == KindWorkspace {
			script := `export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/from/src; cd /from/src; ` + exportScript
			a, e := m.helper(ctx, o.Source, "", script, o.Base)
			if e != nil {
				t.Fatal(e)
			}
			b, e := m.helper(ctx, o.Target, "", script, o.Base)
			if e != nil || a != b {
				t.Fatal("export patch differs")
			}
		}
	}
}

// Generated auxiliary-root families exercise the actual public cold importer,
// GNU archive order, literal admin translation and full bytes/link/UID/mode/time
// preservation. Host orchestration cannot establish this property; opt-in VM.
func TestIntegrationLegacyMigrationAuxiliaryPathFamilies(t *testing.T) {
	if os.Getenv("RWP_IT") != "1" {
		t.Skip("parent lane: actual GNU workers VM required")
	}
	for _, family := range migrationAuxiliaryFamilies() {
		t.Run(family, func(t *testing.T) {
			f, d := setupMigrationVMFixtureWithAuxiliary(t, func(f *migrationFixture) { addMigrationAuxiliaryFamily(t, f, family) })
			check := f.unchanged()
			defer check()
			ctx := context.Background()
			rep, e := MigrateLegacy(ctx, f.spec)
			if e != nil || rep.State != "published" {
				t.Fatalf("admitted full-copy family rejected: state=%s err=%v", rep.State, e)
			}
			m := migrationTransport{docker: d, imageName: DefaultImage}
			for _, o := range rep.Objects {
				if o.Source == legacyEgressPrefix+"-sock" {
					continue
				}
				before, n, e := m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
				if e != nil || before != o.SHA256 || n != o.Files {
					t.Fatal("source retention violated")
				}
				after, count, e := m.manifest(ctx, o.Target, false)
				if e != nil || before != after || n != count {
					t.Fatal("full-copy metadata/content invariant violated")
				}
			}
		})
	}
}

// Real-daemon collision and injected interrupted copy reject publication,
// retain source, deny New/Run/Provision/Export and leave no helper survivors.
func TestIntegrationLegacyMigrationRefusals(t *testing.T) {
	if os.Getenv("RWP_IT") != "1" {
		t.Skip("parent lane: RWP_IT=1, canonical base image and workers VM required")
	}
	for _, fault := range []string{"collision", "partial-copy"} {
		t.Run(fault, func(t *testing.T) {
			f, d := setupMigrationVMFixture(t)
			m := migrationTransport{docker: d, imageName: DefaultImage}
			ctx := context.Background()
			inventory, e := m.inventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			before := map[string]string{}
			for _, o := range inventory {
				if o.Source != legacyEgressPrefix+"-sock" {
					digest, _, e := m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
					if e != nil {
						t.Fatal(e)
					}
					before[o.Source] = digest
				}
			}
			want := ErrMigrationCopy
			if fault == "collision" {
				want = ErrMigrationCollision
				vmFixtureCommand(t, d, []string{"volume", "create", WorkspaceVolume("p", "w")}, nil)
			} else {
				d.failCopy = true
			}
			rep, e := MigrateLegacy(ctx, f.spec)
			if !errors.Is(e, want) {
				t.Fatalf("state=%s err=%v want=%v", rep.State, e, want)
			}
			for _, o := range inventory {
				if digest := before[o.Source]; digest != "" {
					after, _, e := m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
					if e != nil || after != digest {
						t.Fatal("source modified")
					}
				}
			}
			if _, e = os.Stat(f.spec.StateDir); !os.IsNotExist(e) {
				t.Fatal("failed import published")
			}
			if fault == "partial-copy" {
				if _, e = New(Config{StateDir: f.spec.StateDir, Docker: d}); !errors.Is(e, ErrMigrationIncomplete) {
					t.Fatalf("New: %v", e)
				}
				j := &Workplace{state: f.spec.StateDir, docker: d}
				if _, e = j.Run(ctx, Ref{"p", "w"}, RunSpec{Argv: []string{"true"}}); !errors.Is(e, ErrMigrationIncomplete) {
					t.Fatalf("Run: %v", e)
				}
				if _, e = j.Provision(ctx, ProvisionSpec{Ref: Ref{"p", "w"}}); !errors.Is(e, ErrMigrationIncomplete) {
					t.Fatalf("Provision: %v", e)
				}
				if _, e = j.Export(ctx, Ref{"p", "w"}, io.Discard); !errors.Is(e, ErrMigrationIncomplete) {
					t.Fatalf("Export: %v", e)
				}
			}
			survivors := vmFixtureCommand(t, d, []string{"ps", "-q"}, nil)
			if strings.TrimSpace(survivors) != "" {
				t.Fatal("helper survived migration")
			}
		})
	}
}
