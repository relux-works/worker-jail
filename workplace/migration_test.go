package workplace

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// migrationFixture drives MigrateLegacy through the Docker interface. It uses
// real isolated host files/Git, emulates VM copies, and records the actual helper
// argv. This proves orchestration and post-failure state, not GNU tar/VM behavior.
type migrationFixture struct {
	inspectFailureTarget                                   bool
	sourceIdentityDrift, targetIdentityDrift, hostDrift    bool
	imageConfig                                            string
	live                                                   map[string]bool
	removed                                                []string
	cancelCopy                                             context.CancelFunc
	t                                                      *testing.T
	spec                                                   LegacyMigrationSpec
	labels                                                 map[string]map[string]string
	paths                                                  map[string]string
	running                                                string
	partial, corruptCopy, drift, malformed, inspectFailure bool
	helpers                                                [][]string
}

func newMigrationFixture(t *testing.T) *migrationFixture {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	os.Mkdir(source, 0700)
	f := &migrationFixture{t: t, labels: map[string]map[string]string{}, paths: map[string]string{}}
	f.spec = LegacyMigrationSpec{SourceStateDir: source, StateDir: filepath.Join(root, "target"), Image: DefaultImage, Docker: f}
	raw := testPolicy("p", "w")
	raw = []byte("{\n \"note\": \"preserve historical " + strings.TrimPrefix(legacyRoot, "ai.relux.") + " text\", " + string(raw)[1:])
	for _, d := range []string{"policies", "exports", "seeds", "snapshots", "locks", "slots/global", "docker-config"} {
		os.MkdirAll(filepath.Join(source, d), 0700)
	}
	writeFile(t, filepath.Join(source, "policies/p.w.json"), string(raw))
	writeFile(t, filepath.Join(source, "exports/p.w.sha256"), strings.Repeat("b", 64)+"\n")
	writeFile(t, filepath.Join(source, "seeds/p.gomod.tree"), strings.Repeat("a", 40)+"\n")
	writeFile(t, filepath.Join(source, "snapshots/identity"), "historical identity bytes\n")
	for _, p := range []string{"locks/ws.p.w.lock", "locks/cache.p.gomod.lock", "slots/global/0.lock"} {
		writeFile(t, filepath.Join(source, p), "")
	}
	vol := legacyWorkspacePrefix + "p.w"
	f.paths[vol] = t.TempDir()
	git(t, f.paths[vol], "clone", "-q", newRepo(t), "src")
	base := git(t, filepath.Join(f.paths[vol], "src"), "rev-parse", "HEAD")
	git(t, filepath.Join(f.paths[vol], "src"), "config", "user.email", "w@p."+strings.TrimPrefix(legacyRoot, "ai.relux.")+".invalid")
	writeFile(t, filepath.Join(f.paths[vol], legacyAdmin, "provisioned"), "")
	writeFile(t, filepath.Join(f.paths[vol], "home/.config/private"), "synthetic private bytes\n")
	writeFile(t, filepath.Join(f.paths[vol], "src/ignored.bin"), "synthetic ignored bytes\n")
	writeFile(t, filepath.Join(f.paths[vol], "src/untracked"), "synthetic untracked bytes\n")
	if e := os.Symlink("untracked", filepath.Join(f.paths[vol], "src/link")); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(f.paths[vol], "src/untracked"), filepath.Join(f.paths[vol], "src/hardlink")); e != nil {
		t.Fatal(e)
	}
	f.labels[vol] = map[string]string{legacyRoot: "1", legacyRoot + ".kind": KindWorkspace, legacyRoot + ".project": "p", legacyRoot + ".worker": "w", legacyRoot + ".base": base, legacyRoot + ".created": "2026-10-01T00:00:00Z", legacyRoot + ".policy-id": policyID(t, raw), legacyRoot + ".policy-risk": "MEDIUM"}
	cache := legacyCachePrefix + "p.gomod"
	f.paths[cache] = t.TempDir()
	writeFile(t, filepath.Join(f.paths[cache], "cache/item"), "unused full cache bytes\n")
	f.labels[cache] = map[string]string{legacyRoot: "1", legacyRoot + ".kind": KindCache, legacyRoot + ".project": "p", legacyRoot + ".cache": "gomod", legacyRoot + ".created": "2026-10-01T00:00:00Z"}
	for _, suffix := range []string{"-sock", "-policy", "-cache"} {
		n := legacyEgressPrefix + suffix
		f.paths[n] = t.TempDir()
		if suffix == "-policy" {
			writeFile(t, filepath.Join(f.paths[n], "p.w.json"), string(raw))
		} else if suffix != "-sock" {
			writeFile(t, filepath.Join(f.paths[n], "cold-data"), "cold preserved bytes")
		}
		f.labels[n] = map[string]string{legacyRoot: "1", legacyRoot + ".kind": KindEgress, legacyRoot + ".created": "2026-10-01T00:00:00Z"}
	}
	return f
}

// Auxiliary families are generated from ordering relations and literal-name
// boundaries, with file, directory, symlink and hard-link entries in each.
// Both host orchestration and the actual VM class suite use the same inputs.
func migrationAuxiliaryFamilies() []string {
	return []string{"before", "between", "after", "admin-prefix", "admin-lookalike", "nul-records"}
}

func addMigrationAuxiliaryFamily(t *testing.T, f *migrationFixture, family string) {
	t.Helper()
	root := f.paths[legacyWorkspacePrefix+"p.w"]
	names := map[string][]string{
		"before":          {".alpha", ".rwp-extra"},
		"between":         {".vscode", ".sibling"},
		"after":           {"z-notes", "zz.data"},
		"admin-prefix":    {legacyAdmin + "-extra", legacyAdmin + "x"},
		"admin-lookalike": {strings.TrimPrefix(legacyAdmin, "."), "x" + strings.TrimPrefix(legacyAdmin, ".")},
		"nul-records":     {"-leading-option", "space name\nnext-line"},
	}
	// Keep the real regression witness present in every admitted family.
	writeFile(t, filepath.Join(root, ".vscode/settings.json"), "{\"synthetic\":true}\n")
	for i, name := range names[family] {
		dir := filepath.Join(root, name)
		path := filepath.Join(dir, "auxiliary.data")
		writeFile(t, path, fmt.Sprintf("synthetic family=%s member=%d\n", family, i))
		if e := os.Chmod(path, 0400); e != nil {
			t.Fatal(e)
		}
		if e := os.Link(path, filepath.Join(dir, "hardlink")); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink("auxiliary.data", filepath.Join(dir, "symlink")); e != nil {
			t.Fatal(e)
		}
		// Root entries vary in type too, not just directories containing data.
		writeFile(t, dir+".root-file", "synthetic root auxiliary bytes\n")
		if e := os.Chmod(dir+".root-file", 0400); e != nil {
			t.Fatal(e)
		}
		if e := os.Link(path, dir+".root-hardlink"); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink(name+"/auxiliary.data", dir+".root-link"); e != nil {
			t.Fatal(e)
		}
		// Cross-administration hard links must use the same canonical first member.
		if e := os.Link(filepath.Join(root, legacyAdmin, "provisioned"), filepath.Join(dir, "admin-hardlink")); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink("../"+legacyAdmin+"/provisioned", filepath.Join(dir, "admin-symlink")); e != nil {
			t.Fatal(e)
		}
		stamp := time.Unix(1700000000+int64(i), 0)
		if e := os.Chtimes(path, stamp, stamp); e != nil {
			t.Fatal(e)
		}
		if e := os.Chtimes(dir, stamp, stamp); e != nil {
			t.Fatal(e)
		}
	}
}

type migrationArchiveOrderFixture struct {
	*migrationFixture
	orderViolation bool
}

func (f *migrationArchiveOrderFixture) Run(ctx context.Context, a []string, in io.Reader, out, errout io.Writer) (int, error) {
	if a[0] == "run" && flagValue(a, "-c") == migrationManifestScript {
		var source, flag string
		for i, v := range a {
			if v == "--mount" {
				for _, p := range strings.Split(a[i+1], ",") {
					if strings.HasPrefix(p, "src=") {
						source = strings.TrimPrefix(p, "src=")
					}
				}
			}
			if v == "-c" {
				flag = a[i+3]
			}
		}
		root := f.paths[source]
		probe := filepath.Join(f.t.TempDir(), "ordered-paths")
		// Execute production enumeration/invocation with an archive recorder.
		// BSD find lacks GNU -printf; the unrelated count is replaced here only.
		// Neither GNU archive bytes nor its file count is proven by this lane.
		shim := `tar() {
 local required=0 arg
 for arg in "$@"; do
  case "$arg" in --null|--verbatim-files-from|--no-recursion) required=$((required+1));; esac
 done
 [ "$required" = 3 ] || return 77
 cat > "$RWP_TEST_ORDER_OUTPUT"
 printf 'synthetic archive recorder'
}
`
		script := strings.ReplaceAll(migrationManifestScript, "/from", root)
		script = strings.ReplaceAll(script, "find . -xdev -printf x | wc -c", "printf '1\\n'")
		cmd := exec.CommandContext(ctx, "bash", "-c", shim+script, "rwp-order-fixture", flag)
		cmd.Env = append(hostEnv(), "RWP_TEST_ORDER_OUTPUT="+probe)
		if e := cmd.Run(); e != nil {
			f.orderViolation = true
			return 1, nil
		}
		got, e := os.ReadFile(probe)
		if e != nil {
			f.orderViolation = true
			return 1, nil
		}
		// Independent expected list: walk actual entries, translate the exact root
		// component, sort in Go, then undo translation only for source reads.
		var expected []string
		e = filepath.WalkDir(root, func(path string, _ os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			if rel == "." {
				expected = append(expected, ".")
				return nil
			}
			rel = filepath.ToSlash(rel)
			if flag == "translate" && (rel == legacyAdmin || strings.HasPrefix(rel, legacyAdmin+"/")) {
				rel = ".rwp" + strings.TrimPrefix(rel, legacyAdmin)
			}
			expected = append(expected, "./"+rel)
			return nil
		})
		if e != nil {
			return 1, e
		}
		slices.Sort(expected)
		if flag == "translate" {
			for i, path := range expected {
				if path == "./.rwp" || strings.HasPrefix(path, "./.rwp/") {
					expected[i] = "./" + legacyAdmin + strings.TrimPrefix(path, "./.rwp")
				}
			}
		}
		want := strings.Join(expected, "\x00") + "\x00"
		if string(got) != want {
			f.orderViolation = true
			return 1, nil
		}
	}
	return f.migrationFixture.Run(ctx, a, in, out, errout)
}

// Six generated families drive public MigrateLegacy with the real manifest
// enumeration script. The GNU writer is recorded; host copies independently
// check full bytes/metadata and source retention. Real GNU success is VM-only.
func TestMigrateLegacyAuxiliaryPathFamilies(t *testing.T) {
	for _, family := range migrationAuxiliaryFamilies() {
		t.Run(family, func(t *testing.T) {
			fixture := newMigrationFixture(t)
			addMigrationAuxiliaryFamily(t, fixture, family)
			f := &migrationArchiveOrderFixture{migrationFixture: fixture}
			f.spec.Docker = f
			check := f.unchanged()
			defer check()
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if f.orderViolation {
				t.Fatal("canonical manifest ordering/invocation violated")
			}
			if e != nil || rep.State != "published" {
				t.Fatalf("admitted full-copy family rejected: state=%s err=%v", rep.State, e)
			}
		})
	}
}

// Public import without auxiliary root data is the nearby control for narrowed
// ordering mutations. The host recorder proves enumeration, not GNU bytes.
func TestMigrateLegacyManifestOrderPlainControl(t *testing.T) {
	base := newMigrationFixture(t)
	f := &migrationArchiveOrderFixture{migrationFixture: base}
	f.spec.Docker = f
	check := f.unchanged()
	defer check()
	rep, e := MigrateLegacy(context.Background(), f.spec)
	if f.orderViolation || e != nil || rep.State != "published" {
		t.Fatalf("plain valid publication refused: order=%t state=%s err=%v", f.orderViolation, rep.State, e)
	}
}

type migrationAuxiliaryFaultFixture struct {
	*migrationArchiveOrderFixture
	fault string
}

func (f *migrationAuxiliaryFaultFixture) Run(ctx context.Context, a []string, in io.Reader, out, errout io.Writer) (int, error) {
	exit, e := f.migrationArchiveOrderFixture.Run(ctx, a, in, out, errout)
	if e != nil || exit != 0 || a[0] != "run" || flagValue(a, "-c") != migrationCopyScript || a[len(a)-1] != KindWorkspace {
		return exit, e
	}
	root := f.paths[WorkspaceVolume("p", "w")]
	path := filepath.Join(root, ".vscode/auxiliary.data")
	switch f.fault {
	case "content":
		info, e := os.Stat(path)
		if e != nil {
			return 1, e
		}
		if e = os.Chmod(path, 0600); e != nil {
			return 1, e
		}
		if e = os.WriteFile(path, []byte("changed synthetic bytes"), 0600); e != nil {
			return 1, e
		}
		e = preserveHostMetadata(path, info)
		if e != nil {
			return 1, e
		}
	case "mode":
		if e = os.Chmod(path, 0600); e != nil {
			return 1, e
		}
	case "symlink":
		path = filepath.Join(root, ".vscode/symlink")
		if e = os.Remove(path); e != nil {
			return 1, e
		}
		if e = os.Symlink("wrong-target", path); e != nil {
			return 1, e
		}
	case "hardlink":
		path = filepath.Join(root, ".vscode/hardlink")
		info, e := os.Stat(path)
		if e != nil {
			return 1, e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return 1, e
		}
		if e = os.Remove(path); e != nil {
			return 1, e
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			return 1, e
		}
		if e = preserveHostMetadata(path, info); e != nil {
			return 1, e
		}
	case "path":
		if e = os.Rename(filepath.Join(root, ".vscode"), filepath.Join(root, ".vscode-other")); e != nil {
			return 1, e
		}
	}
	return 0, nil
}

// Five one-property destination faults must fail public verification, retain
// source and deny normal entry before any new helper. GNU enforcement is VM-only.
func TestMigrateLegacyAuxiliaryPreservationRefusals(t *testing.T) {
	for _, fault := range []string{"content", "mode", "symlink", "hardlink", "path"} {
		t.Run(fault, func(t *testing.T) {
			base := newMigrationFixture(t)
			addMigrationAuxiliaryFamily(t, base, "between")
			f := &migrationAuxiliaryFaultFixture{migrationArchiveOrderFixture: &migrationArchiveOrderFixture{migrationFixture: base}, fault: fault}
			f.spec.Docker = f
			check := f.unchanged()
			defer check()
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if !errors.Is(e, ErrMigrationCopy) || rep.State != "incomplete" || !rep.SourceRetained {
				t.Fatalf("changed auxiliary copy admitted: state=%s err=%v", rep.State, e)
			}
			if _, e := os.Lstat(f.spec.StateDir); !os.IsNotExist(e) {
				t.Fatal("changed copy published")
			}
			before := len(f.helpers)
			if _, e := New(Config{StateDir: f.spec.StateDir, Docker: f}); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("New admitted incomplete copy: %v", e)
			}
			j := &Workplace{state: f.spec.StateDir, docker: f}
			if _, e := j.Run(context.Background(), Ref{"p", "w"}, RunSpec{Argv: []string{"true"}}); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("Run admitted incomplete copy: %v", e)
			}
			if _, e := j.Export(context.Background(), Ref{"p", "w"}, io.Discard); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("Export admitted incomplete copy: %v", e)
			}
			if len(f.helpers) != before {
				t.Fatal("public refusal created helper")
			}
		})
	}
}
func (f *migrationFixture) Run(ctx context.Context, a []string, in io.Reader, out, errout io.Writer) (exit int, runErr error) {
	if a[0] == "rm" {
		f.removed = append(f.removed, a[len(a)-1])
		delete(f.live, a[len(a)-1])
		return 0, nil
	}
	if a[0] == "run" {
		if f.live == nil {
			f.live = map[string]bool{}
		}
		name := flagValue(a, "--name")
		f.live[name] = true
		defer func() {
			if exit == 0 && runErr == nil {
				delete(f.live, name)
			}
		}()
	}

	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if a[0] == "image" {
		if f.imageConfig != "" {
			fmt.Fprint(out, f.imageConfig)
			return 0, nil
		}
		fmt.Fprintf(out, `{"Labels":{"%s":"2"}}`, LabelImageBase)
		return 0, nil
	}
	if a[0] == "ps" {
		if f.running != "" {
			fmt.Fprintln(out, "running")
		}
		return 0, nil
	}
	if a[0] == "inspect" {
		fmt.Fprintf(out, `[{"Name":%q,"Config":{"Labels":{}}}]`, f.running)
		return 0, nil
	}
	if a[0] == "volume" {
		n := a[len(a)-1]
		switch a[1] {
		case "ls":
			for _, n := range sortedKeys(f.labels) {
				fmt.Fprintln(out, n)
			}
			return 0, nil
		case "inspect":
			if f.inspectFailure || f.inspectFailureTarget && strings.HasPrefix(n, "rwp.") {
				fmt.Fprint(errout, "permission denied")
				return 1, nil
			}
			labels, ok := f.labels[n]
			if !ok {
				fmt.Fprint(errout, "no such volume")
				return 1, nil
			}
			if f.malformed {
				fmt.Fprint(out, "{")
				return 0, nil
			}
			json.NewEncoder(out).Encode(labels)
			return 0, nil
		case "create":
			labels := map[string]string{}
			for i := 0; i+1 < len(a); i++ {
				if a[i] == "--label" {
					k, v, _ := strings.Cut(a[i+1], "=")
					labels[k] = v
				}
			}
			f.labels[n] = labels
			f.paths[n] = f.t.TempDir()
			return 0, nil
		}
	}
	if a[0] != "run" {
		return 1, fmt.Errorf("unexpected fixture verb %s", a[0])
	}
	f.helpers = append(f.helpers, append([]string(nil), a...))
	var source, target string
	for i := range a {
		if a[i] == "--mount" {
			v := a[i+1]
			start := strings.Index(v, "src=") + 4
			name := strings.Split(v[start:], ",")[0]
			if strings.Contains(v, "dst=/from") {
				source = name
			} else {
				target = name
			}
		}
	}
	script := ""
	var args []string
	for i := range a {
		if a[i] == "-c" {
			script = a[i+1]
			args = a[i+3:]
			break
		}
	}
	p := f.paths[source]
	switch script {
	case migrationWorkspaceScript, migrationEgressPolicyScript:
		// Execute the actual gate script, with only the mount root mapped to an
		// isolated host fixture. GNU copy/tar remain the separate gated VM lane.
		cmd := exec.CommandContext(ctx, "bash", append([]string{"-c", strings.ReplaceAll(script, "/from", p), "rwp-fixture"}, args...)...)
		cmd.Env = hostEnv()
		cmd.Stdout = out
		cmd.Stderr = errout
		exit, e := exitOf(cmd.Run())
		return exit, e

	case migrationManifestScript:
		if args[0] == "translate" {
			dir := f.t.TempDir()
			if e := copyHostState(ctx, p, dir); e != nil {
				return 1, e
			}
			st, _ := os.Stat(dir)
			os.Rename(filepath.Join(dir, legacyAdmin), filepath.Join(dir, ".rwp"))
			os.Chtimes(dir, st.ModTime(), st.ModTime())
			p = dir
		}
		digest, n, e := hostManifest(p)
		if e != nil {
			return 1, nil
		}
		fmt.Fprintf(out, "%s\n%d\n", digest, n)
	case migrationCopyScript:
		if f.cancelCopy != nil {
			writeFile(f.t, filepath.Join(f.paths[target], "partial"), "interrupted copy")
			f.cancelCopy()
			return -1, context.Canceled
		}
		if f.partial {
			writeFile(f.t, filepath.Join(f.paths[target], "partial"), "partial copy")
			return 1, nil
		}
		if e := copyHostState(ctx, p, f.paths[target]); e != nil {
			return 1, e
		}
		if args[0] == KindWorkspace {
			st, _ := os.Stat(p)
			os.Rename(filepath.Join(f.paths[target], legacyAdmin), filepath.Join(f.paths[target], ".rwp"))
			os.Chtimes(f.paths[target], st.ModTime(), st.ModTime())
		}
		if f.corruptCopy && source == legacyCachePrefix+"p.gomod" {
			writeFile(f.t, filepath.Join(f.paths[target], "corrupted"), "wrong")
		}
		if f.sourceIdentityDrift {
			f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".created"] = "2026-10-02T00:00:00Z"
		}
		if f.targetIdentityDrift && source == legacyCachePrefix+"p.gomod" {
			f.labels[target][LabelCreated] = "2026-10-02T00:00:00Z"
		}
		if f.hostDrift {
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "snapshots/identity"), "concurrent external change\n")
		}
		if f.drift {
			f.running = "/rwp-call-0000000000000000"
		}
	default:
		return 1, fmt.Errorf("unknown fixed script")
	}
	return 0, nil
}
func (f *migrationFixture) unchanged() func() {
	f.t.Helper()
	host, n, e := hostManifest(f.spec.SourceStateDir)
	if e != nil {
		f.t.Fatal(e)
	}
	volumes := map[string]string{}
	for v, p := range f.paths {
		if f.labels[v][legacyRoot] == "1" {
			d, _, e := hostManifest(p)
			if e != nil {
				f.t.Fatal(e)
			}
			volumes[v] = d
		}
	}
	return func() {
		f.t.Helper()
		d, c, e := hostManifest(f.spec.SourceStateDir)
		if e != nil || d != host || c != n {
			f.t.Fatalf("source host changed: %v", e)
		}
		for v, d := range volumes {
			got, _, e := hostManifest(f.paths[v])
			if e != nil || got != d {
				f.t.Fatalf("source volume changed: %s %v", v, e)
			}
		}
	}
}

// Public import copies full data, keeps source/exports/policies/identity bytes,
// preserves links/modes, regenerates sockets and enables only published state.
func TestMigrateLegacyFullPublication(t *testing.T) {
	f := newMigrationFixture(t)
	check := f.unchanged()
	defer check()
	rep, e := MigrateLegacy(context.Background(), f.spec)
	if e != nil {
		t.Fatal(e)
	}
	if rep.State != "published" || !rep.SourceRetained || !rep.SocketRegenerated || len(rep.Objects) != 5 || rep.HostFiles == 0 {
		t.Fatalf("report: %+v", rep)
	}
	for _, o := range rep.Objects {
		if o.Source != legacyEgressPrefix+"-sock" && (o.Files == 0 || len(o.SHA256) != 64) {
			t.Fatalf("missing verification: %s", o.Target)
		}
	}
	for _, p := range []string{"policies/p.w.json", "exports/p.w.sha256", "snapshots/identity", "seeds/p.gomod.tree"} {
		a, _ := os.ReadFile(filepath.Join(f.spec.SourceStateDir, p))
		b, e := os.ReadFile(filepath.Join(f.spec.StateDir, p))
		if e != nil || string(a) != string(b) {
			t.Fatalf("not preserved: %s", p)
		}
	}
	j, e := New(Config{StateDir: f.spec.StateDir, Docker: f})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = j.volumeLabels(context.Background(), WorkspaceVolume("p", "w")); e != nil {
		t.Fatal(e)
	}
	// A readable, otherwise well-formed receipt with another operation ID is
	// not proof that this state root published the copied volume.
	wrong := rep
	wrong.ID = "0000000000000000"
	otherState := t.TempDir()
	raw, _ := json.Marshal(wrong)
	if e := os.WriteFile(filepath.Join(otherState, migrationReceipt), raw, 0600); e != nil {
		t.Fatal(e)
	}
	forged, e := New(Config{StateDir: otherState, Docker: f})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = forged.volumeLabels(context.Background(), WorkspaceVolume("p", "w")); !errors.Is(e, ErrMigrationIncomplete) {
		t.Fatalf("mismatched receipt admitted: %v", e)
	}
	for _, a := range f.helpers {
		assertMigrationHelper(t, a)
	}
	// A different state root has no authority to adopt these copies.
	other, e := New(Config{StateDir: t.TempDir(), Docker: f})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Export(context.Background(), Ref{"p", "w"}, io.Discard); !errors.Is(e, ErrMigrationIncomplete) {
		t.Fatalf("foreign-state export: %v", e)
	}
}
func assertMigrationHelper(t *testing.T, a []string) {
	t.Helper()
	if flagValue(a, "--network") != "none" || flagValue(a, "--user") != "0:0" || flagValue(a, "--cpus") != "1" || flagValue(a, "--memory") != "256m" || !slices.Contains(a, "--read-only") || flagValue(a, "--entrypoint") != "/bin/bash" {
		t.Fatalf("unbounded helper: %v", a)
	}
	mounts := 0
	caps := []string{}
	for i, v := range a {
		if v == "--mount" {
			mounts++
			m := a[i+1]
			if !strings.HasPrefix(m, "type=volume,src=") || !strings.Contains(m, "volume-nocopy") {
				t.Fatal("non-volume helper mount")
			}
			if strings.Contains(m, "dst=/from") && !strings.Contains(m, ",readonly,") {
				t.Fatal("source writable")
			}
		}
		if v == "--cap-add" {
			caps = append(caps, a[i+1])
		}
		if v == "--privileged" || v == "-v" || v == "--pid" || v == "--device" {
			t.Fatal("forbidden helper authority")
		}
	}
	if mounts < 1 || mounts > 2 || strings.Join(caps, ",") != "DAC_OVERRIDE,CHOWN,FOWNER" {
		t.Fatal("helper authority widened")
	}
}

// Dry-run validates the same objects without any destination state or volume.
func TestMigrateLegacyDryRun(t *testing.T) {
	f := newMigrationFixture(t)
	f.spec.DryRun = true
	check := f.unchanged()
	defer check()
	rep, e := MigrateLegacy(context.Background(), f.spec)
	if e != nil || rep.State != "dry-run" || len(f.labels) != 5 {
		t.Fatalf("dry run: %+v %v", rep, e)
	}
	if _, e = os.Lstat(f.spec.StateDir); !os.IsNotExist(e) {
		t.Fatal("dry run published state")
	}
	if _, e = os.Lstat(f.spec.StateDir + ".migration-incomplete"); !os.IsNotExist(e) {
		t.Fatal("dry run reserved state")
	}
}

// Public admission rejects each planted violation before a destination is
// created. Positive full-publication/dry-run controls show it admits valid data.
func TestMigrateLegacyAdmissionRefusals(t *testing.T) {
	cases := []struct {
		name  string
		plant func(*migrationFixture)
		want  error
	}{
		{"destination-state", func(f *migrationFixture) { os.Mkdir(f.spec.StateDir, 0700) }, ErrMigrationCollision},
		{"unrelated-destination-volume", func(f *migrationFixture) {
			f.labels[WorkspaceVolume("p", "w")] = map[string]string{"unrelated": "owner"}
		}, ErrMigrationCollision},
		{"cache-destination-volume", func(f *migrationFixture) { f.labels[CacheVolume("p", "gomod")] = map[string]string{} }, ErrMigrationCollision},
		{"socket-destination-volume", func(f *migrationFixture) { f.labels[EgressSockVolume] = map[string]string{} }, ErrMigrationCollision},
		{"running-old-caller", func(f *migrationFixture) { f.running = "/" + legacyCallPrefix + "0000000000000000" }, ErrMigrationBusy},
		{"running-new-caller", func(f *migrationFixture) { f.running = "/rwp-call-0000000000000000" }, ErrMigrationBusy},
		{"running-old-service", func(f *migrationFixture) { f.running = "/" + legacyEgressPrefix }, ErrMigrationBusy},
		{"running-new-service", func(f *migrationFixture) { f.running = "/" + EgressContainer }, ErrMigrationBusy},
		{"forged-owner", func(f *migrationFixture) { f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot] = "0" }, ErrMigrationInvalid},
		{"forged-worker", func(f *migrationFixture) {
			labels := f.labels[legacyWorkspacePrefix+"p.w"]
			labels[legacyRoot+".worker"] = "other"
			raw := testPolicy("p", "other")
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "policies/p.other.json"), string(raw))
			labels[legacyRoot+".policy-id"] = policyID(f.t, raw)
		}, ErrMigrationInvalid},
		{"unknown-metadata", func(f *migrationFixture) { f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".unknown"] = "1" }, ErrMigrationInvalid},
		{"missing-policy", func(f *migrationFixture) { os.Remove(filepath.Join(f.spec.SourceStateDir, "policies/p.w.json")) }, ErrMigrationInvalid},
		{"corrupt-policy", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "policies/p.w.json"), "{")
		}, ErrMigrationInvalid},
		{"policy-id-mismatch", func(f *migrationFixture) {
			f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".policy-id"] = strings.Repeat("a", 64)
		}, ErrMigrationInvalid},
		{"policy-risk-mismatch", func(f *migrationFixture) { f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".policy-risk"] = "LOW" }, ErrMigrationInvalid},
		{"missing-marker", func(f *migrationFixture) {
			os.Remove(filepath.Join(f.paths[legacyWorkspacePrefix+"p.w"], legacyAdmin, "provisioned"))
		}, ErrMigrationInvalid},
		{"marker-symlink", func(f *migrationFixture) {
			p := filepath.Join(f.paths[legacyWorkspacePrefix+"p.w"], legacyAdmin, "provisioned")
			os.Remove(p)
			os.Symlink("../src/README.md", p)
		}, ErrMigrationInvalid},
		{"invalid-base", func(f *migrationFixture) { f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".base"] = "not-an-oid" }, ErrMigrationInvalid},
		{"missing-base-object", func(f *migrationFixture) {
			f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".base"] = strings.Repeat("a", 40)
		}, ErrMigrationInvalid},
		{"partial-snapshot-metadata", func(f *migrationFixture) {
			f.labels[legacyWorkspacePrefix+"p.w"][legacyRoot+".snapshot-tree"] = strings.Repeat("a", 40)
		}, ErrMigrationInvalid},
		{"unreadable-source", func(f *migrationFixture) { os.Chmod(filepath.Join(f.spec.SourceStateDir, "snapshots/identity"), 0000) }, ErrMigrationInvalid},
		{"external-host-link", func(f *migrationFixture) {
			os.Symlink("/etc/passwd", filepath.Join(f.spec.SourceStateDir, "snapshots/external"))
		}, ErrMigrationInvalid},
		{"destination-inspect-error-is-not-absence", func(f *migrationFixture) { f.inspectFailureTarget = true }, ErrMigrationInvalid},
		{"malformed-inspect", func(f *migrationFixture) { f.malformed = true }, ErrMigrationInvalid},
		{"inspect-error-is-not-absence", func(f *migrationFixture) { f.inspectFailure = true }, ErrMigrationInvalid},
		{"incomplete-egress-set", func(f *migrationFixture) { delete(f.labels, legacyEgressPrefix+"-cache") }, ErrMigrationInvalid},
		{"overlapping-paths", func(f *migrationFixture) { f.spec.StateDir = filepath.Join(f.spec.SourceStateDir, "dest") }, ErrMigrationInvalid},
		{"relative-path", func(f *migrationFixture) { f.spec.StateDir = "dest" }, ErrMigrationInvalid},
		{"unattested-helper-image", func(f *migrationFixture) { f.imageConfig = `{"Labels":{}}` }, ErrMigrationInvalid},
		{"helper-image-volume", func(f *migrationFixture) {
			f.imageConfig = fmt.Sprintf(`{"Labels":{"%s":"2"},"Volumes":{"/extra":{}}}`, LabelImageBase)
		}, ErrMigrationInvalid},
		{"helper-image-entrypoint", func(f *migrationFixture) {
			f.imageConfig = fmt.Sprintf(`{"Labels":{"%s":"2"},"Entrypoint":["/extra"]}`, LabelImageBase)
		}, ErrMigrationInvalid},
		{"existing-canonical-admin", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.paths[legacyWorkspacePrefix+"p.w"], ".rwp/provisioned"), "")
		}, ErrMigrationInvalid},
		{"corrupt-unused-policy", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "policies/p.other.json"), "{")
		}, ErrMigrationInvalid},
		{"corrupt-export-binding", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "exports/p.w.sha256"), "invalid\n")
		}, ErrMigrationInvalid},
		{"corrupt-seed-binding", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.spec.SourceStateDir, "seeds/p.gomod.tree"), "invalid\n")
		}, ErrMigrationInvalid},
		{"writable-policy", func(f *migrationFixture) { os.Chmod(filepath.Join(f.spec.SourceStateDir, "policies/p.w.json"), 0666) }, ErrMigrationInvalid},
		{"nonprivate-state-root", func(f *migrationFixture) { os.Chmod(f.spec.SourceStateDir, 0755) }, ErrMigrationInvalid},
		{"corrupt-cold-egress-policy", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.paths[legacyEgressPrefix+"-policy"], "p.w.json"), "{corrupt}")
		}, ErrMigrationInvalid},
		{"unknown-cold-egress-policy", func(f *migrationFixture) {
			writeFile(f.t, filepath.Join(f.paths[legacyEgressPrefix+"-policy"], "p.other.json"), string(testPolicy("p", "other")))
		}, ErrMigrationInvalid},
		{"untrusted-helper-name", func(f *migrationFixture) { f.spec.Image = "foreign/base:2" }, ErrMigrationInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMigrationFixture(t)
			tc.plant(f)
			before := len(f.labels)
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if !errors.Is(e, tc.want) || rep.State != "refused" || len(f.labels) != before {
				t.Fatalf("admission: state=%s err=%v want=%v", rep.State, e, tc.want)
			}
			if tc.name != "destination-state" {
				if _, e = os.Lstat(f.spec.StateDir); !os.IsNotExist(e) {
					t.Fatal("refusal created state")
				}
			}
		})
	}
}

// Existing workspace/cache/slot flocks are nonblocking refusals; no new source
// lock files are created or byte state modified by failed admission.
func TestMigrateLegacyHeldLocks(t *testing.T) {
	for _, path := range []string{"locks/ws.p.w.lock", "locks/cache.p.gomod.lock", "slots/global/0.lock"} {
		t.Run(path, func(t *testing.T) {
			f := newMigrationFixture(t)
			release, ok, e := tryLock(filepath.Join(f.spec.SourceStateDir, path))
			if e != nil || !ok {
				t.Fatal(e)
			}
			defer release()
			check := f.unchanged()
			defer check()
			_, e = MigrateLegacy(context.Background(), f.spec)
			if !errors.Is(e, ErrMigrationBusy) {
				t.Fatalf("held lock: %v", e)
			}
		})
	}
}

// Partial/faulted/drifting imports retain source, keep a reservation, refuse
// retries and deny actual public New/Run/Provision/Export paths before effects.
func TestMigrateLegacyInterruptedPublicRefusals(t *testing.T) {
	for _, fault := range []string{"partial", "corrupt", "caller-drift"} {
		t.Run(fault, func(t *testing.T) {
			f := newMigrationFixture(t)
			check := f.unchanged()
			defer check()
			switch fault {
			case "partial":
				f.partial = true
			case "corrupt":
				f.corruptCopy = true
			case "caller-drift":
				f.drift = true
			}
			rep, e := MigrateLegacy(context.Background(), f.spec)
			want := ErrMigrationCopy
			if fault == "caller-drift" {
				want = ErrMigrationBusy
			}
			if len(f.live) != 0 {
				t.Fatal("helper survived failed migration")
			}
			if fault == "partial" && len(f.removed) == 0 {
				t.Fatal("failed helper cleanup untested")
			}
			if !errors.Is(e, want) || rep.State != "incomplete" {
				t.Fatalf("partial: %+v %v", rep, e)
			}
			if _, e = os.Lstat(f.spec.StateDir); !os.IsNotExist(e) {
				t.Fatal("failed import published host state")
			}
			if _, e = MigrateLegacy(context.Background(), f.spec); !errors.Is(e, ErrMigrationCollision) {
				t.Fatalf("retry: %v", e)
			}
			if _, e = New(Config{StateDir: f.spec.StateDir, Docker: f}); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("New: %v", e)
			}
			j := &Workplace{state: f.spec.StateDir, docker: f}
			if _, e = j.Run(context.Background(), Ref{"p", "w"}, RunSpec{Argv: []string{"true"}}); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("Run: %v", e)
			}
			if _, e = j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p", "w"}, Repo: "/irrelevant"}); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("Provision: %v", e)
			}
			if _, e = j.Export(context.Background(), Ref{"p", "w"}, io.Discard); !errors.Is(e, ErrMigrationIncomplete) {
				t.Fatalf("Export: %v", e)
			}
		})
	}
}

// No public clock bypass exists. The internal injected clock accepts just
// before expiry and refuses exactly at the removal instant without effects.
func TestMigrateLegacyReaderExpiry(t *testing.T) {
	f := newMigrationFixture(t)
	f.spec.DryRun = true
	deadline := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	if _, e := migrateLegacy(context.Background(), f.spec, deadline.Add(-time.Nanosecond)); e != nil {
		t.Fatal(e)
	}
	if _, e := migrateLegacy(context.Background(), f.spec, deadline); !errors.Is(e, ErrMigrationExpired) {
		t.Fatalf("expiry: %v", e)
	}
}

// Cancellation never publishes or changes source. This cancellation is before
// admission; copy interruption is tested separately through the fixture lane.
func TestMigrateLegacyCancelled(t *testing.T) {
	f := newMigrationFixture(t)
	check := f.unchanged()
	defer check()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, e := MigrateLegacy(ctx, f.spec)
	if e == nil || rep.State != "refused" {
		t.Fatalf("cancellation: %+v %v", rep, e)
	}
}

// Cancellation after a helper starts must synchronously stop/remove that exact
// helper on the fixed transport before returning; other containers are untouched.
func TestMigrateLegacyHelperCancellationCleanup(t *testing.T) {
	f := newMigrationFixture(t)
	check := f.unchanged()
	defer check()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancelCopy = cancel
	rep, e := MigrateLegacy(ctx, f.spec)
	if !errors.Is(e, ErrMigrationCopy) || rep.State != "incomplete" || len(f.live) != 0 || len(f.removed) != 1 {
		t.Fatalf("cleanup: state=%s err=%v live=%d removed=%v", rep.State, e, len(f.live), f.removed)
	}
	if !callNameRE.MatchString(f.removed[0]) {
		t.Fatal("cleanup exceeded exact generated helper name")
	}
}

// Snapshot labels must bind the preserved real commit/tree/parent; migration
// accepts a valid snapshot and refuses either forged tree or forged parent.
func TestMigrateLegacySnapshotBindings(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-tree", "wrong-parent"} {
		t.Run(mode, func(t *testing.T) {
			f := newMigrationFixture(t)
			vol := legacyWorkspacePrefix + "p.w"
			labels := f.labels[vol]
			repo := filepath.Join(f.paths[vol], "src")
			parent := labels[legacyRoot+".base"]
			tree := git(t, repo, "rev-parse", parent+"^{tree}")
			commit := git(t, repo, "commit-tree", tree, "-p", parent, "-m", "synthetic historical snapshot")
			labels[legacyRoot+".base"], labels[legacyRoot+".snapshot-tree"], labels[legacyRoot+".snapshot-parent"] = commit, tree, parent
			if mode == "wrong-tree" {
				labels[legacyRoot+".snapshot-tree"] = strings.Repeat("a", 40)
			}
			if mode == "wrong-parent" {
				labels[legacyRoot+".snapshot-parent"] = strings.Repeat("b", 40)
			}
			check := f.unchanged()
			defer check()
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if mode == "valid" {
				if e != nil || rep.State != "published" {
					t.Fatalf("valid snapshot: %s %v", rep.State, e)
				}
			} else if !errors.Is(e, ErrMigrationInvalid) || rep.State != "refused" {
				t.Fatalf("forged snapshot: %s %v", rep.State, e)
			}
		})
	}
}

// Bash errexit does not enforce the first member of an AND-list. Every required
// directory/marker check must actually reject through the production importer.
func TestMigrateLegacyMandatoryWorkspacePaths(t *testing.T) {
	for _, path := range []string{"src", "src/.git", "home", legacyAdmin, legacyAdmin + "/provisioned"} {
		t.Run(path, func(t *testing.T) {
			f := newMigrationFixture(t)
			if e := os.RemoveAll(filepath.Join(f.paths[legacyWorkspacePrefix+"p.w"], path)); e != nil {
				t.Fatal(e)
			}
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if !errors.Is(e, ErrMigrationInvalid) || rep.State != "refused" {
				t.Fatalf("mandatory %s admitted: state=%s err=%v", path, rep.State, e)
			}
			if len(f.labels) != 5 {
				t.Fatal("invalid workspace created destination")
			}
		})
	}
}

// Foreign writes during the operator hold are modeled as fixture faults. Identity
// and host-content rechecks must refuse publication; originals are retained, but
// this test intentionally cannot claim the foreign write never occurred.
func TestMigrateLegacyRechecksPublication(t *testing.T) {
	for _, fault := range []string{"source-identity", "target-identity", "host-content"} {
		t.Run(fault, func(t *testing.T) {
			f := newMigrationFixture(t)
			want := ErrMigrationCopy
			switch fault {
			case "source-identity":
				f.sourceIdentityDrift = true
				want = ErrMigrationInvalid
			case "target-identity":
				f.targetIdentityDrift = true
			case "host-content":
				f.hostDrift = true
			}
			rep, e := MigrateLegacy(context.Background(), f.spec)
			if !errors.Is(e, want) || rep.State != "incomplete" {
				t.Fatalf("drift: state=%s err=%v want=%v", rep.State, e, want)
			}
			if _, e = os.Lstat(f.spec.StateDir); !os.IsNotExist(e) {
				t.Fatal("drift published host state")
			}
		})
	}
}

// An object present under the expected OID is not sufficient evidence: its
// decompressed bytes must hash to that OID and its referenced graph must exist.
func TestMigrateLegacyCorruptBaseObject(t *testing.T) {
	f := newMigrationFixture(t)
	volume := legacyWorkspacePrefix + "p.w"
	repo := filepath.Join(f.paths[volume], "src")
	base := f.labels[volume][legacyRoot+".base"]
	contents := git(t, repo, "cat-file", "commit", base) + "\ncorrupted bytes\n"
	var blob bytes.Buffer
	zipper := zlib.NewWriter(&blob)
	fmt.Fprintf(zipper, "commit %d%c%s", len(contents), 0, contents)
	if e := zipper.Close(); e != nil {
		t.Fatal(e)
	}
	object := filepath.Join(repo, ".git", "objects", base[:2], base[2:])
	if e := os.Chmod(object, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(object, blob.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	// This witness proves corrupt input rejection, without attributing the
	// rejection to fsck: current Git also rejects it during typed object lookup.
	check := f.unchanged()
	defer check()
	rep, e := MigrateLegacy(context.Background(), f.spec)
	if !errors.Is(e, ErrMigrationInvalid) || rep.State != "refused" || len(f.labels) != 5 {
		t.Fatalf("corrupt base admitted: state=%s err=%v", rep.State, e)
	}
}

// A valid commit object can exist while its referenced tree is missing. The
// existence control passes, but production graph validation must refuse import.
func TestMigrateLegacyMissingBaseTree(t *testing.T) {
	f := newMigrationFixture(t)
	volume := legacyWorkspacePrefix + "p.w"
	repo := filepath.Join(f.paths[volume], "src")
	base := f.labels[volume][legacyRoot+".base"]
	tree := git(t, repo, "rev-parse", base+"^{tree}")
	object := filepath.Join(repo, ".git", "objects", tree[:2], tree[2:])
	if e := os.Remove(object); e != nil {
		t.Fatal(e)
	}
	if _, e := hostGit(context.Background(), repo, "cat-file", "-e", base+"^{commit}"); e != nil {
		t.Fatalf("graph plant failed existence control: %v", e)
	}
	check := f.unchanged()
	defer check()
	rep, e := MigrateLegacy(context.Background(), f.spec)
	if !errors.Is(e, ErrMigrationInvalid) || rep.State != "refused" || len(f.labels) != 5 {
		t.Fatalf("missing tree admitted: state=%s err=%v", rep.State, e)
	}
}
