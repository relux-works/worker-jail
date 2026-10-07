package workplace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An incomplete canonical cache must remain unavailable from a normal public
// writer even when a caller mints a same-ID receipt in a different state root.
// The injected Docker records mount authority; no real daemon is contacted.
func TestReviewIncompleteReceiptSelfMint(t *testing.T) {
	valid := newMigrationFixture(t)
	completed, err := MigrateLegacy(context.Background(), valid.spec)
	if err != nil || completed.State != "published" {
		t.Fatalf("positive setup: %v", err)
	}
	controlDocker := newFakeDocker()
	controlDocker.volumes[CacheVolume("p", "gomod")] = cloneLabels(valid.labels[CacheVolume("p", "gomod")])
	control, err := New(Config{StateDir: valid.spec.StateDir, Docker: controlDocker})
	if err != nil {
		t.Fatal(err)
	}
	if err = control.SeedCache(context.Background(), "p", "gomod", strings.NewReader("")); err != nil || controlDocker.count("create") != 1 {
		t.Fatalf("published writer positive control: %v", err)
	}
	f := newMigrationFixture(t)
	f.partial = true
	sourceCheck := f.unchanged()
	defer sourceCheck()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if !errors.Is(err, ErrMigrationCopy) || rep.State != "incomplete" {
		t.Fatalf("setup: state=%s err=%v", rep.State, err)
	}
	d := newFakeDocker()
	d.volumes[CacheVolume("p", "gomod")] = cloneLabels(f.labels[CacheVolume("p", "gomod")])
	for _, mint := range []bool{false, true} {
		state := t.TempDir()
		j, err := New(Config{StateDir: state, Docker: d})
		if err != nil {
			t.Fatal(err)
		}
		if mint {
			// Only public daemon metadata is needed: no authentic receipt exists yet.
			id := d.volumes[CacheVolume("p", "gomod")][migrationLabel]
			raw, _ := json.Marshal(map[string]string{"State": "published", "ID": id})
			if err := os.WriteFile(filepath.Join(state, migrationReceipt), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		before := d.count("create")
		err = j.SeedCache(context.Background(), "p", "gomod", strings.NewReader(""))
		if !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != before {
			t.Fatalf("mint=%v: incomplete cache admitted: err=%v, writer creates=%d", mint, err, d.count("create")-before)
		}
	}
}

// Copying a published receipt must not give a distinct state root authority to
// export a migration volume. This tests Export rather than its private guard.
func TestReviewPublishedReceiptRootBinding(t *testing.T) {
	f := newMigrationFixture(t)
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if err != nil || rep.State != "published" {
		t.Fatalf("setup: %v", err)
	}
	d := newFakeDocker()
	d.volumes[WorkspaceVolume("p", "w")] = cloneLabels(f.labels[WorkspaceVolume("p", "w")])
	state := t.TempDir()
	j, err := New(Config{StateDir: state, Docker: d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Export(context.Background(), Ref{"p", "w"}, io.Discard); !errors.Is(err, ErrMigrationIncomplete) {
		t.Fatalf("positive refusal control: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(f.spec.StateDir, migrationReceipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, migrationReceipt), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = j.Export(context.Background(), Ref{"p", "w"}, io.Discard)
	if !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != 0 {
		t.Fatalf("copied receipt admits foreign root: err=%v, reader creates=%d", err, d.count("create"))
	}
}

type reviewInterruptWorkspace struct{ f *migrationFixture }

func (d reviewInterruptWorkspace) Run(ctx context.Context, a []string, in io.Reader, out, errout io.Writer) (int, error) {
	exit, err := d.f.Run(ctx, a, in, out, errout)
	if exit == 0 && err == nil && a[0] == "run" {
		for i := 0; i+1 < len(a); i++ {
			if a[i] == "-c" && a[i+1] == migrationCopyScript && a[len(a)-1] == KindWorkspace {
				return 79, nil
			}
		}
	}
	return exit, err
}

// Even a completed data copy is incomplete authority until verified publication.
// Run must not receive the writable mount based on a caller-minted receipt.
func TestReviewIncompleteWorkspaceRun(t *testing.T) {
	f := newMigrationFixture(t)
	f.spec.Docker = reviewInterruptWorkspace{f}
	sourceCheck := f.unchanged()
	defer sourceCheck()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if !errors.Is(err, ErrMigrationCopy) || rep.State != "incomplete" {
		t.Fatalf("setup: %+v %v", rep, err)
	}
	d := newFakeDocker()
	for name, labels := range f.labels {
		if labels[LabelRoot] == "1" {
			d.volumes[name] = cloneLabels(labels)
		}
	}
	state := t.TempDir()
	j, err := New(Config{StateDir: state, Docker: d})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(f.spec.SourceStateDir, "policies/p.w.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.SetPolicy(context.Background(), Ref{"p", "w"}, policy, SetPolicyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Run(context.Background(), Ref{"p", "w"}, RunSpec{Argv: []string{"true"}}); !errors.Is(err, ErrMigrationIncomplete) {
		t.Fatalf("no receipt refusal control: %v", err)
	}
	raw, _ := json.Marshal(map[string]string{"State": "published", "ID": d.volumes[WorkspaceVolume("p", "w")][migrationLabel]})
	if err := os.WriteFile(filepath.Join(state, migrationReceipt), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = j.Run(context.Background(), Ref{"p", "w"}, RunSpec{Argv: []string{"true"}})
	if !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != 0 {
		t.Fatalf("self-minted receipt starts incomplete workspace: err=%v writer creates=%d", err, d.count("create"))
	}
}
