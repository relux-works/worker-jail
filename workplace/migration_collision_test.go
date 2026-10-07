package workplace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Public admission refuses the root receipt name for files, directories and
// links (including dangling links), even in dry-run, without destination effects.
// Host manifests prove unchanged source data/metadata; volume copies are emulated.
func TestMigrationReservedHostReceiptAdmission(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "dangling-symlink"} {
		for _, dry := range []bool{false, true} {
			mode := "copy"
			if dry {
				mode = "dry-run"
			}
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newMigrationFixture(t)
				f.spec.DryRun = dry
				path := filepath.Join(f.spec.SourceStateDir, "migration.json")
				var err error
				switch kind {
				case "file":
					err = os.WriteFile(path, []byte("source-owned receipt-name bytes\n"), 0400)
				case "directory":
					err = os.Mkdir(path, 0700)
					if err == nil {
						err = os.WriteFile(filepath.Join(path, "auxiliary"), []byte("source-owned directory contents\n"), 0600)
					}
				case "symlink":
					err = os.Symlink("snapshots/identity", path)
				case "dangling-symlink":
					err = os.Symlink("absent-auxiliary", path)
				}
				if err != nil {
					t.Fatal(err)
				}
				check := f.unchanged()
				defer check()
				rep, err := MigrateLegacy(context.Background(), f.spec)
				if !errors.Is(err, ErrMigrationCollision) || rep.State != "refused" {
					t.Fatalf("reserved host receipt must refuse admission: state=%s err=%v", rep.State, err)
				}
				for _, p := range []string{f.spec.StateDir, f.spec.StateDir + ".migration-incomplete"} {
					if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("refusal created destination path %s: %v", filepath.Base(p), err)
					}
				}
				stages, err := filepath.Glob(filepath.Join(filepath.Dir(f.spec.StateDir), ".rwp-migration-*"))
				if err != nil || len(stages) != 0 {
					t.Fatalf("refusal created staging: %v %v", stages, err)
				}
				for _, labels := range f.labels {
					if labels[LabelRoot] == "1" {
						t.Fatal("refusal created canonical volume")
					}
				}
				if len(f.helpers) != 0 || len(f.removed) != 0 {
					t.Fatal("receipt admission reached Docker helper/removal")
				}
			})
		}
	}
}

// Only the root publication name is reserved. A nested same-name auxiliary file
// is preserved, as are differently named root files in the reviewer witness.
func TestMigrationNestedHostReceiptPreserved(t *testing.T) {
	f := newMigrationFixture(t)
	path := filepath.Join("snapshots", "migration.json")
	writeFile(t, filepath.Join(f.spec.SourceStateDir, path), "nested auxiliary bytes\n")
	check := f.unchanged()
	defer check()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if err != nil || rep.State != "published" {
		t.Fatalf("nested auxiliary rejected: state=%s err=%v", rep.State, err)
	}
	want, n, err := hostManifest(filepath.Join(f.spec.SourceStateDir, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	got, copied, err := hostManifest(filepath.Join(f.spec.StateDir, "snapshots"))
	if err != nil || got != want || copied != n {
		t.Fatalf("nested auxiliary bytes/metadata lost: %v", err)
	}
}
