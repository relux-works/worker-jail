package workplace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Ordinary auxiliary host files must survive a successful full import; a
// reserved-name collision may instead refuse before any destination effects.
// Volume copies are emulated; host bytes use the real production path.
func TestReviewAuxiliaryHostReceiptCollision(t *testing.T) {
	for _, name := range []string{"operator-notes.json", "migration.json"} {
		t.Run(name, func(t *testing.T) {
			f := newMigrationFixture(t)
			data := []byte("original auxiliary host file\n")
			path := filepath.Join(f.spec.SourceStateDir, name)
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			check := f.unchanged()
			defer check()
			rep, err := MigrateLegacy(context.Background(), f.spec)
			if err != nil {
				if name != "migration.json" || !(errors.Is(err, ErrMigrationInvalid) || errors.Is(err, ErrMigrationCollision)) {
					t.Fatalf("unexpected refusal: %s %v", rep.State, err)
				}
				if _, e := os.Lstat(f.spec.StateDir); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("refusal published destination: %v", e)
				}
				if _, e := os.Lstat(f.spec.StateDir + ".migration-incomplete"); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("refusal created guard: %v", e)
				}
				for _, labels := range f.labels {
					if labels[LabelRoot] == "1" {
						t.Fatal("refusal created canonical volume")
					}
				}
				return
			}
			if rep.State != "published" {
				t.Fatalf("not published: %s", rep.State)
			}
			got, e := os.ReadFile(filepath.Join(f.spec.StateDir, name))
			if e != nil || string(got) != string(data) {
				t.Fatalf("full-host preservation lost auxiliary file %s: err=%v destination bytes differ=%v", name, e, string(got) != string(data))
			}
		})
	}
}
