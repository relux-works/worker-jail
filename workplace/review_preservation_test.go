package workplace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The frozen contract accepts private read-only source roots and preserves
// modes. Imported host state must publish without requiring a source chmod.
func TestReviewReadOnlySourceRoot(t *testing.T) {
	f := newMigrationFixture(t)
	if err := os.Chmod(f.spec.SourceStateDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.spec.SourceStateDir, 0700)
	// Restore only fixture cleanup authority after asserting final mode below.
	defer os.Chmod(f.spec.StateDir, 0700)
	defer func() {
		dirs, _ := filepath.Glob(filepath.Join(filepath.Dir(f.spec.StateDir), ".rwp-migration-*"))
		for _, d := range dirs {
			os.Chmod(d, 0700)
		}
	}()
	check := f.unchanged()
	defer check()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if err != nil || rep.State != "published" {
		t.Fatalf("private readable source rejected: state=%s err=%v", rep.State, err)
	}
	info, err := os.Stat(f.spec.StateDir)
	if err != nil || info.Mode().Perm() != 0500 {
		t.Fatalf("source root mode lost: info=%v err=%v", info, err)
	}
}
