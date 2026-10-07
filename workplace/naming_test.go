package workplace

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Exported names/defaults and generated runtime identities follow the owner map.
// Workspace meaning, workers transport and policy canonicalization remain v2.1.
func TestRemoteWorkplaceNamingContract(t *testing.T) {
	if WorkspaceVolume("p", "w") != "rwp.p.w" || CacheVolume("p", "gomod") != "rwp-cache.p.gomod" || DefaultImage != "remote-workplace/base:2" || LabelRoot != "ai.relux.remote-workplace" {
		t.Fatal("public naming map differs")
	}
	if !regexp.MustCompile(`^rwp-call-[0-9a-f]{16}$`).MatchString(newCallName()) {
		t.Fatal("call namespace differs")
	}
	if Endpoint("/home/operator") != "unix:///home/operator/.colima/workers/docker.sock" {
		t.Fatal("transport changed")
	}
	if EgressContainer != "rwp-egress" || EgressImage != "remote-workplace/egress:1" || EgressNetwork != "rwp-egress-net" || EgressSockVolume != "rwp-egress-sock" || EgressPolicyVolume != "rwp-egress-policy" || EgressCacheVolume != "rwp-egress-cache" {
		t.Fatal("egress namespace differs")
	}
	cfg := Config{StateDir: t.TempDir(), Docker: newFakeDocker()}
	j, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var _ *Workplace = j
	if _, err = j.SetPolicy(context.Background(), Ref{"p", "w"}, testPolicy("p", "w"), SetPolicyOptions{}); err != nil {
		t.Fatal(err)
	}
}

// The terminology scanner covers current source/docs/config, excluding only the
// focused expiring importer and its fixtures. Vendor sandbox words and actual
// seccomp/AppArmor constants are intentionally outside the product-name gate.
func TestCurrentProductTerminology(t *testing.T) {
	hits, err := scanCurrentProductTerms("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range hits {
		t.Errorf("unbounded product spelling in %s", hit)
	}
}
func scanCurrentProductTerms(root string) ([]string, error) {
	product := strings.TrimPrefix(legacyRoot, "ai.relux.")
	specialist := strings.Split(product, "-")[1]
	prefix := strings.TrimSuffix(legacyWorkspacePrefix, ".")
	old := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(product) + `|\b` + specialist + `\b|\b` + specialist + `ed\b|\b` + prefix + `[._-]|\b` + prefix + `rt\b|\b` + specialist + `[A-Z]`)

	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if path != root && (d.Name() == ".git" || d.Name() == ".temp" || d.Name() == ".task-board" || d.Name() == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == filepath.Join("workplace", "migration.go") || rel == filepath.Join("workplace", "migration_test.go") || rel == filepath.Join("workplace", "migration_integration_test.go") || rel == filepath.Join("cmd", "remote-workplace", "migration_test.go") {
			return nil
		}
		if rel == ".git" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if old.Match(data) {
			hits = append(hits, rel)
		}
		return nil
	})
	return hits, err
}

// The gate's own instrument must detect a known old-product heading in a
// disposable fixture; a skipped root is not evidence of terminology absence.
func TestTerminologyScannerDetectsPlant(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "README.md")
	if err := os.WriteFile(path, []byte("# "+strings.TrimPrefix(legacyRoot, "ai.relux.")), 0600); err != nil {
		t.Fatal(err)
	}
	hits, err := scanCurrentProductTerms(root)
	if err != nil || len(hits) != 1 || hits[0] != "README.md" {
		t.Fatalf("control plant undetected: hits=%v err=%v", hits, err)
	}
}

// The actual root Docker context excludes private runtime/recovery directories
// and config files by literal patterns while retaining product source. This
// checks the effective literal inputs, not a VM builder execution.
func TestImageBuildContextExcludesPrivateState(t *testing.T) {
	data, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			active[line] = true
		}
	}
	for _, required := range []string{".git", ".temp", ".task-board", "bin", ".codex/hooks.json", ".claude/settings.local.json", "task-board.config.json"} {
		if !active[required] {
			t.Errorf("private context exclusion absent: %s", required)
		}
	}
	for _, source := range []string{"*", "workplace", "egress", "cmd", "images", "go.mod", "docs"} {
		if active[source] {
			t.Errorf("source hidden from context: %s", source)
		}
	}
}
