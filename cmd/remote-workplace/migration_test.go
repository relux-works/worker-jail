package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/remote-workplace/workplace"
)

// Historical environment spellings are only negative fixtures. Production run
// must ignore each one, initialize a disposable canonical home, and reach its
// ordinary unknown-command response without consulting a daemon.
func TestNoLegacyEnvironmentAlias(t *testing.T) {
	for _, suffix := range []string{"STATE_DIR", "IMAGE", "SLOTS", "PROJECT_SLOTS"} {
		t.Run(suffix, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			for _, key := range []string{"STATE_DIR", "IMAGE", "SLOTS", "PROJECT_SLOTS"} {
				t.Setenv("RWP_"+key, "")
				t.Setenv("WJ_"+key, "")
			}
			value := "-1"
			if suffix == "IMAGE" {
				value = "invalid image with spaces"
			}
			if suffix == "STATE_DIR" {
				value = filepath.Join(t.TempDir(), "reserved")
				if e := os.WriteFile(value+".migration-incomplete", []byte("fixture\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			t.Setenv("WJ_"+suffix, value)
			var out, errout bytes.Buffer
			if code := run(context.Background(), []string{"unsupported-fixture-command"}, nil, &out, &errout); code != 2 {
				t.Fatalf("historical %s affected production: code=%d err=%s", suffix, code, errout.String())
			}
		})
	}
}

// The actual CLI reports the intended collision exit for copy and dry-run,
// leaving synthetic source bytes intact and creating no destination artifacts.
// Admission stops before Docker initialization, so no live transport is used.
func TestMigrationCLIReservedHostReceipt(t *testing.T) {
	for _, dry := range []bool{false, true} {
		name := "copy"
		if dry {
			name = "dry-run"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(source, "migration.json")
			data := "original auxiliary host file\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--state-dir", target, "--image", workplace.DefaultImage, "migrate-legacy", "--source-state-dir", source}
			if dry {
				args = append(args, "--dry-run")
			}
			var out, errout bytes.Buffer
			if code := run(context.Background(), args, nil, &out, &errout); code != 3 || !strings.Contains(errout.String(), workplace.ErrMigrationCollision.Error()) {
				t.Fatalf("collision exit: code=%d err=%s", code, errout.String())
			}
			var rep workplace.LegacyMigrationReport
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.State != "refused" || !rep.SourceRetained {
				t.Fatalf("collision report: %+v %v", rep, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != data {
				t.Fatalf("source changed: %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "source" {
				t.Fatalf("collision caused destination effects: %v %v", entries, err)
			}
		})
	}
}
