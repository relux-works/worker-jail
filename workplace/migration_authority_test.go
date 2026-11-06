package workplace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func importedFake(f *migrationFixture) *fakeDocker {
	d := newFakeDocker()
	for name, labels := range f.labels {
		if labels[LabelRoot] == "1" {
			d.volumes[name] = cloneLabels(labels)
		}
	}
	return d
}

// Each real public path admits genuinely published objects but refuses receipt
// adoption by a distinct root, before container/volume/network creates, removals
// or kills. Docker is recorded, not executed: VM enforcement remains a bound.
func TestMigrationPublicRootAuthority(t *testing.T) {
	f := newMigrationFixture(t)
	if rep, err := MigrateLegacy(context.Background(), f.spec); err != nil || rep.State != "published" {
		t.Fatalf("setup: %s %v", rep.State, err)
	}
	receipt, err := os.ReadFile(filepath.Join(f.spec.StateDir, migrationReceipt))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	paths := []struct {
		name string
		call func(*Workplace) error
	}{
		{"seed", func(j *Workplace) error { return j.SeedCache(ctx, "p", "gomod", nil) }},
		{"run", func(j *Workplace) error { _, e := j.Run(ctx, Ref{"p", "w"}, RunSpec{Argv: []string{"true"}}); return e }},
		{"export", func(j *Workplace) error { _, e := j.Export(ctx, Ref{"p", "w"}, io.Discard); return e }},
		{"deprovision", func(j *Workplace) error { return j.Deprovision(ctx, Ref{"p", "w"}, true) }},
		{"purge", func(j *Workplace) error { return j.Purge(ctx, "p") }},
		{"provision", func(j *Workplace) error {
			_, e := j.Provision(ctx, ProvisionSpec{Ref: Ref{"p", "w"}, Repo: newRepo(t)})
			return e
		}},
		{"egress-up", func(j *Workplace) error { return j.EgressUp(ctx) }},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			for _, canonical := range []bool{true, false} {
				d := importedFake(f)
				state := f.spec.StateDir
				if !canonical {
					state = t.TempDir()
				}
				j, err := New(Config{StateDir: state, Docker: d, Colima: fakeColima{mounts: fixtureMounts(t)}})
				if err != nil {
					t.Fatal(err)
				}
				j.home = fixtureHome
				if !canonical {
					writeFile(t, filepath.Join(state, migrationReceipt), string(receipt))
					policy, err := os.ReadFile(filepath.Join(f.spec.SourceStateDir, "policies/p.w.json"))
					if err != nil {
						t.Fatal(err)
					}
					writeFile(t, filepath.Join(state, "policies/p.w.json"), string(policy))
				}
				err = path.call(j)
				if canonical {
					if err != nil {
						t.Fatalf("positive %s: %v", path.name, err)
					}
				} else {
					if !errors.Is(err, ErrMigrationIncomplete) {
						t.Fatalf("foreign %s: %v", path.name, err)
					}
					for _, verb := range []string{"create", "run", "start", "volume create", "volume rm", "network create", "rm", "kill"} {
						if d.count(verb) != 0 {
							t.Fatalf("refusal wrote via %s", verb)
						}
					}
					if len(d.volumes) != 5 {
						t.Fatal("refusal removed an object")
					}
				}
			}
		})
	}
}

// Caller-readable metadata alone cannot fabricate membership. Each single
// damaged receipt/immutable-label member refuses SeedCache without writer mounts;
// the unmodified receipt is the nearby positive. Source bytes stay unchanged.
func TestMigrationReceiptMembership(t *testing.T) {
	f := newMigrationFixture(t)
	check := f.unchanged()
	defer check()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.spec.StateDir, migrationReceipt)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.RemoveAll(path); os.WriteFile(path, good, 0600) }()
	for _, fault := range []string{"valid", "minimal", "wrong-id", "wrong-root", "unlisted", "duplicate", "not-owned", "wrong-metadata", "missing-label", "root-without-id", "malformed", "missing", "unreadable"} {
		t.Run(fault, func(t *testing.T) {
			var receipt LegacyMigrationReport
			if err := json.Unmarshal(good, &receipt); err != nil {
				t.Fatal(err)
			}
			d := importedFake(f)
			volume := CacheVolume("p", "gomod")
			switch fault {
			case "minimal":
				receipt = LegacyMigrationReport{State: "published", ID: rep.ID, StateDir: rep.StateDir}
			case "wrong-id":
				receipt.ID = "0000000000000000"
			case "wrong-root":
				receipt.StateDir = t.TempDir()
			case "missing-label":
				delete(d.volumes[volume], migrationStateLabel)
			case "root-without-id":
				delete(d.volumes[volume], migrationLabel)
			case "unlisted", "duplicate", "not-owned", "wrong-metadata":
				for i, o := range receipt.Objects {
					if o.Target != volume {
						continue
					}
					switch fault {
					case "unlisted":
						receipt.Objects[i].Target = CacheVolume("p", "other")
					case "duplicate":
						receipt.Objects = append(receipt.Objects, o)
					case "not-owned":
						receipt.Objects[i].DestinationOwned = false
					case "wrong-metadata":
						receipt.Objects[i].Labels[LabelCreated] = "2026-10-02T00:00:00Z"
					}
					break
				}
			}
			os.RemoveAll(path) // Only this isolated fixture receipt is replaced.
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "malformed" {
				raw = []byte("{")
			}
			if fault == "unreadable" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if fault != "missing" {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			j, err := New(Config{StateDir: f.spec.StateDir, Docker: d})
			if err != nil {
				t.Fatal(err)
			}
			err = j.SeedCache(context.Background(), "p", "gomod", nil)
			if fault == "valid" {
				if err != nil || d.count("create") != 1 {
					t.Fatalf("positive: %v", err)
				}
			} else if !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != 0 || d.count("volume create") != 0 {
				t.Fatalf("%s: %v creates=%d", fault, err, d.count("create"))
			}
		})
	}
}

// A caller can populate every receipt field from an incomplete report and
// public labels. Even that well-shaped self-mint must not adopt a cache via a
// different root. The original guard and partial copy remain, with no writers.
func TestMigrationIncompleteFullReceiptSelfMint(t *testing.T) {
	f := newMigrationFixture(t)
	f.partial = true
	check := f.unchanged()
	defer check()
	rep, err := MigrateLegacy(context.Background(), f.spec)
	if !errors.Is(err, ErrMigrationCopy) || rep.State != "incomplete" {
		t.Fatalf("setup: %s %v", rep.State, err)
	}
	d := importedFake(f)
	state := t.TempDir()
	j, err := New(Config{StateDir: state, Docker: d})
	if err != nil {
		t.Fatal(err)
	}
	rep.State = "published"
	rep.StateDir, err = normalizedStateRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	// Only the cache has been copied far enough to be owned in this fault.
	for _, o := range rep.Objects {
		if o.Target == CacheVolume("p", "gomod") && !o.DestinationOwned {
			t.Fatal("fault did not reserve cache")
		}
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(state, migrationReceipt), string(raw))
	if err := j.SeedCache(context.Background(), "p", "gomod", nil); !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != 0 {
		t.Fatalf("fully populated self-mint: %v creates=%d", err, d.count("create"))
	}
	if _, err := os.Lstat(f.spec.StateDir + ".migration-incomplete"); err != nil {
		t.Fatal("reservation lost")
	}
}

// Purge must preflight a mixed set before any kill/removal, even when its only
// imported object is a cache. Normal unrelated workspace removal is a positive
// control alongside genuine imported cache removal; no actual daemon is used.
func TestMigrationPurgeCacheAuthority(t *testing.T) {
	f := newMigrationFixture(t)
	if _, err := MigrateLegacy(context.Background(), f.spec); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.spec.StateDir, migrationReceipt))
	if err != nil {
		t.Fatal(err)
	}
	for _, canonical := range []bool{true, false} {
		d := newFakeDocker()
		// A published root may have resumed callers. Foreign-root refusal must
		// happen before Purge kills this recorded call, even if dockerOut later
		// independently refuses the first imported volume removal.
		d.ps = "synthetic-existing-call\n"
		d.volumes[CacheVolume("p", "gomod")] = cloneLabels(f.labels[CacheVolume("p", "gomod")])
		addWorkspace(d, "p", "fresh", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		state := f.spec.StateDir
		if !canonical {
			state = t.TempDir()
			writeFile(t, filepath.Join(state, migrationReceipt), string(raw))
		}
		j, err := New(Config{StateDir: state, Docker: d})
		if err != nil {
			t.Fatal(err)
		}
		err = j.Purge(context.Background(), "p")
		if canonical {
			if err != nil || len(d.volumes) != 0 {
				t.Fatalf("positive purge: %v remaining=%d", err, len(d.volumes))
			}
		} else if !errors.Is(err, ErrMigrationIncomplete) || len(d.volumes) != 2 || d.count("volume rm") != 0 || d.count("kill") != 0 {
			t.Fatalf("foreign cache purge: %v remaining=%d removals=%d", err, len(d.volumes), d.count("volume rm"))
		}
	}
}

// A symlink/relative alias of the actual root retains legitimate authority;
// aliases also resolve the persistent reservation before New or a writer call.
func TestMigrationNormalizedRootAuthority(t *testing.T) {
	f := newMigrationFixture(t)
	aliasParent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(f.spec.StateDir), aliasParent); err != nil {
		t.Fatal(err)
	}
	f.spec.StateDir = filepath.Join(aliasParent, filepath.Base(f.spec.StateDir))
	if rep, err := MigrateLegacy(context.Background(), f.spec); err != nil || rep.State != "published" {
		t.Fatalf("setup: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, f.spec.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	rootAlias := filepath.Join(t.TempDir(), "published")
	if err := os.Symlink(f.spec.StateDir, rootAlias); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{f.spec.StateDir, relative, rootAlias} {
		d := importedFake(f)
		j, err := New(Config{StateDir: state, Docker: d})
		if err != nil {
			t.Fatal(err)
		}
		if err := j.SeedCache(context.Background(), "p", "gomod", nil); err != nil {
			t.Fatalf("alias: %v", err)
		}
		writeFile(t, f.spec.StateDir+".migration-incomplete", "operator reservation")
		if _, err := New(Config{StateDir: state, Docker: d}); !errors.Is(err, ErrMigrationIncomplete) {
			t.Fatalf("alias New: %v", err)
		}
		before := d.count("create")
		if err := j.SeedCache(context.Background(), "p", "gomod", nil); !errors.Is(err, ErrMigrationIncomplete) || d.count("create") != before {
			t.Fatalf("alias writer: %v", err)
		}
		if err := os.Remove(f.spec.StateDir + ".migration-incomplete"); err != nil {
			t.Fatal(err)
		}
	}
}

// Publication retains readable private root/subdirectory metadata (0500 and
// the nearby 0700 control), source hashes, and leaves no host staging. Failure
// after a copy also cleans restrictive staging without touching originals.
func TestMigrationReadOnlyMetadataAndCleanup(t *testing.T) {
	for _, mode := range []os.FileMode{0500, 0700} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%04o-fault=%t", mode, fail), func(t *testing.T) {
				f := newMigrationFixture(t)
				// Independent cleanup of our fixture after assertions keeps a
				// planted production cleanup violation from adding unrelated
				// TempDir errors to the intended staging-retention failure.
				t.Cleanup(func() {
					stages, _ := filepath.Glob(filepath.Join(filepath.Dir(f.spec.StateDir), ".rwp-migration-*"))
					for _, stage := range stages {
						filepath.WalkDir(stage, func(path string, d os.DirEntry, err error) error {
							if err != nil {
								return err
							}
							if d.IsDir() {
								return os.Chmod(path, 0700)
							}
							return nil
						})
						os.RemoveAll(stage)
					}
				})
				f.partial = fail
				for _, p := range []string{f.spec.SourceStateDir, filepath.Join(f.spec.SourceStateDir, "snapshots")} {
					if err := os.Chmod(p, mode); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { os.Chmod(p, 0700) })
				}
				t.Cleanup(func() { os.Chmod(f.spec.StateDir, 0700); os.Chmod(filepath.Join(f.spec.StateDir, "snapshots"), 0700) })
				check := f.unchanged()
				defer check()
				rep, err := MigrateLegacy(context.Background(), f.spec)
				if fail {
					if !errors.Is(err, ErrMigrationCopy) || rep.State != "incomplete" {
						t.Fatalf("fault: %s %v", rep.State, err)
					}
					if _, err := os.Lstat(f.spec.StateDir); !os.IsNotExist(err) {
						t.Fatal("failure published")
					}
				} else {
					if err != nil || rep.State != "published" {
						t.Fatalf("publish: %s %v", rep.State, err)
					}
					for _, p := range []string{".", "snapshots"} {
						source, err := os.Stat(filepath.Join(f.spec.SourceStateDir, p))
						if err != nil {
							t.Fatal(err)
						}
						target, err := os.Stat(filepath.Join(f.spec.StateDir, p))
						if err != nil {
							t.Fatal(err)
						}
						a, b := source.Sys().(*syscall.Stat_t), target.Sys().(*syscall.Stat_t)
						if target.Mode() != source.Mode() || !target.ModTime().Equal(source.ModTime()) || a.Uid != b.Uid || a.Gid != b.Gid {
							t.Fatalf("metadata lost on %s", p)
						}
					}
				}
				stages, err := filepath.Glob(filepath.Join(filepath.Dir(f.spec.StateDir), ".rwp-migration-*"))
				if err != nil || len(stages) != 0 || rep.RetainedStageDir != "" {
					t.Fatalf("staging unaccounted: %v %s", stages, rep.RetainedStageDir)
				}
			})
		}
	}
}
