# worker-jail v1: integration notes

Status: informative. For remote-worker-harness (rwh) and for the orchestrators who review worker patches.
The rules are in [`protocol.md`](protocol.md); where this page and the protocol differ, the protocol wins.
Every command below exists in `cmd/worker-jail` and every identifier in `jail/`; the doctor, round-trip, apply and verification snippets were run against the real workers VM (setup and image builds were not re-run).

## 1. One-time setup (operator)

Start the workers VM. Memory is at least N × 2 GiB + 2 GiB (protocol section 11); N = 6 here:

```sh
colima start -p workers --cpus 6 --memory 14 --disk 60 --mount none --activate=false
```

Then set these two keys in `~/.colima/workers/colima.yaml` and restart the profile (`colima stop -p workers && colima start -p workers`):

```yaml
docker:
  features:
    containerd-snapshotter: false   # classic overlay2; doctor requires it
binfmt: false                       # no foreign-architecture emulation
```

Never add `mounts:` or `--ssh-agent`. Build the images and the CLI, then check:

```sh
make image    # worker-jail/base:1 and worker-jail/go:1, built into the workers VM
make build    # bin/worker-jail
bin/worker-jail doctor
```

Expected output (exit 0):

```
ok   endpoint  colima-workers, overlay2
ok   vm-shares only colima's read-only image cache is shared
ok   image     worker-jail/base:1
```

## 2. Images

| image | built from | use |
| --- | --- | --- |
| `worker-jail/base:1` | `images/base` | The default (`jail.DefaultImage`). Debian trixie-slim, git, uid 10001, no setuid bits. |
| `worker-jail/go:1` | `images/go` | Reference Go-toolchain parent: base plus Go 1.25. |

Rules for derived images (protocol 9.9): derive from `worker-jail/base:1`, declare no `VOLUME` (doctor refuses it), hold no secrets, and build into the workers VM only.
rwh's `images/rwh-worker/Dockerfile` defaults to `ARG BASE=worker-jail/base:latest`, but the only tag is `:1`, so build it with:

```sh
docker --context colima-workers build --build-arg BASE=worker-jail/base:1 -t rwh-worker:dev images/rwh-worker
```

Caches: `/cache/<name>` is the read-only volume `wj-cache.<project>.<name>`. When a project has a `gomod` cache, every call gets
`GOMODCACHE=/cache/gomod GOPROXY=off GOTOOLCHAIN=local`. `GOFLAGS` is the image's choice (`worker-jail/go:1` sets none; rwh's image sets `-mod=mod`).

## 3. Go API: one worker session

```go
j, err := jail.New(jail.Config{Image: "rwh-worker:dev"})       // no docker call yet
if _, err := j.Doctor(ctx); err != nil { return err }            // at harness startup: ErrDoctor → start no jailed worker

ref := jail.Ref{Project: "myproj", Worker: "w-7f3a"}           // [a-z0-9][a-z0-9-]{0,31}
ws, err := j.Provision(ctx, jail.ProvisionSpec{Ref: ref, Repo: projectDir, RefName: "main"})
err = j.SeedGoMod(ctx, ref.Project, projectDir, "main")        // Go projects; additive, per project

// per tool call
res, err := j.Run(ctx, ref, jail.RunSpec{
	Argv: []string{"/opt/rwh/rwh-tool"}, Stdin: bytes.NewReader(req),
	Timeout: toolTimeout + 30*time.Second,                       // rwh's callGrace
})
rr := tools.RunResult{Stdout: res.Stdout, Stderr: res.Stderr, Exit: res.Exit, TimedOut: res.TimedOut, Truncated: res.Truncated}
audit(res.QueueWait, res.Duration, len(res.Stdout), len(res.Stderr))

// after every turn: ok, failed, interrupted, timed out
f := createTemp(".temp/rwh/<worker>/")                         // on the host, outside any workspace
info, err := j.Export(ctx, ref, f)                              // on error: delete the partial file, report the turn
rename(f, fmt.Sprintf(".temp/rwh/%s/turn-%d.patch", worker, n)) // info.Bytes == 0: nothing to review

// end of the worker's life
err = j.Deprovision(ctx, ref, false)                           // ErrUnexported: export, hand the patch over, then force=true
```

`Run` returns an error only when the jail failed; a non-zero exit, a timeout and truncation are in `Result`. Use a context
that survives the turn for `Export` and `Deprovision`, so an interrupted turn is still exported.

## 4. Errors and results

| condition | meaning | harness / orchestrator |
| --- | --- | --- |
| `ErrDoctor` | A doctor check failed (VM, shares, driver, image). | Start no jailed worker; tell the operator (section 8). |
| `ErrNoWorkspace` | No volume `wj.<P>.<W>`. | Provision, or treat the session as ended. |
| `ErrIncomplete` | The volume exists but was never fully provisioned (a crash mid-provision). | `Deprovision(force=true)`, then provision again. |
| `ErrBusy` | A call still uses the workspace. | `Kill(P, W)` if the session is over, then retry. |
| `ErrUnexported` | The workspace differs from base and from the last export. | Export, hand the patch to the orchestrator, then force. |
| `ErrExportTooLarge` | The patch exceeds 64 MiB. | Discard the partial patch; report to the orchestrator; do not force-deprovision silently. |
| `ErrDirty` | `apply` target has changes or untracked files. | Use a fresh worktree at base. |
| `ErrGitPath` | The patch touches a `.git` path. | Reject the patch outright; it is hostile. |
| `ErrReviewRequired` | Flagged paths (CI, hooks, agent files, symlinks, gitlinks); CLI exit 4. | Read every flagged hunk; only then re-run with `--allow-review-required`, or reject. |
| `Result.TimedOut` | The call hit its timeout and was killed (CLI exit 124). | Report a timed-out tool call to the model. |
| `Result.Truncated` | Output exceeded MaxOutput; the call was killed. | rwh treats it as a failed call. |
| context cancelled | The host killed the container (`docker kill`); the in-container `timeout` is the backstop. | Record the call as interrupted; still export the turn. |

## 5. Capacity

- Slots: at most N calls at once (default: the VM's CPU count, from `docker info`) and M per project (default ⌈N/2⌉).
  Every container takes a slot: calls, provision, export, seeding, usage.
- Set them in `jail.Config{Slots, ProjectSlots}`, or with `--slots`/`--project-slots` or `WJ_SLOTS`/`WJ_PROJECT_SLOTS` for the CLI.
  Slots are host file locks in `~/.local/state/worker-jail/slots/`, so every process with the same state dir shares them.
- `Result.QueueWait` is the time spent waiting for a slot. Record it in the audit log next to `Duration`: it separates a slow tool from a saturated VM
  and shows when a project's budget (protocol 9.7) needs tightening.
- Many workers per project are fine. An idle worker is only a volume: it costs disk, never CPU or memory.
- `Usage(ctx, ref)` (CLI `usage`) returns the workspace's bytes. Check it after each turn and stop a worker over its soft quota; the VM disk is the hard cap.

## 6. Orchestrator: reviewing and landing a worker patch

```sh
less .temp/rwh/w-7f3a/turn-3.patch                                    # 1. read it as text first
git worktree add --detach .temp/review-w-7f3a <base>                  # 2. clean worktree at base (base= in the export line)
bin/worker-jail apply --repo .temp/review-w-7f3a .temp/rwh/w-7f3a/turn-3.patch   # 3. prints applied paths
git -C .temp/review-w-7f3a switch -c worker/w-7f3a-turn-3
git -C .temp/review-w-7f3a -c core.hooksPath=/dev/null commit -S -m "..."        # 4. hooks disabled
git -C .temp/review-w-7f3a -c core.hooksPath=/dev/null push -u origin worker/w-7f3a-turn-3   # 5. then open a PR
```

On exit 4 `apply` lists `flagged: <path> (<reason>)` and applies nothing. Read each flagged hunk; re-run with `--allow-review-required` only if every one is acceptable.

6. Validate in a jail, never on the host:

```sh
bin/worker-jail --image worker-jail/go:1 provision --project myproj --worker verify-w-7f3a --repo .temp/review-w-7f3a --ref worker/w-7f3a-turn-3
bin/worker-jail --image worker-jail/go:1 run --project myproj --worker verify-w-7f3a --timeout 10m -- go test ./...
bin/worker-jail deprovision --project myproj --worker verify-w-7f3a
```

Never run `seed-gomod` on a worker branch. Seeding runs the host's Go, with the owner's credentials, on that ref's `go.mod`: a worker could name private
modules of other repositories and have them copied into its project's cache, which its next calls can read. The verification workspace uses the cache
seeded from `main`. If the change adds a dependency, the offline build fails; land the dependency on `main` yourself after review, reseed from `main`, and verify again.

7. Worker-produced code (tests, Makefile targets, `go generate`, scripts) does not run on the host until the PR has landed.

## 7. What rwh no longer does for jailed workers

- No host-side file tools: read, write, edit and search all run as `rwh-tool` inside `jail.Run`.
- No bash under Seatbelt presented as jailed. A session without `JailRun` reports its backend as local and MUST NOT be called jailed (protocol 9).
- No direct `docker` against the workers VM; only the operator (building images) and the red-team suite may.
- No apply, commit or push of a worker's patch: patches go to the orchestrator.

## 8. Operations

| command | use |
| --- | --- |
| `worker-jail ls [--project P]` | Workspaces (base, created), caches, calls in flight. |
| `worker-jail kill [--project P] [--worker W]` | Kill calls in flight; prints `killed N`. |
| `worker-jail usage --project P --worker W` | Workspace bytes. |
| `worker-jail purge --project P` | Kill P's calls and remove all of P's workspaces, caches and digests. |

- Dead sessions: `ls` shows workspaces no live session owns. `export -o` each one for the orchestrator, then `deprovision` (with `--force` only after the patch is handed over).
- VM restart: volumes (workspaces, caches) survive; calls in flight die, and their turns show a failed call. Export as usual.
- Doctor failures:

| check | cause | fix |
| --- | --- | --- |
| `endpoint` docker error | workers VM not running | `colima start -p workers` |
| `endpoint` want colima-workers/overlay2 | containerd snapshotter still on | set `containerd-snapshotter: false`, restart the profile |
| `vm-shares` | a host share is mounted into the VM | remove `mounts:`, restart with `--mount none` |
| `image` missing | image not built in the workers VM | `make image`, or build the derived image |
| `image` declares VOLUME | derived image has `VOLUME` | remove it and rebuild |

## 9. Verification

- `make it` (with `make image` first): the integration suite on the real VM, over throwaway `wjit-*` projects that it purges. It proves the
  provision, run, export, apply and deprovision path, timeouts, the output flood cap, that no container survives a call, and an offline Go build from a seeded cache.
- `make redteam` (planned; neither the target nor the report exists at this commit): the probes and positive controls of protocol section 12, with its report in `docs/redteam-report.md`.
- rwh adds its own host-side probes on top (tool dispatch never leaves `jail.Run`, no secret in argv, stdin or environment).
