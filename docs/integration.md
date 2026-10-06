# worker-jail integration notes (v1 to v2.1)

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
make image    # worker-jail/base:1 (base image v2, with socat), worker-jail/go:1 and worker-jail/egress:1, built into the workers VM
make build    # bin/worker-jail and bin/wj-egress
bin/worker-jail egress up    # v2.1: only if a worker will have a network mode other than none; idempotent
bin/worker-jail doctor
```

Expected output (exit 0):

```
ok   endpoint  colima-workers, overlay2
ok   vm-shares only colima's read-only image cache is shared
ok   image     worker-jail/base:1
```

When a stored policy has a network mode other than `none`, doctor adds a fourth line, `ok   egress    wj-egress hardened (...)`.

## 2. Images

| image | built from | use |
| --- | --- | --- |
| `worker-jail/base:1` | `images/base` | The default (`jail.DefaultImage`). Debian trixie-slim, git, uid 10001, no setuid bits. Base image v2 (v2.1) adds `socat`, the relay of every call with egress; rebuild derived images so they inherit it. |
| `worker-jail/go:1` | `images/go` | Reference Go-toolchain parent: base plus Go 1.25. |
| `worker-jail/egress:1` | `images/egress` (context: the repository root) | v2.1: the egress service `wj-egress`. A static binary in an empty image; not a call image, never pass it as `--image`. |

Rules for derived images (protocol 9.9): derive from `worker-jail/base:1`, declare no `VOLUME` (doctor refuses it), hold no secrets, and build into the workers VM only.
rwh's `images/rwh-worker/Dockerfile` defaults to `ARG BASE=worker-jail/base:latest`, but the only tag is `:1`, so build it with:

```sh
docker --context colima-workers build --build-arg BASE=worker-jail/base:1 -t rwh-worker:dev images/rwh-worker
```

Caches: `/cache/<name>` is the read-only volume `wj-cache.<project>.<name>`. When a project has a `gomod` cache, every call gets
`GOMODCACHE=/cache/gomod GOPROXY=off GOTOOLCHAIN=local`. `GOFLAGS` is the image's choice (`worker-jail/go:1` sets none; rwh's image sets `-mod=mod`).
v2.1: a call whose policy has `network.mode: modules` gets instead `GOPROXY=file:///cache/gomod/cache/download,http://127.0.0.1:3128/gomod GOMODCACHE=/work/home/go/pkg/mod GOSUMDB=sum.golang.org GOTOOLCHAIN=local`: the seeded cache first, then the egress service through the relay (protocol section 7).
A call whose policy has `network.mode` `allowlist`, `denylist` or `all` keeps the `gomod` cache's environment (Go stays offline from the cache)
and adds `HTTP_PROXY=HTTPS_PROXY=ALL_PROXY=http://127.0.0.1:3128` and an empty `NO_PROXY` (section 6c).

## 3. Go API: one worker session

```go
j, err := jail.New(jail.Config{Image: "rwh-worker:dev"})       // no docker call yet
if _, err := j.Doctor(ctx); err != nil { return err }            // at harness startup: ErrDoctor → start no jailed worker

ref := jail.Ref{Project: "myproj", Worker: "w-7f3a"}           // [a-z0-9][a-z0-9-]{0,31}
pol, err := j.LoadPolicy(ref)                                   // v2.0: stored by the operator (`policy set`); ErrNoPolicy → no worker
expose(pol.Tools); audit(pol.ID(), jail.EffectiveRisk(pol).Level) // tool exposure is the harness's layer (protocol section 14)
ws, err := j.Provision(ctx, jail.ProvisionSpec{Ref: ref, Repo: projectDir, RefName: "main"}) // labels the workspace with pol.ID()
err = j.SeedGoMod(ctx, ref.Project, projectDir, "main")        // Go projects; additive, per project
// v2.0, instead of the two lines above: start from the Story worktree as it is now (section 6a)
ws, err = j.Provision(ctx, jail.ProvisionSpec{Ref: ref, FromWorktree: storyDir}) // ws.SnapshotTree, ws.SnapshotParent
tree, err := j.SeedGoModWorktree(ctx, ref.Project, storyDir, jail.SnapshotOptions{}) // no credentials

// per tool call
res, err := j.Run(ctx, ref, jail.RunSpec{
	Argv: []string{"/opt/rwh/rwh-tool"}, Stdin: bytes.NewReader(req),
	Timeout: toolTimeout + 30*time.Second,                       // rwh's callGrace; at most the policy's call_timeout_s
})                                                              // read-only mount and cpus/memory/pids come from the policy
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
| `ErrDirty` | `apply` target has changes or untracked files. | Use a fresh worktree at base, or (v2.0) `--allow-dirty` into a linked worktree. |
| `ErrSnapshot` | v2.0: the worktree cannot be snapshotted: unborn HEAD, a merge, rebase, cherry-pick, revert or bisect in progress, unmerged paths, a sparse checkout, a nested repository among the untracked files, an untracked file over 10 MiB or more than the untracked total (256 MiB unless `--max-untracked-mib`). Nothing is created. | Finish or abort the operation, remove or ignore the file, then provision again. |
| `ErrSecret` | v2.0: the secret guard found likely secrets in the snapshot's delta; the message lists the paths and the rule (name or content), never the text. Also an `--allow-secret-path` for a HIGH or CRITICAL policy. | Remove the file, ignore it, or (name rule only, operator's decision, never from worker input) pass `--allow-secret-path PATH`. |
| `ErrSeed` | v2.0: `seed-gomod --from-worktree` refused a filesystem `replace`, a `go.work`, a `toolchain` line or a `vendor/` that disagrees with `go.mod`. | Seed from a landed ref, or fix the worktree. |
| `ErrDirtyTarget` | v2.0: `apply --allow-dirty` refused the target: a primary checkout, unmerged paths, or an operation in progress. | Apply into a linked worktree (`git worktree add`) in a settled state. |
| `ErrGitPath` | The patch touches a `.git` path. | Reject the patch outright; it is hostile. |
| `ErrReviewRequired` | Flagged paths (CI, hooks, agent files, symlinks, gitlinks); CLI exit 4. | Read every flagged hunk; only then re-run with `--allow-review-required`, or reject. |
| `ErrNoPolicy` | No stored policy for (P, W) (v2.0). Provision and Run refuse; nothing is created. | Ask the operator for a policy (`worker-jail policy set`); never write one from worker input. |
| `ErrPolicyChanged` | The stored policy's id differs from the workspace's label, or the workspace predates v2.0. Run refuses. | Export, deprovision, provision again (re-provision adopts the new policy). |
| `ErrEgressUnavailable` | v2.1: a policy with egress (`modules`, `allowlist`, `denylist`, `all`) that the egress service does not serve: service down or never set up, not confirmed by `policy set`, or a stale id at `run`. CLI exit 5. | `worker-jail egress status`, `egress up`, then `policy set` again. |
| `ErrPolicyInvalid` | A policy breaks a rule; the message names the field and the rule. `policy` CLI exit 1. | Fix the file and review it like code. |
| `ErrRiskExceeded` | `policy check --max-risk` exceeded, or `policy set` of CRITICAL without `--accept-risk CRITICAL` or HIGH without a `note`. CLI exit 4. | A decision for the operator, not the harness. |
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
bin/worker-jail apply --repo .temp/review-w-7f3a --write-scope jail/,docs/integration.md .temp/rwh/w-7f3a/turn-3.patch   # 3. the task's scope; prints applied paths
git -C .temp/review-w-7f3a switch -c worker/w-7f3a-turn-3
git -C .temp/review-w-7f3a -c core.hooksPath=/dev/null commit -S -m "..."        # 4. hooks disabled
git -C .temp/review-w-7f3a -c core.hooksPath=/dev/null push -u origin worker/w-7f3a-turn-3   # 5. then open a PR
```

On exit 5 `apply` lists the paths outside the write scope and applies nothing; that is a refusal, not a question (widen the scope only if the task really covers them). On exit 4 it lists `flagged: <path> (<reason>)` and applies nothing. Read each flagged hunk; re-run with `--allow-review-required` only if every one is acceptable.

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

## 6a. v2.0: seeding from a dirty worktree and applying into it

The Story worktree is a **linked** worktree (`git worktree add ../myproj-story -b story/42`) that holds only what the orchestrator wrote or
applied after review. rwh's flow (`rwh run --backend jail`, worktree-seeding.md §5):

```sh
bin/worker-jail policy set --project myproj --worker w1 w1.json                       # no policy, no run
bin/worker-jail provision --project myproj --worker w1 --from-worktree ../myproj-story
# myproj.w1 base=<snapshot commit> existed=false snapshot-tree=<tree> snapshot-parent=<HEAD>
bin/worker-jail seed-gomod --project myproj --from-worktree ../myproj-story          # when the project has a gomod cache
# ... runs; export after every turn; the report carries the snapshot tree and the policy id and risk ...
bin/worker-jail apply --repo ../myproj-story --allow-dirty --policy myproj.w1 --snapshot-tree <tree> turn-3.patch
# target diverged since snapshot: 2 paths     (on stderr, only when the worktree moved; it never blocks)
```

- The snapshot never writes to the worktree or its repository (not even an object's mtime), and it runs none of its filters, hooks or fsmonitor.
  Its commit has a fixed identity and date, so the same state gives the same base. `export` diffs against that base: the patch is the worker's delta only.
- Provision is idempotent: an existing workspace is returned unchanged even if the worktree has moved. To start from the new state,
  export, deprovision and provision again; `jail.SnapshotTree(ctx, dir)` compared with `Workspace.SnapshotTree` tells whether it moved.
- The secret guard checks every added or modified path, tracked or not. `--allow-secret-path` is exact, repeatable, covers the name rule only,
  and is refused for a HIGH or CRITICAL policy. Ignored files never enter the snapshot.
- `seed-gomod --from-worktree` downloads only public modules, with no credentials: a private module fails and needs `seed-gomod --repo` from a landed ref.
- `apply --allow-dirty` keeps every v1 gate (`.git`, write scope, symlinks, gitlinks, review-required) and then runs one all-or-nothing
  `git apply` on the working tree with hooks disabled. It never touches the index, HEAD or refs: stage and commit the result yourself, with hooks disabled.
  A conflict with your own dirty changes refuses the whole patch and leaves the tree as it was. The primary checkout is always refused.
- Validate in a jail: `provision --from-worktree` of the same worktree under a verification worker, then `run` the tests.

## 6b. v2.1: Go modules through the egress service

A worker whose policy has `network.mode: modules` downloads the modules its `go_modules` masks allow, during its calls, through the egress
service. The operator sets it up once; after that, nothing changes for the harness: the same `jail.Run`, the same `RunSpec`.

```sh
bin/worker-jail egress up                                              # once per VM; idempotent (starts a stopped service)
bin/worker-jail policy template developer --project myproj --worker w1 --write-scope internal/,docs/ --go-modules 'golang\.org/x/.*' > w1.json
bin/worker-jail policy check w1.json --max-risk MEDIUM
bin/worker-jail policy set --project myproj --worker w1 w1.json        # myproj.w1 id=... risk=MEDIUM egress=confirmed
bin/worker-jail provision --project myproj --worker w1 --from-worktree ../myproj-story
bin/worker-jail run --project myproj --worker w1 -- go mod download    # through 127.0.0.1:3128 -> socat -> /run/wj/egress.sock
bin/worker-jail egress log --project myproj --worker w1 --since 10m    # one JSON line per request: path, decision, code, bytes, cache
```

- `policy set` stores the file, writes it into the service's policy volume through a hardened call, signals the service (`SIGHUP`) and waits
  up to 30 s for `wj-egress status` to print the stored id. Exit 5 (`ErrEgressUnavailable`) means "stored, not confirmed": fix the service
  (`egress status`, `egress up`) and run `policy set` again.
- `Run` asks the service before every call of a `modules` worker and refuses (`ErrEgressUnavailable`) unless it serves exactly the stored id:
  a stopped service, a reload that did not happen, or a policy edited behind the jail's back never widens or silently narrows a worker.
- A denied request is answered in-band, so `go` prints it: `403 Forbidden` with `X-Worker-Jail-Denied: module` (unlisted module), `grammar`,
  `mode` (`CONNECT` or an absolute URI: the call has no general proxy), `method`, `rate` (the policy's `network.rate`), `size`, `guard`, or
  `502` `upstream`. Widening `go_modules` is a reviewed policy change: export, deprovision, `policy set`, provision again.
- The seeded `gomod` cache stays first in `GOPROXY`: what it holds never touches the network. Downloads land in `/work/home/go/pkg/mod`
  (the workspace), and in the service's per-worker cache (at most 2 GiB per worker; nothing is shared between workers).
- `policy rm` withdraws the policy from the service first (its socket and cache go); `deprovision` keeps the stored policy and its delivery.
- A worker image must derive from base image v2 (it needs `socat`); otherwise a `modules` call exits 125 with a message naming the relay.

## 6c. v2.1: hosts through the egress service (allowlist, denylist, all)

A worker whose policy has `network.mode` `allowlist`, `denylist` or `all` reaches the hosts and ports its policy allows, through the same
socket, relay and service as `modules`. Setup, delivery (`policy set` ... `egress=confirmed`), the loaded-id check at `run`, `policy rm` and the
logs work the same; nothing changes for the harness.

```json
"network": {"mode": "allowlist", "hosts": ["proxy\\.golang\\.org"], "ports": [443],
            "rate": {"requests_per_min": 600, "max_conns": 8, "bytes_per_day": 1073741824}}
```

```sh
bin/worker-jail policy set --project myproj --worker w2 w2.json        # HIGH: the file needs a note; denylist/all: --accept-risk CRITICAL
bin/worker-jail provision --project myproj --worker w2 --from-worktree ../myproj-story
bin/worker-jail run --project myproj --worker w2 -- curl -sS https://proxy.golang.org/   # CONNECT proxy.golang.org:443 through the relay
bin/worker-jail run --project myproj --worker w2 -- curl -sS https://example.com/        # curl: CONNECT tunnel failed, response 403
bin/worker-jail egress log --project myproj --worker w2 --since 10m    # host, port, decision, code, bytes, end
```

- The call gets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` set to `http://127.0.0.1:3128` and an empty `NO_PROXY`. They are hints: a tool
  that ignores them has no route at all (`--network none`). curl honours `HTTPS_PROXY` and `ALL_PROXY`; Go, git and most package managers honour
  `HTTPS_PROXY`/`HTTP_PROXY`. `GOPROXY` is not changed, so Go builds use the seeded `gomod` cache as before.
- Served forms: `CONNECT host:port` (https and any other TCP protocol, as an opaque tunnel), and absolute-URI `GET` or `HEAD` of
  `http://...` (plain HTTP). Everything else is refused in-band with `X-Worker-Jail-Denied`: `mode` (an origin-form request such as
  `/gomod/...`: the generic modes have no module proxy), `method` (`POST`, `PUT`, ...: no request body leaves through plain HTTP; use https),
  `grammar` (an `https://` absolute URI, userinfo, a bad port), `host` (no mask matched under `allowlist`, a mask matched under `denylist`, a
  `Host` header that differs from the URI, a non-ASCII IDN), `port` (not listed: 80 and 443 are never implied), `guard` (a private, loopback,
  link-local or metadata address, also behind a name), `rate`, and `502 upstream`.
- Hosts are matched in canonical form against `^(?:mask)$`: write `proxy\.golang\.org`, not `proxy.golang.org` (an unescaped `.` gets a
  warning from `policy check`). Uppercase and a trailing dot do not matter; `proxy.golang.org.evil.io` and IP literals do not match. A
  `denylist` matches names only: an IP literal of a denied server passes. IDNs must be sent as punycode (`xn--...`).
- A tunnel ends after 60 s without traffic or after 1 h; its bytes count against `bytes_per_day`, and the day's budget cuts it.
  Redirects of plain HTTP are passed back to the client, which asks again and is checked again.
- **Residual risk: no TLS interception.** The service never sees inside a tunnel. Anything the worker can read can be sent to an allowed host
  (or through it: an attacker's repository on an allowed `github.com`, an upload to an allowed registry) or fronted through an allowed CDN
  host. `denylist` and `all` contain only private addresses and volume. Give these modes only to workers whose readable content may leave,
  keep `hosts` narrow, and watch `egress log` (new hosts, bytes near the limit, any `guard` denial).

## 7. What rwh no longer does for jailed workers

- No host-side file tools: read, write, edit and search all run as `rwh-tool` inside `jail.Run`.
- No bash under Seatbelt presented as jailed. A session without `JailRun` reports its backend as local and MUST NOT be called jailed (protocol 9).
- No direct `docker` against the workers VM; only the operator (building images) and the red-team suite may.
- No apply, commit or push of a worker's patch: patches go to the orchestrator.

## 8. Operations

| command | use |
| --- | --- |
| `worker-jail ls [--project P]` | Workspaces (base, snapshot tree and parent, created), caches (snapshot tree of the last worktree seed), calls in flight. |
| `worker-jail kill [--project P] [--worker W]` | Kill calls in flight; prints `killed N`. |
| `worker-jail usage --project P --worker W` | Workspace bytes. |
| `worker-jail purge --project P` | Kill P's calls and remove all of P's workspaces, caches and digests. |
| `worker-jail egress up\|down` | v2.1: create (or start) and remove the egress service. `down` keeps its volumes (policies, caches) and network. |
| `worker-jail egress status` | v2.1: the service's state and, per networked policy, stored and loaded ids (`ok`, `NOT LOADED`, `STALE`); exit 5 unless all are `ok`. |
| `worker-jail egress log [--project P] [--worker W] [--since D]` | v2.1: the service's JSON log lines (`docker logs`), filtered. |

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
| `egress` missing | a stored policy has a network mode, but the service was never started | `worker-jail egress up` |
| `egress` weakened (rootfs writable, capabilities, root, limits, log driver, network, mounts) | the container was not started by `egress up` | `worker-jail egress down && worker-jail egress up` |

## 9. Verification

- `make it` (with `make image` first): the integration suite on the real VM, over throwaway `wjit-*` projects that it purges. It proves the
  provision, run, export, apply and deprovision path, timeouts, the output flood cap, that no container survives a call, and an offline Go build from a seeded cache.
- `make image-redteam && make redteam`: the probes and positive controls of protocol section 12 (about 2 minutes, in the test-only image `worker-jail/redteam:1`); the report of the accepted run is `docs/redteam-report.md`, and every run writes `.temp/redteam/report.{md,json}`.
- v2.1: `make redteam` also runs the egress probes E1, E2, E2-generic, E5 (allowlist anchoring against the real service), E8 and E10 (`TestRedTeamEgress`; needs `egress up`, writes `.temp/redteam/egress-report.json`), and `make it` runs `go mod download` and, under an allowlist of `proxy.golang.org:443`, `curl https://proxy.golang.org/` (and a refused `https://example.com/`) through the service (needs `egress up` and internet). The service's parser, grammar, dial guard, rate limits, cache isolation, redirect refusal and fail-closed loading are unit tests (`go test ./egress`), and so are the generic modes' forms, host masks, ports, deny-wins, header stripping, `Host` check, byte and tunnel caps and log fields; the fuzz targets are `FuzzReadRequest`, `FuzzModulesPath` and `FuzzParseAuthority` (`go test -fuzz FuzzParseAuthority ./egress`).
- rwh adds its own host-side probes on top (tool dispatch never leaves `jail.Run`, no secret in argv, stdin or environment).
