# worker-jail

The security protocol and the reference jail for **remote workers**: agents whose model runs elsewhere (Codex or Claude on the dedicated Mac mini)
and whose tool calls execute on the project's machine. Assume the worker is **compromised and hostile**. It must still be unable to reach beyond its
workspace and the tools it was given, and unable to damage the host.

**Design rule (owner): as simple and reliable as possible. One strong boundary, few moving parts, everything testable. No overloaded frameworks.**

Consumers: `relux-works/remote-worker-harness` (runs the workers) and `relux-works/a2a-swarm` (the swarm's channel). Room: `#worker-jail:a2a.local`.
**Normative spec: [`docs/protocol.md`](docs/protocol.md)** (v2.0: v1.1 plus the per-worker policy and worktree seeding; egress is v2.1): the threat model, the jail's guarantees G1-G8, the interface, the network policy,
the change-extraction path, and what the harness, orchestrators and the operator must do.
**Integration notes: [`docs/integration.md`](docs/integration.md)** (setup, the Go API walk-through, errors, capacity, reviewing patches, operations).
Research (non-normative): `docs/research/` holds the apiary reconciliation, the Claude Code / Codex sandbox study and the egress proxy design draft.
`docs/design-brief.md` is the agreed starting design (history; the protocol wins where they differ). `BOOTSTRAP.md` is for this project's orchestrator.

## Design in one paragraph
Every tool call of a worker runs in a **fresh, hardened container** (`--network none`, all capabilities dropped, no-new-privileges, uid 10001,
read-only rootfs, cpu/memory/pids/time limits) inside a **dedicated colima VM (`workers`) started with `--mount none`**. A worker's state is its
**workspace volume** (a clone of the project at a base commit); read-only per-project caches (Go modules) are the only shared data.
Changes leave only as a **patch** that an orchestrator reviews and applies with hooks disabled.

## Per-worker policy (v2.0)
No policy, no worker: `provision` and `run` refuse a (project, worker) without a stored policy. A policy is one explicit JSON file per worker,
host-owned and reviewed like code: the tools the harness exposes (`allowlist` with per-tool settings, or `yolo`), the workspace mount
(`read-write` or `read-only`) and the `write_scope` that `apply --policy` enforces, the network mode, and the call limits (cpus, memory,
pids, timeout, output cap, soft disk quota). `policy check` validates a file strictly and prints its effective risk (LOW to CRITICAL) and its
id (sha256 of the canonical form). `policy set` stores it in `~/.local/state/worker-jail/policies/P.W.json`, refusing CRITICAL without
`--accept-risk CRITICAL` and HIGH without a `note`. A new workspace is labelled with the policy's id and risk; `run` fails closed if the stored
policy is gone or changed (re-provision to adopt a change) and applies its access and limits to every call. Network modes other than `none`
are validated and rated but refused until egress arrives in v2.1. Start from a template:

```sh
bin/worker-jail policy template developer --project myproj --worker w1 --write-scope internal/,docs/ --go-modules 'golang\.org/x/.*' > w1.json
# developer uses network mode modules (v2.1); edit it to {"mode":"none"} for v2.0, or start from reviewer or yolo-offline
bin/worker-jail policy check w1.json --max-risk MEDIUM
bin/worker-jail policy set --project myproj --worker w1 w1.json
```
Spec: [`docs/protocol.md`](docs/protocol.md) section 14 and [`docs/design/v2/policy.md`](docs/design/v2/policy.md).

## Worktree seeding (v2.0)
A worker can start from the orchestrator's Story worktree as it is now, dirty and unlanded changes included, and its reviewed patch can go
back into that worktree while it keeps moving. `provision --from-worktree DIR` snapshots DIR in a temporary repository (empty config, no
hooks, no filters, the source only an alternate: DIR is never written) and provisions from the snapshot commit. A secret guard refuses
likely secrets anywhere in the delta (`.env`, keys, `.npmrc`, ... by name; private keys and tokens by content); `--allow-secret-path`
overrides the name rule only, and never for a HIGH or CRITICAL policy. `seed-gomod --from-worktree` seeds the Go module cache from the same
snapshot without credentials. `apply --allow-dirty` applies a patch into a dirty **linked** worktree (never the primary checkout): the working
tree only, all v1 gates first, all or nothing.

```sh
bin/worker-jail provision --project myproj --worker w1 --from-worktree ../myproj-story   # prints snapshot-tree= and snapshot-parent=
bin/worker-jail seed-gomod --project myproj --from-worktree ../myproj-story
bin/worker-jail apply --repo ../myproj-story --allow-dirty --policy myproj.w1 --snapshot-tree <tree> turn-3.patch
```
Spec: [`docs/protocol.md`](docs/protocol.md) section 15 and [`docs/design/v2/worktree-seeding.md`](docs/design/v2/worktree-seeding.md).

## Engineering baseline
Go for tooling; tests with the go-testing-tools skill, including a red-team suite; signed commits; code and docs through PRs; local task-board (gitignored).

## Tools
| tool | used for | how to run | outputs |
| --- | --- | --- | --- |
| `go` (1.25, stdlib only) | the `jail` package and the `worker-jail` CLI | `make build`, `make test`, `make vet`, `make cover` | `bin/worker-jail` (gitignored) |
| `worker-jail` CLI | every jail operation: `doctor`, `provision [--from-worktree DIR]`, `run`, `export`, `apply [--policy P.W] [--allow-dirty [--snapshot-tree OID]]`, `deprovision`, `seed-cache`, `seed-gomod [--from-worktree DIR]`, `usage`, `ls`, `kill`, `purge`, and `policy check\|set\|show\|template\|rm` | `bin/worker-jail [--image IMG] [--state-dir DIR] [--slots N] [--project-slots M] COMMAND ...` (env `WJ_IMAGE`, `WJ_STATE_DIR`, `WJ_SLOTS`, `WJ_PROJECT_SLOTS`) | host state in `~/.local/state/worker-jail/` (slot and workspace locks, export digests, stored policies, snapshot trees, seed records, empty docker config) |
| `docker` CLI | talks only to the colima `workers` VM (`unix://$HOME/.colima/workers/docker.sock`); the jail pins the endpoint and an empty `DOCKER_CONFIG` itself | through the CLI or package, never directly (protocol section 6) | volumes `wj.<project>.<worker>`, `wj-cache.<project>.<name>`; containers `wj-call-*` (removed after each call) |
| `colima` | `doctor` reads the VM's `/proc/mounts` via `colima ssh -p workers` | `bin/worker-jail doctor` | none |
| `git` (host) | provision bundles, worktree snapshots (temporary repository, empty config), `apply` (hooks disabled), `seed-gomod` archives | via the CLI | none |
| images | `worker-jail/base:1` (`images/base`), `worker-jail/go:1` (`images/go`) | `make image` (builds into the workers VM) | images in the workers VM |
| integration tests | the real VM path: provision, run, export, apply, deprovision, timeout, flood, no survivors, offline Go build | `make image && make it` (sets `WJ_IT=1`) | test projects `wjit-*`, purged at the end |

Exit codes of `worker-jail`: `run` exits with the call's status (124 on timeout); usage errors 2; jail errors 3 (including no stored policy, a changed policy, and the worktree refusals `ErrSnapshot`, `ErrSecret`, `ErrSeed`, `ErrDirtyTarget`);
`apply` refused for review 4; `apply --write-scope P1,P2,...` or `apply --policy P.W` refused for a path outside the write scope 5; egress unavailable (a network mode other than `none`) 5.
`policy` commands: 0 ok, 1 invalid policy, 2 usage, 3 not found, 4 risk above `--max-risk` or not accepted, 5 egress unavailable.
