# worker-jail

The security protocol and the reference jail for **remote workers**: agents whose model runs elsewhere (Codex or Claude on the dedicated Mac mini)
and whose tool calls execute on the project's machine. Assume the worker is **compromised and hostile**. It must still be unable to reach beyond its
workspace and the tools it was given, and unable to damage the host.

**Design rule (owner): as simple and reliable as possible. One strong boundary, few moving parts, everything testable. No overloaded frameworks.**

Consumers: `relux-works/remote-worker-harness` (runs the workers) and `relux-works/a2a-swarm` (the swarm's channel). Room: `#worker-jail:a2a.local`.
**Normative spec: [`docs/protocol.md`](docs/protocol.md)** (v1): the threat model, the jail's guarantees G1-G8, the interface, the network policy,
the change-extraction path, and what the harness, orchestrators and the operator must do.
**Integration notes: [`docs/integration.md`](docs/integration.md)** (setup, the Go API walk-through, errors, capacity, reviewing patches, operations).
Research (non-normative): `docs/research/` holds the apiary reconciliation, the Claude Code / Codex sandbox study and the egress proxy design draft.
`docs/design-brief.md` is the agreed starting design (history; the protocol wins where they differ). `BOOTSTRAP.md` is for this project's orchestrator.

## Design in one paragraph
Every tool call of a worker runs in a **fresh, hardened container** (`--network none`, all capabilities dropped, no-new-privileges, uid 10001,
read-only rootfs, cpu/memory/pids/time limits) inside a **dedicated colima VM (`workers`) started with `--mount none`**. A worker's state is its
**workspace volume** (a clone of the project at a base commit); read-only per-project caches (Go modules) are the only shared data.
Changes leave only as a **patch** that an orchestrator reviews and applies with hooks disabled.

## Engineering baseline
Go for tooling; tests with the go-testing-tools skill, including a red-team suite; signed commits; code and docs through PRs; local task-board (gitignored).

## Tools
| tool | used for | how to run | outputs |
| --- | --- | --- | --- |
| `go` (1.25, stdlib only) | the `jail` package and the `worker-jail` CLI | `make build`, `make test`, `make vet`, `make cover` | `bin/worker-jail` (gitignored) |
| `worker-jail` CLI | every jail operation: `doctor`, `provision`, `run`, `export`, `apply`, `deprovision`, `seed-cache`, `seed-gomod`, `usage`, `ls`, `kill`, `purge` | `bin/worker-jail [--image IMG] [--state-dir DIR] [--slots N] [--project-slots M] COMMAND ...` (env `WJ_IMAGE`, `WJ_STATE_DIR`, `WJ_SLOTS`, `WJ_PROJECT_SLOTS`) | host state in `~/.local/state/worker-jail/` (slot and workspace locks, export digests, empty docker config) |
| `docker` CLI | talks only to the colima `workers` VM (`unix://$HOME/.colima/workers/docker.sock`); the jail pins the endpoint and an empty `DOCKER_CONFIG` itself | through the CLI or package, never directly (protocol section 6) | volumes `wj.<project>.<worker>`, `wj-cache.<project>.<name>`; containers `wj-call-*` (removed after each call) |
| `colima` | `doctor` reads the VM's `/proc/mounts` via `colima ssh -p workers` | `bin/worker-jail doctor` | none |
| `git` (host) | provision bundles, `apply` (hooks disabled), `seed-gomod` archives | via the CLI | none |
| images | `worker-jail/base:1` (`images/base`), `worker-jail/go:1` (`images/go`) | `make image` (builds into the workers VM) | images in the workers VM |
| integration tests | the real VM path: provision, run, export, apply, deprovision, timeout, flood, no survivors, offline Go build | `make image && make it` (sets `WJ_IT=1`) | test projects `wjit-*`, purged at the end |

Exit codes of `worker-jail`: `run` exits with the call's status (124 on timeout); usage errors 2; jail errors 3; `apply` refused for review 4.
