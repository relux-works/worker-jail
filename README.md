# worker-jail

The security protocol and the reference jail for **remote workers**: agents whose model runs elsewhere (Codex or Claude on the dedicated Mac mini)
and whose tool calls execute on the project's machine. Assume the worker is **compromised and hostile**. It must still be unable to reach beyond its
workspace and the tools it was given, and unable to damage the host.

**Design rule (owner): as simple and reliable as possible. One strong boundary, few moving parts, everything testable. No overloaded frameworks.**

Consumers: `relux-works/remote-worker-harness` (runs the workers) and `relux-works/a2a-swarm` (the swarm's channel). Room: `#worker-jail:a2a.local`.
**Normative spec: [`docs/protocol.md`](docs/protocol.md)** (v1): the threat model, the jail's guarantees G1-G8, the interface, the network policy,
the change-extraction path, and what the harness, orchestrators and the operator must do.
`docs/design-brief.md` is the agreed starting design (history; the protocol wins where they differ). `BOOTSTRAP.md` is for this project's orchestrator.

## Design in one paragraph
Every tool call of a worker runs in a **fresh, hardened container** (`--network none`, all capabilities dropped, no-new-privileges, uid 10001,
read-only rootfs, cpu/memory/pids/time limits) inside a **dedicated colima VM (`workers`) started with `--mount none`**. A worker's state is its
**workspace volume** (a clone of the project at a base commit); read-only per-project caches (Go modules) are the only shared data.
Changes leave only as a **patch** that an orchestrator reviews and applies with hooks disabled.

## Engineering baseline
Go for tooling; tests with the go-testing-tools skill, including a red-team suite; signed commits; code and docs through PRs; local task-board (gitignored).
