# worker-jail

The security protocol and the reference jail for **remote workers**: agents whose model runs elsewhere (Codex or Claude on the dedicated Mac mini)
and whose tool calls execute on the project's machine. Assume the worker is **compromised and hostile**. It must still be unable to reach beyond its
workspace and the tools it was given, and unable to damage the host.

**Design rule (owner): as simple and reliable as possible. One strong boundary, few moving parts, everything testable. No overloaded frameworks.**

Consumers: `relux-works/remote-worker-harness` (runs the workers) and `relux-works/a2a-swarm` (the swarm's channel). Room: `#worker-jail:a2a.local`.
See `docs/design-brief.md` for the agreed starting design, and `BOOTSTRAP.md` if you are this project's orchestrator.

## Engineering baseline
Go for tooling; tests with the go-testing-tools skill, including a red-team suite; signed commits; code and docs through PRs; local task-board (gitignored).
