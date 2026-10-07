# 2026-09-29: v2 direction, v1.1, and working mode

Recorded by remote-workplace-72.
Sources: owner decisions relayed in #remote-workplace protocol-v1 by m1max_local-models_orch, the keeper, acting under the owner's explicit delegation ("можешь принять решения", 2026-09-29); the owner's direction relayed earlier that day; and the owner's budget notice in #lobby.

## Decisions
1. **Policy, not one egress shape (D1).** The workplace gets a per-worker policy modelled on Claude Code and Codex: a tool-call allowlist, a yolo mode, and per-tool extended settings.
   The network modes are `all`, `whitelist` (allowlist) and `blacklist` (denylist) with regex masks, plus the read-only Go module proxy as its own `modules` mode with a prefix whitelist.
2. **No implicit defaults (D2).** A worker without an explicit policy does not start. `yolo` and `network=all` must be written out. The policy prints its effective risk per mode, because host allowlists do not stop exfiltration (per the vendors' own docs).
3. **v2 is design elaboration for now (D3).** In scope:
   - the policy schema;
   - a threat model per mode;
   - how the module proxy fits;
   - the seeding gap that forced Seatbelt in `rwh run` v1 (provision from a dirty or unlanded Story worktree, apply into a dirty target).
   Implementation waits. The paused implementation work is kept on the local branch `feat/v2-worktree`.
4. **v1 unfrozen for two changes (D4).** The write scope (`apply --write-scope`, PR #5) and the donor-profile harness obligation land as protocol **v1.1**.
5. **Hooks.** The owner's side asked for the doorbell-only a2a hooks. remote-workplace-72 installs them once the owner confirms in its own session: a hook changes the session's own Claude Code config.
6. **Working mode.** Record decisions first, as here. Then the v2 elaboration is written **by a remote worker** on the Mac mini (`rwh run`), and remote-workplace-72 orchestrates and reviews. How the worker runs (tools, network, backend) is remote-workplace-72's explicit choice, noted in the run report.
7. **Budget.** The MacBook's Claude subscription is low. Heavy work goes to the remote workers; no implementer sessions on this machine; no status chatter.

## Consequences
- Protocol v1.1 lands with PR #5. Red-team PASS at c29ab55 covers the new G8-write-scope probe; the code is unchanged since.
- `docs/research/worker-policy.md` (draft PR #7) and `docs/research/egress-proxy-design.md` are the starting drafts for the elaboration.
- The superseded `docs/notes/apiary-comparison.md` is removed in favour of `docs/research/apiary-reconciliation.md`.
