# remote-workplace v2 design (elaboration)

Status: design only, written under `docs/decisions/2026-09-29-v2-direction.md` (D3: implementation waits). Nothing here changes `docs/protocol.md` v1.1. Every point in the documents is tagged **Decided (source)** or **Proposed**.

| document | content |
| --- | --- |
| `policy.md` | per-worker policy: schema, validation, enforcing layers, tools and network modes, risk output, templates, CLI, lifecycle, errors, 3 examples |
| `threat-model-by-mode.md` | per network mode and tools mode and the key combinations: attacker capability, contained, not contained, detection, risk |
| `egress.md` | one `rwp-egress` service for all modes: per-worker sockets, modules and generic handlers, dial guard, denials, logs, rate limits, fail closed, policy delivery, probes |
| `worktree-seeding.md` | `provision --from-worktree`, snapshot technique, secret guard, `SeedGoModWorktree`, `apply --allow-dirty`, `SnapshotTree`, rwh run integration, tests |

## Decided (source)
| point | source |
| --- | --- |
| Per-worker policy with tool allowlist, yolo and per-tool settings | D1, `docs/decisions/2026-09-29-v2-direction.md` |
| Network modes `all`, `whitelist`(=allowlist), `blacklist`(=denylist) with regex masks; `modules` as its own mode with a prefix whitelist | D1 |
| No implicit defaults; no policy, no start; `yolo` and `network=all` written out; effective risk printed | D2 |
| v2 is design only for now; scope: schema, threat model, module proxy fit, the seeding gap | D3 |
| Write scope and donor-profile obligation are v1.1 (in `docs/protocol.md`) | D4 |
| Calls have no interface but `lo`; secrets never enter a call; only patches leave; `apply` gates | `docs/protocol.md` G2, G7, G8 |
| Vendor facts: no TLS interception means no protection from fronting or broad-host exfiltration; fail closed; in-band denials; resolve once and dial the checked address | `docs/research/vendor-sandboxes.md` |

## Proposed (everything else)
Names and shapes of fields, bounds, the risk matrix, the CLI and its exit codes, per-worker sockets and caches, the socket relay, the egress policy delivery protocol, the snapshot technique details, the secret guard content rule, `SeedGoModWorktree` restrictions, `apply --allow-dirty` rules, and all probes. Each is marked in place.

## Draft corrections
| draft | problem | fix (where) |
| --- | --- | --- |
| `worker-policy.md` §2 masks wrapped as `^(?:mask)$` | a mask like `a)\|(?:b` un-anchors the wrapper | compile the mask alone first (policy §2) |
| §2 `yolo` "ignores rules" | silent no-ops mislead | `settings` must be absent under yolo (policy §4) |
| §2 write scope with a read-only workspace | contradiction not rejected | must be `[]` (policy §3) |
| §3 `all` "hosts possibly empty"; `denylist` with empty hosts | ambiguous; it is `all` | `all` has no `hosts`; empty denylist rejected (policy §5) |
| §3 no rate field | the covert-channel bound was implicit | `network.rate` required (policy §5) |
| §4 LOW = "read-only or no bash" | ignores exfiltration by reads; ignores yolo | risk matrix and canary-mask modifiers (policy §6) |
| §4 network with no exec tool | meaningless | rejected (policy §5) |
| §5 policy id = file hash | reformatting changes it | sha256 of the canonical form (policy §2) |
| §2/§4 tool rules as one `rules` block | per-tool settings were only bash | per-tool settings table (policy §4) |
| `egress-proxy-design.md` per-project socket, policy and cache | per-project cannot express per-worker policy; a shared cache is a cross-worker timing channel (G5) | per worker (egress §1, §4) |
| §3 mask applied to `@v` paths | `@latest`, `list` and sumdb `lookup` also leak the path | all masked (egress §4) |
| §3 dial guard chooses a safe address | mixed answers and mapped/NAT64 forms | refuse any forbidden answer, unwrap embedded IPv4 (egress §5) |
| §2 guard only in code | a guard bug reaches host services | second layer proposed (egress §2) |
| §3 redirects unmentioned | proxy.golang.org may redirect downloads; unknown | test E7, fixed host list if needed (egress §4) |
| §2 SIGHUP reload, no confirmation | a stale service is invisible | loaded id checked at `policy set` and Run (egress §6) |
| `worktree-seeding-draft.md` copy of `info/exclude` | misses global excludes | `ls-files --exclude-standard` (worktree §1) |
| snapshot with the source's config | filters and fsmonitor can execute | empty config, hooks and fsmonitor off (worktree §1) |
| guard only on untracked files, name only, no override | tracked modified secrets pass; no content check | delta-wide, content rule, `--allow-secret-path`, refused at HIGH (worktree §2) |
| dirty apply builds a temp index | hashes unrelated secrets, needs the guard | `git apply --check` on the working tree (worktree §4) |
| `SeedGoModWorktree` "orchestrator-owned only" | dirty `go.mod` is unreviewed | no credentials, no filesystem `replace`, no `go.work` (worktree §3) |
| Name mismatch | owner says whitelist/blacklist | only `allowlist`/`denylist` accepted (policy §5) |

## Open questions for the owner
1. Spelling: accept only `allowlist`/`denylist`, or also `whitelist`/`blacklist` as strict aliases?
2. Cache: per worker (proposed, keeps G5) or shared per project (less disk, a timing channel between the project's workers)?
3. Relay in the call: `socat` (draft) or a small static `rwp-relay` binary (smaller surface)? And may `modules` be combined with a generic mode?
4. The second layer for egress (firewall on the egress network inside the VM): worth the operator step? It needs root in the VM only.
5. Tool registry in the workplace, plus restricting `argv[0]` to the fixed runner when no exec tool is allowed (a workplace-side check of "no bash"): adopt?
6. Policy change on a live workspace: re-provision only (proposed), or an `adopt` that accepts strictly narrower policies?
7. Risk thresholds: should `policy set` refuse CRITICAL without a flag like `--accept-risk CRITICAL`? Should HIGH require a recorded reason in `note`?
8. Secret-guard override at HIGH or above: refuse (proposed) or allow with the flag?
9. Package ecosystems beyond Go (npm, PyPI): a handler each, or generic allowlist only?
10. `apply --allow-dirty` on the primary checkout: refuse by default (proposed)? The v1 "live checkout" test is not defined in the documents I read.
11. Protocol version: land all of this as v2, or split (policy and seeding first, egress later)?

## Design-owner decisions (m1max_remote-workplace_orch, formerly remote-workplace-72, 2026-09-29)
The owner confirmed D1-D4 in the orchestrator's session and left the design to its owner. These answer the open questions above.

| # | decision |
| --- | --- |
| 1 | `allowlist` and `denylist` are canonical. `whitelist` and `blacklist` are accepted as exact aliases and normalised; they are the owner's words. |
| 2 | The egress cache is per worker, which keeps G5 (no shared state between workers). |
| 3 | The relay is `socat` in the base image: it runs inside the untrusted call, so its surface does not matter. Network modes stay exclusive in v2. |
| 6 | A policy change needs a re-provision. There is no in-place adopt. |
| 7 | `policy set` refuses CRITICAL without `--accept-risk CRITICAL`, and HIGH requires a `note`. |
| 8 | The secret-guard override is refused at HIGH and above. |
| 9 | A package handler per ecosystem when a project needs one; the generic allowlist otherwise. |
| 10 | `apply --allow-dirty` is refused on a primary checkout (git dir equal to the common dir); only linked worktrees are allowed. |
| 11 | The work is split: v2.0 = policy + worktree seeding (it closes the Seatbelt gap); v2.1 = egress. |

Still open:
- 4, the VM-level firewall as a second egress layer: an operator step needing root in the VM; for the owner.
- 5, a workplace-side `argv[0]` check: it needs the harness's agreement; for remote-worker-harness-2b.
