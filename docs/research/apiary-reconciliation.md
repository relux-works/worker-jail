# Reconciliation: remote-workplace v1 against apiary

Input: relux-works/apiary-docs e4249a6, which is the paper v3.2 plus the book: ch04 "Среда исполнения", ch08 "Ноды, независимость, остановка" and ch09 "Модель угроз".
Baseline: remote-workplace v1 as shipped (main 8233a12, frozen by the owner on 2026-09-29).
This note is research. Nothing in it is normative until a later protocol version adopts it.

## 1. Terms
| apiary | remote-workplace v1 |
| --- | --- |
| Environment (the project's authoritative machine) | The project host (macOS) plus the `workers` colima VM |
| Sandbox: a CoW copy of the tree plus an OS policy | A workspace volume (a clone at base) plus a fresh hardened container per call |
| Slot, queue | The same: N global slots (VM CPUs) and M per project, queued with file locks |
| Worker node (an untrusted contributor running an agent loop) | A remote worker: the model on the Mac mini plus the harness (rwh) on the project host |
| Core node, orchestrator (leases, quorum) | The project's orchestrator agent and the owner. L0, a single trusted owner. |
| Journal, QC, light client | None. Authority is the harness configuration, Matrix decisions and git. |
| Receipt (signed, hash-chained) | The harness audit log: tool, request sha256, timing, exit, sizes |
| Runner operations holding project secrets | None in the workplace. Signing, publishing and pushing are done by the orchestrator on the host after review. |
| Write scope | Not in v1. Ready as a delta (D1). |
| Restriction inventory (I9) | The protocol's known-limits table plus `doctor` |
| Sandbox entry by an SSH certificate bound to the assignment | No inbound entry: the harness is local and calls `workplace.Run` |

## 2. Invariants
Status is one of: holds; partial; n/a at L0 (it only makes sense with several owners or untrusted core nodes).

| # | apiary invariant (short) | remote-workplace v1 | delta |
| --- | --- | --- | --- |
| I1 | No effect on the environment without a committed, current authorization checked at the execution boundary | n/a at L0: the trusted harness decides; allow-from, the budget and the kill switch are its checks | none |
| I2 | Authority only narrows; a revision changes nothing outside its write scope | partial: review-required paths and the review gate only | **D1** |
| I3 | The main branch advances only by an atomic swap to an immutable, approved candidate | holds at L0: the exact reviewed head, signed, fast-forward only | none |
| I4 | Judgment stays out of consensus | n/a at L0 | none |
| I5 | Producer, reviewer and checker are independent | partial: the worker never reviews its own patch, and validation runs in a workplace or CI. Model-family independence is orchestrator policy, not workplace policy. | none (policy) |
| I6 | Contributor keys stay on their machine; project secrets live only in the runner, unreachable from any sandbox | holds: no secret reaches a call (G7). At L0 the harness host is the owner's own machine. | none |
| I7 | The journal is the only authority; a model session is a cache | partial: a workspace holds work until it is exported; export after every turn keeps the loss window to one turn | none |
| I8 | Any core node halts; the environment refuses to go back | partial: `kill` and `purge` stop calls and the harness has a kill switch, but the workplace has no halt state that refuses new calls | **D10** |
| I9 | Restrictions are declared facts; a task refuses a partial one | partial: known-limits table and `doctor`, not machine-readable | D5 |
| I10 | Every call has verifiable provenance (a receipt chain) | partial: the harness audit log, unsigned | D6 |

## 3. Execution environment (book ch04)
- **The copy is not the boundary.** Agreed. We are in apiary's "Linux, thousands of sandboxes" row (namespaces, seccomp, cgroups), plus an extra VM that holds nothing.
  apiary's table puts foreign agents on gVisor, and a remote vendor model is a foreign agent: **D4**.
- **Slots and queue.** Agreed, including "an idle sandbox costs nothing" (a volume).
- **Protected paths.** apiary mounts tests, build config, validator rules and the manifest read-only in every sandbox and changes them only through privileged tasks.
  remote-workplace enforces at extraction instead. v1 refuses review-required paths; D1 adds the per-task write scope, which also protects tests.
  Read-only mounts would only make a worker fail earlier (D8, not taken).
- **Runner operations.** Not needed. The workplace never holds a secret, and effects on the world (push, publish) are made by the orchestrator after review, outside the workplace.
- **Receipts.** apiary receipts carry digests of the command, the input state, the output and the result state, and they are chained. Ours carry no state digests and no signatures. See D6.
- **Egress proxy.** apiary's policy allows network only through a local egress proxy with an allowlist, and that proxy is "the point where external responses are recorded for replay". v1 has no network at all. **D3** is the next goal's design.
- **Sandbox entry.** apiary gives five conditions for SSH straight into a sandbox (restrict, an unprivileged user with no secrets, certificates only, the sshd surface, the sandbox still being the boundary).
  They do not apply today because nothing connects into our environment. If remote nodes ever execute here, `remote-workplace run` over stdio is the forced command, and all five conditions apply.
- **Shell "indistinguishable from local".** apiary treats this as a quality property, not a security one: restored cwd and env, serialized mutating calls, background processes by descriptor.
  Per-call containers keep every CPU second inside a slot. A restored session can live in the workspace, implemented by the tool runner (rwh-tool). Background-by-descriptor is not taken (G6).

## 4. Threat model (book ch09)
- **Participants.** They match. The worker is untrusted and can be poisoned through the task, repository or dependency content. The environment is trusted for integrity. The model provider sees the sandbox. The network is untrusted.
- **Not guaranteed.** The same honest list: model judgment, prevention of an environment compromise, confidentiality from the provider, and kernel escapes. Both designs answer the last one by sharing no writable storage and keeping everything valuable out of reach.
- **The malicious worker scenario.** apiary's layers are the sandbox, the write scope, an independent reviewer, tests run by a third party, and vesting and reputation.
  remote-workplace has the sandbox, orchestrator review, and validation in a workplace or CI. The write scope is missing (D1). Vesting and reputation are n/a at L0.

## 5. Identity layer and nodes (paper sections "Рабочие ноды", "Независимость и репутация"; book ch08)
- Identity keys are proven against external identities (DNS TXT under DNSSEC, HTTPS well-known, code-host keys). Node keys are short-lived and certified by the identity key, and revisions are signed with node keys in the git SSH format.
  This matters once workers belong to other owners (Ivan's swarm, L1). At L0 the orchestrator signs what it lands: **D7** later.
- **Donor profile.** Of apiary's two client forms, ours is "the environment as a tool server inside the vendor's native harness": rwh exposes workplace tools to Codex as dynamic tools.
  The donor profile then rests on policy: the vendor's built-in tools must be off on the model host, so an injected task has no local tools to abuse there. rwh's bootstrap already says "no provider built-ins running remotely".
  The protocol should make that a harness obligation: **D2**.

## 6. Deltas, in priority order
| id | delta | value | cost | status |
| --- | --- | --- | --- | --- |
| D1 | Write scope in `apply` (I2). Orchestrators keep tests out of scope. | High: stops test weakening and silent Makefile or config edits | Small; done | Ready on branch feat/write-scope (draft PR #5, red-team PASS). Waits for the v1 freeze to lift. |
| D2 | Donor profile as a harness obligation: the model's native tools are off on the model host, and every tool the model has is workplace | High | Text only | Proposed for the next protocol version |
| D3 | Allowlisted egress proxy for calls, recording external responses | High: builds that need dependencies | Medium | Next goal, step 2; design after the vendor study |
| D4 | gVisor (`runsc`) as the call runtime | High against kernel exploits | Medium; must measure start cost | Candidate hardening goal |
| D10 | Workplace halt state (`remote-workplace halt`/`resume`): kill calls in flight and refuse Provision and Run until resumed (I8) | Medium: one switch for incidents | Small | Proposed |
| D5 | Machine-readable restriction inventory (I9) | Low until a consumer exists | Small | Deferred |
| D6 | Signed, chained receipts with state digests (I10) | Low at L0 | Medium | Deferred to L1 |
| D7 | Identity-bound signing of worker patches | Low at L0 | Medium | Deferred to L1 |
| D8 | Read-only protected mounts inside calls | Low: the guarantee sits at apply | Medium | Not taken |
| D9 | One workspace per task instead of per worker | Policy choice | None in the workplace | Harness decision |
