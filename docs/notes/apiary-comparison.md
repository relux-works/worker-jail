# worker-jail v1 compared with the apiary execution environment

Input weighed: relux-works/apiary-docs e4249a6 (paper v3.2, sections "Термины и уровни доверия", "Инварианты", "Среда исполнения"; book ch04 "Среда исполнения" and ch09 "Модель угроз"), shared by the owner as input, not a decision (2026-09-29).
The protocol stays normative; this note records what we took, what we did not, and why.

## Where the two agree
- **The copy is not the boundary.** Both designs rest on one rule: a copy of the working tree isolates file versions, not processes, sockets, caches or build scripts, so only a kernel mechanism can be the boundary.
  apiary (ch04): Seatbelt, namespaces with seccomp and cgroups, gVisor, microVM. worker-jail: one hardened container per call (namespaces, seccomp, AppArmor, cgroups) inside a VM that mounts nothing from the host.
- **Execution is metered, not sandboxes.** Sandboxes are cheap and many; concurrent execution is limited by slots and the queue is part of the protocol. worker-jail: an idle workspace is only a volume; N global plus M per-project slots.
- **No secrets inside.** Project secrets never exist in a sandbox (apiary I6; worker-jail G7). Signing and publishing happen outside: apiary uses runner operations, worker-jail leaves them to the orchestrator after review.
- **Escape costs little.** Sandboxes share no writable directory and nothing valuable is reachable, so a kernel escape yields little (apiary ch09; worker-jail G5 and the known-limits table).
- **Same threat model for the worker.** The worker is untrusted, may be poisoned through task, repository or dependency content, and the model provider sees what the sandbox holds.

## What we took
- **Write scope (apiary I2): adopted for v1.1.**
  - The rule: a revision may change nothing outside its task's write scope. apiary enforces it on the revision; worker-jail enforces it in `apply`.
  - The mechanism: an optional list of path prefixes, set by the orchestrator per task. Any path outside it is refused, deterministically.
  - It also carries apiary's point that tests are the validator of the result and so are protected more strongly than code. An orchestrator leaves test and validator paths out of a task's scope unless the task is about them. That stops a worker from weakening the tests that judge its own work, and from quietly editing a Makefile.

## What we did not take, and why
| apiary | worker-jail v1 | reason |
| --- | --- | --- |
| Long-lived sandbox per task, background processes "by descriptor", a restored shell session | A fresh container per call; only the workspace persists (G6) | Every CPU second is spent inside a slot, so capacity accounting is exact, and nothing can hide between calls. Measured cost: 0.34 s per call. A restored session (cwd, env) can live in the workspace, implemented by the harness's tool runner. |
| Egress proxy with an allowlist | `--network none`, no exception | Simplest possible policy. A proxy needs protocol v2 (section 7). |
| Signed, hash-chained receipts with state digests (I10) | The harness's audit log (tool, request sha256, timing, exit, sizes) | At L0 the harness is local and trusted. Signed receipts matter once untrusted nodes or several core nodes exist. |
| Machine-readable restriction inventory; a task refuses a partial one (I9) | `doctor` plus the protocol's known-limits table | No consumer needs it yet. It is cheap to add when one does. |
| Protected paths mounted read-only inside the sandbox | Write scope and review-required paths enforced at `apply` | The guarantee sits at extraction either way. Read-only mounts would only make a worker fail earlier. |
| Entry by a short-lived SSH certificate bound to the assignment, with a forced command | No inbound entry: the harness is local and calls `jail.Run`; the model host never connects in | Not applicable to this topology. If remote nodes ever execute in our environment, `worker-jail run` over stdio is the forced command, and apiary's five conditions apply. |
| gVisor for foreign agents, microVM for VM strength | Docker inside a no-mount VM | A remote model is effectively a foreign agent, so gVisor is the recommended next hardening step. It is listed in the protocol's known limits. |
