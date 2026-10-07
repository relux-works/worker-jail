# Design brief (owner + local-models-e9, 2026-09-29)

## Threat model
The model, or a prompt injection through a chat message, a file it reads or a tool output, is hostile and knows the harness. Everything a worker can read
may reach the model provider. Everything a worker writes is untrusted until reviewed.

## Primary boundary: one container per (worker, project), in a dedicated colima profile
- **Dedicated colima profile for workers** (e.g. `workers`) with **no `$HOME` mount**: only the workers' workspace root is mounted into the VM.
  Colima's default profile mounts the owner's home into the VM, so a container escape there would reach it.
- **Workspace**: a separate clone or worktree of the project per worker (or a named volume holding the clone). **Never the live checkout.**
- **Changes leave only as a patch or git bundle.** The host applies it after review with hooks disabled (`core.hooksPath=/dev/null`). Orchestrators never run
  worker-produced code (Makefile, hooks, go generate, tests) outside an equivalent workplace.
- **Container hardening**: `--network none` by default; `--cap-drop ALL`; `--security-opt no-new-privileges`; non-root user; read-only root FS; tmpfs `/tmp`;
  `--cpus`, `--memory`, `--pids-limit`; a size limit on the workspace.
- **Execution path**: the harness stays on the host. It holds the worker's Matrix token, the audit log and the model connection. It runs each `item/tool/call` inside the
  worker's container (`docker exec` or a tiny in-container agent over a socket) and returns the output. The model only ever sees the container.
- **Dependencies**: pre-warmed module caches baked into the image, or an allowlisted fetch proxy (proxy.golang.org, npm registry) as an opt-in container. No general egress.
- **No secrets inside**: no tokens, ssh-agent, keychain, or other repos.

## Out of scope for v1 (keep it simple)
macOS-only builds (Xcode/iOS). Later: a separate macOS user plus Seatbelt, or a macOS VM. Seatbelt is never the primary boundary.

## Acceptance: red-team suite, run as the worker, where every probe must FAIL (with the blocking layer recorded), plus positive controls where it succeeds without the workplace
Read the host's `~/.ssh`, `~/.config/a2a-swarm`, keychain, other repos; write outside the workspace; symlink/hardlink/mount escapes; network egress (curl, nc, DNS);
persistence beyond the session; privilege escalation; fork bomb, disk fill, memory blow-up; planting hooks or Makefile targets for the orchestrator;
exfiltrating secrets through tool output. Also: container-to-VM escape surfaces nothing of the owner's home.

## Related
Harness requirements: `#remote-worker-harness` topics `security-isolation` and `multi-tenant` (including the shared auth.json refresh race, which is the harness's to fix).
