# How Claude Code and Codex jail their models: what worker-jail adopts or avoids

Primary-source findings, with file:line and URL citations:
- `vendor/claude-code.md`: anthropic-experimental/sandbox-runtime 3ed9739 plus the Claude Code docs.
- `vendor/codex.md`: openai/codex 18194bf plus the Codex docs.

Both were researched on 2026-09-29. This note distils them against worker-jail v1 (main 8233a12). It is research, not protocol.

## Where both vendors converge
1. **Two layers.** A kernel-enforced sandbox (Seatbelt; bubblewrap with namespaces and seccomp; a Windows firewall or WFP) and a separate approval layer that decides when to cross it.
   Both say command-text rules are not a security boundary.
2. **Egress only through a proxy outside the sandbox, enforced by the kernel.**
   - Linux: the sandbox's network namespace has no route. On Linux the only way out is a bridge to the host proxy (srt bind-mounts a Unix socket and runs socat inside; Codex bridges socketpair fds into an in-netns loopback listener), and seccomp restricts socket families.
   - macOS: Seatbelt allows outbound connections only to the proxy port.
   - Proxy environment variables are only hints. A per-session proxy token (srt) stops other local processes from riding the proxy.
3. **Host allowlist.** The proxy matches the CONNECT authority or the absolute-URI host, canonicalised. Deny wins. `*.x` means subdomains only (Codex adds `**.x` for the apex too). Ports can be pinned.
   **Fail closed**: an empty allowlist blocks everything (srt once failed open, GHSA-9gqj), and a DNS failure or an unreachable proxy means no network.
4. **Resolve once, dial the checked address.** Loopback, link-local, metadata and private ranges are refused. Codex blocks RFC1918, CGNAT and ULA by default; srt does not. Both call DNS-rebinding protection best-effort.
5. **No TLS interception by default.** Both therefore document domain fronting and exfiltration through broad allowed hosts (github.com, googleapis, githubusercontent).
   Method limits (GET, HEAD and OPTIONS only) require MITM: Codex's "limited" mode and cloud method filter, srt's `tlsTerminate` with `filterRequest`.
6. **Credentials stay outside.** The sandbox sees a dummy or sentinel value, and the proxy swaps in the real one for matched hosts over terminated TLS (Codex credential broker, srt masking).
   The Claude cloud GitHub proxy holds the real token outside the VM and limits pushes to the session branch.
7. **Setup phase vs agent phase** (Codex cloud): the setup script gets internet and secrets, the secrets are removed, and the agent runs with internet off by default or behind an allowlist.
8. **Denials come back in-band.** A 403 with a reason, and a violations block in stderr, so the agent adapts instead of retrying blindly. Decisions are logged per host, port and method.
9. **Protected paths inside the writable area.** `.git` including hooks and config, agent config dirs (`.codex`, `.agents`, `.claude`), `.mcp.json`, shell rc files, `.gitconfig`, `.vscode`, `.idea` and `.aws`.
   They are read-only even where the agent may write, cover paths that do not exist yet, are matched case-insensitively, and closed against rename, unlink and symlink tricks.
10. **Recurring escape class** (advisories): a privileged host-side component follows a path the sandbox shaped. Examples: symlinks (Claude GHSA-vp62), worktree `.git` confusion (GHSA-7835), a model-supplied cwd treated as the writable root (Codex CVE-2025-59532), and project config auto-loaded on open (Codex CVE-2025-61260).

## Against worker-jail v1
| pattern | worker-jail v1 | verdict |
| --- | --- | --- |
| Kernel boundary, not text rules | A container per call in a no-mount VM; the harness takes no approvals from the model | Already stronger: no shell on the host at all |
| Egress only via an out-of-sandbox proxy (2) | No egress at all (`--network none`) | Adopt for v2 (D3), keeping the no-interface property: the only path is a mounted Unix socket |
| Fail closed (3, 4) | `doctor` and Provision fail closed; there is no network to fail open | Adopt as hard rules for the proxy |
| Host allowlist without TLS termination (5) | n/a | Avoid as the default: a generic CONNECT allowlist to broad hosts is an exfiltration channel by the vendors' own docs. Prefer a protocol-aware, read-only package proxy (below). |
| Credential swap at the proxy (6) | No credentials anywhere near a call | Keep none in v2. If one is ever needed, swap at the proxy over terminated TLS, never an env secret. |
| Setup vs agent phase (7) | Already the model: `seed-gomod` runs on the host with network and credentials from a landed ref; calls get none | Keep, and cite as convergent evidence |
| In-band denials (8) | Run returns stderr and exit; there is no proxy yet | Adopt in the proxy: 403 plus `X-Worker-Jail-Denied: <reason>` |
| Protected paths in the writable area (9) | The workspace is never shared with the host. Protection sits at `apply`: review-required paths, and write scope (D1, held). | Keep the extraction-side design. Extend the review-required list with `.gitconfig`, `.idea`, `.aws` and shell rc files (a delta, frozen until v1 reopens). |
| Host components following sandbox-shaped paths (10) | The host never reads the workspace; only a patch leaves, parsed by `git apply` (no write through symlinks), and symlinks are refused unless reviewed. Base, cwd and mounts come from the host, never from the model. | Already covered by red-team G8-symlink, G8-traversal and G8-git-dir. Keep as a standing review rule for every new host-side component, the proxy included. |
| Env scrubbing | Explicit env only (G7) | Already stronger than Codex's local default (inherit all, secret filter off) |
| Approvals | None from the model; the owner and orchestrator decide policy | Keep. Network approvals are never persisted from worker-writable content (Claude GHSA-ff64), and a policy change is a reviewed config change. |

## What worker-jail should avoid, learned from the advisories
- Anything that fails open when a dependency is missing or a list is empty.
- Broad "trusted" presets (github.com, googleapis.com, amazonaws.com, githubusercontent.com). They are attacker-writable storage.
- Env-var-only proxying (Codex Windows unelevated).
- Persisting approvals into files the worker can write.
- Letting any value from inside the jail (cwd, a path, a git dir) decide a host-side boundary.

## Consequence for the proxy design
Both vendors ship a generic host-allowlist proxy and then document that it does not stop exfiltration through broad hosts or domain fronting without TLS interception.
worker-jail's need is narrower: fetch dependencies. So the design (`egress-proxy-design.md`) starts from a protocol-aware, read-only package proxy.
Go modules come first: the call speaks plain HTTP to a local service, and the service makes its own TLS connection to the upstream. Method and path policy is then enforceable without MITM.
A generic CONNECT allowlist stays an explicit, per-project, exfiltration-capable opt-in.
