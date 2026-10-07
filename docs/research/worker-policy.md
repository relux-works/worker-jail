# Worker policy: design draft for v2

Status: a draft for the owner's review, not normative yet. Source: the owner's direction of 2026-09-29, relayed by the keeper: "the workplace should be configured exactly like Claude or Codex".
Each worker gets an explicit policy: an allowlist of tool calls, a YOLO mode, and per-tool settings. The network tool has modes (all, whitelist, blacklist) matched by regex masks.
This draft folds that in with the vendor lessons (`vendor-sandboxes.md`) and the egress design (`egress-proxy-design.md`).

## 1. Principle: who enforces what
Both vendors separate a kernel-enforced sandbox from permission rules, and both say that rules on command text are not a security boundary. The policy keeps that separation visible. Every field says who enforces it:

| layer | enforced by | strength |
| --- | --- | --- |
| Workspace access (read-write or read-only), network mode, limits | the workplace: mounts, the egress service, cgroups | **boundary**: kernel and proxy |
| Write scope | `remote-workplace apply` on the host | **boundary** at extraction |
| Which tools the model sees | the harness: tool exposure; calls to unexposed tools are refused | **strong**: the model cannot call what it is not given |
| Argument rules on tools (for example bash command masks) | the harness, by text matching | **advisory only**: `sh -c`, interpreters and paths bypass it. It shapes behaviour but contains nothing |

## 2. Schema (JSON, strict: unknown keys are rejected)
```json
{
  "version": 1,
  "project": "remote-worker-harness",
  "worker": "rwh-codex-rwh",
  "tools": {
    "mode": "allowlist",
    "allow": ["read_file", "search", "write_file", "apply_patch", "bash"],
    "rules": {
      "bash": { "allow": ["go (build|test|vet) .*", "git (status|diff|log).*"], "deny": ["curl .*"] }
    }
  },
  "workspace": {
    "access": "read-write",
    "write_scope": ["internal/", "cmd/", "docs/"]
  },
  "network": {
    "mode": "modules",
    "go_modules": ["golang\\.org/x/.*", "github\\.com/relux-works/.*"]
  },
  "limits": { "cpus": 2, "memory_mib": 2048, "pids": 512, "call_timeout_s": 600 }
}
```

### Required fields
There are no implicit defaults. A worker without a stored policy is not provisioned (`ErrNoPolicy`).

| field | values | meaning |
| --- | --- | --- |
| `tools.mode` | `allowlist` or `yolo` | `allowlist` exposes only the listed tools. `yolo` exposes every tool the harness has and ignores `rules`. |
| `workspace.access` | `read-write` or `read-only` | `read-only` mounts the workspace read-only in every call, which suits reviewers and analysts. Kernel-enforced. |
| `workspace.write_scope` | a list of path prefixes, or `["*"]` | What `apply` accepts from this worker: a trailing `/` means a directory, otherwise an exact file. `["*"]` must be written out to mean the whole repository. |
| `network.mode` | `none`, `modules`, `allowlist`, `denylist` or `all` | See section 3. |

### Masks
Regexes (RE2), always anchored: the workplace wraps each one as `^(?:mask)$`, so `github\.com` can never match `github.com.evil.io`.
- Host masks match the canonical host: lowercase, no trailing dot, punycode.
- Module masks match the module path.
- Bash masks match the command string. They are advisory, as section 1 says.

### YOLO
`"tools": {"mode": "yolo"}` gives every tool inside the workplace. The boundary is unchanged: container, no host, the workspace access as set. The network is **not** implied: `network.mode` must still be stated. So "yolo and offline" is expressed as `tools.mode=yolo` plus `network.mode=none`.

## 3. Network modes
All egress goes through the per-worker egress socket, so calls never get a network interface. In every mode the dial guard refuses loopback, private (RFC1918), link-local, CGNAT, ULA, metadata and the lima gateway ranges, and none of this is configurable. DNS is resolved by the proxy, never in the call.

| mode | allows | contains | does NOT contain |
| --- | --- | --- | --- |
| `none` | nothing | everything: v1 behaviour | nothing |
| `modules` | GET/HEAD in the Go module proxy and sumdb grammar, for module paths matching `go_modules`, over the service's own TLS to fixed upstreams | methods, paths and upstreams; it is read-only by construction | a low-bandwidth covert channel through module-path lookups (bounded by the masks, a rate limit and the log) |
| `allowlist` | CONNECT or absolute-URI HTTP to hosts matching `hosts` on `ports` | which hosts and ports | anything sent to an allowed host: without TLS interception the proxy sees only host:port, so exfiltration to or through allowed hosts and domain fronting remain possible. URL masks apply only to plain HTTP. |
| `denylist` | any public host except those matching `hosts` | only the listed hosts | effectively open egress: exfiltration of anything the worker can read |
| `all` | any public host | only the dial guard (no private ranges) | open egress: exfiltration of anything the worker can read |

`allowlist`, `denylist` and `all` need `hosts` (a list, possibly empty for `all`) and `ports` (for example `[443]`), both explicit.

## 4. Effective risk: `remote-workplace policy check FILE`
It validates the file and prints one line per section, then an overall level. Example output:
```
tools      allowlist: read_file search write_file apply_patch bash   (bash: arbitrary code inside the workplace; rules advisory)
workspace  read-write; apply accepts internal/ cmd/ docs/
network    modules: 2 Go module masks; read-only fetches; covert channel via module paths (rate-limited, logged)
limits     2 CPUs, 2048 MiB, 512 pids, 600 s per call
risk       MEDIUM
```

| level | condition |
| --- | --- |
| LOW | network `none`, and the workspace read-only or no bash |
| MEDIUM | network `none` or `modules`, with bash and a read-write workspace |
| HIGH | network `allowlist` |
| CRITICAL | network `denylist` or `all` |

The level is recorded in the workspace label and the harness audit log, and `ls` shows it.

## 5. Lifecycle
- `remote-workplace policy set --project P --worker W FILE` validates the file and stores it host-side in `~/.local/state/remote-workplace/policies/P.W.json`. Its sha256 becomes the policy id.
  The network part is pushed to the egress service. Policies are host-owned configuration, reviewed like code, and never derived from worker files.
- `policy show` and `policy check` read it back.
- **Provision** refuses without a policy and records the policy id on the workspace.
  **Run** mounts according to `workspace.access`, applies `limits` and the egress socket for `network.mode`, and fails closed if the stored policy changed since provisioning (re-provision to adopt a new policy).
- **The harness** reads the same file (`workplace.LoadPolicy`) to decide which tools to expose and whether to pre-check bash text.
- **Apply** takes the write scope from the policy of the worker that produced the patch (`apply --policy P.W`), so the orchestrator no longer passes it by hand.
- **Templates** are shipped, not implied:
  - `reviewer`: tools read_file and search, workspace read-only, network none;
  - `developer`: allowlist of the five tools, read-write, the task's scope, network modules;
  - `yolo-offline`: tools yolo, read-write, `["*"]`, network none.

## 6. Mapping to the vendors
| remote-workplace | Claude Code | Codex |
| --- | --- | --- |
| `tools.mode=allowlist` with `allow` | permission rules `allow: [Tool, ...]` | the approval policy plus the tool set |
| `tools.rules` (advisory) | `Bash(cmd:*)` rules ("not a security boundary") | execpolicy `prefix_rule` (the same caveat) |
| `tools.mode=yolo` | `bypassPermissions` inside a sandbox | `danger-full-access` or `never` inside a container |
| `workspace.access` | sandbox `allowWrite` | `read-only` vs `workspace-write` |
| `network.mode` with masks | `network.allowedDomains` / `deniedDomains` | `network_proxy` domains, plus `limited` (method) mode |
| `modules` mode | no equivalent (a generic proxy only) | no equivalent |
| no implicit defaults | defaults exist (prompting) | defaults exist (trust-based) |
