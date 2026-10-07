# Per-worker policy: specification (remote-workplace v2 design)

Status: design, not normative. Elaborates `docs/research/worker-policy.md` under `docs/decisions/2026-09-29-v2-direction.md` (D1, D2). Baseline: `docs/protocol.md` v1.1.
Tags: **Decided (source)** is fixed by the owner or the protocol. **Proposed** is this document's choice, open to the owner.
Fixes to the draft are listed in README.md.

## 1. Model
- One policy file per (project, worker). No policy, no worker: **Decided (D2)**.
- Nothing is implied: every field below is written out. `yolo` and `network.mode=all` included. **Decided (D2)**.
- A policy is host-owned configuration, reviewed like code, never derived from worker files or worker messages. **Decided (docs/research/vendor-sandboxes.md, "Approvals"; GHSA-ff64)**.
- Text rules are not a boundary; each field names its enforcing layer. **Decided (docs/research/vendor-sandboxes.md, "two layers")**.

| layer | meaning | strength |
| --- | --- | --- |
| workplace | mounts, env, cgroups, ulimits, the egress socket (`docs/protocol.md` Appendix A) | boundary |
| egress | `rwp-egress` (see egress.md); enforces network fields | boundary |
| apply | `remote-workplace apply` on the host (`docs/protocol.md` §8) | boundary at extraction |
| harness | tool exposure and per-tool settings in the harness. The workplace sees only argv, so it cannot tell tools apart | strong for exposure, advisory for settings once an exec tool exists |
| advisory | shapes behaviour, contains nothing | none |

## 2. Format rules (Proposed)
- Strict JSON (RFC 8259), UTF-8, at most 64 KiB. Rejected: comments, trailing commas, duplicate keys at any level, `null`, unknown keys, wrong types, NaN or Inf, a float where an integer is required.
- Every key marked *req* must be present. The only optional key is `note`. Absent lists are errors; `[]` must be written out.
- **Masks** are RE2 (Go `regexp`). A mask must compile on its own, at most 256 bytes, at most 64 per list. The workplace then matches `^(?:mask)$`.
  Compiling alone first blocks breakout such as `a)|(?:b`, which would un-anchor the wrapper (the draft wrapped without this check).
- Host masks match the canonical host: lowercase, punycode, no trailing dot, no brackets on IPv6, no port. IP literals match as text.
- Module masks match the unescaped module path. Path masks match the workspace-relative path with `/`. Command masks match the command string (advisory).
- `policy check` warns on an unescaped `.` in a host mask. It probes each host and module mask with canary names (`canary-1.invalid/x`, ...). A mask that matches a canary is treated as matching everything (see §6).
- The policy id is the sha256 of the canonical form (keys sorted, no whitespace). Reformatting keeps the id.

## 3. Fields
| field | type | req | rules | layer |
| --- | --- | --- | --- | --- |
| `version` | int | req | must be `1` (schema version) | workplace |
| `project`, `worker` | string | req | `[a-z0-9][a-z0-9-]{0,31}`; must equal the target of `policy set` | workplace |
| `note` | string | opt | at most 200 bytes; ignored | none |
| `tools.mode` | `allowlist` \| `yolo` | req | see §4 | harness |
| `tools.allow` | string[] | req if allowlist, absent if yolo | 1..16 unique names from the tool registry (§4) | harness |
| `tools.settings` | object | req if allowlist, absent if yolo | one entry per allowed tool, no others; keys per §4 | harness / advisory |
| `workspace.access` | `read-write` \| `read-only` | req | mount mode of `/work` in every Run | workplace |
| `workspace.write_scope` | string[] | req | see below | apply |
| `network` | object | req | §5 | workplace + egress |
| `limits.cpus` | number | req | 0.25..4 | workplace |
| `limits.memory_mib` | int | req | 256..8192 (`/tmp` included) | workplace |
| `limits.pids` | int | req | 16..4096 | workplace |
| `limits.call_timeout_s` | int | req | 1..3600 (protocol maximum 60 min) | workplace |
| `limits.max_output_bytes` | int | req | 1024..67108864 | workplace |
| `limits.disk_soft_mib` | int | req | 64..65536; soft, checked through `usage` | harness |

`write_scope`: repository-relative prefixes, a trailing `/` means a directory, otherwise an exact file. Rules: no leading `/`, no `..`, nothing under `.git`, unique.
`["*"]` (alone) means the whole repository and must be written out. With `access=read-only` it must be `[]`; any other value is a contradiction (`ErrPolicyInvalid`).
Bounds on `limits` are Proposed; the timeout maximum is Decided (`docs/protocol.md` §6).
Scope semantics **Decided (D4, `docs/protocol.md` §8)**: no override, review-required paths stay refused even under `["*"]` unless `--allow-review-required`.

## 4. Tools
**Decided (D1)**: an allowlist mode, a yolo mode, per-tool extended settings.
- `allowlist`: the harness exposes only the listed tools and refuses calls to others (`ErrToolNotAllowed`, harness side).
- `yolo`: every tool the harness has, run inside the workplace. The boundary does not change. `settings` must be absent (the draft ignored it silently; a silently ignored rule is a false comfort).
- **Registry** (Proposed): `read_file`, `search`, `write_file`, `apply_patch`, `bash`. The workplace ships the list; a new tool is a workplace release. Unknown name: `ErrPolicyInvalid`.
- **Exec tools**: `bash` and `yolo`. Without one, calls run only fixed tool runners.

Settings (all keys of a present tool are required; write `[".*"]` to say "any"):

| tool | key | type | meaning | layer |
| --- | --- | --- | --- | --- |
| `read_file` | `paths`, `max_bytes` | mask[], int | readable path masks; size cap | harness |
| `search` | `paths`, `max_results` | mask[], int | searched path masks; result cap | harness |
| `write_file` | `paths`, `max_bytes` | mask[], int | writable path masks; size cap. `write_scope` still decides at apply | harness |
| `apply_patch` | `paths` | mask[] | path masks a patch may touch | harness |
| `bash` | `allow`, `deny` | mask[] | command masks; deny wins; `allow` must be non-empty | advisory |

The file-tool settings are strong only when no exec tool exists: with `bash`, the worker can read or write anything in `/work` by other means.
`policy check` prints that as "advisory" per tool. Proposed hardening (open question 5): with no exec tool, `Run` accepts only the fixed runner as `argv[0]`.

## 5. Network
Modes **Decided (D1)**: `none`, `modules`, `allowlist`, `denylist`, `all`. The owner's words `whitelist`/`blacklist` are the same as `allowlist`/`denylist`; only the latter are accepted (one spelling, strict).
Calls always keep `--network none`. Egress, when any, is one Unix socket (egress.md). The dial guard (no loopback, private, link-local, CGNAT, ULA, metadata, `192.168.5.0/24`) is fixed and has no field.

| mode | keys (all req) | rules |
| --- | --- | --- |
| `none` | `mode` | nothing else allowed; no socket, no mount: identical to v1 |
| `modules` | `mode`, `go_modules`, `rate` | 1..64 module masks; requires `access=read-write`; read-only Go proxy and sumdb grammar |
| `allowlist` | `mode`, `hosts`, `ports`, `rate` | 1..64 host masks; `ports` explicit |
| `denylist` | `mode`, `hosts`, `ports`, `rate` | 1..64 host masks (deny wins); an empty list must be written as `all` |
| `all` | `mode`, `ports`, `rate` | `hosts` absent |

- `ports`: 1..16 integers in 1..65535, or `["*"]` alone (only `denylist` and `all`). `allowlist` must list ports.
- `rate`: `{"requests_per_min": int 1..6000, "max_conns": int 1..64, "bytes_per_day": int}`, per worker, enforced by egress. Required so that no limit is implicit.
- Any mode other than `none` needs an exec tool (`ErrPolicyInvalid`): without one nothing in a call can speak to the socket.
- `modules` combined with generic modes is not offered (open question 3).
- Semantics, containment and residual risk per mode: threat-model-by-mode.md.

## 6. Effective risk (`policy check`)
Level = table cell, raised by the modifiers. **Proposed** (the draft's LOW rule "read-only or no bash" ignored that read-only does not stop exfiltration).

| network | rw + exec | ro or no exec |
| --- | --- | --- |
| `none` | MEDIUM | LOW |
| `modules` | MEDIUM | (n/a: needs rw + exec) |
| `allowlist` | HIGH | HIGH |
| `denylist`, `all` | CRITICAL | CRITICAL |

Modifiers: a module mask that matches a canary path raises `modules` to HIGH (a vanity-domain lookup is an exfiltration channel); a host mask that matches a canary makes `allowlist` CRITICAL ("allowlist that is `all`"); a broad host in `hosts` (`github.com`, `googleapis.com`, `githubusercontent.com`, `amazonaws.com`, `huggingface.co`) adds a warning, not a level.
`yolo` counts as exec with no rules; it never lowers a level. Reasons: host allowlists without TLS interception do not stop exfiltration or fronting (`docs/research/vendor-sandboxes.md`, item 5).

```
$ remote-workplace policy check policy.json
tools      allowlist: read_file search write_file apply_patch bash  (file settings advisory: bash present; bash masks advisory)
workspace  read-write; apply accepts internal/ cmd/ docs/
network    modules: 2 masks; read-only GET/HEAD; covert channel via module paths (rate-limited, logged)
limits     2 CPUs, 2048 MiB, 512 pids, 600 s, out 4 MiB, disk 4096 MiB soft
risk       MEDIUM
policy id  9c1f...e2 (sha256 canonical)
```
`--json` prints `{"level","reasons":[...],"warnings":[...],"policy_id"}`. `--max-risk LEVEL` exits 4 when exceeded. The level is stored in the workspace label, written to the harness audit log, and shown by `ls`.

## 7. Templates (Proposed)
Templates are generators, not inheritance: `remote-workplace policy template NAME --project P --worker W [--write-scope ...] [--go-modules ...]` prints a complete explicit file. What is stored is always the full file.

| template | tools | workspace | network | limits |
| --- | --- | --- | --- | --- |
| `reviewer` | `read_file`, `search` (paths `[".*"]`) | read-only, `[]` | none | 1 CPU, 1024 MiB, 256 pids, 300 s |
| `developer` | the five tools; bash `allow` `["go (build\|test\|vet)( .*)?", "git (status\|diff\|log)( .*)?"]`, `deny` `["curl .*", "wget .*"]` | read-write; `--write-scope` required | modules; `--go-modules` required; 600/min | 2 CPUs, 2048 MiB, 512 pids, 600 s |
| `yolo-offline` | yolo | read-write, `["*"]` | none | 2 CPUs, 2048 MiB, 512 pids, 600 s |

## 8. CLI (Proposed; the verbs `set`/`show`/`check` are from the draft)
| command | effect |
| --- | --- |
| `policy check FILE [--json] [--max-risk L]` | validate, print effective risk; touches nothing |
| `policy set --project P --worker W FILE` | check, store `~/.local/state/remote-workplace/policies/P.W.json` (0600, atomic rename), push the network part to egress, print the id. Exit non-zero if egress does not confirm the id |
| `policy show P W [--json]` | stored policy, id, risk, egress-confirmed id |
| `policy template NAME ...` | print a template |
Exit codes: 0 ok; 1 invalid policy; 2 usage; 3 not found; 4 above `--max-risk`; 5 egress not confirmed.

## 9. Lifecycle
- **Provision** refuses without a stored policy (`ErrNoPolicy`) and labels the workspace with policy id and risk. **Decided (D2)** for the refusal; label Proposed.
- **Run** reads the stored policy again. It fails closed (`ErrPolicyChanged`) if the id differs from the label, or (`ErrNoPolicy`) if the file is gone. For `network.mode != none` it also fails (`ErrEgressUnavailable`) unless egress confirms that it loaded the same id. Then it applies `access`, `limits`, env and the socket mount. Fail-closed Run and the egress check are Proposed (from `docs/research/worker-policy.md` §5).
- **Adopting a change**: export, deprovision, provision again. There is no in-place adopt (open question 6).
- **Apply**: `apply --policy P.W` takes `write_scope` from the producing worker's policy. With `--write-scope` also given, the effective scope is the intersection (authority only narrows; `docs/research/apiary-reconciliation.md` I2). Proposed protocol change to §6/§8.
- **Harness**: reads the same file (`workplace.LoadPolicy`), exposes tools, applies settings, logs the policy id and risk. Proposed addition to `docs/protocol.md` §9.
- **Deprovision** removes the workspace; the stored policy stays until `policy rm` (Proposed) so that a later provision does not silently drop it.

## 10. Errors
| error | when |
| --- | --- |
| `ErrPolicyInvalid` (with field path and rule) | any §2 to §5 violation, including project/worker not matching |
| `ErrNoPolicy` | Provision or Run without a stored policy |
| `ErrPolicyChanged` | Run with a stored id different from the workspace label |
| `ErrEgressUnavailable` | network mode other than none, and egress down or not on the same id |
| `ErrToolNotAllowed` | harness, a call to a tool that is not exposed |
| `ErrRiskExceeded` | `--max-risk` |

## 11. Examples
Reviewer (LOW):
```json
{"version":1,"project":"remote-workplace","worker":"rev-1",
 "tools":{"mode":"allowlist","allow":["read_file","search"],
  "settings":{"read_file":{"paths":[".*"],"max_bytes":1048576},"search":{"paths":[".*"],"max_results":200}}},
 "workspace":{"access":"read-only","write_scope":[]},
 "network":{"mode":"none"},
 "limits":{"cpus":1,"memory_mib":1024,"pids":256,"call_timeout_s":300,"max_output_bytes":4194304,"disk_soft_mib":2048}}
```
Developer with the module proxy (MEDIUM):
```json
{"version":1,"project":"remote-worker-harness","worker":"rwh-codex-rwh","note":"story 2b",
 "tools":{"mode":"allowlist","allow":["read_file","search","write_file","apply_patch","bash"],
  "settings":{"read_file":{"paths":[".*"],"max_bytes":1048576},"search":{"paths":[".*"],"max_results":200},
   "write_file":{"paths":["(internal|cmd|docs)/.*"],"max_bytes":1048576},"apply_patch":{"paths":["(internal|cmd|docs)/.*"]},
   "bash":{"allow":["go (build|test|vet)( .*)?","git (status|diff|log)( .*)?"],"deny":["curl .*","wget .*"]}}},
 "workspace":{"access":"read-write","write_scope":["internal/","cmd/","docs/"]},
 "network":{"mode":"modules","go_modules":["golang\\.org/x/.*","github\\.com/relux-works/.*"],
  "rate":{"requests_per_min":600,"max_conns":8,"bytes_per_day":2147483648}},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}
```
Yolo with a registry allowlist (HIGH; check prints "yolo: no tool rules", "allowlist: exfiltration to or through allowed hosts and fronting are not contained"):
```json
{"version":1,"project":"webapp","worker":"npm-1",
 "tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"allowlist","hosts":["registry\\.npmjs\\.org"],"ports":[443],
  "rate":{"requests_per_min":300,"max_conns":16,"bytes_per_day":5368709120}},
 "limits":{"cpus":2,"memory_mib":4096,"pids":1024,"call_timeout_s":1200,"max_output_bytes":4194304,"disk_soft_mib":8192}}
```

## 12. Tests (Proposed)
Table-driven validator tests for every rule in §2 to §5 (duplicate key, `null`, `2.0` for pids, `["*"]` with read-only, `yolo` with settings, mask `a)|(?:b`, `github\.com` against `github.com.evil.io`). Golden `policy check` output per template. Run-time: changed policy id, deleted file, egress on a stale id.
