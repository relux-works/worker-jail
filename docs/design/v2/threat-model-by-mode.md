# Threat model by mode (remote-workplace v2 design)

Status: design, not normative. Extends `docs/protocol.md` §1 and §5 (G1 to G8). Policy fields: policy.md. Egress mechanics: egress.md.
Tags: **Decided (source)** or **Proposed**. Vendor facts come only from `docs/research/vendor-sandboxes.md` and `docs/research/vendor/*.md`.

## 1. Attacker and baseline
- The attacker is a hostile model or a prompt injection reaching it through a task, file, tool output or dependency. It knows this design and controls every tool request. **Decided (`docs/protocol.md` §1)**.
- Baseline in every mode (unchanged by policy):
  - Everything the worker reads may reach its model provider. The provider channel is outside the workplace and cannot be closed by any network mode. **Decided (`docs/protocol.md` §1)**.
  - What the worker writes is untrusted until reviewed. Only a patch leaves, through `apply` gates: `.git`, write scope, symlinks, gitlinks, review-required paths. **Decided (G8, D4)**.
  - The workplace keeps G1, G3 to G7 in every mode: no host files, no privilege, bounded resources, isolation between workers, nothing outlives a call, no secrets inside.
- Assets at risk from a network mode: the workspace (source, history, anything seeded from a dirty worktree, see worktree-seeding.md), `/cache/*`, and the workers VM's reachable network.
- Ingress also matters: a network delivers attacker-authored content (a poisoned module, a page with instructions). It stays inside the workplace until review (`docs/protocol.md` §8 step 5).

Layers: **K** = `--network none` and the absence of a route (kernel); **S** = one per-worker socket (mount); **E** = egress service policy; **D** = dial guard; **R** = rate limits; **A** = apply gates; **H** = harness tool exposure; **L** = logs.

## 2. Network modes
Assumes an exec tool and read-write workspace unless stated.

### none — LOW/MEDIUM (policy.md §6)
| | |
| --- | --- |
| Attacker can | compute, read the workspace, write to it, plant code and text in the patch |
| Contained | all egress (K, **Decided G2**); DNS; the host and VM; other workers |
| Not contained | the provider channel (baseline); output through stdout to the harness, capped by `max_output_bytes`; payloads in the patch that reviewers miss (A plus review) |
| Detection | harness audit log (argv, exit, sizes); `apply` refusals |
| Risk | MEDIUM with rw + exec, LOW read-only or no exec |

### modules — MEDIUM (HIGH with broad masks)
| | |
| --- | --- |
| Attacker can | GET/HEAD Go proxy and sumdb paths for modules matching `go_modules`; fetch and cache attacker-authored modules; put data in module paths within the masks |
| Contained | methods (GET/HEAD only), paths (grammar), upstreams (fixed in code), private ranges (D), volume (R), reach beyond the worker's socket (S) |
| Not contained | **covert channel by lookups**: a path like `evil.example/<data>` makes `proxy.golang.org` contact the origin, so a mask that admits arbitrary hosts exfiltrates at low bandwidth (`docs/research/egress-proxy-design.md` §6). Narrow masks (a single org prefix) shrink it to whoever controls that prefix. **Malicious dependencies**: a hostile module in `go.mod` runs only in workplace calls; the diff is reviewed |
| Not applicable | TLS-fronting and CONNECT: not served (E) |
| Detection | egress JSON log per worker (path, decision, bytes, cache hit); rate-limit denials; the `go.mod` diff |
| Risk | MEDIUM with narrow masks; HIGH when a mask matches a canary path (policy.md §6) |

### allowlist — HIGH
| | |
| --- | --- |
| Attacker can | CONNECT or absolute-URI HTTP to hosts matching `hosts` on `ports`; anything inside the tunnel |
| Contained | hosts and ports outside the masks (E); private ranges, loopback, metadata, the Matrix gateway (D); DNS from the call (K) |
| Not contained | **exfiltration to or through allowed hosts**, and **domain fronting**: without TLS interception the proxy sees only host:port (`docs/research/vendor-sandboxes.md` item 5). Broad hosts (`github.com`, `googleapis.com`, `githubusercontent.com`) are attacker-writable storage: `git push` to the attacker's repository with the attacker's token. Method and URL limits do not apply to TLS. Also: ingress from allowed hosts |
| Detection | egress log: host, port, bytes, duration, resolved IP; no content. Volume and unusual hosts only |
| Risk | HIGH. CRITICAL if a mask matches a canary (allowlist that is `all`) |
| Note | interception (vendors' `limited` mode, `tlsTerminate`) is not adopted; it needs a CA in calls and is Proposed only as a future option |

### denylist — CRITICAL
| | |
| --- | --- |
| Attacker can | reach every public host and port not matching `hosts`; alternate names and IP literals bypass a name denylist |
| Contained | private ranges and metadata (D); the listed hosts by name only |
| Not contained | exfiltration of anything readable; command and control; downloads of arbitrary code |
| Detection | egress log (same limits as allowlist) |
| Risk | CRITICAL: effectively `all` |

### all — CRITICAL
Like denylist with nothing denied. Contained: only D (no private ranges) and R. Everything the worker can read (workspace, seeded caches, snapshot content) can leave. Use only for an offline-equivalent content set: a workspace that holds nothing worth stealing. **Decided (D2)**: must be written out, and the risk is printed.

### Fixed guards in every mode with a socket
- Dial guard (D): loopback, private, link-local, CGNAT, ULA, metadata, `192.168.5.0/24`, including addresses embedded in IPv4-mapped, NAT64 and 6to4 forms. Not configurable. Resolve once, dial the checked address (`docs/research/vendor-sandboxes.md` item 4). Best-effort against DNS rebinding, as the vendors say.
- Not contained by D: the egress service itself is a trusted component reachable from calls. A parser bug there gives the attacker the service's network view (see §5).

## 3. Tools modes
| mode | attacker can | contained by | not contained | detection | risk contribution |
| --- | --- | --- | --- | --- | --- |
| `allowlist`, no exec (`read_file`, `search`, ...) | read what the tools read; write through file tools | H (exposure), workplace limits; K/S/E for network; A for output | reading everything inside `paths` and sending it to the provider; a bug in a tool runner | harness audit log | none added; network mode requires an exec tool, so it is `none` |
| `allowlist` with `bash` | run any program of the image as uid 10001 | workplace (G1 to G7); bash masks are advisory (`sh -c`, interpreters and paths bypass them, as both vendors state) | anything the network mode allows; file-tool settings become advisory | audit log records argv (tool name plus request size and sha256 for fixed runners) | MEDIUM at `none` |
| `yolo` | same as `bash` with no rules, plus every future tool the harness has | workplace, unchanged; every tool executes in a call (**Decided** harness obligation 2 and 10, `docs/protocol.md` §9) | rules do not exist; a tool that gains a side effect on the host would break G1, so tools must all run through `workplace.Run` | same | same as exec; policy check prints "no rules" |
| `read-only` workspace | read only | read-only mount (workplace) | exfiltration if a network mode exists | | LOW at `none` |

## 4. Combinations
| combination | what changes | risk | why |
| --- | --- | --- | --- |
| reviewer: allowlist read tools, ro, `none` | can read all and answer the provider only | LOW | v1 property: nothing to run, nothing to write |
| developer: bash, rw, `modules` (narrow) | fetches known modules, builds, tests | MEDIUM | covert channel bounded by masks, rate and log |
| developer, `modules` with `.*` | any vanity host receives lookups | HIGH | data in module paths |
| yolo-offline | full toolbox, no network | MEDIUM | v1 boundary intact |
| yolo + `allowlist` (registry) | can run arbitrary code and tunnel to the registry host | HIGH | fronting and registry-hosted exfiltration (uploading is possible to many registries) |
| bash + `allowlist` with `github.com` | push project to an attacker-controlled repo | HIGH, warning printed | vendors' own documentation of the same case |
| yolo + `all` | exfiltrate, download tools, C2 | CRITICAL | only the workplace boundary remains: kernel escape reaches the VM and the shared egress (`docs/protocol.md` §5 limits) |
| ro workspace + `allowlist` (reviewer with a docs site) | reads private source and sends it out | HIGH | read-only does not stop exfiltration; policy.md §6 does not lower the level |
| seeded from a dirty worktree + any network | unlanded files and any leftover secrets are exposed to the mode | raise attention | secret guard (worktree-seeding.md) refuses override at HIGH or above |
| two workers, same project, `modules` | a shared cache would let one signal the other | avoided | per-worker cache namespaces (egress.md §2), keeps G5 |

## 5. What egress adds to the trusted base
| new exposure | control | residual |
| --- | --- | --- |
| Calls reach a service with network access through a mounted socket | per-worker socket dir via volume subpath; the service is unprivileged, read-only rootfs, no capabilities | HTTP parser bug reachable from calls: fuzz the grammar, keep the code small |
| The egress container can route to the VM gateway and the host services behind it (the Matrix homeserver) | dial guard in code; Proposed second layer: a dedicated Docker network with firewall rules in the VM | a guard bug otherwise reaches the host loopback services (G2) |
| A container escape already reaches the VM's egress (`docs/protocol.md` §5 limits table) | unchanged | egress modes add the socket of every worker to the escaped attacker's reach |
| Policies change reachability | host-owned, reviewed; loaded ids are checked at Run; egress fails closed | a mistaken policy is a decision, printed with its risk |

## 6. Detection summary
| source | records | limits |
| --- | --- | --- |
| harness audit log (host; `docs/protocol.md` §9.6) | argv or tool name, size and sha256, timing, exit, sizes, policy id and risk | no network content |
| `rwp-egress` JSON log (egress.md §5) | worker, policy id, handler, method, host, port, path for modules, decision, reason, bytes, duration | CONNECT content is invisible; plain HTTP bodies and headers are never logged |
| `apply` | refusals with the gate name | after the fact |
| `ls` | risk label per workspace | |
Alert candidates (Proposed): denials over a threshold per worker; new hosts for an allowlist worker; bytes near `bytes_per_day`; any dial-guard denial (never legitimate).

## 7. Not contained in any mode
Provider channel; kernel and hypervisor escapes (`docs/protocol.md` §5: gVisor is a candidate, D4 of `docs/research/apiary-reconciliation.md`); a reviewer approving a hostile patch; a hostile policy written by the operator.
