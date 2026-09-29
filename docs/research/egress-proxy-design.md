# Egress proxy for jailed calls: design draft (protocol v2 candidate)

Status: a draft for the owner's decision; nothing here is normative yet. It follows the apiary reconciliation (`apiary-reconciliation.md`, delta D3) and the vendor study (`vendor-sandboxes.md`).
Goal: jailed calls can fetch dependencies without an open network, without a high-bandwidth exfiltration channel, and without giving up v1's single boundary.

## 1. Decision: a protocol-aware, read-only package proxy, not a generic tunnel
Both vendors ship a host-allowlist CONNECT proxy, and both document that without TLS interception it does not stop exfiltration through broad allowed hosts or domain fronting.
A worker that may CONNECT to github.com can push the project to an attacker's repository using the attacker's own token.
worker-jail's need is narrower: fetch dependencies. So v2 serves one package protocol end to end:
- The call speaks plain HTTP to a local service.
- The service validates method and path against the protocol's grammar and the project's policy.
- The service opens its own TLS connection to a fixed upstream.
Method and path limits are then enforceable without MITM, and the call never talks to the internet.
Go modules come first (every relux-works project is Go). npm or PyPI get their own handler when a project needs one.
A generic CONNECT allowlist stays out of v2 (section 8, open decision 1).

## 2. Architecture
```
call container (--network none, only lo)                 wj-egress container (trusted; the workers VM)
  go build ─ GOPROXY=http://127.0.0.1:3128/gomod
    └▶ socat 127.0.0.1:3128 ─▶ /run/wj/egress.sock ─────▶ policy of project P ─TLS─▶ proxy.golang.org
                          (read-only mount of P's socket dir)                     └─TLS─▶ sum.golang.org
```
- **The boundary is unchanged.** Calls keep `--network none`: no interface but `lo`, no DNS, no route.
  A call of an egress-enabled project gets exactly one more thing: its project's socket directory, mounted read-only with `--mount type=volume,src=wj-egress-sock,dst=/run/wj,volume-subpath=<P>,readonly`.
  Verified on the workers VM (Docker 29) on 2026-09-29. A call running as uid 10001 with a read-only rootfs, no capabilities and no-new-privileges could connect to the socket. It saw only its own project's directory (another project's was absent), could not write there, and had only `lo`.
- **The relay** is `socat` in the base image, started by the jail's argv wrapper before the tool runs. It listens on `127.0.0.1:3128` inside the call and forwards to the socket.
  It sits on the untrusted side on purpose: killing it or running another only reaches the same socket, and the service enforces the policy.
- **wj-egress** is one small Go program in this repository (`cmd/wj-egress`), run as one container in the workers VM:
  - `--read-only --cap-drop ALL --security-opt no-new-privileges`, a non-root user, and memory and pids limits;
  - the default bridge network with a public resolver (`--dns 1.1.1.1`; the VM's own resolver does not answer, as seen in red-team G2);
  - volumes for sockets (rw), policies (ro) and the response cache (rw).
  It creates one listener per project that has a policy: `/run/wj/<P>/egress.sock`, mode 0666 inside the project directory. The mount itself is the capability.
- **Policies** are host-owned configuration, reviewed like code, never worker-writable. `worker-jail egress set --project P --policy FILE` validates the file and pushes it into the policy volume through a seeding call. The service reloads it on SIGHUP.
  Default: no policy, which means no socket, which means no egress (fail closed).

## 3. Go module handler
- **Methods:** GET and HEAD only. Anything else gets a 403.
- **Paths**, the Go module proxy protocol only, validated strictly:
  - `/gomod/<module>/@v/list`, `/gomod/<module>/@v/<version>.info|.mod|.zip`, `/gomod/<module>/@latest`;
  - `/gomod/sumdb/sum.golang.org/supported|latest|lookup/<module>@<version>|tile/<H>/<L>/<K>[.p/<W>]`.
  - `<module>` must be a valid escaped module path and match the project's allowlist of module prefixes. `<version>` must be canonical semver or a pseudo-version.
  - Encoded separators, `..` components and non-canonical forms are rejected before anything is forwarded.
- **Upstreams are fixed in code:** `https://proxy.golang.org` and `https://sum.golang.org`. Client headers are not forwarded, and the Host header is always the upstream.
  Go verifies every module against the checksum database's signed tree heads with its built-in key, so integrity is end to end even though the proxy sits in the middle.
- **Dial guard:** resolve once and dial the checked address. Refuse loopback, private (RFC1918), link-local, CGNAT, ULA, multicast, cloud-metadata and the lima gateway range (192.168.5.0/24). This covers DNS poisoning of the fixed upstreams.
- **Cache:** immutable objects (a version's `.info`, `.mod` and `.zip`, and sumdb tiles) are cached by path in the cache volume. `list`, `@latest` and sumdb `latest` are not cached.
  The cache doubles as apiary's "point where external responses are recorded for replay", and repeated fetches become offline.
- **Env the jail sets** for calls of an egress-enabled Go project:
  - `GOPROXY=file:///cache/gomod/cache/download,http://127.0.0.1:3128/gomod`, so the seeded cache is read first and the proxy only for new modules;
  - `GOMODCACHE=/work/home/go/pkg/mod`, per worker and writable, because new modules must land somewhere writable;
  - `GOSUMDB=sum.golang.org`, which goes through the proxy's sumdb paths;
  - `GOTOOLCHAIN=local`.
  `GOFLAGS` stays the image's choice.

## 4. Denials, logs, limits
- **In-band denials:** `403` with `X-Worker-Jail-Denied: <reason>` and a one-line body, for example `module path not allowed for project P: evil.example/x`. The go command prints it, so the worker learns why and asks its orchestrator.
- **Log:** JSON lines on the service's stdout with time, project, method, path, decision, status, bytes, cache hit and upstream latency. Read them with `worker-jail egress log [--project P] [--since D]`.
- **Per-project rate limits** (token bucket on requests per minute, plus a daily byte cap) bound the covert channel described in section 6.
- **Fail closed:** no policy, the service down, a DNS failure, an upstream TLS error, an oversized response or a timeout each give a denial or a failed fetch, never a fallback to open network.

## 5. Protocol changes this would make (v2)
- **G2** becomes: "A call has only a loopback interface. A call of a project with an egress policy additionally has one Unix socket to that project's egress service, which serves only the protocol handlers that policy enables. Nothing else routes out of a call."
- **Section 7 (network policy)** is rewritten around per-project egress policies. They are owner or orchestrator configuration, off by default, and never derived from worker files.
- **New operations:** `egress set | show | log`, and `egress up | down` for the operator. `doctor` checks that the service runs with its hardening whenever any policy exists.
- **New known limit:** the service is a trusted component with network access, and its HTTP parser is reachable from calls. Mitigation: keep it small, fuzz the path grammar, and run it hardened.
- **Base image v2** adds `socat`. Derived images (rwh-worker) rebuild on `worker-jail/base:2`. rwh's call path does not change, because the jail sets the env.

## 6. Residual risks
- **Covert channel through lookups.** A module path is data. A lookup of `github.com/attacker/<encoded data>` makes proxy.golang.org fetch from that origin.
  It is bounded by the module-prefix allowlist, the rate limit and the log, not eliminated. The threat model already accepts that the model provider sees everything a worker reads; this adds a low-bandwidth path to third parties.
- **Malicious dependencies.** A worker can add a hostile module to go.mod. It runs only inside jailed calls until the patch is reviewed. The go.mod diff is visible in review, and supply-chain review stays with the orchestrator.
- **Upstream compromise** of proxy.golang.org: integrity is still protected by sum.golang.org. Availability and privacy are out of scope.

## 7. Verification (red-team additions)
Probes that must fail, each with a positive control:
- **Direct egress:** direct TCP and DNS without the socket (existing G2).
- **Methods and non-protocol requests through the socket:** CONNECT, an absolute-URI request to example.com, and POST.
- **Paths through the socket:** a non-allowlisted module, path traversal and encoded separators, a non-sumdb host under `/gomod/sumdb/`, and an oversized path.
- **Cross-project and host-side reach:**
  - another project's socket directory is not present;
  - the service refuses an allowlisted name that resolves to 192.168.5.2 (fake resolver);
  - the rate limit engages.

Positive controls:
- `go mod download` of an allowlisted module succeeds in a call of an egress-enabled project, and the same command fails in a project without a policy.
- `go build` offline from the seeded cache still works with the proxy down.

## 8. Decisions needed from the owner
1. **Scope:** start with module mode only (recommended), or also add a generic CONNECT allowlist per project?
   The CONNECT allowlist is what "a proxy with permissions" may have meant. It can reach any allowlisted host, but by the vendors' own documentation it is an exfiltration channel to those hosts and cannot enforce methods without TLS interception.
2. **Default module allowlist:** empty per project, with the orchestrator listing prefixes (recommended), or a small shared default (`golang.org/x/`, `google.golang.org/`, `gopkg.in/`, `github.com/`)? `github.com/` is broad for the covert channel described in section 6.
3. **Timing:** v1 is frozen. Building this is v2 of the protocol, implemented on Opus 5.5 at low effort after the decision.
