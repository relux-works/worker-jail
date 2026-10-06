# wj-egress: one service for all network modes (worker-jail v2 design)

Status: design, not normative. Elaborates `docs/research/egress-proxy-design.md` (drafted per project) for the five modes of D1 (`docs/decisions/2026-09-29-v2-direction.md`).
Tags: **Decided (source)** or **Proposed**. Policy fields: policy.md. Risks: threat-model-by-mode.md.

## 1. Shape
- Calls keep `--network none`: only `lo`, no DNS, no route. **Decided (`docs/protocol.md` G2; D1 and D3 of the decision record add the modes, and `docs/research/vendor-sandboxes.md` verdict "adopt for v2" keeps the no-interface property)**.
- The only way out is one Unix socket per worker, mounted read-only into the call. **Proposed** (the draft mounted one per project; per worker gives per-worker policy, limits, logs and G5 isolation).
- One Go program, `cmd/wj-egress`, one container in the workers VM, serves every worker and every mode. **Proposed** (from the draft).

```
call (--network none, lo only)                          wj-egress (workers VM, one container)
  tool ─ HTTP(S)_PROXY / GOPROXY = 127.0.0.1:3128
   └▶ socat 127.0.0.1:3128 ─▶ /run/wj/egress.sock ─────▶ listener of worker P.W ─▶ mode handler ─▶ dial guard ─▶ internet
          (volume wj-egress-sock, subpath P.W, ro)
```

| mode | socket exists | handler enabled |
| --- | --- | --- |
| `none` | no; no mount; container identical to v1 | none |
| `modules` | yes | modules only |
| `allowlist`, `denylist`, `all` | yes | generic only |

Mounting: `--mount type=volume,src=wj-egress-sock,dst=/run/wj,volume-subpath=<P>.<W>,readonly`. The draft verified this for a project directory on Docker 29 (uid 10001, read-only rootfs, no caps, no-new-privileges, connect works, other directories absent, `lo` only). Per-worker subpaths need the same verification (red-team probe E1). A missing subpath makes `docker create` fail: that is fail closed.
The socket directory is owned by the service (0755), the socket is 0666 in it. The mount is the capability; there is no token.

## 2. Service container (Proposed, from the draft)
- `--read-only --cap-drop ALL --security-opt no-new-privileges`, non-root, memory and pids limits, `--log-driver local` with size limits.
- Own Docker network with a public resolver (`--dns 1.1.1.1`; the VM resolver does not answer, red-team G2).
- Volumes: `wj-egress-sock` (rw), `wj-egress-policy` (ro), `wj-egress-cache` (rw). None is mounted in a call except the worker's own socket subpath.
- Second layer (Proposed, open question 4): the egress network gets firewall rules in the VM that drop RFC1918, link-local and the gateway, so a guard bug does not reach host services. Host services behind the gateway (the Matrix homeserver, G2) are what the guard protects.
- Exception to Appendix A of the protocol (this container needs a network): the protocol text must list it. Every other container keeps `--network none`.
- Relay in the call: `socat TCP-LISTEN:3128,bind=127.0.0.1,fork UNIX-CONNECT:/run/wj/egress.sock`, started by the jail's argv wrapper before the tool (base image v2 adds `socat`). It is untrusted by design; it dies with the call (`--init`, container removal, G6). Alternative: a static `wj-relay` binary (open question 3).
- Env set by the jail:

| mode | env |
| --- | --- |
| `modules` | `GOPROXY=file:///cache/gomod/cache/download,http://127.0.0.1:3128/gomod`, `GOMODCACHE=/work/home/go/pkg/mod`, `GOSUMDB=sum.golang.org`, `GOTOOLCHAIN=local` |
| generic | `HTTP_PROXY=HTTPS_PROXY=ALL_PROXY=http://127.0.0.1:3128` (hints only; the missing route is the enforcement), `NO_PROXY` empty |

## 3. Request routing
One HTTP/1.1 parser per listener, strict: header block at most 8 KiB, no request smuggling forms (duplicate `Content-Length`, `Transfer-Encoding` with it), 5 s header timeout.

| request form | modules | generic |
| --- | --- | --- |
| origin form `GET /gomod/...` | modules handler | 403 `mode` |
| `CONNECT host:port` | 403 `mode` | generic CONNECT |
| absolute form `GET http://host/...` | 403 `mode` | generic HTTP |
| anything else, any other method | 403 `method` | 403 `method` |

## 4. Handlers
### Modules (Proposed, from the draft with fixes)
- Methods GET and HEAD. Paths (validated before anything leaves):
  - `/gomod/<module>/@v/list`, `/@v/<version>.info|.mod|.zip`, `/@latest`;
  - `/gomod/sumdb/sum.golang.org/supported|latest|lookup/<module>@<version>|tile/<H>/<L>/<K>[.p/<W>]`. Any other sumdb name is refused.
- `<module>` is an escaped module path; unescape, then match the policy's `go_modules`. **Fix**: the draft matched masks only for `@v` paths; `@latest`, `list` and sumdb `lookup` reveal the module path too, so they are all masked.
  `<version>` is canonical semver or a pseudo-version. Reject encoded separators, `..`, non-canonical forms and paths over 1 KiB.
- Upstreams are fixed in code: `https://proxy.golang.org`, `https://sum.golang.org`, over the service's own TLS. Client headers are not forwarded; Host is the upstream's. Go verifies against the signed tree heads with its built-in key, so integrity is end to end.
- Redirects: not followed by default. The draft does not say whether the upstream redirects `.zip` downloads to another host. Test it (E7); if it does, follow at most 2 redirects and only to a fixed host list compiled into the binary, each through the dial guard.
- **Cache**: immutable objects (`.info`, `.mod`, `.zip`, sumdb tiles) by path, 200 responses only, per-object cap, total cap per worker. `list`, `@latest`, sumdb `latest` and errors are not cached. The mask check happens before the cache lookup.
  **Fix**: the draft's cache was shared; here the namespace is per worker (`<P>.<W>/`), because a shared cache is a timing channel between workers (G5). Sharing per project is open question 2.

### Generic (Proposed)
- `CONNECT host:port`: canonicalise host (lowercase, punycode, no trailing dot, IPv6 unbracketed) and match the policy. `allowlist`: host matches a mask and port is listed. `denylist`: no mask matches (deny wins) and port is allowed. `all`: port is allowed. Then dial (§5), reply `200`, splice bytes. No TLS interception: the tunnel content is invisible (threat-model-by-mode.md §2).
- Absolute-URI HTTP (`http://` only): same host/port check on the URI authority; the request is rewritten to origin form; `Host` is set from the checked authority (mismatch is refused); hop-by-hop and `Proxy-*` headers are dropped; the response passes back. Redirects are not followed: the client re-asks and is re-checked.
- Port 80/443 are not implied: an unlisted port is denied.
- Idle timeout 60 s, tunnel lifetime cap 1 h, per-connection byte cap = the worker's remaining daily bytes.

## 5. Always on (all modes with a socket)
| control | rule |
| --- | --- |
| Dial guard | Resolve in the service (DNS exists only here; the call has none). Refuse if **any** answer is forbidden (stricter than the vendors' pick-the-safe-one), dial the checked IP, and re-check the peer address in the dialer's control hook. Forbidden: `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16` (metadata), `172.16/12`, `192.0.0.0/24`, `192.168/16` (includes lima `192.168.5.0/24`), `198.18/15`, `224/4`, `240/4`, `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`. IPv4-mapped, NAT64 `64:ff9b::/96` and 6to4 `2002::/16` are unwrapped and re-checked. No field can change it. **Decided (D3, `docs/research/egress-proxy-design.md` §3)** for the list; the unwrap and any-answer rules Proposed |
| Denials | In-band: `403`, header `X-Worker-Jail-Denied: <code>` and a one-line body naming the denied name, never the policy. Codes: `no-policy`, `mode`, `method`, `grammar`, `module`, `host`, `port`, `guard`, `rate`, `size`, `upstream`. **Decided (`docs/research/vendor-sandboxes.md` item 8)** |
| Logs | JSON lines on stdout: `ts`, `project`, `worker`, `policy_id`, `mode`, `handler`, `method`, `host`, `port`, `path` (modules; plain HTTP: first 256 bytes plus length and sha256, query stripped), `decision`, `code`, `status`, `bytes_in`, `bytes_out`, `dur_ms`, `cache`, `ip`. Never bodies or headers. `worker-jail egress log [--project P] [--worker W] [--since D]` reads them (via `docker logs`) |
| Rate limits | Per worker from `network.rate`: token bucket on requests per minute, a concurrent-connection cap, `bytes_per_day` (resets 00:00 UTC). Exceeded: `403 rate` for every request form (one status only) |
| Fail closed | Table below. **Decided as a rule (`docs/research/vendor-sandboxes.md` items 3, 4)** |

| failure | behaviour |
| --- | --- |
| no policy, or the policy is `none` | no listener, no socket |
| policy file unreadable, invalid or unknown version | that worker's listener is closed (deny all); others unaffected; error logged |
| service down or restarting | sockets vanish or refuse; calls have no route; `Run` fails with `ErrEgressUnavailable` |
| DNS failure, upstream TLS error, upstream timeout (10 s connect, 30 s first byte) | 502 `upstream`; never a direct or fallback path |
| oversized response (per-object cap), oversized header | abort, 403 `size` |
| panic in a handler | connection closed, service continues; the worker's listener stays |
| log sink blocked for 5 s | new connections are refused until it recovers |

## 6. How policies reach the service (Proposed)
1. `policy set` validates (policy.md) and stores the file host-side, then runs a hardened seeding call (same technique as `seed-cache`) that writes `<P>.<W>.json` into `wj-egress-policy` by atomic rename. The file holds only `project`, `worker`, `network`, the policy id.
   **Implemented differently in v2.1 part A:** the whole policy file is written (it holds no secret), and the service validates it with the jail's own `ParsePolicy`, so the loaded id is exactly the host's policy id (`docs/protocol.md` section 7).
2. It signals the service (`docker kill -s HUP wj-egress`). The service re-reads every file with the same validator package, opens or closes listeners and creates the worker's socket directory.
3. `docker exec wj-egress wj-egress status <P.W>` prints the loaded id. `policy set` waits for it (exit 5 on timeout). `Run` compares the loaded id with the stored one before every network-enabled call (`ErrEgressUnavailable` otherwise), so a stale service can neither widen nor silently narrow access.
4. Removal: `deprovision` (or `policy rm`) removes the file; the listener and its cache namespace go on the next reload.
5. Policy files are never writable from calls: the policy volume is not mounted in any call, and the sockets are mounted read-only.
Operator commands `egress up|down|status|log` (Proposed, from the draft). `doctor` verifies the service's hardening whenever any worker has a network mode other than `none`.

## 7. Protocol changes this needs (v2)
G2: "a call has only a loopback interface and, when its policy says so, one Unix socket to its own egress listener"; §7 rewritten around policies; §13 drops "an egress proxy"; Appendix A gains the egress exception; `doctor` gains the egress check; base image v2 adds `socat`. Policy-driven `apply --policy` (policy.md §9). Known-limits table: the egress service is a trusted, network-capable component reachable from calls.

## 8. Verification (probes must fail; each has a positive control)
| id | probe | control |
| --- | --- | --- |
| E1 | another worker's subpath absent; write to the socket dir fails; `lo` only | own socket connects |
| E2 | mode confusion: CONNECT and absolute URI in `modules`; origin form in generic; POST | the permitted form works |
| E3 | grammar: unlisted module, `..`, `%2f`, non-sumdb name under `/gomod/sumdb/`, huge path, `@latest` of an unlisted module | listed module downloads |
| E4 | dial guard with a fake resolver returning each forbidden range, a mixed answer, a mapped v6, and a rebinding second lookup | the same name with a public address works |
| E5 | host mask anchoring (`github.com.evil.io`), IP literals, trailing dot, uppercase, punycode | exact host works |
| E6 | rate: requests, connections, bytes per day engage; cache probes across two workers do not hit each other | the limit is lifted in the control policy |
| E7 | redirects: modules upstream 302 (fake) is refused or limited to the fixed list | real `go mod download` works |
| E8 | fail closed: kill the service, corrupt a policy file, stale id at Run | service up and matching: works |
| E9 | fuzz the request parser and the path grammar (`go test -fuzz`), smuggling forms | n/a |
| E10 | offline: `go build` from the seeded cache with the service down | |
