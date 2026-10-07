# remote-workplace

The security protocol and the reference workplace for **remote workers**: agents whose model runs elsewhere (Codex or Claude on the dedicated Mac mini)
and whose tool calls execute on the project's machine. Assume the worker is **compromised and hostile**. It must still be unable to reach beyond its
workspace and the tools it was given, and unable to damage the host.

**Design rule (owner): as simple and reliable as possible. One strong boundary, few moving parts, everything testable. No overloaded frameworks.**

Consumers: `relux-works/remote-worker-harness` (runs the workers) and `relux-works/a2a-swarm` (the swarm's channel). Room: `#swarm-remote-workplace:a2a.local`.
**Normative spec: [`docs/protocol.md`](docs/protocol.md)** (v2.1: v2.0, which is v1.1 plus the per-worker policy and worktree seeding, plus the egress service for the network modes `modules`, `allowlist`, `denylist` and `all`): the threat model, the workplace's guarantees G1-G8, the interface, the network policy,
the change-extraction path, and what the harness, orchestrators and the operator must do.
**Integration notes: [`docs/integration.md`](docs/integration.md)** (setup, the Go API walk-through, errors, capacity, reviewing patches, operations).
Research (non-normative): `docs/research/` holds the apiary reconciliation, the Claude Code / Codex sandbox study and the egress proxy design draft.
`docs/design-brief.md` is the agreed starting design (history; the protocol wins where they differ). `BOOTSTRAP.md` is for this project's orchestrator.

## Design in one paragraph
Every tool call of a worker runs in a **fresh, hardened container** (`--network none`, all capabilities dropped, no-new-privileges, uid 10001,
read-only rootfs, cpu/memory/pids/time limits) inside a **dedicated colima VM (`workers`) started with `--mount none`**. A worker's state is its
**workspace volume** (a clone of the project at a base commit); read-only per-project caches (Go modules) are the only shared data.
Changes leave only as a **patch** that an orchestrator reviews and applies with hooks disabled.

## Per-worker policy (v2.0)
No policy, no worker: `provision` and `run` refuse a (project, worker) without a stored policy. A policy is one explicit JSON file per worker,
host-owned and reviewed like code: the tools the harness exposes (`allowlist` with per-tool settings, or `yolo`), the workspace mount
(`read-write` or `read-only`) and the `write_scope` that `apply --policy` enforces, the network mode, and the call limits (cpus, memory,
pids, timeout, output cap, soft disk quota). `policy check` validates a file strictly and prints its effective risk (LOW to CRITICAL) and its
id (sha256 of the canonical form). `policy set` stores it in `~/.local/state/remote-workplace/policies/P.W.json`, refusing CRITICAL without
`--accept-risk CRITICAL` and HIGH without a `note`. A new workspace is labelled with the policy's id and risk; `run` fails closed if the stored
policy is gone or changed (re-provision to adopt a change) and applies its access and limits to every call. Every network mode
but `none` (`modules`, `allowlist`, `denylist`, `all`) is served by the egress service (v2.1, below). Start from a template:

```sh
bin/remote-workplace policy template developer --project myproj --worker w1 --write-scope internal/,docs/ --go-modules 'golang\.org/x/.*' > w1.json
# developer uses network mode modules: run `egress up` first (below), or edit it to {"mode":"none"}, or start from reviewer or yolo-offline
bin/remote-workplace policy check w1.json --max-risk MEDIUM
bin/remote-workplace policy set --project myproj --worker w1 w1.json
```
Spec: [`docs/protocol.md`](docs/protocol.md) section 14 and [`docs/design/v2/policy.md`](docs/design/v2/policy.md).

## Worktree seeding (v2.0)
A worker can start from the orchestrator's Story worktree as it is now, dirty and unlanded changes included, and its reviewed patch can go
back into that worktree while it keeps moving. `provision --from-worktree DIR` snapshots DIR in a temporary repository (empty config, no
hooks, no filters, the source only an alternate: DIR is never written) and provisions from the snapshot commit. A secret guard refuses
likely secrets anywhere in the delta (`.env`, keys, `.npmrc`, ... by name; private keys and tokens by content); `--allow-secret-path`
overrides the name rule only, and never for a HIGH or CRITICAL policy. `seed-gomod --from-worktree` seeds the Go module cache from the same
snapshot without credentials. `apply --allow-dirty` applies a patch into a dirty **linked** worktree (never the primary checkout): the working
tree only, all v1 gates first, all or nothing.

```sh
bin/remote-workplace provision --project myproj --worker w1 --from-worktree ../myproj-story   # prints snapshot-tree= and snapshot-parent=
bin/remote-workplace seed-gomod --project myproj --from-worktree ../myproj-story
bin/remote-workplace apply --repo ../myproj-story --allow-dirty --policy myproj.w1 --snapshot-tree <tree> turn-3.patch
```
Spec: [`docs/protocol.md`](docs/protocol.md) section 15 and [`docs/design/v2/worktree-seeding.md`](docs/design/v2/worktree-seeding.md).

## Egress for Go modules (v2.1)
A worker whose policy has `network.mode: modules` can download the Go modules its `go_modules` masks allow, and nothing else.
Its calls keep `--network none`; the only way out is its own Unix socket, mounted read-only from the volume `rwp-egress-sock`, behind which
one service container, `rwp-egress` (`cmd/rwp-egress`, image `remote-workplace/egress:1`), answers the Go module proxy and checksum database grammar:
masks on every path that names a module, fixed upstreams (`proxy.golang.org`, `sum.golang.org`), a per-worker cache, a dial guard against
private and metadata addresses, in-band `403` denials with `X-Remote-Workplace-Denied`, JSON logs and the policy's rate limits. A `socat` relay
from base image v2 bridges the call's `127.0.0.1:3128` to the socket; the workplace sets `GOPROXY`, `GOMODCACHE`, `GOSUMDB` and `GOTOOLCHAIN`.
`policy set` delivers the policy to the service and waits for it to confirm the id; `run` refuses unless the service serves exactly the stored id.

```sh
make image                    # remote-workplace/base:2 (base image v2, socat), remote-workplace/go:2 and remote-workplace/egress:1, built into the workers VM
bin/remote-workplace egress up     # network rwp-egress-net, the volumes rwp-egress-{sock,policy,cache}, the hardened service
bin/remote-workplace policy set --project myproj --worker w1 w1.json     # prints ... egress=confirmed; exit 5 if not confirmed
bin/remote-workplace run --project myproj --worker w1 -- go mod download
bin/remote-workplace egress status # the service and every networked policy's stored and loaded ids
bin/remote-workplace egress log --project myproj --worker w1 --since 1h
```
Spec: [`docs/protocol.md`](docs/protocol.md) section 7 and [`docs/design/v2/egress.md`](docs/design/v2/egress.md).

## Generic egress: allowlist, denylist, all (v2.1)
A worker whose policy has `network.mode` `allowlist`, `denylist` or `all` reaches hosts through the same per-worker socket and service, as an
HTTP proxy: `CONNECT host:port` tunnels (https and anything else over TCP) and absolute-URI `http://` `GET`/`HEAD`. The service canonicalises the
host (lowercase, no trailing dot, IP literals in canonical form; non-ASCII IDNs are refused, send punycode) and checks it against the
anchored `hosts` masks and the listed `ports` (80 and 443 are never implied): `allowlist` needs a match, `denylist` refuses any match (deny wins),
`all` checks only the port. Then it dials through the dial guard; tunnels end after 60 s idle or 1 h, and their bytes count against
`bytes_per_day`. Plain HTTP goes upstream in origin form with `Host` from the checked authority (a mismatching `Host` is refused) and without
hop-by-hop or `Proxy-*` headers; redirects are passed back, not followed. The workplace sets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` to
`http://127.0.0.1:3128` and an empty `NO_PROXY`; these are hints, the missing route is the enforcement.

**Residual risk, stated plainly: there is no TLS interception.** The service sees host, port, bytes and timing, never the content of a tunnel.
Exfiltration to or through allowed hosts (a push to an attacker's repository on an allowed `github.com`) and domain fronting are not contained,
and `denylist` and `all` leave only the dial guard and the rate limits. So `allowlist` is HIGH (it needs a `note`) and `denylist` and `all`
are CRITICAL (they need `--accept-risk CRITICAL`).

```sh
# hosts: ["proxy\\.golang\\.org"], ports: [443], a rate, and a note (HIGH)
bin/remote-workplace policy set --project myproj --worker w2 w2.json                       # myproj.w2 id=... risk=HIGH egress=confirmed
bin/remote-workplace run --project myproj --worker w2 -- curl -sS https://proxy.golang.org/   # through 127.0.0.1:3128 -> socat -> the service
bin/remote-workplace run --project myproj --worker w2 -- curl -sS https://example.com/        # CONNECT tunnel failed, response 403 (denied: host)
```
Spec: [`docs/protocol.md`](docs/protocol.md) sections 5 (known limits) and 7, and [`docs/design/v2/threat-model-by-mode.md`](docs/design/v2/threat-model-by-mode.md).

## Engineering baseline
Go for tooling; tests with the go-testing-tools skill, including a red-team suite; signed commits; code and docs through PRs; local task-board (gitignored).

## Tools
| tool | used for | how to run | outputs |
| --- | --- | --- | --- |
| `go` (1.25, stdlib only) | the `workplace` and `egress` packages, the `remote-workplace` CLI and the `rwp-egress` service | `make build`, `make test`, `make vet`, `make cover` | `bin/remote-workplace`, `bin/rwp-egress` (gitignored) |
| `remote-workplace` CLI | every workplace operation: `doctor`, `provision [--from-worktree DIR]`, `run`, `export`, `apply [--policy P.W] [--allow-dirty [--snapshot-tree OID]]`, `deprovision`, `seed-cache`, `seed-gomod [--from-worktree DIR]`, `usage`, `ls`, `kill`, `purge`, `policy check\|set\|show\|template\|rm`, and (v2.1) `egress up\|down\|status\|log` | `bin/remote-workplace [--image IMG] [--state-dir DIR] [--slots N] [--project-slots M] COMMAND ...` (env `RWP_IMAGE`, `RWP_STATE_DIR`, `RWP_SLOTS`, `RWP_PROJECT_SLOTS`) | host state in `~/.local/state/remote-workplace/` (slot and workspace locks, export digests, stored policies, snapshot trees, seed records, empty docker config) |
| `docker` CLI | talks only to the colima `workers` VM (`unix://$HOME/.colima/workers/docker.sock`); the workplace pins the endpoint and an empty `DOCKER_CONFIG` itself | through the CLI or package, never directly (protocol section 6) | volumes `rwp.<project>.<worker>`, `rwp-cache.<project>.<name>`; containers `rwp-call-*` (removed after each call); v2.1: the container `rwp-egress`, its network `rwp-egress-net` and volumes `rwp-egress-sock`, `rwp-egress-policy`, `rwp-egress-cache` |
| `colima` | `doctor` reads the VM's `/proc/mounts` via `colima ssh -p workers` | `bin/remote-workplace doctor` | none |
| `git` (host) | provision bundles, worktree snapshots (temporary repository, empty config), `apply` (hooks disabled), `seed-gomod` archives | via the CLI | none |
| `rwp-egress` | the egress service (v2.1, every network mode but `none`): `serve --sockroot D --policydir D --cachedir D`, `status P.W` (prints the loaded policy id or `none`, exit 0 or 3) | inside the container `rwp-egress`, started by `remote-workplace egress up`; `docker exec rwp-egress rwp-egress status P.W` | JSON log lines on its stdout (`remote-workplace egress log`) |
| images | `remote-workplace/base:2` (`images/base`, base image v2: adds `socat` and the labels `ai.relux.remote-workplace.base-image=2`, `ai.relux.remote-workplace.egress-relay=socat`), `remote-workplace/go:2` (`images/go`), `remote-workplace/egress:1` (`images/egress`, built from the repository root) | `make image` (builds into the workers VM) | images in the workers VM |
| integration tests | the real VM path: provision, run, export, apply, deprovision, timeout, flood, no survivors, offline Go build, and (v2.1) `go mod download` and an allowlisted `curl https://proxy.golang.org/` through the egress service (need `egress up` and internet) | `make image && make it` (sets `RWP_IT=1`) | test projects `rwpit-*`, purged at the end |

Exit codes of `remote-workplace`: `run` exits with the call's status (124 on timeout); usage errors 2; workplace errors 3 (including no stored policy, a changed policy, an image without the egress relay `ErrImageNoRelay`, and the worktree refusals `ErrSnapshot`, `ErrSecret`, `ErrSeed`, `ErrDirtyTarget`);
`apply` refused for review 4; `apply --write-scope P1,P2,...` or `apply --policy P.W` refused for a path outside the write scope 5; egress unavailable 5 (a policy with egress whose id the egress service does not serve); `egress status` 5 unless the service runs and serves every networked policy's stored id.
`policy` commands: 0 ok, 1 invalid policy, 2 usage, 3 not found, 4 risk above `--max-risk` or not accepted, 5 egress unavailable or not confirmed.

## Cold state migration

`workplace.MigrateLegacy` and the separate `migrate-legacy` command copy the complete
owned cold inventory into the canonical namespace. The reader expires at
**2026-11-07T00:00:00Z**. There are no previous CLI/API/environment aliases or
ordinary fallback readers. Use explicit absolute, disjoint source/destination
paths; the destination root and every destination volume must be absent.

```sh
bin/remote-workplace --state-dir /absolute/new-state --image remote-workplace/base:2 migrate-legacy --source-state-dir /absolute/original-state --dry-run
bin/remote-workplace --state-dir /absolute/new-state --image remote-workplace/base:2 migrate-legacy --source-state-dir /absolute/original-state
```

Before either operation, hold consumer dispatch, drain callers, stop both egress
services and capture recovery exports against original bases. The importer uses
only the fixed workers-VM transport. Its bounded operator helpers mount source
read-only, grant only the file capabilities needed to preserve owners/modes and
write only operation-owned destinations. They accept no user commands or host
mounts. Stored policy bytes, Git objects/config/index, HOME, ignored/untracked
files, cache ownership, historical identities and export/seed records are kept;
only the workspace administration directory and technical ownership keys/names
are translated. Cold egress policy/cache data is copied; sockets are regenerated.
Volume manifests enumerate NUL-separated literal paths in canonical destination
order before archive generation, with recursion disabled for the explicit full
entry list. Administration translation applies only to the exact root component;
auxiliary names, symlink targets and hard-link identity remain part of verification.
The stopped service cannot preserve in-memory budgets: observe the existing UTC
budget reset before restarting a service that spent an active budget.

The JSON report exposes technical mappings, label metadata, policy/base/snapshot
IDs and verification counts/digests; it never prints file names or policy bodies.
Host state is staged privately and published by one atomic rename. A sibling
`DEST.migration-incomplete` reservation and per-volume migration identity deny
normal operations until publication. The published private `migration.json`
receipt must list each copied object with its preserved labels. Immutable volume
labels pin the normalized canonical state root and migration identity; selecting
another root or copying a receipt grants no authority. Docker and host filesystem
administrators remain trusted operators. Publication writes the receipt before
restoring the source root's mode/owner/timestamps, including private mode 0500.
The root name `migration.json` is reserved for publication evidence: any existing
source entry at that name (file, directory or link, including a dangling link)
returns `ErrMigrationCollision` during admission, including dry-run, before
Docker access, staging or canonical reservation. Nothing is renamed or overwritten.
Differently named root auxiliary data and nested `migration.json` files are copied
with their original bytes and metadata.

An interrupted import keeps originals, its reservation and any owned incomplete
volumes. Retry refuses collisions. Keep dispatch held; inspect the report/receipt
and exact operation identity, confirm no canonical writers, then retire only the
recorded failed destinations and reservation through a scoped operator procedure.
There is no overwrite/force/automatic cleanup command. A reported helper cleanup
failure requires confirming that exact named helper has stopped before recovery.
Task-owned host staging is removed on failure, including read-only directories;
if cleanup fails, `RetainedStageDir` identifies the retained recovery copy.
Before canonical writers resume, rollback selects the preserved original runtime
and data and verifies policy/export/base bindings under the same dispatch hold.
After canonical writes, capture and reconcile those changes before rollback;
never select stale originals over new work. Source deletion is a later scoped
retirement action.

| Tool/lane | Exact command | Outputs and limits |
| --- | --- | --- |
| Cold importer | commands above; `workplace.MigrateLegacy(ctx, LegacyMigrationSpec)` | JSON stdout; private sibling staging/reservation, canonical state receipt and canonical VM volumes; original state/volumes retained |
| Local migration/rename controls | `GOMAXPROCS=2 go test -p 1 ./workplace -run '^Test(MigrateLegacy\|RemoteWorkplaceNamingContract\|CurrentProductTerminology)' -count=1` | Go test results; isolated temporary fixtures; actual workspace-check shell with host mount paths substituted; GNU volume copy/tar not established here |
| Synthetic VM migration | `RWP_IT=1 GOMAXPROCS=2 go test -p 1 ./workplace -run '^TestIntegrationLegacyMigration' -count=1 -v -timeout 10m` | Disposable `rwp-migration-it-*` volumes; fixture-only discovery adapter, real fixed-daemon helper scripts; never inventories existing user volumes |
| Generated migration path controls | `GOMAXPROCS=2 go test -p 1 ./workplace -run '^TestMigrateLegacyAuxiliaryPathFamilies$' -count=1 -v` | Six generated root-name/type families; complete production enumeration with a host archive recorder; GNU bytes remain the synthetic VM lane |
| Red-team lane | `make image-redteam && make redteam` | Test-only canonical adversarial image and `.temp/redteam/` evidence; requires the parent VM slot |

Synthetic VM discovery is deliberately scoped to disposable fixtures; it does
not prove unscoped live inventory/cutover or consumer integration. Unit fixtures
cover source retention and public admission, but live rollout remains gated on
independent review, exact-head VM integration/red-team checks and consumer ACK.
