# Seeding from a dirty worktree and applying into a dirty target (remote-workplace v2 design)

Status: design, not normative. Elaborates `docs/research/worktree-seeding-draft.md` under D3 of `docs/decisions/2026-09-29-v2-direction.md` (the seeding gap that forced Seatbelt in `rwh run` v1). The paused code is on the local branch `feat/v2-worktree`; this document does not depend on reading it.
Tags: **Decided (source)** or **Proposed**. Baseline: `docs/protocol.md` §6 (provision, seed-gomod, apply) and §8.
Gap in v1: `provision` needs a landed ref, and `apply` needs a clean target at base.

## 1. Provision from a worktree (`provision P W --from-worktree DIR`)
- Mutually exclusive with `--ref`. Needs a stored policy like any Provision (policy.md §9). **Decided (D2)** for the policy; the flag is Proposed as the draft's name.
- An unlanded ref already works with `--ref`: a bundle carries any named ref. **Fact** (v1.1: `provision --ref` bundles any named ref, `docs/protocol.md` §6).
- Refused (`ErrSnapshot` with the cause): unborn HEAD; a merge, rebase, cherry-pick or bisect in progress; unmerged paths; a nested git repository among the untracked paths; an untracked file over 10 MiB or a total over 256 MiB (flag `--max-untracked-mib` raises it). Proposed.

### Snapshot technique (Proposed; the draft's steps with fixes)
The source is never written: no index refresh, no object, no ref.
1. `T` = a fresh 0700 temp dir outside the source and outside any workspace. `git init --bare T/seed.git`; `objects/info/alternates` names the source's common object dir (`git rev-parse --git-common-dir`, so linked worktrees work); copy `info/exclude`.
2. Environment for every git call below: `GIT_DIR=T/seed.git`, `GIT_WORK_TREE=<source top>`, `GIT_INDEX_FILE=T/index`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, and `-c core.hooksPath=/dev/null -c core.fsmonitor=false`.
   **Fix**: the fresh bare repository has an empty config, so the source's `filter.*.clean`, textconv, fsmonitor or hook settings never run (a clean filter runs during `git add`). Snapshot bytes are raw.
3. `read-tree HEAD`; `add -u` (modified and deleted tracked files); then the untracked list from the source with `git -C <source> ls-files -z --others --exclude-standard` (honours nested `.gitignore` and the owner's global excludes, which the draft's copy of `info/exclude` missed), fed to `add --pathspec-from-file=- --pathspec-file-nul`. `write-tree` gives the **snapshot tree**.
4. Secret guard (§2) on the delta, before any commit is made.
5. `commit-tree -p HEAD` with `--no-gpg-sign`, `-c commit.gpgsign=false`, and fixed `GIT_AUTHOR_*`/`GIT_COMMITTER_*` (name, email, date `2000-01-01T00:00:00Z`): the owner has `commit.gpgsign=true`. The commit id is then a function of the content.
6. `update-ref refs/heads/snapshot`; `git bundle create - refs/heads/snapshot`; feed the existing provision path (clone inside a call). Remove `T` on every exit path.
- Gitlinks (submodules) are carried as pointers only; the submodule content is not in the workspace. Symlinks are stored as link text (git never follows them at add time). Proposed.
- Verified in the draft on a scratch repo: source index bytes, refs and object count unchanged, and the bundle clones. The new steps 2 and 3 need the tests of §6.

### Base, result and idempotence
- The workspace's base is the snapshot commit, so `export` holds only the worker's delta. **Proposed** (it follows from `export` diffing against the base label, `docs/protocol.md` §6).
- `Provision` returns `Base`, `SnapshotTree`, `SnapshotParent` (HEAD at snapshot time) and `Existed`, and stores them as labels `ai.relux.remote-workplace.snapshot-tree` and `...snapshot-parent`. `ls` shows them.
- Idempotent like v1: an existing workspace is returned unchanged with `Existed=true`, whatever the worktree looks like now. A caller that wants a fresh snapshot deprovisions first; it compares `SnapshotTree` to detect the difference.

## 2. Secret guard (Proposed; extends the draft)
Applies to every path in the delta between the snapshot tree and HEAD (added or modified; the draft checked only untracked files, so a modified tracked `.npmrc` slipped through).
- **Name rule** (case-insensitive basename), from the draft, also adopted by rwh's Seatbelt snapshot: `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `.netrc`, `.npmrc`, `.pypirc`, `credentials*.json`. Ignored files are out of the snapshot and so out of the check (control in the tests).
- **Content rule** (new): in files of the delta up to 1 MiB, refuse a line matching `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{50,}`, `xox[bp]-[A-Za-z0-9-]{20,}`. Heuristic; it stops accidents, not a determined owner.
- Error: `ErrSecret` listing paths (never the matching text). Override: `--allow-secret-path PATH` (exact repository path, repeatable). Refused when the worker's policy risk is HIGH or CRITICAL (policy.md §6): a worker that can send data out must not be seeded with a file the owner flagged. Not overridable for the content rule at HIGH or above.
- Why here: everything the worker can read may reach its provider (`docs/protocol.md` §1); the guard is the only thing between an untracked scratch file and that channel.

## 3. SeedGoModWorktree (Proposed)
`seed-gomod P --from-worktree DIR` builds the Go module tar from the same snapshot instead of a landed ref. The v1 rule (`docs/protocol.md` §6) was: landed ref only, because seeding runs with the owner's credentials.
- Content rule: **orchestrator-owned content only**. The Story worktree holds what the orchestrator wrote or applied after review; never a worker branch or an unreviewed patch (draft, kept).
- Build from a checkout of the snapshot tree in `T` (the source is never touched), with: `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOENV=off`, `GOPRIVATE=` and `GONOPROXY=` empty, `GOPROXY=https://proxy.golang.org`, `GONOSUMDB` unset, `HOME` and `GOCACHE` set to empty dirs under `T`, no `.netrc`, `CGO_ENABLED=0`.
  **Fix**: the draft only changed the source of `go.mod`. A dirty `go.mod` is unreviewed, so the seed takes no credentials: private modules fail, and need the landed-ref path.
- Refused (`ErrSeed`): `replace` to a filesystem path, `go.work`, a `toolchain` line, `vendor/` that disagrees with `go.mod`. A filesystem `replace` would copy a host path into the cache.
- Output tar and cache name as in v1 (`gomod`); seeding stays additive. The seed is tagged with the snapshot tree in its metadata, so `ls` shows which snapshot fed which cache.

## 4. `apply --allow-dirty` (Proposed)
Purpose: import a patch (computed against the snapshot) into the Story worktree that has moved since. Without the flag: `ErrDirty`, unchanged from v1.
- **Target rules**: a linked worktree, or a non-live checkout by the v1 test; the primary checkout needs `--allow-main-worktree`. No unmerged paths; no merge or rebase in progress. The v1 base requirement does not apply: the patch is by content.
- **Gates, all unchanged and still first, evaluated on the patch text**: `.git` (hard), write scope (hard, from `--policy` and/or `--write-scope`), then symlinks, gitlinks and review-required unless `--allow-review-required`. Case-insensitive path matching. **Decided (protocol §8, D4)**.
- **Dry run**: `git -c core.hooksPath=/dev/null apply --check` against the working tree, no index, no temp objects.
  **Fix**: the draft built a temp index of the target and hashed its untracked files, which would pull unrelated secrets into an object store for no benefit and needed the guard. `apply --check` on the working tree already refuses a conflicting hunk and a new file that collides with an untracked one. The secret guard is not part of apply.
- **Real apply**: `git -c core.hooksPath=/dev/null apply` (no `--index`, `--whitespace=nowarn`). The index, HEAD and refs are never written. The check and the apply are one atomic `git apply` per patch; a conflict refuses the whole patch and leaves the tree untouched. Never commits, never pushes. **Decided (protocol G8)**.
- **Snapshot check** (optional): `--snapshot-tree OID` computes the target's current snapshot tree (temp object dir, discarded) and prints `target diverged since snapshot: N paths` when different. It informs the reviewer; it never blocks.
- **Validation** of the result, in a workplace: `provision --from-worktree` of the same worktree and run the tests (protocol §8 step 5). Worker code never runs on the host.

## 5. rwh run integration
- **Agreed** (in scope by D3; accepted by remote-worker-harness-2b in #remote-workplace harness-integration): `rwh run --backend workplace` moves from "a clean landed ref" to `FromWorktree`; the flag is unchanged. That removes the reason for Seatbelt in `rwh run` v1.
- Flow (Proposed): `policy set` (or a policy file passed to rwh) → `provision --from-worktree` (secret guard) → `seed-gomod --from-worktree` when the project has a `gomod` cache → runs → `export` after every turn → the report carries `workspace.snapshot_tree` and the policy id/risk → orchestrator reviews → `apply --allow-dirty --policy P.W [--snapshot-tree OID]` into the same worktree.
- rwh has no policy of its own to invent: no policy means no run (D2). rwh-side changes are out of scope here; the workplace API above is the contract.

## 6. Tests and red-team probes (Proposed; from the draft's brief plus new ones)
| area | test |
| --- | --- |
| Snapshot content | modified, staged and untracked files in; ignored, excluded and global-excluded files out; deletions recorded |
| Snapshot isolation | source index bytes, refs, object count, mtimes identical afterwards; linked worktree works |
| No source-config execution | a `filter.x.clean` or `core.fsmonitor` or `pre-*` hook in the source config that writes a canary: not run. Control: plain `git add` in the source runs the filter |
| Signing | bogus `gpg.program` and `commit.gpgsign=true` in the source: still commits; same content gives the same commit id |
| Secret guard | each name pattern; a modified tracked `.npmrc`; each content pattern; the ignored-file control; `--allow-secret-path` refused at HIGH |
| Refusals | unborn HEAD, mid-rebase, nested repo, oversized untracked file |
| SeedGoModWorktree | filesystem `replace`, `go.work`, `toolchain` refused; private module fails without credentials (control: the landed-ref path with credentials); the source unchanged |
| Apply dirty | an unrelated dirty file intact; a conflicting hunk refused whole (tree byte-identical); an untracked collision refused; index and HEAD unchanged; hooks planted in the target never fire; each gate still active (`.git`, scope, symlink, review-required); without the flag `ErrDirty` |
| Integration | snapshot a dirty repo, worker edits, export holds only the delta, apply dirty, earlier dirty changes intact |
| Red team | G8-snapshot-isolation, G8-dirty-conflict, G7-snapshot-secret (draft); new: G7-snapshot-tracked-secret, G8-snapshot-filter, G8-seed-replace, G8-dirty-hooks. Each has a positive control that removes exactly one layer, as protocol §12 requires |
