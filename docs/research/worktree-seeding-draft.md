# Seeding from a dirty or unlanded worktree, and applying into a dirty target: design draft

Status: a draft for the v2 elaboration (decision record 2026-09-29, D3); not normative.
Why it exists: `rwh run --backend workplace` needs a landed ref and a clean checkout. That is the only reason `rwh run` v1 uses Seatbelt (docs/decisions/2026-09-29-v2-direction.md).
A paused implementation exists on the local branch `feat/v2-worktree`.

## Provision from a worktree snapshot (`provision --from-worktree`)
- **An unlanded ref already works.** A bundle carries any named ref (a local branch, or HEAD in a worktree).
- **Snapshot of the working tree as it is now:** HEAD, plus staged, unstaged and untracked non-ignored files. Built without touching the source:
  1. `git init --bare T/seed.git`. Its `objects/info/alternates` points at the source's common object dir. Copy the source's `info/exclude`.
  2. With `GIT_DIR=T/seed.git`, `GIT_WORK_TREE=<source top>` and `GIT_INDEX_FILE=T/index`, run `read-tree HEAD`, then `add -A`, then `write-tree`.
  3. `commit-tree --no-gpg-sign -p HEAD` with a fixed author: the owner has `commit.gpgsign=true`, and commit-tree honours it.
  4. `update-ref refs/heads/snapshot`, then `bundle create - refs/heads/snapshot`.
  5. Verified on a scratch repo: the source's index bytes, refs and object count are unchanged, and the bundle clones.
- **Secret guard.** Refuse when an untracked file's basename (case-insensitive) matches:
  `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `.netrc`, `.npmrc`, `.pypirc`, `credentials*.json`.
  The error lists the paths. rwh's Seatbelt snapshot adopted the same list.
- **Base and export.** The workspace's base is the snapshot commit, so an export holds only the worker's delta.
  `Provision` returns `SnapshotTree` (the snapshot's tree oid) and stores it in a label. rwh reports it as `workspace.snapshot_tree` so the importer can check the target still matches.
- **Caches.** `SeedGoModWorktree` builds the Go module seed from the same snapshot. The rule becomes "orchestrator-owned content only", never an unreviewed worker branch.

## Apply into a dirty target (`apply --allow-dirty`)
- **Dry run.** Build a temp index of the target's current state (same technique; the secret guard applies because untracked files get hashed), then run `apply --cached` and a raw diff.
  The same gates run: `.git` (hard), write scope (hard), then symlink, gitlink and review-required unless allowed.
- **Real apply.** Plain `git apply` into the working tree only. The target's index is never written, and hooks are off.
  `git apply` is atomic: a conflict with edits made after the snapshot refuses the whole patch.
- **Validation** of the result, in a workplace: `provision --from-worktree` of that worktree, then run the tests.

## rwh integration
`rwh run --backend workplace` switches from "clean landed ref" to `FromWorktree` (remote-worker-harness-2b: "within a day of the landing"). The flag stays the same.
The patch comes back against the snapshot. The orchestrator imports it with `apply --allow-dirty --write-scope ...` into the same Story worktree.

## Tests to write (from the paused brief)
- **Snapshot:** content (modified, staged and untracked files in; ignored and excluded files out); the source byte-identical afterwards; signing avoided (bogus signer in the repo config); the secret guard with its ignored-file control.
- **Apply:** an unrelated dirty file intact; a conflicting hunk refused whole; an untracked collision refused; the gates still active; without the flag, still `ErrDirty`.
- **Integration:** snapshot a dirty repo, let the worker edit, export (only the delta), then apply dirty (earlier dirty changes intact, index unchanged).
- **Red team:** G8-snapshot-isolation, G8-dirty-conflict, G7-snapshot-secret.
