# SQL Port Stage 0 Inventory

Snapshot date: 2026-07-10

In this snapshot, we pin the source branches that define the SQL project and
classify the full PR ecosystem before moving code onto the port-first branch.
The inventory covers the 39 PRs that targeted `interface-wallet`, the 103 PRs
that targeted `sql-wallet`, nine intermediate feeders, and the master-based
umbrella PR #1083. That gives us 152 PRs in total, with no PR omitted between
the counts in the salvage plan and the generated inventory.

The snapshot found 126 merged PRs, 17 closed PRs, and nine open PRs. Two of
the open PRs are the umbrella PRs #1083 and #1110. The seven remaining open
feeders are #1154, #1244, #1258, and #1270 through #1272, plus #1279. Their
head SHAs are pinned separately from the three source branches. The manifest
keeps the base repository used for `refs/pull/<number>/head` separate from the
contributor's head repository.

## Files

[`pr_inventory.csv`](./pr_inventory.csv) records each PR's cohort, state, base,
head, current head SHA, head repository, author, title, URL, disposition
category, and port-first action. [`source_refs.csv`](./source_refs.csv) records
the immutable commit IDs for `master`, `interface-wallet`, `sql-wallet`, and
all seven open feeder heads. [`api_baseline.md`](./api_baseline.md) records the
59-method `wallet.Interface`, direct calls made through that interface across
lnd, and exported wallet package identifiers referenced by the pinned lnd
checkout. [`commit_map.csv`](./commit_map.csv) records every commit in the
umbrella range, its original author and co-author metadata, PR evidence,
changed paths, category, planned disposition, and destination cut.

The frozen snapshot can be verified without refreshing GitHub attribution:

```bash
./scripts/sql-port-api-baseline.sh \
    /path/to/lnd
go run ./scripts/sql-port-commit-map.go
```

The API generator defaults to the frozen btcwallet and lnd revisions and
creates clean detached worktrees for both inputs. Optional second and third
arguments select explicit btcwallet and lnd revisions. To refresh live GitHub
metadata, run the PR generator and select the commit-map live mode explicitly:

```bash
./scripts/sql-port-pr-inventory.sh
go run ./scripts/sql-port-commit-map.go -mode=live
```

The PR generator fails unless it finds exactly 39 interface targets, 103 SQL
targets, nine intermediate feeders, and one master umbrella. It also fails if
a PR number is duplicated, absent from GitHub's response, or missing an
explicit disposition category.

## Disposition categories

The category is the PR's primary intent, not a claim that every commit in the
PR shares that intent. Mixed PRs will be split at commit or patch level during
the attribution map.

| Category | PRs | Port-first action |
| --- | ---: | --- |
| `sql-foundation` | 20 | Salvage now. |
| `reusable-semantic-fix` | 30 | Salvage after checking behavior against the current KV wallet. |
| `wallet-routing` | 19 | Rework behind the current public API and control flow. |
| `public-refactor` | 11 | Defer until after the SQL port. |
| `runtime-rewrite` | 16 | Defer until after the SQL port. |
| `key-vault-signing-rewrite` | 11 | Defer until after the SQL port. |
| `test-tooling` | 40 | Salvage the pieces that test or build the port-first stack. |
| `superseded-work` | 5 | Keep as source history, but don't transplant as a unit. |

## Commit map

The commit map contains exactly 969 unique rows for the pinned
`master..sql-wallet` SHAs in `source_refs.csv`, in oldest-first ancestry order,
plus one CSV header. Author name, author email, co-author trailers, author date,
and subject come directly from Git. Co-authors are deduplicated and sorted
without changing their names or addresses. Changed paths come from
`git diff-tree` for each commit. The generator fails if the range doesn't
contain exactly 969 unique commits.

Canonical feeder attribution follows this order:

1. Use an exact non-umbrella PR commit-list match. Among multiple matches,
   choose the earliest merged PR, then the earliest closed PR, then the lowest
   numbered open PR.
2. If exact commit lists don't retain the commit, use a non-umbrella GitHub
   associated PR only when it is merged or closed, with the same date and
   number ordering.
3. Otherwise write `unresolved`. We don't promote an umbrella or an open
   descendant stack to the introducing feeder merely because GitHub associates
   it with every ancestor in the branch.

The generator queried the current exact commit lists for all non-umbrella PRs.
PRs #1241, #1244, and #1254 currently report 664, 691, and 785 commits,
respectively. Those lists describe broad stack ancestry rather than a focused
feeder, so the generator excludes exact lists over 100 commits. GitHub's exact
lists resolved 107 commits to merged feeders. The remaining 862 commits have
no retained non-umbrella exact match and no merged or closed association, so
their canonical PR is explicitly `unresolved`. Repeated rebases and known
force-pushes explain why current PR metadata can lose historical commit IDs,
but the map doesn't guess which missing feeder introduced a commit.

The default `verify` mode compares immutable Git metadata, paths, categories,
and dispositions with the committed CSV. It preserves the recorded PR
associations as snapshot evidence. The explicit `live` mode queries current
GitHub associations and PR commit lists and rewrites the CSV. It can produce
different association fields after rebases, force-pushes, or GitHub metadata
changes, even though the frozen source range is unchanged.

`related_prs` is the sorted union of exact PR-list matches and GitHub associated
PRs, minus the canonical PR. It is context, not attribution. This is why an
unresolved row can still list #1083, #1110, or an open runtime descendant.

### Path categories

Categories are derived from changed paths, not from PR titles. SQL migrations,
queries, and generated sqlc code map to `sql-foundation`. PostgreSQL, SQLite,
common `wallet/internal/db`, and KV adapter implementations map to
`reusable-semantic-fix` for Stage 2 review. Existing-wallet production paths
map to `wallet-routing`; role-interface files map to `public-refactor`;
controller, syncer, state, rescan, recovery, and chain paths map to
`runtime-rewrite`.
Key-vault, secret, and encryption paths map to
`key-vault-signing-rewrite`. Test, documentation, build, and tooling paths map
to `test-tooling` when no production category is present. A commit touching
more than one production class gets a sorted `mixed:` category.

The path-category counts are:

| Category | Commits |
| --- | ---: |
| `reusable-semantic-fix` | 333 |
| `public-refactor` | 162 |
| `test-tooling` | 161 |
| `mixed:reusable-semantic-fix+sql-foundation` | 75 |
| `mixed:public-refactor+wallet-routing` | 53 |
| `runtime-rewrite` | 48 |
| `wallet-routing` | 29 |
| `sql-foundation` | 29 |
| `key-vault-signing-rewrite` | 12 |
| `mixed:runtime-rewrite+wallet-routing` | 11 |
| `mixed:public-refactor+runtime-rewrite+wallet-routing` | 8 |
| `mixed:public-refactor+reusable-semantic-fix` | 7 |
| `mixed:public-refactor+reusable-semantic-fix+sql-foundation` | 7 |
| `mixed:reusable-semantic-fix+wallet-routing` | 7 |
| `mixed:public-refactor+runtime-rewrite` | 6 |
| `mixed:key-vault-signing-rewrite+reusable-semantic-fix` | 6 |
| `mixed:key-vault-signing-rewrite+public-refactor+runtime-rewrite+wallet-routing` | 2 |
| `mixed:public-refactor+reusable-semantic-fix+wallet-routing` | 2 |
| `mixed:reusable-semantic-fix+runtime-rewrite` | 2 |
| `mixed:key-vault-signing-rewrite+wallet-routing` | 2 |
| `mixed:key-vault-signing-rewrite+public-refactor+runtime-rewrite` | 2 |
| `mixed:public-refactor+reusable-semantic-fix+sql-foundation+wallet-routing` | 1 |
| `mixed:public-refactor+reusable-semantic-fix+runtime-rewrite` | 1 |
| `mixed:reusable-semantic-fix+runtime-rewrite+wallet-routing` | 1 |
| `rebase-marker` | 1 |
| `mixed:key-vault-signing-rewrite+reusable-semantic-fix+sql-foundation` | 1 |

Commit `90eaaccf27a0b4f95fed7fe4f8039cc34693566f` has no changed paths. Its
subject identifies it as the empty SQL-wallet rebase completion marker, so it
is classified as `rebase-marker` and marked `superseded`, not left as an
unclassified code commit.

### Planned dispositions

SQL-foundation commits are `extract` candidates because the Stage 1 schema and
queries must be reconstructed around current KV semantics. No commit is marked
`pick` solely from its paths. Internal backend implementations and common
semantic changes remain `review` for Stage 2. Wallet-routing and mixed
port+rewrite commits are `extract` candidates. Public interfaces, runtime
rewrites, key-vault work, and deferred-only mixed commits are `defer`.

A SHA-keyed semantic override table handles commits whose paths don't reveal
their design choice. It supersedes the dummy sqlc bootstrap, extracts the
legacy dual-passphrase constraints, defers retained transaction-status and
replacement-history flows, and keeps runtime helpers and batch implementations
in Stage 2 review. It also defers plaintext public metadata, derived
address-use state, and normalized address-identity rewrites. Each overridden
row records the reason in `destination_stage_cut`. The empty rebase marker is
also `superseded`.

| Disposition | Commits |
| --- | ---: |
| `extract` | 228 |
| `defer` | 243 |
| `review` | 494 |
| `superseded` | 4 |

## Evidence boundary

GitHub reports the current head SHA for every PR. For merged PRs, the base,
head, author, title, and state are useful inventory metadata. For closed and
force-pushed PRs, the current head is not sufficient provenance. PR #1181 is
the known example: its head was replaced with unrelated work. Thus only the
three source branches and open feeder heads are treated as pinned source refs.
Closed-PR attribution must come from commits reachable from the umbrella tips
and canonical merge commits.

The PR-level categories and the 969-commit map now cover the same closed source
universe. Every commit has its SHA, author metadata, changed paths, category,
planned disposition, and destination cut recorded. Canonical feeder PRs remain
`unresolved` for 862 commits because the current GitHub associations and exact
PR commit lists no longer retain those historical SHA links after the stack's
rebases and force-pushes. We keep that gap explicit while preserving complete
commit-level attribution and disposition data, so missing PR history can't
silently turn into missing contributor history.

The lnd API audit uses Go type information and is pinned to btcwallet
`d7d47d08558e67f6c4d6b19381b64543547aec99` and lnd
`31168557c3a8602d7669c1eb86eddd07d9892bc6`. It resolves wallet import aliases
and distinguishes interface methods, concrete-type methods, and package-level
identifiers. The actual compatibility gate remains an unmodified lnd compile
and test run against each candidate btcwallet tip.
