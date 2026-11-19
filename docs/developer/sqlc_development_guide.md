# SQLC Development Guide

`btcwallet` uses sqlc to generate Go bindings for PostgreSQL and SQLite. The
Makefile runs SQLFluff and sqlc separately for each dialect; edit both sets of
SQL sources when a change affects both backends.

## Setup and layout

Run commands from the repository root with Docker running. `make sqlc` builds
the `btcwallet-tools` image from [tools/Dockerfile](../../tools/Dockerfile),
using the sqlc version pinned in [tools/go.mod](../../tools/go.mod). SQLFluff
runs in a separate image pinned by digest in the [Makefile](../../Makefile).
Use the Go version required by [go.mod](../../go.mod) for database tests.

- [sqlc.yaml](../../sqlc.yaml) maps each dialect's schema and queries to its
  generated Go package.
- [.sqlfluff](../../.sqlfluff) configures SQL parsing, formatting, and linting.
- [wallet/internal/sql/pg](../../wallet/internal/sql/pg) and
  [wallet/internal/sql/sqlite](../../wallet/internal/sql/sqlite) each contain
  `migrations/`, `bootstrap/`, `queries/`, and generated `sqlc/` files.
- SQLite also has `assets/` for embedded startup SQL. These files are checked
  by SQLFluff but are not inputs to sqlc.
- [wallet/internal/db](../../wallet/internal/db) contains the database
  adapters; its `itest/` directory tests both SQL backends.

The schema inputs to sqlc include numbered migrations and bootstrap DDL.
Bootstrap DDL establishes database identity before migrations run; see
[ADR 0014](./adr/0014-sql-database-identity.md) before changing that boundary.
Generated files under `wallet/internal/sql/{pg,sqlite}/sqlc/` must not be
edited by hand.

## Change queries or schema

1. Edit the relevant `queries/*.sql` in both dialect directories. Follow
   nearby queries for sqlc annotations, parameter binding, and result types.
   For example, `-- name: GetBlockByHeight :one` generates a method returning
   one row; `:many` returns multiple rows and `:exec` returns only an error.
   Use the existing
   [PostgreSQL](../../wallet/internal/sql/pg/queries/blocks.sql) and
   [SQLite](../../wallet/internal/sql/sqlite/queries/blocks.sql) queries as
   working examples.
2. For schema changes, add the next `NNNNNN_description.up.sql` and
   `NNNNNN_description.down.sql` pair under each dialect's `migrations/`.
   Match existing numbering and conventions, and keep backend differences
   explicit.
3. Run the local SQL workflow:

   ```bash
   make sql
   ```

   This attempts lint fixes, verifies linting, formats SQL, parses it, and
   regenerates Go bindings. It rewrites files: start with unrelated changes
   committed or isolated, and inspect the resulting diff. If linting fails,
   fix the reported violations before retrying.
4. Update the Go database adapters and integration tests for the changed
   queries. Commit the SQL sources and generated bindings together.

## Test and check the result

Run the database integration tests for both backends:

```bash
make itest-db db=sqlite
make itest-db db=postgres
```

SQLite tests use temporary database files. PostgreSQL tests use a shared
Docker container with a separate database per test. The Makefile selects the
required build tags. Use `make itest-db-race db=sqlite` or
`make itest-db-race db=postgres` to run with the race detector.

After committing the expected SQL and generated changes, run the same SQL
checks used by [CI](../../.github/workflows/main.yml):

```bash
make sqlc-check
make sql-format-check
make sql-lint-check
git diff
git status --short
```

`sqlc-check` regenerates bindings and checks for uncommitted Go changes;
`sql-format-check` formats SQL and checks for uncommitted SQL changes. They
can modify the tree even when they fail. Commit intended changes before
running them so the checks distinguish stale output from expected edits.

## Individual SQL commands

Use these targets to isolate a failing step:

| Command | Purpose |
| --- | --- |
| `make sql-parse` | Parse migrations, bootstrap DDL, queries, and SQLite assets. |
| `make sqlc` | Parse SQL, build the tools image, and generate Go bindings. |
| `make sql-format` | Format SQL sources in place. |
| `make sql-lint` | Apply available SQL lint fixes. |
| `make sql-lint-check` | Report SQL lint violations without fixing them. |

For sqlc errors, check the paths in `sqlc.yaml`, the migration schema, and
the query annotation or parameter types. For Docker connection errors, check
`docker info` before rerunning the command. Use the pinned tools rather
than installing the latest sqlc or SQLFluff release locally.
