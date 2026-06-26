# Wallet SQL AGENTS.md

This is the knowledge base for the `wallet/internal/sql/` subsystem. It manages
  SQL schema definitions, queries, migrations, and generates sqlc code for
  PostgreSQL and SQLite backends.

## RESPONSIBILITIES
- **Schema & Migrations:** Defines database tables, indexes, and schema
  migrations for both backends.
- **Query Definitions:** Houses raw SQL queries used by the database layer.
- **Code Generation:** Manages sqlc configuration and generated Go code.
- **Backend Specifics:** Maintains separate SQL assets for PostgreSQL and SQLite
  to handle dialect differences.

## WHERE TO LOOK
| Component                 | Path                 | Description                                 |
|:--------------------------|:---------------------|:--------------------------------------------|
| **PostgreSQL Queries**    | `pg/queries/`        | Raw SQL query files for PostgreSQL.         |
| **PostgreSQL Migrations** | `pg/migrations/`     | Schema migration files for PostgreSQL.      |
| **PostgreSQL Generated**  | `pg/sqlc/`           | Generated Go code from sqlc for PostgreSQL. |
| **SQLite Queries**        | `sqlite/queries/`    | Raw SQL query files for SQLite.             |
| **SQLite Migrations**     | `sqlite/migrations/` | Schema migration files for SQLite.          |
| **SQLite Generated**      | `sqlite/sqlc/`       | Generated Go code from sqlc for SQLite.     |

## GENERATED CODE BOUNDARIES
- Don't edit any files under `sqlc/` directories directly, including `*.sql.go`,
  `models.go`, `db.go`, and `querier.go`.
- Modify the source `.sql` files under `queries/` or `migrations/` instead.
- Run `make sql` to regenerate the Go code after making changes. This command is
  mutating, runs lint auto-fixes, and rewrites files. Always run it on a clean
  git tree.

## LOCAL CONVENTIONS
- Format and lint SQL with SQLFluff. Keywords and types must be uppercase,
  while identifiers and function names must be lowercase.
- Prefer `!=` over `<>`. SQL indentation uses 4 spaces.
- Keep PostgreSQL and SQLite differences explicit. Don't try to force a single
  query file.
- Match database layer expectations. Ensure query names and parameter types
  align with the Go database adapters.
- Write migrations that are clean and reversible. Always provide both `.up.sql`
  and `.down.sql` files.

## TESTING FOCUS
- Verify SQL changes by running `make sql` and checking for clean git status.
- Run database integration tests in `wallet/internal/db/itest/` to verify schema
  and query changes.
- Use `make itest-db db=[sqlite|postgres]` to run tests against specific
  backends.
