# Wallet SQL AGENTS.md

This is the knowledge base for the `wallet/internal/sql/` subsystem. The
  subsystem contains the SQL schema, queries, and migrations. It also
  generates the sqlc code for the PostgreSQL and SQLite backends.

## RESPONSIBILITIES
- **Schema & Migrations:** Defines the database tables, indexes, and schema
  migrations for the two backends.
- **Query Definitions:** Contains the raw SQL queries that the database layer
  uses.
- **Code Generation:** Contains the sqlc configuration and the generated Go
  code.
- **Backend Specifics:** Keeps separate SQL assets for PostgreSQL and SQLite,
  because their dialects are different.

## WHERE TO LOOK
| Component                 | Path                 | Description                                 |
|:--------------------------|:---------------------|:--------------------------------------------|
| **PostgreSQL Queries**    | `pg/queries/`        | Raw SQL query files for PostgreSQL.         |
| **PostgreSQL Migrations** | `pg/migrations/`     | Schema migration files for PostgreSQL.      |
| **PostgreSQL Bootstrap**  | `pg/bootstrap/`      | Pre-migration identity DDL for PostgreSQL.  |
| **PostgreSQL Generated**  | `pg/sqlc/`           | Generated Go code from sqlc for PostgreSQL. |
| **SQLite Queries**        | `sqlite/queries/`    | Raw SQL query files for SQLite.             |
| **SQLite Migrations**     | `sqlite/migrations/` | Schema migration files for SQLite.          |
| **SQLite Bootstrap**      | `sqlite/bootstrap/`  | Pre-migration identity DDL for SQLite.      |
| **SQLite Generated**      | `sqlite/sqlc/`       | Generated Go code from sqlc for SQLite.     |

## GENERATED CODE BOUNDARIES
- Do not directly edit files in `sqlc/` directories. This includes `*.sql.go`,
  `models.go`, `db.go`, and `querier.go`.
- Change the source `.sql` files in `queries/`, `migrations/`, or
  `bootstrap/`.
- After you change them, run `make sql` to generate the Go code again. This
  command changes files: it applies lint fixes and writes files again. Run it
  only on a clean git tree.

## LOCAL CONVENTIONS
- Use SQLFluff to format and lint SQL. Keywords and types must be uppercase.
  Identifiers and function names must be lowercase.
- Prefer `!=` to `<>`. Use 4 spaces for SQL indentation.
- Keep the differences between PostgreSQL and SQLite explicit. Do not force
  the two backends into one query file.
- Match the expectations of the database layer. Query names and parameter
  types must agree with the Go database adapters.
- Write clean, reversible migrations. Always supply an `.up.sql` file and a
  `.down.sql` file.

## TESTING FOCUS
- To verify SQL changes, run `make sql` and make sure that the git status is
  clean.
- To verify schema and query changes, run the database integration tests in
  `wallet/internal/db/itest/`.
- To run the tests against one backend, use
  `make itest-db db=[sqlite|postgres]`.
