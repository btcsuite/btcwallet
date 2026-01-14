# SQLC Development Guide

This document explains the SQLC code generation infrastructure used in
`btcwallet` for type-safe SQL database operations. The project supports both
**PostgreSQL** and **SQLite** backends using a unified development workflow.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Makefile Commands](#makefile-commands)
- [Development Workflow](#development-workflow)
- [Writing SQL Queries](#writing-sql-queries)
- [Writing Migrations](#writing-migrations)
- [Integration Tests](#integration-tests)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

`btcwallet` is transitioning from a key-value database (kvdb) to SQL-based
backends. The SQLC tool generates type-safe Go code from SQL queries and
migrations, providing compile-time verification of SQL operations.

**Key benefits:**

- Type-safe database operations with compile-time checks
- Support for both PostgreSQL and SQLite from the same codebase
- Automatic Go code generation from SQL definitions
- Consistent formatting and linting across SQL files

## Architecture

The dual-database support follows this pattern:

```
SQL Files (postgres/ and sqlite/)
        |
        v
   [sqlfluff] -----> Formatting & Linting
        |
        v
    [sqlc] --------> Go Code Generation
        |
        v
Generated Go Code (sqlcpg/ and sqlcsqlite/)
        |
        v
   Application Code
```

### Why Separate Directories?

PostgreSQL and SQLite have different SQL dialects:

| Feature | PostgreSQL | SQLite |
|---------|-----------|--------|
| Parameter placeholders | `$1, $2, $3` | `?, ?, ?` |
| Binary data type | `BYTEA` | `BLOB` |
| Integer type | `BIGINT` | `INTEGER` |
| Upsert syntax | `ON CONFLICT ... DO NOTHING` | `INSERT OR IGNORE` |

Rather than using complex transformations at runtime, we maintain separate SQL
files for each dialect that are optimized for their respective engines.

## Directory Structure

```
btcwallet/
├── config/
│   ├── sqlc.yaml           # SQLC configuration
│   └── sqlfluff.cfg        # SQL linting rules
├── tools/
│   ├── Dockerfile          # Docker image with sqlc tool
│   ├── go.mod              # Tool dependencies (includes sqlc)
│   └── go.sum
├── wallet/internal/db/
│   ├── migrations/
│   │   ├── postgres/       # PostgreSQL migration files
│   │   │   ├── 000001_blocks.up.sql
│   │   │   ├── 000001_blocks.down.sql
│   │   │   └── ...
│   │   └── sqlite/         # SQLite migration files
│   │       ├── 000001_blocks.up.sql
│   │       ├── 000001_blocks.down.sql
│   │       └── ...
│   ├── queries/
│   │   ├── postgres/       # PostgreSQL query files
│   │   │   ├── blocks.sql
│   │   │   ├── wallets.sql
│   │   │   └── ...
│   │   └── sqlite/         # SQLite query files
│   │       ├── blocks.sql
│   │       ├── wallets.sql
│   │       └── ...
│   ├── sqlc/
│   │   ├── postgres/       # Generated Go code for PostgreSQL
│   │   │   ├── db.go
│   │   │   ├── models.go
│   │   │   ├── querier.go
│   │   │   └── *.sql.go
│   │   └── sqlite/         # Generated Go code for SQLite
│   │       ├── db.go
│   │       ├── models.go
│   │       ├── querier.go
│   │       └── *.sql.go
│   └── itest/              # Integration tests
│       ├── pg_test.go
│       └── sqlite_test.go
└── Makefile                # Build commands
```

## Prerequisites

### Required Tools

The following tools are managed via Docker for consistency:

- **Docker**: Required for running tools in isolated environments
- **sqlc**: SQL-to-Go code generator (v1.30.0+)
- **sqlfluff**: SQL linter and formatter

### Building the Tools Docker Image

```bash
make docker-tools
```

This builds a Docker image containing `sqlc`, `golangci-lint`, `gosimports`,
and `protolint`. The image is built from `tools/Dockerfile`.

### Alternative: Local Installation

If you prefer local installation:

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

For sqlfluff (used via Docker by default):

```bash
pip install sqlfluff
```

## Makefile Commands

### SQL Code Generation

| Command | Description |
|---------|-------------|
| `make sqlc` | Generate Go code from SQL files |
| `make sqlc-check` | Verify generated code is up-to-date |
| `make sql-parse` | Validate SQL syntax without generating code |

### SQL Formatting and Linting

| Command | Description |
|---------|-------------|
| `make sql-format` | Format all SQL files |
| `make sql-format-check` | Check if SQL files are properly formatted |
| `make sql-lint` | Lint SQL files and auto-fix issues |
| `make sql-lint-check` | Lint SQL files without auto-fixing |

### Integration Tests

| Command | Description |
|---------|-------------|
| `make itest-db db=sqlite` | Run SQLite integration tests |
| `make itest-db db=postgres` | Run PostgreSQL integration tests |
| `make itest-db-race db=sqlite` | Run SQLite tests with race detector |
| `make itest-db-race db=postgres` | Run PostgreSQL tests with race detector |

## Development Workflow

### Adding a New Query

1. **Write the SQL query** in both dialect directories:

   ```sql
   -- wallet/internal/db/queries/postgres/example.sql
   -- name: GetExampleByID :one
   SELECT id, name, created_at
   FROM examples
   WHERE id = $1;
   ```

   ```sql
   -- wallet/internal/db/queries/sqlite/example.sql
   -- name: GetExampleByID :one
   SELECT id, name, created_at
   FROM examples
   WHERE id = ?;
   ```

2. **Format the SQL files**:

   ```bash
   make sql-format
   ```

3. **Generate the Go code**:

   ```bash
   make sqlc
   ```

4. **Verify everything is correct**:

   ```bash
   make sqlc-check
   make sql-lint-check
   ```

### Adding a New Migration

1. **Create migration files** with sequential numbering:

   ```
   migrations/postgres/000005_new_feature.up.sql
   migrations/postgres/000005_new_feature.down.sql
   migrations/sqlite/000005_new_feature.up.sql
   migrations/sqlite/000005_new_feature.down.sql
   ```

2. **Write the migration** in both dialects (see examples below).

3. **Regenerate code** to include new schema:

   ```bash
   make sqlc
   ```

## Writing SQL Queries

### Query Annotations

SQLC uses special comments to generate Go code:

```sql
-- name: QueryName :return_type
```

Return types:

| Annotation | Description |
|------------|-------------|
| `:one` | Returns a single row (error if not found) |
| `:many` | Returns a slice of rows |
| `:exec` | Returns only error (INSERT, UPDATE, DELETE) |
| `:execrows` | Returns affected row count |
| `:execresult` | Returns sql.Result |

### PostgreSQL Example

```sql
-- name: InsertWallet :one
INSERT INTO wallets (name, birthday, encrypted_seed)
VALUES ($1, $2, $3)
RETURNING id, name, birthday, created_at;

-- name: GetWalletByName :one
SELECT id, name, birthday, encrypted_seed, created_at
FROM wallets
WHERE name = $1;

-- name: UpdateWalletBirthday :exec
UPDATE wallets
SET birthday = $2
WHERE id = $1;
```

### SQLite Example

```sql
-- name: InsertWallet :one
INSERT INTO wallets (name, birthday, encrypted_seed)
VALUES (?, ?, ?)
RETURNING id, name, birthday, created_at;

-- name: GetWalletByName :one
SELECT id, name, birthday, encrypted_seed, created_at
FROM wallets
WHERE name = ?;

-- name: UpdateWalletBirthday :exec
UPDATE wallets
SET birthday = ?2
WHERE id = ?1;
```

## Writing Migrations

### Migration File Naming

Files must follow the pattern: `NNNNNN_description.{up|down}.sql`

- `NNNNNN`: Six-digit sequential number (e.g., `000001`, `000002`)
- `description`: Brief lowercase description with underscores
- `.up.sql`: Forward migration
- `.down.sql`: Rollback migration

### PostgreSQL Migration Example

```sql
-- 000002_wallets.up.sql
CREATE TABLE wallets (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    birthday BIGINT NOT NULL CHECK (birthday >= 0),
    encrypted_seed BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_wallets_name ON wallets(name);
```

```sql
-- 000002_wallets.down.sql
DROP INDEX IF EXISTS idx_wallets_name;
DROP TABLE IF EXISTS wallets;
```

### SQLite Migration Example

```sql
-- 000002_wallets.up.sql
CREATE TABLE wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    birthday INTEGER NOT NULL CHECK (birthday >= 0),
    encrypted_seed BLOB,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_wallets_name ON wallets(name);
```

```sql
-- 000002_wallets.down.sql
DROP INDEX IF EXISTS idx_wallets_name;
DROP TABLE IF EXISTS wallets;
```

### Dialect Differences to Remember

| Feature | PostgreSQL | SQLite |
|---------|-----------|--------|
| Auto-increment | `SERIAL` or `BIGSERIAL` | `INTEGER PRIMARY KEY AUTOINCREMENT` |
| Binary data | `BYTEA` | `BLOB` |
| Timestamp | `TIMESTAMP WITH TIME ZONE` | `TEXT` with datetime() |
| Boolean | `BOOLEAN` | `INTEGER` (0/1) |
| Large integers | `BIGINT` | `INTEGER` |

## Integration Tests

Integration tests verify that the generated code works correctly with real
databases.

### Running Tests

```bash
# SQLite tests (default, uses in-memory database)
make itest-db db=sqlite

# PostgreSQL tests (uses Docker container)
make itest-db db=postgres

# With race detector
make itest-db-race db=postgres
```

### Test Architecture

- **SQLite tests**: Use in-memory databases for speed
- **PostgreSQL tests**: Use testcontainers-go to spin up Docker containers
- Each test gets an isolated database for test independence
- The PostgreSQL container is shared across tests for performance

### Writing Integration Tests

Tests are located in `wallet/internal/db/itest/` and use build tags:

```go
//go:build itest && test_db_postgres

package itest

func TestWalletStore(t *testing.T) {
    store, db := NewTestStore(t)
    // ... test code
}
```

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/main.yml`) includes:

1. **`make sqlc-check`**: Ensures generated code is committed
2. **`make sql-format-check`**: Ensures SQL files are formatted
3. **`make sql-lint-check`**: Ensures SQL files pass linting
4. **`make itest-db db=sqlite`**: Runs SQLite integration tests
5. **`make itest-db db=postgres`**: Runs PostgreSQL integration tests

All checks must pass before a PR can be merged.

## Troubleshooting

### "Generated code is out of date"

```bash
make sqlc
git add wallet/internal/db/sqlc/
git commit -m "regen: update sqlc generated code"
```

### "SQL files not formatted correctly"

```bash
make sql-format
git add wallet/internal/db/migrations/ wallet/internal/db/queries/
git commit -m "style: format SQL files"
```

### Docker permission issues

```bash
# Ensure Docker daemon is running
sudo systemctl start docker

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER
```

### SQLC version mismatch

The generated files include the sqlc version. If you see version mismatches:

```bash
# Rebuild the tools image to get the latest version
make docker-tools
make sqlc
```

### PostgreSQL integration tests fail to start

```bash
# Check Docker is running
docker ps

# Pull the postgres image manually
docker pull postgres:18-alpine

# Increase timeout if on slow connection
# (Modify pgInitTimeout in itest/pg_test.go if needed)
```

## Further Reading

- [SQLC Documentation](https://docs.sqlc.dev/)
- [SQLFluff Documentation](https://docs.sqlfluff.com/)
- [golang-migrate Documentation](https://github.com/golang-migrate/migrate)
- [ADR 0001: Multi-Wallet Architecture](./adr/0001-multi-wallet-architecture.md)
