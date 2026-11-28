# Wallet DB AGENTS.md

This is the knowledge base for the `wallet/internal/db/` subsystem. It provides
  a multi-backend persistence layer for the wallet, supporting PostgreSQL,
  SQLite, and legacy kvdb (BDB).

## RESPONSIBILITIES
- **Persistence Layer:** Implements the `Store` interface for wallets, accounts,
  addresses, UTXOs, and transactions.
- **Backend Adapters:** Provides concrete implementations for `pg`, `sqlite`,
  and `kvdb`.
- **Shared Workflows:** Orchestrates complex DB operations using
  backend-specific "ops" interfaces to minimize logic duplication.
- **Runtime Helpers:** Handles SQL retries, transaction management, and error
  classification (`runtime/`, `err/`).
- **Pagination:** Provides shared cursor-based pagination logic (`page/`).

## WHERE TO LOOK
| Component             | Path           | Description                                                |
|:----------------------|:---------------|:-----------------------------------------------------------|
| **Interfaces**        | `interface.go` | Central `Store` contract and shared error definitions.     |
| **PostgreSQL**        | `pg/`          | Postgres-specific driver, config, and query adapters.      |
| **SQLite**            | `sqlite/`      | SQLite-specific driver and query adapters.                 |
| **KVDB**              | `kvdb/`        | Legacy waddrmgr/BDB adapter (limited feature set).         |
| **Runtime**           | `runtime/`     | Shared SQL execution (`Read`/`Write`), retries, and stats. |
| **Errors**            | `err/`         | SQL error classification (Fatal, Transient, Constraint).   |
| **Integration Tests** | `itest/`       | Database integration tests for SQLite and PostgreSQL.      |

## GENERATED CODE BOUNDARIES
- **DO NOT** edit `*.sql.go` or `models.go` files.
- SQL code is generated via `sqlc` and lives in
  `wallet/internal/sql/{pg,sqlite}/sqlc/`.
- To update queries or schema: modify the relevant `.sql` files under
  `wallet/internal/sql/` and run `make sql`.

## LOCAL CONVENTIONS
- **Ops Pattern:** For complex writes (`CreateWallet`, `CreateDerivedAccount`,
  `CreateImportedAccount`, `CreateTx`, `LeaseOutput`), use one method-specific
  `ops` interface plus one backend-independent helper for the shared workflow;
  keep backend-specific query/prep details in backend files. Method-specific
  files are preferred.
- **Error Handling:** Pass `context.Context` to all store methods. Use `err/`
  package to classify backend errors; only retriable errors trigger the
  `runtime.Read` retry loop.
- **Data Types:** Common DB-compatible data types and safe casting logic live in
  `data_types.go` and `safecasting.go`.

## TESTING FOCUS
- Prefer `itest-db` in addition to unit tests for DB-layer changes.
- **DB Integration Tests:** Located in `wallet/internal/db/itest/`. These run
  against `sqlite` and `postgres` backends. Use
  `make itest-db db=[sqlite|postgres]`. Legacy `kvdb` tests are separate and run
  as unit tests under `wallet/internal/db/kvdb/`.
- **Unit Tests:** Shared logic tests live in `*_common_test.go`.
  Backend-specific unit tests live within their respective directories.
- **Mocking:** `mock_test.go` provides basic mocks for the `Store` interfaces.
