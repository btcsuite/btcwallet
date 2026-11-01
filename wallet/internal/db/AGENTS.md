# Wallet DB AGENTS.md

This is the knowledge base for the `wallet/internal/db/` subsystem. The
  subsystem is the persistence layer of the wallet. It supports these backends:
  PostgreSQL, SQLite, and legacy kvdb (BDB).

## RESPONSIBILITIES
- **Persistence Layer:** Implements the `Store` interface for wallets,
  accounts, addresses, UTXOs, and transactions.
- **Backend Adapters:** Gives the implementations for `pg`, `sqlite`, and
  `kvdb`.
- **Shared Workflows:** Controls complex DB operations. Backend-specific "ops"
  interfaces keep the duplicate logic to a minimum.
- **Runtime Helpers:** Manages SQL retries and transactions, and classifies
  errors (`runtime/`, `err/`).
- **Pagination:** Gives the shared cursor-based pagination logic (`page/`).

## WHERE TO LOOK
| Component             | Path           | Description                                                |
|:----------------------|:---------------|:-----------------------------------------------------------|
| **Interfaces**        | `interface.go` | The central `Store` contract and the shared errors.        |
| **PostgreSQL**        | `pg/`          | The Postgres driver, config, and query adapters.           |
| **SQLite**            | `sqlite/`      | The SQLite driver and query adapters.                      |
| **KVDB**              | `kvdb/`        | The legacy waddrmgr/BDB adapter (limited features).        |
| **Runtime**           | `runtime/`     | Shared SQL execution (`Read`/`Write`), retries, and stats. |
| **Errors**            | `err/`         | SQL error classes (Fatal, Transient, Constraint).          |
| **Integration Tests** | `itest/`       | Database integration tests for SQLite and PostgreSQL.      |

## GENERATED CODE BOUNDARIES
- **DO NOT** edit `*.sql.go` or `models.go` files.
- `sqlc` generates the SQL code into `wallet/internal/sql/{pg,sqlite}/sqlc/`.
- To change queries or the schema, change the applicable `.sql` files in
  `wallet/internal/sql/`. Then run `make sql`.

## LOCAL CONVENTIONS
- **Ops Pattern:** Use this pattern for complex writes, such as
  `CreateWallet`, `CreateDerivedAccount`, `CreateImportedAccount`, `CreateTx`,
  and `LeaseOutput`:
  - One `ops` interface for the method.
  - One backend-independent helper for the shared workflow.
  - Backend-specific query and preparation details in the backend files.

  Prefer one file for each method.
- **Error Handling:** Pass `context.Context` to all store methods. Use the
  `err/` package to classify backend errors. Only retriable errors start the
  `runtime.Read` retry loop.
- **Data Types:** `data_types.go` and `safecasting.go` contain the common
  DB-compatible data types and the safe casting logic.

## TESTING FOCUS
- For DB-layer changes, you should run `itest-db` in addition to the unit
  tests.
- **DB Integration Tests:** These tests are in `wallet/internal/db/itest/`.
  They run against the `sqlite` and `postgres` backends. Use
  `make itest-db db=[sqlite|postgres]`. The legacy `kvdb` tests are separate.
  They are unit tests in `wallet/internal/db/kvdb/`.
- **Unit Tests:** The tests for shared logic are in `*_common_test.go`. The
  backend-specific unit tests are in the directory of each backend.
- **Mocking:** `mock_test.go` gives basic mocks for the `Store` interfaces.
