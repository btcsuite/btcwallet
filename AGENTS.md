# AGENTS.md

Welcome to the `btcwallet` knowledge base. This file defines the global project
  structure, subsystem mappings, and critical operational constraints for all
  subagents.

## SCOPE & PRIORITY
- Follow this file first for repo-specific workflow and style.
- If guidance conflicts, prefer the stricter rule and match nearby code.

## OVERVIEW
`btcwallet` is a Bitcoin wallet daemon supporting BIP0032 (HD) and BIP0044. It
  acts as a client to `btcd`, `bitcoin-core` and `neutrino`, and provides both
  legacy JSON-RPC and gRPC APIs to wallet clients.

## REPO STRUCTURE & MAP
| Path                   | Component                 | Description                                                | Sub-Agent Config                |
|------------------------|:--------------------------|:-----------------------------------------------------------|:--------------------------------|
| `docs/developer/`      | **Docs**                  | Deep-dive design docs (ADRs) and development guides.       | None                            |
| `wallet/`              | **Wallet Core**           | Business logic, HD key derivation, transaction building.   | `wallet/AGENTS.md`              |
| `wallet/internal/db/`  | **Database Layer**        | Storage drivers, migrations, SQL-based relational logic.   | `wallet/internal/db/AGENTS.md`  |
| `wallet/internal/sql/` | **SQL Assets**            | SQL schema, query, migration, and sqlc codegen.            | `wallet/internal/sql/AGENTS.md` |
| `rpc/`                 | **RPC**                   | gRPC and legacy JSON-RPC APIs and server implementations.  | None                            |
| `chain/`               | **Blockchain**            | Sync clients for Neutrino, `btcd` RPC, and `bitcoind` RPC. | None                            |
| `itest/`               | **Integration Scenarios** | Actual daemon-level test cases and E2E flows.              | None                            |
| `bwtest/`              | **Harness Layer**         | Test harness definitions and backend wrappers.             | None                            |

## REPO & WORKTREE WORKFLOW
- Keep the main checkout at the repo root.
- Place auxiliary worktrees under `<repo-root>/.worktrees/<name>`.
- Use short, task-oriented worktree names.
- Don't create sibling worktrees outside the repo root unless asked.
- Remove finished worktrees with `git worktree remove <path>`.
- Clean stale worktree metadata with `git worktree prune`.

## CRITICAL GOTCHAS & CONSTRAINTS
- **Go Version:** The workspace root requires Go `1.24.6`. Nested modules keep
  their own `go.mod` metadata and should be tested in their own module context
  when touched.
- **Docker-backed Tooling:** Mutating operations (`make fmt`, `make sql`,
  `make rpc`, `make lint`) and PostgreSQL integration tests require Docker
  (`btcwallet-tools` image).
- **Mutating Checks:** Targets like `make fmt-check`, `make sqlc-check`,
  `make rpc-check`, and `make tidy-module-check` **mutate files** before
  checking Git cleanliness. Never run them on a dirty tree unless you want
  auto-fixes applied.
- **Generated File Boundaries:** Do not manually edit `*.pb.go` or any code in
  directories populated by `sqlc` or protobuf generators. Modify source
  definitions (SQL/Proto) and run `make sql` or `make rpc`.
- **Test Locations:** Unit tests live alongside code. DB integration tests live
  in `wallet/internal/db/itest`. E2E integration tests are orchestrated from
  `itest/`.
- **ADR** Before changing architecture-sensitive areas, review
  `docs/developer/adr/README.md` for recorded design decisions, context,
  tradeoffs, and consequences.

## VERIFICATION STRATEGY
- Start by running the narrowest relevant test.
- Before handing off a significant change, run at least package-level tests.
- Run the matching generation or check the target for SQL, proto, module, or
  config changes.
- Verify backend flow or RPC changes with `make itest`.
- Add or run a benchmark if a change claims performance improvement.
- CI covers formatting, imports, modules, proto, SQL, lint, unit, DB, and e2e.

## COMMANDS

### Build & Install
- `make build`: Compile the workspace.
- `make install`: Install `btcwallet`, `dropwtxmgr`, and `sweepaccount` binaries
  to `$GOBIN`.

### Linting, Formatting & Code Generation
- `make fmt`: Fix imports (`gosimports`) and format Go code (`gofmt`).
- `make lint`: Run `golangci-lint` with fix mode enabled (uses Docker).
- `make sql`: Lint, format, and regenerate SQL models/queries (uses
  SQLFluff/sqlc).
- `make rpc-format`: Format protobuf definition files.
- `make rpc`: Regenerate gRPC code from protobuf definitions.
- `make tidy-module`: Tidy all Go modules in the workspace.

### Verification & Checks
- `make fmt-check`: Check Go formatting and imports.
- `make lint-check`: Run linter in check-only mode.
- `make sqlc-check`: Ensure generated SQL code is up to date.
- `make rpc-check`: Ensure generated protobuf code is up to date.
- `make tidy-module-check`: Confirm Go modules are tidy.

### Testing
- `make unit`: Run all package unit tests.
- `make unit pkg=wallet case=TestName`: Targeted unit test.
- `make unit-race pkg=wallet case=TestName`: Test with race detector enabled.
- `make itest-db db=[sqlite|postgres]`: Perform database layer integration
  tests.
- `make itest chain=[btcd|bitcoind|neutrino]`: Start E2E daemon integration
  tests.
- `make itest chain=btcd db=kvdb icase=manager`: Filter E2E tests by case name.

## CONVENTIONS

Use the developer docs as the source of truth for detailed conventions:

- `docs/developer/contribution_guidelines.md`: contribution workflow, PRs,
  commits, review expectations, and function comment requirements.
- `docs/developer/code_formatting_rules.md`: formatting, layout, naming, and
  local style.
- `docs/developer/unit_testing_guidelines.md`: unit test structure, coverage,
  and test documentation.
- `docs/developer/ENGINEERING_GUIDE.md`: package design, architecture, error
  handling, logging, and concurrency.

Keep these high-signal reminders in mind when editing code:

- Let `make fmt` manage imports. Go files use tab indentation. Markdown files
  use LF and wrap near 80 columns.
- Avoid generic package names like `utils`, `common`, or `helpers`.
- Put `context.Context` first for blocking or long-running operations.
- Wrap dependency errors with context using `%w` and check sentinels with
  `errors.Is`.
- Ensure every goroutine has a clear shutdown path, don't access maps
  concurrently without synchronization, and pass sync primitives by pointer.
- Preserve local logging style. Use `error` for unexpected internal failures and
  keep structured log messages static.
- Comment every function and method with its intended purpose and assumptions.
  Function comments must start with the declaration name; exported APIs also
  need the caller-facing detail required by the contribution guide.
- Write regression tests for bug fixes and cover positive and negative paths.
  Test comments should explain why the test exists and what it checks.
- Run `make rpc-format` for proto formatting and avoid ad hoc local `replace`
  directives in Go submodules.
- Test case names must follow `component action` and must not use `_`.
- E2E test logs are written under `itest/test-logs/`.
