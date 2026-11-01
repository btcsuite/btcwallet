# AGENTS.md

This file is the knowledge base for `btcwallet`. It defines the global project
  structure, the map of subsystems, and the important operational constraints
  for all subagents.

## SCOPE & PRIORITY
- Follow this file first for the workflow and style of this repository.
- If two rules conflict, follow the stricter rule and match the nearby code.

## OVERVIEW
`btcwallet` is a Bitcoin wallet daemon. It supports BIP0032 (HD) and BIP0044.
  It is a client of `btcd`, `bitcoin-core`, and `neutrino`. It gives wallet
  clients a legacy JSON-RPC API and a gRPC API.

## REPO STRUCTURE & MAP
| Path                   | Component                 | Description                                                | Sub-Agent Config                |
|------------------------|:--------------------------|:-----------------------------------------------------------|:--------------------------------|
| `docs/developer/`      | **Docs**                  | Design docs (ADRs) and development guides.                 | None                            |
| `wallet/`              | **Wallet Core**           | Business logic, HD key derivation, transaction building.   | `wallet/AGENTS.md`              |
| `wallet/bench/`        | **Benchmarks**            | Independent measurements of the SQL Wallet.                | `wallet/bench/AGENTS.md`        |
| `wallet/internal/db/`  | **Database Layer**        | Storage drivers, migrations, relational SQL logic.         | `wallet/internal/db/AGENTS.md`  |
| `wallet/internal/sql/` | **SQL Assets**            | SQL schema, queries, migrations, and sqlc codegen.         | `wallet/internal/sql/AGENTS.md` |
| `rpc/`                 | **RPC**                   | gRPC and legacy JSON-RPC APIs and their servers.           | None                            |
| `chain/`               | **Blockchain**            | Sync clients for Neutrino, `btcd` RPC, and `bitcoind` RPC. | None                            |
| `itest/`               | **Integration Scenarios** | Daemon-level test cases and E2E flows.                     | `itest/AGENTS.md`               |
| `bwtest/`              | **Harness Layer**         | Test harness definitions and backend wrappers.             | None                            |

## REPO & WORKTREE WORKFLOW
- Keep the main checkout at the root of the repository.
- Put auxiliary worktrees in `<repo-root>/.worktrees/<name>`.
- Give each worktree a short name for its task.
- Do not make sibling worktrees outside the root of the repository, unless a
  person tells you to.
- When the work is complete, remove the worktree with
  `git worktree remove <path>`.
- Remove stale worktree metadata with `git worktree prune`.

## CRITICAL GOTCHAS & CONSTRAINTS
- **Go Version:** The workspace root requires Go `1.24.6`. Nested modules keep
  their own `go.mod` metadata. When you change a nested module, you should
  test it in the context of its own module.
- **Docker-backed Tooling:** These targets require Docker (the
  `btcwallet-tools` image): `make fmt`, `make sql`, `make rpc`, `make lint`,
  and the PostgreSQL integration tests.
- **Mutating Checks:** Some check targets **change files** before they check
  that Git is clean. Examples are `make fmt-check`, `make sqlc-check`,
  `make rpc-check`, and `make tidy-module-check`. Do not run them on a dirty
  tree, unless you want them to apply fixes.
- **Generated File Boundaries:** Do not manually edit `*.pb.go` files or code in
  directories that `sqlc` or the protobuf generators fill. Change the source
  definitions (SQL or proto) and run `make sql` or `make rpc`.
- **Test Locations:** Unit tests are next to the code. DB integration tests are
  in `wallet/internal/db/itest`. `itest/` controls the E2E integration tests.
- **ADR:** Before you change an area that is sensitive to architecture, read
  the recorded decisions in `docs/developer/adr/README.md`. Read their context,
  tradeoffs, and consequences. For a design task, read that guide and use
  `docs/developer/adr/template.md`.
- **Simple English:** All new or changed prose must follow
  `docs/developer/writing_style.md`. This includes docs, ADRs, `AGENTS.md`
  files, code comments, and commit messages. Reviewers apply it to every ADR.

## VERIFICATION STRATEGY
- First, run the narrowest test that applies.
- Before you hand off a significant change, run at least the package-level
  tests.
- For SQL, proto, module, or config changes, run the matching generation or
  check target.
- For changes to the backend flow or the RPC, run `make itest`.
- If a change claims a performance improvement, add or run a benchmark.
- CI checks formatting, imports, modules, proto, SQL, lint, unit, DB, and e2e.

## COMMANDS

### Build & Install
- `make build`: Compile the workspace.
- `make install`: Install the `btcwallet`, `dropwtxmgr`, and `sweepaccount`
  binaries to `$GOBIN`.

### Linting, Formatting & Code Generation
- `make fmt`: Fix imports (`gosimports`) and format Go code (`gofmt`).
- `make lint`: Run `golangci-lint` in fix mode (uses Docker).
- `make sql`: Lint, format, and generate the SQL models and queries again
  (uses SQLFluff and sqlc).
- `make rpc-format`: Format the protobuf definition files.
- `make rpc`: Generate the gRPC code from the protobuf definitions again.
- `make tidy-module`: Tidy all Go modules in the workspace.

### Verification & Checks
- `make fmt-check`: Check the Go formatting and imports.
- `make lint-check`: Run the linter in check-only mode.
- `make sqlc-check`: Make sure that the generated SQL code is current.
- `make rpc-check`: Make sure that the generated protobuf code is current.
- `make tidy-module-check`: Make sure that the Go modules are tidy.

### Testing
- `make unit`: Run all package unit tests.
- `make unit pkg=wallet case=TestName`: Run one unit test.
- `make unit-race pkg=wallet case=TestName`: Run one test with the race
  detector.
- `make itest-db db=[sqlite|postgres]`: Run the integration tests of the
  database layer.
- `make itest chain=[btcd|bitcoind|neutrino]`: Run the E2E daemon integration
  tests.
- `make itest chain=btcd db=kvdb icase=manager`: Filter the E2E tests by case
  name.

## CONVENTIONS

The developer docs are the source of truth for detailed conventions:

- `docs/developer/contribution_guidelines.md`: contribution workflow, PRs,
  commits, review expectations, and the requirements for function comments.
- `docs/developer/code_formatting_rules.md`: formatting, layout, naming, and
  local style.
- `docs/developer/unit_testing_guidelines.md`: unit test structure, coverage,
  and test documentation.
- `docs/developer/ENGINEERING_GUIDE.md`: package design, architecture, error
  handling, logging, and concurrency.
- `docs/developer/writing_style.md`: the Simple English rules for all prose.

Remember these important rules when you edit code:

- Let `make fmt` manage imports. Go files use tab indentation. Markdown files
  use LF and wrap near 80 columns.
- Do not use generic package names such as `utils`, `common`, or `helpers`.
- Put `context.Context` first for blocking or long-running operations.
- Wrap dependency errors with context with `%w`. Check sentinel errors with
  `errors.Is`.
- Give each goroutine a clear shutdown path. Do not access maps concurrently
  without synchronization. Pass sync primitives by pointer.
- Keep the local logging style. Use `error` for unexpected internal failures.
  Keep structured log messages static.
- Write a comment for each function and method. The comment tells its purpose
  and its assumptions. A function comment must start with the declaration
  name. An exported API also needs the detail for callers that the
  contribution guide requires.
- Write regression tests for bug fixes. Test the positive and the negative
  paths. A test comment should tell why the test exists and what it checks.
- Use `make rpc-format` to format proto files. Do not add ad hoc local
  `replace` directives in Go submodules.
- Test case names must use the form `component action` and must not use `_`.
- E2E tests write their logs to `itest/test-logs/`.
- Write all prose in Simple English. Use short sentences, the active voice,
  and one word for one meaning.
