# AGENTS.md

This file is for coding agents working in `btcwallet`.

## Scope and Priority

- Follow this file first for repo-specific workflow and style.
- Then follow `docs/developer/` for deeper rationale.
- If guidance conflicts, prefer the stricter rule and match nearby code.

## Repo Workflow

- Keep the main checkout at the repo root.
- Place auxiliary worktrees under `<repo-root>/.worktrees/<name>`.
- Use short issue- or task-oriented worktree names.
- Do not create sibling worktrees outside the repo root unless asked.
- Remove finished worktrees with `git worktree remove <path>`.
- Clean stale worktree metadata with `git worktree prune`.

## Tooling and Environment

- The authoritative Go version is `1.24.6`.
- Sources: `go.mod`, `.golangci.yml`, and `.github/workflows/main.yml`.
- Some older docs mention older Go versions; ignore them.
- Many maintenance targets use Docker-backed tooling.
- `make fmt`, `make lint*`, `make sqlc`, and `make protolint` use Docker.
- PostgreSQL DB integration tests also require Docker via testcontainers.
- No Cursor rules were found in `.cursor/rules/` or `.cursorrules`.
- No Copilot instructions were found in `.github/copilot-instructions.md`.
- There is an additional style summary in `.gemini/styleguide.md`.

## Primary Build, Format, and Codegen Commands

- Build everything: `make build`
- Install binaries: `make install`
- CI compile check: `go install -v ./...`
- Default `make` target is `make build`.
- `make install` installs `btcwallet`, `cmd/dropwtxmgr`, and `cmd/sweepaccount`.
- Go format/imports: `make fmt`; verify with `make fmt-check`
- Lint: `make lint-config-check`, `make lint-check`, `make lint`; optional `workers=4`
- Proto: `make rpc-format`, `make rpc`, `make rpc-check`, `make protolint`
- SQL: `make sql-parse`, `make sql-format`, `make sql-format-check`, `make sql-lint`, `make sql-lint-check`, `make sqlc`, `make sqlc-check`, `make sql`
- Modules and config: `make tidy-module`, `make tidy-module-check`, `make sample-conf-check`

## Command Gotchas

- Several `*-check` targets modify files before checking git cleanliness.
- `make fmt-check` runs `make fmt` first.
- `make rpc-check` runs code generation first.
- `make sqlc-check` runs SQL codegen first.
- `make sql-format-check` formats SQL first.
- `make tidy-module-check` runs `go mod tidy` first.
- Do not run those blindly in a dirty tree unless you expect edits.

## Unit Test Commands

- Run all unit tests: `make unit`
- Run one package: `make unit pkg=wallet`
- Run one specific test: `make unit pkg=wallet case=TestBuildTxDetail`
- Common flags: `verbose=1`, `nocache=1`, `timeout=5m`
- Run unit tests with race detector: `make unit-race`
- Run targeted race test: `make unit-race pkg=wallet case=TestBuildTxDetail`
- Run unit coverage: `make unit-cover`
- Run targeted coverage: `make unit-cover pkg=wallet`
- Run benchmarks for one package: `make unit-bench pkg=wallet`
- Include alloc stats: `make unit-bench pkg=wallet benchmem=1`

## Integration Test Commands

- DB itests: `make itest-db db=sqlite` or `make itest-db db=postgres`
- Single DB itest: `make itest-db db=postgres case=TestWhatever verbose=1`
- DB coverage/race: `make itest-db db=postgres cover=1 verbose=1`, `make itest-db-race db=sqlite verbose=1`
- The DB integration suite lives in `wallet/internal/db/itest`.
- E2E default: `make itest`
- E2E backends: `make itest chain=btcd db=kvdb`, `make itest chain=neutrino db=kvdb`, `make itest chain=bitcoind db=kvdb`
- E2E case filter: `make itest icase=manager` or `make itest chain=btcd db=kvdb icase=manager`
- E2E logs go to `itest/test-logs/`; case names must follow `component action` and must not use `_`.

## Verification Strategy

- Run the narrowest relevant test first.
- Before handing off a substantial change, run at least package-level tests.
- For SQL, proto, module, or config changes, run the matching generation/check target.
- For DB-layer changes, prefer `itest-db` in addition to unit tests.
- For backend flow or RPC changes, consider `make itest` coverage.
- If a change claims performance improvement, add or run a benchmark.
- CI covers formatting, imports, modules, proto, SQL, lint, unit, DB, and e2e.

## Go Formatting and Imports

- Follow `Effective Go` and the repo docs in `docs/developer/`.
- Let `make fmt` manage imports through `gosimports` and `gofmt`.
- Do not manually fight import grouping; accept formatter output.
- Go files use tab indentation.
- Markdown files use LF and wrap to 80 characters.
- Keep lines near 80 columns on a best-effort basis.
- The style docs mention treating tabs as width 8 for visual wrapping.
- `.editorconfig` and linter settings use width 4; keep lines conservative.
- Formatting excludes generated `*.pb.go` files.

## Code Layout and Naming

- Break functions into logical stanzas separated by blank lines.
- Add comments where intent is not obvious; explain why, not the mechanics.
- Every function should have a purpose comment; comments must start with the function name.
- Exported functions need caller-oriented comments, not just maintainer notes.
- Wrap long function calls one argument per line with `)` on its own line.
- If a function declaration spans multiple lines, start the body after a blank line.
- Avoid generic package names like `utils`, `common`, or `helpers`; use `internal` for non-public code.
- Prefer domain-focused package boundaries, avoid circular dependencies, and accept interfaces while returning concrete structs.
- Match existing names in the surrounding package before inventing new terms.

## Types, Errors, and Concurrency

- Put `context.Context` first for blocking or long-running operations.
- Wrap dependency errors with context using `%w`.
- Prefer sentinel errors for important conditions and check with `errors.Is`.
- Define normal non-exceptional cases out of the error path when practical.
- Prefer communicating over shared memory.
- Never start a goroutine without a clear shutdown path.
- Do not access maps concurrently without synchronization.
- Treat slices as shared mutable state unless ownership is explicit.
- Pass sync primitives by pointer, not by value.

## Logging Guidelines

- Supported levels are `trace`, `debug`, `info`, `warn`, `error`, `critical`.
- Use `error` for unexpected internal failures.
- Expected external failures usually belong at `info`, `debug`, or `warn`.
- Much of the repo still uses legacy `log.Tracef/Debugf/...` patterns.
- In files that already use legacy logging, preserve the local style.
- If adding structured logging, keep the message static and put data in attributes.
- Use `slog.Attr` or helpers like `btclog.Fmt` for structured log fields.
- Log and error formatting are exceptions to the usual multiline call wrapping.

## Test Style Guidelines

- New non-trivial behavior and bug fixes should come with regression tests.
- Cover both positive paths and negative or error paths.
- Prefer `require` over `assert` for most checks.
- Structure tests as Arrange, Act, Assert with blank lines between sections.
- Use table-driven tests only when setup shape is identical across cases.
- If setup differs across cases, prefer separate standalone tests and keep case structs data-only.
- Use descriptive flat test names and `t.Parallel()` where safe.
- Tests commonly use fast scrypt parameters; do not remove that optimization.

## SQL, Proto, Modules, and PRs

- SQL is formatted and linted with SQLFluff.
- SQL keywords and types should be uppercase; identifiers and function names should be lowercase.
- Prefer `!=` over `<>`; SQL indentation uses 4 spaces.
- Protos are formatted with `clang-format` through `make rpc-format`.
- Proto messages use UpperCamelCase; filenames use lower_snake_case.
- Proto imports should be sorted, package names lowercase, and services/RPCs commented.
- The repo contains multiple Go submodules; avoid ad hoc local `replace` directives.
- Favor small, reviewable commits.
- Commit subjects typically look like `subsystem: short description`.
- Use present tense, keep the subject near 50 chars, and wrap bodies near 72.
- PRs should include clear test steps and cover positive and negative cases.
- Insubstantial typo-only changes are discouraged by the contribution guide.
