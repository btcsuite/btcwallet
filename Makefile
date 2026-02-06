PKG := github.com/btcsuite/btcwallet
TOOLS_DIR := tools

GOBUILD := GO111MODULE=on go build -v
GOINSTALL := GO111MODULE=on go install -v

GOFILES = $(shell find . -type f -name '*.go' -not -name "*.pb.go")


# SQL directories.
SQL_MIGRATIONS_DIR := wallet/internal/db/migrations
SQL_QUERIES_DIR := wallet/internal/db/queries

# SQL file paths.
SQL_POSTGRES_MIGRATIONS := $(SQL_MIGRATIONS_DIR)/postgres
SQL_POSTGRES_QUERIES := $(SQL_QUERIES_DIR)/postgres
SQL_SQLITE_MIGRATIONS := $(SQL_MIGRATIONS_DIR)/sqlite
SQL_SQLITE_QUERIES := $(SQL_QUERIES_DIR)/sqlite

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1

include make/testing_flags.mk

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

DOCKER_TOOLS = docker run \
  --rm \
  -v $(shell bash -c "mkdir -p /tmp/go-build-cache; echo /tmp/go-build-cache"):/root/.cache/go-build \
  -v $$(pwd):/build btcwallet-tools

SQLFLUFF = docker run \
	--rm \
	--user $$(id -u):$$(id -g) \
    -v $$(pwd):/sql \
    -w /sql \
    sqlfluff/sqlfluff

GREEN := "\\033[0;32m"
NC := "\\033[0m"
define print
	echo $(GREEN)$1$(NC)
endef

#? default: Run `make build`
default: build

#? all: Run `make build` and `make check`
all: build check

# ============
# INSTALLATION
# ============

#? build: Compile and build btcwallet
build:
	@$(call print, "Compiling btcwallet.")
	$(GOBUILD) $(PKG)/...

#? install: Install btcwallet, dropwtxmgr and sweepaccount, place them in $GOBIN
install:
	@$(call print, "Installing btcwallet.")
	$(GOINSTALL) $(PKG)
	$(GOINSTALL) $(PKG)/cmd/dropwtxmgr
	$(GOINSTALL) $(PKG)/cmd/sweepaccount

# =======
# TESTING
# =======

#? check: Run `make unit`
check: unit

#? unit: Run unit tests
unit:
	@$(call print, "Running unit tests.")
	$(UNIT)

#? unit-cover: Run unit coverage tests
unit-cover:
	@$(call print, "Running unit coverage tests.")
	$(UNIT_COVER)

#? unit-race: Run unit race tests
unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(UNIT_RACE)

#? unit-debug: Run unit tests with verbose debug output enabled
unit-debug:
	@$(call print, "Running debug unit tests.")
	$(UNIT_DEBUG)

#? unit-bench: Run benchmark tests
unit-bench:
	@$(call print, "Running benchmark tests.")
	$(UNIT_BENCH)

#? itest-db: Run integration tests for wallet database
itest-db:
	@if [ -z "$(IT_DB_LABEL)" ]; then \
		echo "Unknown integration test database '$(db)'. Use db=sqlite or db=postgres." ; \
		exit 1 ; \
	fi
	@$(call print, "Running $(IT_DB_LABEL) integration tests.")
	$(ITEST_DB)
	@if [ -n "$(ITEST_DB_COVERPROFILE)" ]; then \
		echo  "Filtering coverage report."; \
		./scripts/filter_coverage.sh $(IT_DB_TYPE); \
	fi

#? itest-db-race: Run integration tests for wallet database with race detector
itest-db-race:
	@if [ -z "$(IT_DB_LABEL)" ]; then \
		echo "Unknown integration test database '$(db)'. Use db=sqlite or db=postgres." ; \
		exit 1 ; \
	fi
	@$(call print, "Running $(IT_DB_LABEL) integration tests (race).")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(ITEST_DB_RACE)

# =========
# UTILITIES
# =========

#? fmt: Fix imports and format source code
fmt: docker-tools
	@$(call print, "Fixing imports.")
	$(DOCKER_TOOLS) gosimports -w $(GOFILES)
	@$(call print, "Formatting source.")
	$(DOCKER_TOOLS) gofmt -l -w -s $(GOFILES)

#? fmt-check: Make sure source code is formatted and imports are correct
fmt-check: fmt
	@$(call print, "Checking fmt results.")
	if test -n "$$(git status --porcelain)"; then echo "code not formatted correctly, please run `make fmt` again!"; git status; git diff; exit 1; fi

#? rpc-format: Format protobuf definition files
rpc-format:
	@$(call print, "Formatting protos.")
	cd ./rpc; find . -name "*.proto" | xargs clang-format --style=file -i

#? lint-config-check: Verify golangci-lint configuration
lint-config-check: docker-tools
	@$(call print, "Verifying golangci-lint configuration.")
	$(DOCKER_TOOLS) golangci-lint config verify -v --config .golangci.yml

#? lint: Lint source and check errors
lint-check: lint-config-check
	@$(call print, "Linting source.")
	$(DOCKER_TOOLS) golangci-lint run -v --config .golangci.yml $(LINT_WORKERS)

#? lint: Lint source and fix
lint: lint-config-check
	@$(call print, "Linting source.")
	$(DOCKER_TOOLS) golangci-lint run -v --fix --config .golangci.yml $(LINT_WORKERS)

#? docker-tools: Build tools docker image
docker-tools:
	@$(call print, "Building tools docker image.")
	docker build -q -t btcwallet-tools -f $(TOOLS_DIR)/Dockerfile .

#? rpc: Compile protobuf definitions
rpc:
	@$(call print, "Compiling protos.")
	cd ./rpc; ./gen_protos_docker.sh

#? rpc-check: Make sure protobuf definitions are up to date
rpc-check: rpc
	@$(call print, "Verifying protos.")
	if test -n "$$(git status --porcelain rpc/walletrpc/)"; then echo "Generated protobuf files are not up-to-date. Please run 'make rpc' and commit the changes."; git status; git diff rpc/walletrpc/; exit 1; fi

#? protolint: Lint proto files using protolint
protolint:
	@$(call print, "Linting proto files.")
	$(DOCKER_TOOLS) protolint lint -config_dir_path=. rpc/

#? sample-conf-check: Make sure default values in the sample-btcwallet.conf file are set correctly
sample-conf-check: install
	@$(call print, "Checking that default values in the sample-btcwallet.conf file are set correctly")
	scripts/check-sample-btcwallet-conf.sh

#? clean: Clean source
clean:
	@$(call print, "Cleaning source.$(NC)")
	$(RM) coverage.txt

#? tidy-module: Run 'go mod tidy' for all modules
tidy-module:
	echo "Running 'go mod tidy' for all modules"
	scripts/tidy_modules.sh

#? tidy-module-check: Run 'go mod tidy' for all modules and check results
tidy-module-check: tidy-module
	if test -n "$$(git status --porcelain)"; then echo "modules not updated, please run `make tidy-module` again!"; git status; exit 1; fi

#? sql-parse: Ensures SQL files are syntactically valid
sql-parse:
	@$(call print, "Validating SQL files (postgres migrations).")
	$(SQLFLUFF) parse --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_MIGRATIONS) --format none
	@$(call print, "Validating SQL files (postgres queries).")
	$(SQLFLUFF) parse --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_QUERIES) --format none
	@$(call print, "Validating SQL files (sqlite migrations).")
	$(SQLFLUFF) parse --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_MIGRATIONS) --format none
	@$(call print, "Validating SQL files (sqlite queries).")
	$(SQLFLUFF) parse --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_QUERIES) --format none

#? sqlc: Generate Go code from SQL queries and migrations
sqlc: sql-parse docker-tools
	@$(call print, "Generating sql models and queries in Go")
	$(DOCKER_TOOLS) sqlc generate -f sqlc.yaml

#? sqlc-check: Verify generated Go SQL queries and migrations are up-to-date
sqlc-check: sqlc
	@$(call print, "Verifying sql code generation.")
	if test -n "$$(git status --porcelain '*.go')"; then echo "SQL models not properly generated!"; git status --porcelain '*.go'; exit 1; fi

#? sql-format: Format SQL migration and query files (like 'make fmt')
sql-format:
	@$(call print, "Formatting SQL files (postgres migrations).")
	$(SQLFLUFF) format --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_MIGRATIONS)
	@$(call print, "Formatting SQL files (postgres queries).")
	$(SQLFLUFF) format --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_QUERIES)
	@$(call print, "Formatting SQL files (sqlite migrations).")
	$(SQLFLUFF) format --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_MIGRATIONS)
	@$(call print, "Formatting SQL files (sqlite queries).")
	$(SQLFLUFF) format --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_QUERIES)

#? sql-check: Verify SQL migration and query files are formatted correctly (like 'make fmt-check')
sql-format-check: sql-format
	@$(call print, "Checking SQL formatting.")
	if test -n "$$(git status --porcelain '$(SQL_MIGRATIONS_DIR)/**/*.sql' '$(SQL_QUERIES_DIR)/**/*.sql')"; then echo "SQL files not formatted correctly, please run 'make sql-format' again!"; git status; git diff; exit 1; fi

#? sql-lint: Lint SQL migration and query files and fix issues (like 'make lint')
sql-lint:
	@$(call print, "Linting SQL files (postgres migrations).")
	$(SQLFLUFF) fix --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_MIGRATIONS)
	@$(call print, "Linting SQL files (postgres queries).")
	$(SQLFLUFF) fix --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_QUERIES)
	@$(call print, "Linting SQL files (sqlite migrations).")
	$(SQLFLUFF) fix --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_MIGRATIONS)
	@$(call print, "Linting SQL files (sqlite queries).")
	$(SQLFLUFF) fix --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_QUERIES)

#? sql-lint-check: Lint SQL files and report errors (like 'make lint-check')
sql-lint-check:
	@$(call print, "Linting SQL files (postgres migrations).")
	$(SQLFLUFF) lint --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_MIGRATIONS)
	@$(call print, "Linting SQL files (postgres queries).")
	$(SQLFLUFF) lint --config /sql/.sqlfluff --dialect postgres $(SQL_POSTGRES_QUERIES)
	@$(call print, "Linting SQL files (sqlite migrations).")
	$(SQLFLUFF) lint --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_MIGRATIONS)
	@$(call print, "Linting SQL files (sqlite queries).")
	$(SQLFLUFF) lint --config /sql/.sqlfluff --dialect sqlite $(SQL_SQLITE_QUERIES)

.PHONY: all \
	default \
	build \
	check \
	unit \
	unit-cover \
	unit-race \
	unit-debug \
	unit-bench \
	itest-db \
	itest-db-race \
	fmt \
	fmt-check \
	tidy-module \
	tidy-module-check \
	sql-parse \
	sqlc \
	sqlc-check \
	sql-format \
	sql-lint \
	sql-lint-check \
	sql-format-check \
	rpc-format \
	lint \
	lint-config-check \
	docker-tools \
	rpc \
	rpc-check \
	protolint \
	sample-conf-check \
	clean

#? help: Get more info on make commands
help: Makefile
	@echo " Choose a command run in btcwallet:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'

.PHONY: help
