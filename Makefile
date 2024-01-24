PKG := github.com/btcsuite/btcwallet

LINT_PKG := github.com/golangci/golangci-lint/cmd/golangci-lint
GOACC_PKG := github.com/ory/go-acc
GOIMPORTS_PKG := golang.org/x/tools/cmd/goimports

GO_BIN := ${GOPATH}/bin
LINT_BIN := $(GO_BIN)/golangci-lint
GOACC_BIN := $(GO_BIN)/go-acc

LINT_COMMIT := v1.46.0
GOACC_COMMIT := 80342ae2e0fcf265e99e76bcc4efd022c7c3811b
GOIMPORTS_COMMIT := v0.1.10

GOBUILD := GO111MODULE=on go build -v
GOINSTALL := GO111MODULE=on go install -v
GOTEST := GO111MODULE=on go test 

GOLIST := go list -deps $(PKG)/... | grep '$(PKG)'
GOLIST_COVER := $$(go list -deps $(PKG)/... | grep '$(PKG)')
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

LINT = $(LINT_BIN) run -v $(LINT_WORKERS)

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
# DEPENDENCIES
# ============

$(LINT_BIN):
	@$(call print, "Fetching linter")
	$(GOINSTALL) $(LINT_PKG)@$(LINT_COMMIT)

$(GOACC_BIN):
	@$(call print, "Fetching go-acc")
	$(GOINSTALL) $(GOACC_PKG)@$(GOACC_COMMIT)

#? goimports: Install goimports
goimports:
	@$(call print, "Installing goimports.")
	$(GOINSTALL) $(GOIMPORTS_PKG)@${GOIMPORTS_COMMIT}

# ============
# INSTALLATION
# ============

#? build: Compile and build btcwallet
build:
	@$(call print, "Compiling btcwallet.")
	$(GOBUILD) $(PKG)/...

#? install: Install btcwallet, dropwtxmgr and sweepaccount, place them in $GOPATH/bin
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
	$(GOLIST) | $(XARGS) env $(GOTEST) -test.timeout=20m

#? unit-cover: Run unit coverage tests
unit-cover: $(GOACC_BIN)
	@$(call print, "Running unit coverage tests.")
	$(GOACC_BIN) $(GOLIST_COVER)

#? unit-race: Run unit race tests
unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOLIST) | $(XARGS) env $(GOTEST) -race -test.timeout=20m

# =========
# UTILITIES
# =========

#? fmt: Fix imports and formatting source
fmt: goimports
	@$(call print, "Fixing imports.")
	goimports -w $(GOFILES_NOVENDOR)
	@$(call print, "Formatting source.")
	gofmt -l -w -s $(GOFILES_NOVENDOR)

#? lint: Lint source
lint: $(LINT_BIN)
	@$(call print, "Linting source.")
	$(LINT)

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

.PHONY: all \
	default \
	build \
	check \
	unit \
	unit-cover \
	unit-race \
	fmt \
	lint \
	clean

#? help: Get more info on make commands
help: Makefile
	@echo " Choose a command run in btcwallet:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'

.PHONY: help