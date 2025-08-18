PKG := github.com/btcsuite/btcwallet
TOOLS_DIR := tools

GOCC ?= go

LINT_PKG := github.com/golangci/golangci-lint/cmd/golangci-lint
GOACC_PKG := github.com/ory/go-acc
GOIMPORTS_PKG := github.com/rinchsan/gosimports/cmd/gosimports

GO_BIN := $(shell go env GOBIN)

# If GOBIN is not set, default to GOPATH/bin.
ifeq ($(GO_BIN),)
GO_BIN := $(shell go env GOPATH)/bin
endif

GOIMPORTS_BIN := $(GO_BIN)/gosimports
LINT_BIN := $(GO_BIN)/golangci-lint
GOACC_BIN := $(GO_BIN)/go-acc

LINT_VERSION := v1.60.1
GOACC_VERSION := v0.2.8

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

$(GOIMPORTS_BIN):
	@$(call print, "Installing goimports.")
	cd $(TOOLS_DIR); $(GOCC) install -trimpath $(GOIMPORTS_PKG)

$(LINT_BIN):
	@$(call print, "Fetching linter")
	$(GOINSTALL) $(LINT_PKG)@$(LINT_VERSION)

$(GOACC_BIN):
	@$(call print, "Fetching go-acc")
	$(GOINSTALL) $(GOACC_PKG)@$(GOACC_VERSION)

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

#? fmt: Fix imports and format source code
fmt: $(GOIMPORTS_BIN)
	@$(call print, "Fixing imports.")
	$(GOIMPORTS_BIN) -w $(GOFILES_NOVENDOR)
	@$(call print, "Formatting source.")
	gofmt -l -w -s $(GOFILES_NOVENDOR)

#? fmt-check: Make sure source code is formatted and imports are correct
fmt-check: fmt
	@$(call print, "Checking fmt results.")
	if test -n "$$(git status --porcelain)"; then echo "code not formatted correctly, please run `make fmt` again!"; git status; git diff; exit 1; fi

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
	fmt-check \
	lint \
	clean

#? help: Get more info on make commands
help: Makefile
	@echo " Choose a command run in btcwallet:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'

.PHONY: help
