DEV_TAGS = dev
LOG_TAGS =

GOCC ?= go
GOLIST := $(GOCC) list -tags="$(DEV_TAGS)" -deps $(PKG)/... | grep '$(PKG)'
GOTEST := GO111MODULE=on $(GOCC) test

TEST_FLAGS =
COVER_PKG = $$($(GOCC) list -deps -tags="$(DEV_TAGS)" ./... | grep '$(PKG)')
COVER_FLAGS = -coverprofile=coverage.txt -covermode=atomic -coverpkg=$(PKG)/...

# If specific package is being unit tested, construct the full name of the
# subpackage.
ifneq ($(pkg),)
UNITPKG := $(PKG)/$(pkg)
UNIT_TARGETED = yes
COVER_PKG = $(PKG)/$(pkg)
endif

# If a specific unit test case is being target, construct test.run filter.
ifneq ($(case),)
TEST_FLAGS += -test.run=$(case)
UNIT_TARGETED = yes
endif

# If a timeout was requested, construct initialize the proper flag for the go
# test command. If not, we set 20m (btcwallet default).
ifneq ($(timeout),)
TEST_FLAGS += -test.timeout=$(timeout)
else
TEST_FLAGS += -test.timeout=20m
endif

ifneq ($(verbose),)
TEST_FLAGS += -test.v
endif

ifneq ($(nocache),)
TEST_FLAGS += -test.count=1
endif

# Define the log tags that will be applied only when running unit tests. If none
# are provided, we default to "debug stdlog" which will be standard debug log
# output.
ifneq ($(log),)
LOG_TAGS := $(log)
else
LOG_TAGS := debug stdlog
endif

# UNIT_TARGETED is undefined iff a specific package and/or unit test case is
# not being targeted.
UNIT_TARGETED ?= no

# If a specific package/test case was requested, run the unit test for the
# targeted case. Otherwise, default to running all tests.
ifeq ($(UNIT_TARGETED), yes)
UNIT := $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(UNITPKG)
UNIT_DEBUG := $(GOTEST) -v -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(UNITPKG)
UNIT_RACE := $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) -race $(UNITPKG)

# NONE is a special value which selects no other tests but only executes the
# benchmark tests here.
UNIT_BENCH := $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" -test.bench=. -test.run=NONE $(UNITPKG)
endif

ifeq ($(UNIT_TARGETED), no)
UNIT := $(GOLIST) | $(XARGS) env $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS)
UNIT_DEBUG := $(GOLIST) | $(XARGS) env $(GOTEST) -v -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS)

# NONE is a special value which selects no other tests but only executes the
# benchmark tests here.
UNIT_BENCH := $(GOLIST) | $(XARGS) env $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" -test.bench=. -test.run=NONE
UNIT_RACE := $(UNIT) -race
endif

UNIT_COVER := $(GOTEST) $(COVER_FLAGS) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(COVER_PKG)
