TEST_FLAGS =
COVER_PKG = $$($(GOCC) list -deps ./... | grep '$(PKG)')
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

GOLIST := $(GOCC) list -deps $(PKG)/... | grep '$(PKG)'

# UNIT_TARGETED is undefined iff a specific package and/or unit test case is
# not being targeted.
UNIT_TARGETED ?= no

# If a specific package/test case was requested, run the unit test for the
# targeted case. Otherwise, default to running all tests.
ifeq ($(UNIT_TARGETED), yes)
UNIT := $(GOTEST) $(TEST_FLAGS) $(UNITPKG)
endif

ifeq ($(UNIT_TARGETED), no)
UNIT := $(GOLIST) | $(XARGS) env $(GOTEST) $(TEST_FLAGS)
endif

UNIT_COVER := $(GOTEST) $(COVER_FLAGS) $(TEST_FLAGS) $(COVER_PKG)
