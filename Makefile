DATE    ?= $(shell date +%FT%T%z)
GOPATH   = $(CURDIR)/vendor/gopath
BIN      = $(CURDIR)/vendor
BASE     = $(CURDIR)
MODULE = $(shell cd $(BASE) && $(GO) list -m)
PKGS     = $(or $(PKG),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list ./...))
BUILDS   = $(or $(BUILD),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list -f "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}" ./...))
GIT_VERSION=$(shell git describe --match "v*" 2> /dev/null || cat $(CURDIR)/.version 2> /dev/null || echo v0.0-0-)
BASE_VERSION=$(shell echo $(GIT_VERSION) | cut -f1 -d'-')
MAJOR_VERSION=$(shell echo $(BASE_VERSION) | cut -f1 -d'.' | cut -f2 -d'v')
MINOR_VERSION=$(shell echo $(BASE_VERSION) | cut -f2 -d'.')
BUILD_VERSION=$(shell echo $(BASE_VERSION) | cut -f3 -d'.' || echo 0)
BUILD_OFFSET=$(shell echo $(GIT_VERSION) | cut -s -f2 -d'-' )
CODE_OFFSET=$(shell [ -z "$(BUILD_OFFSET)" ] && echo "0" || echo "$(BUILD_OFFSET)")
BUILD_NUMBER=$(shell echo $$(( $(BUILD_VERSION) + $(CODE_OFFSET) )))
VERSION ?= ${MAJOR_VERSION}.${MINOR_VERSION}.${BUILD_NUMBER}

export -n GOBIN
export GOPATH
#export PATH=$(BIN): $(shell printenv PATH)

GO      = go
GODOC   = godoc
GOFMT   = gofmt
TIMEOUT = 25
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

SHELL=bash

.PHONY: all
all: log-variables checkfmt lint test-short | $(BASE) ; $(info $(M) building executable(s)… $(VERSION) $(DATE)) @ ## Build program binary
	$Q cd $(CURDIR) && $(GO) generate ./...
	@ret=0 && for d in $(BUILDS); do \
		if expr \"$$d\" : \"${MODULE}\" 1>/dev/null; then SRCPATH=$(CURDIR) ; else SRCPATH=$(CURDIR)/$${d/${MODULE}\//} ; fi ;  \
		echo $$d; \
		cd $${SRCPATH} && env GOBIN=$(CURDIR)/bin $(GO) install \
			-tags release \
			-ldflags '-X main.Version=$(VERSION) -X main.Build=$(DATE)' || ret=$$? ; \
	 done ; exit $$ret

# Tools

$(BIN):
	@mkdir -p $@
	
$(BIN)/%: | $(BIN) $(BASE) ; $(info $(M) building $(REPOSITORY)…)
	$Q tmp=$$(mktemp -d); \
		(cd $(tmp) && GOPATH=$$tmp $(GO) get $(REPOSITORY) && cp $$tmp/bin/* $(BIN)/.) || ret=$$?; \
		rm -rf $$tmp ; exit $$ret

GOLINT = $(BIN)/golint
$(GOLINT): REPOSITORY=golang.org/x/lint/golint

# Tests

TEST_TARGETS := test-default test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test-xml check test tests
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
check test tests: checkfmt lint | $(BASE) ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q cd $(CURDIR) && $(GO) test -v -gcflags=-l -timeout $(TIMEOUT)s $(ARGS) ./...

.PHONY: cover
cover: checkfmt lint | $(BASE) ; $(info $(M) running coverage…) @ ## Run code coverage tests
	$Q cd $(BASE) && 2>&1 $(GO) test -v -gcflags=-l ./... -coverprofile=c.out
	$Q cd $(BASE) && 2>&1 $(GO) tool cover -html=c.out
	$Q cd $(BASE) && 2>&1 rm -f c.out

.PHONY: lint
lint:  $(BASE) $(GOLINT) ; $(info $(M) running golint…) @ ## Run golint
	$Q cd $(BASE) && $(GOLINT) -set_exit_status $(PKGS)

.PHONY: checkfmt
checkfmt: ; $(info $(M) Checking formatting…) @ ## Run gofmt to cehck formatting on all source files 
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./...); do \
	    if [ $$($(GOFMT) -l $$d/*.go | wc -l | sed 's| ||g') -ne "0" ] ; then \
	    $(GOFMT) -l $$d/*.go ; \
        ret=1 ; \
    	fi ; \
	 done ; exit $$ret

.PHONY: fixfmt
fixfmt: ; $(info $(M) Fixings formatting…) @ ## Run gofmt to fix formatting on all source files
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./...); do \
		$(GOFMT) -l -w $$d/*.go || ret=$$? ; \
	 done ; exit $$ret

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	@rm -rf bin
	@chmod -R +w vendor
	@rm -rf vendor
	@rm -f c.out
	@rm -f go.sum
	@rm -f test.html

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: swagger
swagger: ;
	swag init -g driver/web/adapter.go

.PHONY: log-variables
log-variables: ; $(info $(M) Log info…) @ ## Log the variables values
	@echo "DATE:"$(DATE)
	@echo "GOPATH:"$(GOPATH)
	@echo "BIN:"$(BIN)
	@echo "BASE:"$(BASE)
	@echo "MODULE:"$(MODULE)
	@echo "PKGS:"$(PKGS)
	@echo "BUILDS:"$(BUILDS)
	@echo "GIT_VERSION:"$(GIT_VERSION)
	@echo "BASE_VERSION:"$(BASE_VERSION)
	@echo "MAJOR_VERSION:"$(MAJOR_VERSION)
	@echo "MINOR_VERSION:"$(MINOR_VERSION)
	@echo "BUILD_VERSION:"$(BUILD_VERSION)
	@echo "BUILD_OFFSET:"$(BUILD_OFFSET)
	@echo "CODE_OFFSET:"$(CODE_OFFSET)
	@echo "BUILD_NUMBER:"$(BUILD_NUMBER)
	@echo "VERSION:"$(VERSION)




