DATE    ?= $(shell date +%FT%T%z)
GOBIN    = $(CURDIR)/bin
BASE     = $(CURDIR)
MODULE = $(shell cd $(BASE) && $(GO) list -m)
PKGS     = $(or $(PKG),$(shell cd $(BASE) && $(GO) list ./...))
BUILDS   = $(or $(BUILD),$(shell cd $(BASE) && $(GO) list -f "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}" ./...))
GIT_VERSION=$(shell git describe --tags --match "v*" 2> /dev/null || cat $(CURDIR)/.version 2> /dev/null || echo v0.0-0-)
BASE_VERSION=$(shell echo $(GIT_VERSION) | cut -f1 -d'-')
MAJOR_VERSION=$(shell echo $(BASE_VERSION) | cut -f1 -d'.' | cut -f2 -d'v')
MINOR_VERSION=$(shell echo $(BASE_VERSION) | cut -f2 -d'.')
PATCH_VERSION=$(shell echo $(BASE_VERSION) | cut -f3 -d'.' || echo 0)
COMMIT_OFFSET=$(shell echo $(GIT_VERSION) | cut -s -f2 -d'-')
COMMIT_HASH=$(shell echo $(GIT_VERSION) | cut -s -f3 -d'-')
VERSION=${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}$(if $(COMMIT_OFFSET),+$(COMMIT_OFFSET),)

export -n GOBIN

GO      = go
GODOC   = godoc
GOFMT   = gofmt
GOVET	= go vet
GOLINT  = $(GOBIN)/golint
GOVULN  = $(GOBIN)/govulncheck
TIMEOUT = 25
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

SHELL=sh

.PHONY: all
all: vendor log-variables checkfmt lint vet vuln test-short | $(BASE) ; $(info $(M) building executable(s)... $(VERSION) $(DATE)) @ ## Build program binary
	$Q cd $(CURDIR) && $(GO) generate ./...
	@ret=0 && for d in $(BUILDS); do \
		if expr \"$$d\" : \"${MODULE}\" 1>/dev/null; then SRCPATH=$(CURDIR) ; else SRCPATH=$(CURDIR)/$${d/${MODULE}\//} ; fi ;  \
		echo $$d; \
		cd $${SRCPATH} && $(GO) install \
			-tags release \
			-ldflags '-X main.Version=$(VERSION) -X main.Build=$(DATE)' || ret=$$? ; \
	 done ; exit $$ret

# Tests

TEST_TARGETS := test-default test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test-xml check test tests
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
check test tests: checkfmt lint vet | $(BASE) ; $(info $(M) running $(NAME:%=% )tests...) @ ## Run tests
	$Q cd $(CURDIR) && $(GO) test -v -gcflags=-l -timeout $(TIMEOUT)s $(ARGS) ./...

.PHONY: cover
cover: tools checkfmt lint vet | $(BASE) ; $(info $(M) running coverage...) @ ## Run code coverage tests
	$Q cd $(BASE) && 2>&1 $(GO) test -v -gcflags=-l ./... -coverprofile=c.out
	$Q cd $(BASE) && 2>&1 $(GO) tool cover -html=c.out
	$Q cd $(BASE) && 2>&1 rm -f c.out

.PHONY: lint
lint: tools | $(BASE) $(GOLINT) ; $(info $(M) running golint...) @ ## Run golint
	$Q cd $(BASE) && $(GOLINT) -set_exit_status $(PKGS)

.PHONY: vet
vet: ; $(info $(M) running go vet...) @ ## Run go vet
	$Q cd $(CURDIR) && $(GOVET) $(PKGS)

.PHONY: checkfmt
checkfmt: ; $(info $(M) checking formatting...) @ ## Run gofmt to cehck formatting on all source files 
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./...); do \
	    if [ $$($(GOFMT) -l $$d/*.go | wc -l | sed 's| ||g') -ne "0" ] ; then \
	    $(GOFMT) -l $$d/*.go ; \
        ret=1 ; \
    	fi ; \
	 done ; exit $$ret

.PHONY: fixfmt
fixfmt: vendor ; $(info $(M) fixing formatting...) @ ## Run gofmt to fix formatting on all source files
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./...); do \
		$(GOFMT) -l -w $$d/*.go || ret=$$? ; \
	 done ; exit $$ret

.PHONY: vuln
vuln: tools ; $(info $(M) running govulncheck...) @ ## Run govulncheck
	$Q cd $(CURDIR) && $(GOVULN) ./...

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning...)	@ ## Cleanup everything
	@rm -rf bin
	@chmod -R +w vendor
	@rm -rf vendor
	@rm -f c.out
	@rm -f test.html

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: vendor
vendor:
	$(GO) mod vendor

.PHONY: oapi-gen-types
oapi-gen-types: ;
	oapi-codegen --config oapi-codegen-config.yaml driver/web/docs/gen/def.yaml

.PHONY: oapi-gen-docs
oapi-gen-docs: ;
	swagger-cli bundle driver/web/docs/index.yaml --outfile driver/web/docs/gen/def.yaml --type yaml

.PHONY: log-variables
log-variables: ; $(info $(M) logging variables...) @ ## Log the variables values
	@echo "DATE:"$(DATE)
	@echo "GOBIN:"$(GOBIN)
	@echo "BASE:"$(BASE)
	@echo "MODULE:"$(MODULE)
	@echo "PKGS:"$(PKGS)
	@echo "BUILDS:"$(BUILDS)
	@echo "GIT_VERSION:"$(GIT_VERSION)
	@echo "BASE_VERSION:"$(BASE_VERSION)
	@echo "MAJOR_VERSION:"$(MAJOR_VERSION)
	@echo "MINOR_VERSION:"$(MINOR_VERSION)
	@echo "PATCH_VERSION:"$(PATCH_VERSION)
	@echo "COMMIT_OFFSET:"$(COMMIT_OFFSET)
	@echo "COMMIT_HASH:"$(COMMIT_HASH)
	@echo "VERSION:"$(VERSION)

# Tools

.PHONY: tools
tools: ; $(info $(M) installing tools...) @ ## Install tools
	go install golang.org/x/tools/cmd/cover@latest
	go install golang.org/x/lint/golint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
