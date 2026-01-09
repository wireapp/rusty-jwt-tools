.PHONY: help
# Parse the comment starting with a double ## next to a target as the target description
# in the help message
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

SHELL := /usr/bin/env bash

# Only build in release mode if explicitly requested by
# setting the `RELEASE` variable to any non-empty value, e.g.
#
#   make all RELEASE=1
ifeq ($(RELEASE),)
  CARGO_BUILD_ARGS :=
  RELEASE_MODE := debug
else
  CARGO_BUILD_ARGS := --release
  RELEASE_MODE := release
endif

TARGET_DIR := target/$(RELEASE_MODE)

# Detect host platform for NDK and library extensions
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  PLATFORM_DIR       := linux-x86_64
  LIBRARY_EXTENSION  := so
else ifeq ($(UNAME_S),Darwin)
  PLATFORM_DIR       := darwin-x86_64
  LIBRARY_EXTENSION  := dylib
else
  $(error Unsupported host platform $(UNAME_S))
endif

.DEFAULT_GOAL = all
.PHONY: all
all: ## Build the FFI library
	cargo build $(CARGO_BUILD_ARGS) --locked

.PHONY: test
test: ## Run Rust tests
	cargo nextest run $(CARGO_BUILD_ARGS) --locked

.PHONY: ffi-test
ffi-test: ## Test the FFI library
	python ffi/test/test-bindings.py $(TARGET_DIR)/librusty_jwt_tools_ffi.$(LIBRARY_EXTENSION)

.PHONY: clean
clean: ## Clean up everything
	cargo clean
