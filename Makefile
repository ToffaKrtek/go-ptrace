.PHONY: build test example clean

BUILD_DIR := bin
EXAMPLE_DIR := examples/hooklib

build:
	@echo "Building go-ptrace..."
	go build -o $(BUILD_DIR)/go-ptrace ./cmd/cli/
	@echo "Built $(BUILD_DIR)/go-ptrace"

test:
	@echo "Running tests..."
	go test -v ./...

example:
	@echo "Building hooklib.so..."
	gcc -shared -fPIC -o $(EXAMPLE_DIR)/hooklib.so $(EXAMPLE_DIR)/hooklib.c
	@echo "Built $(EXAMPLE_DIR)/hooklib.so"

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(EXAMPLE_DIR)/hooklib.so
	rm -f /tmp/go-ptrace-hook.log
	@echo "Cleaned"
