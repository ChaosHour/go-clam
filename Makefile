# Makefile for go-clam project

# Variables
BINARY_NAME = clam
BINARY_PATH = bin/go-clam
GO = go
SRC_DIR = cmd/clam
MAIN_FILE = $(SRC_DIR)/main.go
GOFLAGS = -ldflags="-s -w"

# Ensure the build directory exists
$(shell mkdir -p $(dir $(BINARY_PATH)))

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build:
	@echo "Building go-clam..."
	$(GO) build $(GOFLAGS) -o $(BINARY_PATH) $(MAIN_FILE)
	@echo "Binary created at $(BINARY_PATH)"

# Clean the build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_PATH)
	@echo "Cleaned!"

# Install the application
.PHONY: install
install: build
	@echo "Installing go-clam..."
	mkdir -p $(HOME)/bin
	cp $(BINARY_PATH) $(HOME)/bin/$(BINARY_NAME)
	@echo "Installed to $(HOME)/bin/$(BINARY_NAME)"

# Run the application
.PHONY: run
run: build
	@echo "Running go-clam..."
	./$(BINARY_PATH)

# Build with debug information
.PHONY: debug
debug:
	@echo "Building with debug info..."
	$(GO) build -o $(BINARY_PATH) $(MAIN_FILE)

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test ./...

# Show help
.PHONY: help
help:
	@echo "go-clam Makefile"
	@echo "Available targets:"
	@echo "  all      - Build the application (default)"
	@echo "  build    - Build the application"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install the application to ~/bin"
	@echo "  run      - Build and run the application"
	@echo "  debug    - Build with debug information"
	@echo "  test     - Run tests"
	@echo "  help     - Show this help message"
