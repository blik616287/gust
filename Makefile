.PHONY: all install install-dev build clean dist test coverage lint format check help

PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
PYLINT := $(PYTHON) -m pylint
BLACK := $(PYTHON) -m black

PACKAGE := gust
SRC_DIR := gust
TEST_DIR := tests

# Default target - do everything
all: clean install-dev check coverage build install

# Install package in production mode
install:
	$(PIP) install .

# Install package in development mode with dev dependencies
install-dev:
	$(PIP) install -e ".[dev]"

# Uninstall the package
uninstall:
	$(PIP) uninstall -y $(PACKAGE)

# Build distribution packages
build: clean
	$(PYTHON) -m build

# Create source and wheel distributions
dist: build

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf $(SRC_DIR)/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .eggs/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true

# Run tests
test:
	$(PYTEST) $(TEST_DIR)/ -v

# Run tests with coverage report
coverage:
	$(PYTEST) $(TEST_DIR)/ --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

# Run pylint
lint:
	$(PYLINT) $(SRC_DIR)/

# Run black formatter
format:
	$(BLACK) $(SRC_DIR)/ $(TEST_DIR)/

# Check formatting without modifying files
format-check:
	$(BLACK) --check $(SRC_DIR)/ $(TEST_DIR)/

# Run all checks (lint + format-check)
check: lint format-check

# Show help
help:
	@echo "Gust - CLI tool for managing NVIDIA AIR Spectrum-X simulations"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          Full build: clean, install-dev, check, coverage, build, install (default)"
	@echo "  install      Install package in production mode"
	@echo "  install-dev  Install package in development mode with dev dependencies"
	@echo "  uninstall    Uninstall the package"
	@echo "  build        Build distribution packages (sdist and wheel)"
	@echo "  dist         Alias for build"
	@echo "  clean        Remove build artifacts and cache files"
	@echo "  test         Run tests"
	@echo "  coverage     Run tests with coverage report"
	@echo "  lint         Run pylint"
	@echo "  format       Format code with black"
	@echo "  format-check Check code formatting without changes"
	@echo "  check        Run lint and format-check"
	@echo "  help         Show this help message"
