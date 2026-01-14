# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make                 # Full build: clean, install-dev, check, coverage, build, install
make install-dev     # Install with dev dependencies
make test            # Run tests
make coverage        # Run tests with coverage (must be >= 95%)
make lint            # Run pylint (must achieve 10.0/10)
make format          # Format code with black
make format-check    # Check formatting
make check           # Run lint + format-check

# Run a single test file
python -m pytest tests/test_cli.py -v

# Run a specific test
python -m pytest tests/test_cli.py::test_function_name -v
```

## Code Quality Requirements

All changes must pass:
- **Pylint**: Score of 10.0/10 (no exceptions)
- **Coverage**: >= 95% test coverage
- **Formatting**: Code formatted with black

## Architecture Overview

Gust is a CLI tool for managing NVIDIA AIR Spectrum-X simulations. It automates SSH key generation, GitHub key management, and secure connections to simulation environments.

### Core Modules

- **cli.py**: Main CLI entry point and all command handlers. Commands are routed via `_route_command()` based on mutually exclusive argparse groups.
- **keys.py**: `SSHKeyManager` class for ED25519 key generation, `GitHubKeyManager` for GitHub SSH key operations via `gh` CLI.
- **topology.py**: Loads default Spectrum-X topology from `default_topology.json`.

### Simulation Creation Workflow (9 steps in `cmd_create`)

1. Get GitHub username (auto-detect via `gh api user`)
2. Generate simulation name: `{username_prefix}-{epoch}-{label}`
3. Generate ED25519 SSH key pair named after simulation
4. Upload public key to GitHub
5. Update topology's ZTP script with GitHub username
6. Authenticate with NVIDIA AIR API
7. Add SSH key to AIR user profile
8. Get organization details
9. Create simulation via POST to `air.nvidia.com/api/v2/simulation/import/`

### External Dependencies

The codebase requires these external tools:
- `gh` CLI (GitHub CLI) for SSH key management
- `ssh-keygen`, `ssh`, `scp` (OpenSSH tools)

### Key Patterns

- **Per-simulation SSH keys**: Each simulation gets its own ED25519 key pair named after the simulation title, stored in `~/.ssh/`
- **Password automation**: Uses pexpect to handle initial SSH password change (nvidia → SpectrumX123!)
- **Interactive SSH**: `cmd_connect` uses `os.execvp()` to replace process with SSH session
