# Gust

A CLI tool for managing NVIDIA AIR Spectrum-X simulations.

Gust automates the entire workflow of creating, managing, and connecting to NVIDIA AIR simulations, including SSH key generation, GitHub key management, and secure connections to simulation environments.

## Features

- **Simulation Management**: Create, start, stop, and delete NVIDIA AIR simulations
- **Automatic SSH Key Handling**: Generates per-simulation SSH keys and uploads them to GitHub
- **Secure Connections**: Connect to simulation oob-mgmt-server with automatic password management
- **File Transfer**: SCP files to simulations before connecting
- **Default Topology**: Built-in Spectrum-X topology for quick simulation creation
- **Custom Topologies**: Support for custom JSON topology files

## Prerequisites

- **Python**: 3.9 or higher
- **GitHub CLI**: `gh` must be installed and authenticated (`gh auth login`)
- **NVIDIA AIR Account**: Valid credentials with API token
- **SSH**: OpenSSH client for key generation and connections

### Installing GitHub CLI

```bash
# Ubuntu/Debian
sudo apt install gh

# macOS
brew install gh

# Then authenticate
gh auth login
```

## Installation

### From PyPI (when published)

```bash
pip install gust
```

### From Source

```bash
git clone https://github.com/spectrocloud/gust.git
cd gust
pip install .
```

### Development Installation

```bash
git clone https://github.com/spectrocloud/gust.git
cd gust
make install-dev
```

## Quick Start

1. **Set up credentials**:
   ```bash
   export AIR_USERNAME="your-email@example.com"
   export AIR_TOKEN="your-nvidia-air-api-token"
   ```

2. **Authenticate GitHub CLI**:
   ```bash
   gh auth login
   ```

3. **Create a simulation**:
   ```bash
   gust -l "my-test"
   ```

4. **Start the simulation**:
   ```bash
   gust --start <SIM_ID>
   ```

5. **Connect to the simulation**:
   ```bash
   gust --connect <SIM_ID>
   ```

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `AIR_USERNAME` | NVIDIA AIR username (email address) |
| `AIR_TOKEN` | NVIDIA AIR API token |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_KEY_DIR` | `~/.ssh` | Directory for storing SSH keys |
| `GITHUB_USERNAME` | Auto-detected via `gh` | GitHub username for ZTP script |

### Command-Line Options

```
gust [OPTIONS]

Options:
  --version             Show version and exit
  -u, --username TEXT   NVIDIA AIR username (overrides AIR_USERNAME)
  -t, --token TEXT      NVIDIA AIR API token (overrides AIR_TOKEN)
  -j, --json FILE       Path to custom topology JSON file
  -k, --key-dir DIR     Directory for SSH keys (default: ~/.ssh)
  -l, --label TEXT      Label suffix for simulation name
  -o, --org TEXT        Organization name (default: spectrocloud2)

Commands (mutually exclusive):
  --list                List all simulations
  --start ID            Start a simulation
  --stop ID             Stop a simulation
  --connect ID          Connect to a simulation
  --delete ID           Delete simulation(s), comma-separated

Additional:
  --copy PATH           File/directory to SCP (requires --connect)
```

## Usage

### Creating Simulations

**Create with default Spectrum-X topology:**
```bash
gust -l "dev-test"
```

**Create with custom topology:**
```bash
gust -j my-topology.json -l "custom-test"
```

**Create in a specific organization:**
```bash
gust -l "dev-test" -o "my-organization"
```

### Listing Simulations

```bash
gust --list
```

Output shows all simulations with ID, title, state, owner, and creation date. Your simulations are marked with `*`.

### Starting and Stopping

**Start a simulation:**
```bash
gust --start <SIM_ID>
```

**Stop a simulation:**
```bash
gust --stop <SIM_ID>
```

### Connecting to Simulations

**Basic connection:**
```bash
gust --connect <SIM_ID>
```

**Copy files before connecting:**
```bash
gust --connect <SIM_ID> --copy ./my-files/
```

This will:
1. Find or create an SSH service for `oob-mgmt-server`
2. Handle initial password change (nvidia → SpectrumX123!)
3. SCP the specified files (if `--copy` provided)
4. Open an interactive SSH session

### Deleting Simulations

**Delete a single simulation:**
```bash
gust --delete <SIM_ID>
```

**Delete multiple simulations:**
```bash
gust --delete <SIM_ID1>,<SIM_ID2>,<SIM_ID3>
```

Deletion also removes:
- Associated SSH key from GitHub
- Local SSH key files

## SSH Key Management

Gust automatically manages SSH keys for each simulation:

1. **Key Generation**: Creates an ED25519 key pair named after the simulation
2. **GitHub Upload**: Uploads the public key to your GitHub account
3. **AIR Integration**: Adds the key to your NVIDIA AIR profile
4. **ZTP Configuration**: Updates the topology's ZTP script with your GitHub username
5. **Cleanup**: Removes keys from GitHub and locally when deleting simulations

Keys are stored in `SSH_KEY_DIR` (default: `~/.ssh`):
```
~/.ssh/
├── username-1234567890-dev-test      # Private key
└── username-1234567890-dev-test.pub  # Public key
```

## Simulation Naming Convention

Simulations are named using the pattern:
```
{username_prefix}-{epoch_timestamp}-{label}
```

Example: `john-doe-1704067200-dev-test`

- **username_prefix**: Email prefix with dots replaced by dashes
- **epoch_timestamp**: Unix timestamp at creation
- **label**: Optional label provided via `-l`

## Development

### Setup

```bash
git clone https://github.com/spectrocloud/gust.git
cd gust
make install-dev
```

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make` | Run checks and tests (default) |
| `make install` | Install package |
| `make install-dev` | Install with dev dependencies |
| `make uninstall` | Uninstall package |
| `make build` | Build distribution packages |
| `make clean` | Remove build artifacts |
| `make test` | Run tests |
| `make coverage` | Run tests with coverage report |
| `make lint` | Run pylint |
| `make format` | Format code with black |
| `make format-check` | Check formatting |
| `make check` | Run lint + format-check |
| `make ci` | Full CI pipeline |
| `make help` | Show all targets |

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run specific test file
python -m pytest tests/test_cli.py -v
```

### Code Quality

```bash
# Check pylint score (must be 10.0/10)
make lint

# Format code
make format

# Check formatting
make format-check
```

## Project Structure

```
gust/
├── gust/
│   ├── __init__.py           # Package version
│   ├── cli.py                # Main CLI and commands
│   ├── keys.py               # SSH and GitHub key management
│   ├── topology.py           # Topology loading utilities
│   └── default_topology.json # Built-in Spectrum-X topology
├── tests/
│   ├── conftest.py           # Pytest fixtures
│   ├── test_cli.py           # CLI tests
│   ├── test_keys.py          # Key management tests
│   └── test_topology.py      # Topology tests
├── Makefile                  # Build and development commands
├── pyproject.toml            # Package configuration
└── README.md                 # This file
```

## Troubleshooting

### "gh CLI not authenticated"

Run `gh auth login` and follow the prompts to authenticate with GitHub.

### "Missing GitHub permission for SSH key management"

Gust will automatically request the `admin:public_key` scope. Follow the browser prompt to grant permission.

### "SSH key not found"

Ensure the simulation was created with gust, or manually create a key:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/<simulation-title>
```

### "Simulation not found"

Verify the simulation ID with `gust --list`.

### "Cannot delete/stop simulation - owned by another user"

You can only manage simulations you created. Check the owner column in `gust --list`.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make ci`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Standards

- Pylint score must be 10.0/10
- Test coverage must be >= 95%
- Code must be formatted with black

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [NVIDIA AIR](https://air.nvidia.com/)
- [NVIDIA AIR Documentation](https://docs.nvidia.com/networking-ethernet-software/nvidia-air/)
