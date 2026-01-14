#!/usr/bin/env python3
"""
Gust - CLI tool for managing NVIDIA AIR Spectrum-X simulations.

Automates: SSH key gen, GitHub key upload, JSON update,
AIR simulation creation, and SSH connection.
Uses the official NVIDIA AIR Python SDK.
"""

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from air_sdk import AirApi
import requests as req
import pexpect

from . import __version__
from .keys import SSHKeyManager, GitHubKeyManager
from .topology import load_default_topology


# Default password for oob-mgmt-server (changed from 'nvidia')
DEFAULT_OOB_PASSWORD = "SpectrumX123!"

# Request timeout in seconds
REQUEST_TIMEOUT = 60


@dataclass
class Colors:
    """ANSI color codes for terminal output."""

    red: str = "\033[0;31m"
    green: str = "\033[0;32m"
    yellow: str = "\033[1;33m"
    cyan: str = "\033[0;36m"
    reset: str = "\033[0m"


@dataclass
class SSHConnection:
    """SSH connection parameters."""

    host: str
    port: int
    key_path: Path
    user: str


def log(msg: str) -> None:
    """Print an info message to stdout."""
    print(f"{Colors.green}[INFO]{Colors.reset} {msg}")


def warn(msg: str) -> None:
    """Print a warning message to stdout."""
    print(f"{Colors.yellow}[WARN]{Colors.reset} {msg}")


def error(msg: str) -> None:
    """Print an error message and exit with code 1."""
    print(f"{Colors.red}[ERROR]{Colors.reset} {msg}")
    sys.exit(1)


def update_json_ssh_url(json_data, github_username: str) -> dict:
    """
    Update SSH_URL in JSON data and return the modified data.

    Args:
        json_data: Dict or Path to JSON file
        github_username: GitHub username to use

    Returns:
        Modified JSON data as dict
    """
    if isinstance(json_data, Path):
        with open(json_data, encoding="utf-8") as file:
            data = json.load(file)
    else:
        data = copy.deepcopy(json_data)

    if "ztp" in data:
        data["ztp"] = re.sub(
            r"github\.com/[^.]*\.keys",
            f"github.com/{github_username}.keys",
            data["ztp"],
        )
        log(f"Updated SSH_URL to use GitHub username: {github_username}")

    return data


def generate_sim_name(username: str, label: Optional[str] = None) -> str:
    """
    Generate simulation name: {username_prefix}-{epoch}-{label}.

    Args:
        username: User email address
        label: Optional label suffix

    Returns:
        Generated simulation name
    """
    prefix = username.split("@")[0].replace(".", "-")
    epoch = int(time.time())

    if label:
        return f"{prefix}-{epoch}-{label}"
    return f"{prefix}-{epoch}"


def get_air_client(username: str, password: str) -> AirApi:
    """
    Create and authenticate AIR API client.

    Args:
        username: AIR username
        password: AIR API token

    Returns:
        Authenticated AirApi client
    """
    try:
        return AirApi(username=username, password=password)
    except (ConnectionError, ValueError) as exc:
        error(f"Failed to authenticate with AIR API: {exc}")
        return None  # Never reached, but satisfies return type


def create_simulation_from_json(
    air: AirApi, json_data: dict, start: bool = True
) -> str:
    """
    Create a simulation using JSON topology via the import endpoint.

    Args:
        air: Authenticated AirApi client
        json_data: Topology JSON data
        start: Whether to start the simulation

    Returns:
        Simulation ID

    Raises:
        ValueError: If API returns an error
    """
    json_data["start"] = start

    auth_header = air.client.headers.get("authorization")
    if not auth_header:
        raise ValueError("No authorization token found in SDK client")

    response = req.post(
        "https://air.nvidia.com/api/v2/simulations/import/",
        headers={"Authorization": auth_header, "Content-Type": "application/json"},
        json=json_data,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code != 201:
        raise ValueError(f"API returned {response.status_code}: {response.text}")

    return response.json().get("id")


def wait_for_simulation(
    air: AirApi, sim_id: str, target_states: list, max_wait: int = 300
) -> str:
    """
    Wait for simulation to reach target state.

    Args:
        air: Authenticated AirApi client
        sim_id: Simulation ID
        target_states: List of acceptable target states
        max_wait: Maximum wait time in seconds

    Returns:
        Final simulation state
    """
    wait_interval = 10
    elapsed = 0

    while elapsed < max_wait:
        sim = air.simulations.get(sim_id)
        state = sim.state
        log(f"Simulation state: {state} (waited {elapsed}s)")

        if state in target_states:
            return state
        if state in ("ERROR", "FAILED"):
            error(f"Simulation failed with state: {state}")

        time.sleep(wait_interval)
        elapsed += wait_interval

    error(f"Timeout waiting for simulation after {max_wait}s")
    return ""  # Never reached


def _get_worker_fqdn(air: AirApi, node) -> Optional[str]:
    """Get worker FQDN from node."""
    if hasattr(node.worker, "fqdn"):
        return node.worker.fqdn
    worker = air.workers.get(node.worker)
    return worker.fqdn


def get_or_create_ssh_service(air: AirApi, simulation) -> Optional[tuple]:
    """
    Get or create SSH service for oob-mgmt-server.

    Args:
        air: Authenticated AirApi client
        simulation: Simulation object

    Returns:
        Tuple of (ssh_port, worker_fqdn) or None
    """
    services = air.services.list(simulation=simulation)
    for svc in services:
        if svc.name == "ssh" and svc.dest_port == 22:
            nodes = air.simulation_nodes.list(simulation=simulation)
            for node in nodes:
                if node.name == "oob-mgmt-server":
                    fqdn = _get_worker_fqdn(air, node)
                    if fqdn:
                        return svc.src_port, fqdn

    log("Creating SSH service for oob-mgmt-server...")
    try:
        svc = simulation.create_service(
            "ssh", "oob-mgmt-server:eth0", 22, service_type="ssh"
        )
        log(f"Created SSH service on port {svc.src_port}")

        nodes = air.simulation_nodes.list(simulation=simulation)
        for node in nodes:
            if node.name == "oob-mgmt-server":
                fqdn = _get_worker_fqdn(air, node)
                if fqdn:
                    return svc.src_port, fqdn
    except (ConnectionError, ValueError) as exc:
        warn(f"Failed to create SSH service: {exc}")

    return None


def _handle_password_prompt(child, old_password: str, new_password: str) -> bool:
    """Handle the password change interaction."""
    child.sendline(old_password)
    child.expect(r"New password:", timeout=10)
    child.sendline(new_password)
    child.expect(r"Retype new password:", timeout=10)
    child.sendline(new_password)

    index = child.expect(
        [
            r"passwd: password updated successfully",
            r"Connection to .* closed",
            r"\$ ",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ],
        timeout=10,
    )

    return index <= 2


def change_ssh_password(
    conn: SSHConnection, old_password: str, new_password: str
) -> bool:
    """
    Handle initial SSH password change using pexpect.

    Args:
        conn: SSH connection parameters
        old_password: Current password
        new_password: New password to set

    Returns:
        True if password was changed successfully
    """
    ssh_cmd = (
        f"ssh -p {conn.port} -i {conn.key_path} "
        f"-o StrictHostKeyChecking=no {conn.user}@{conn.host}"
    )
    log(f"Connecting to change password: {conn.user}@{conn.host}:{conn.port}")

    try:
        child = pexpect.spawn(ssh_cmd, timeout=30, encoding="utf-8")

        index = child.expect(
            [
                r"Current password:",
                r"WARNING: Your password has expired",
                r"\$ ",
                r"Permission denied",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ]
        )

        if index == 2:
            log("No password change required")
            child.sendline("exit")
            child.close()
            return True

        if index == 3:
            warn("Permission denied - SSH key not authorized")
            child.close()
            return False

        if index >= 4:
            warn("Timeout or unexpected response during SSH connection")
            child.close()
            return False

        if index == 1:
            child.expect(r"Current password:", timeout=10)

        success = _handle_password_prompt(child, old_password, new_password)
        child.close()

        if success:
            log("Password changed successfully")
            return True

        warn("Unexpected response after password change")
        return False

    except pexpect.ExceptionPexpect as exc:
        warn(f"pexpect error during password change: {exc}")
        return False


def cmd_list(args: argparse.Namespace) -> None:
    """List all simulations."""
    air = get_air_client(args.username, args.token)

    log("Listing all simulations...")
    sims = air.simulations.list()

    print()
    header = f"{'ID':<38} {'TITLE':<25} {'STATE':<12} {'OWNER':<30} {'CREATED':<20}"
    print(header)
    print("=" * 130)

    for sim in sims:
        sim_id = str(sim.id)
        title = (sim.title or "")[:23]
        state = sim.state or ""
        owner = (sim.name or "")[:28]
        created = str(sim.created)[:19] if sim.created else ""
        marker = "*" if owner == args.username else " "
        print(
            f"{sim_id:<38} {title:<25} {state:<12} {owner:<30} {created:<20} {marker}"
        )

    print()
    print("* = Your simulations (can be deleted)")


def _delete_simulation_keys(title: str, key_dir: Path) -> None:
    """Delete SSH keys associated with a simulation."""
    if GitHubKeyManager.is_authenticated():
        if GitHubKeyManager.delete_key(title):
            log(f"Deleted GitHub SSH key: {title}")
        else:
            warn(f"Could not delete GitHub SSH key: {title} (may not exist)")

    key_path = key_dir / title
    pub_key_path = Path(str(key_path) + ".pub")

    if key_path.exists():
        key_path.unlink()
        log(f"Deleted local SSH key: {key_path}")
    if pub_key_path.exists():
        pub_key_path.unlink()
        log(f"Deleted local SSH public key: {pub_key_path}")


def cmd_delete(args: argparse.Namespace) -> None:
    """Delete simulation(s) and associated SSH keys."""
    air = get_air_client(args.username, args.token)
    ids = [sim_id.strip() for sim_id in args.delete.split(",")]
    key_dir = Path(args.key_dir) if hasattr(args, "key_dir") else Path.home() / ".ssh"

    for sim_id in ids:
        try:
            sim = air.simulations.get(sim_id)
        except (ConnectionError, ValueError):
            warn(f"Simulation not found: {sim_id}")
            continue

        owner = sim.name
        title = sim.title or sim_id

        if owner != args.username:
            warn(f"Cannot delete '{title}' ({sim_id}) - owned by {owner}")
            continue

        log(f"Deleting simulation: {title} ({sim_id})")
        try:
            sim.delete()
            log(f"Successfully deleted simulation: {sim_id}")
        except (ConnectionError, ValueError) as exc:
            warn(f"Failed to delete simulation {sim_id}: {exc}")
            continue

        _delete_simulation_keys(title, key_dir)


def scp_to_server(conn: SSHConnection, local_path: str) -> bool:
    """
    SCP file or directory to remote server.

    Args:
        conn: SSH connection parameters
        local_path: Local file/directory path

    Returns:
        True if copy was successful
    """
    local = Path(local_path)
    if not local.exists():
        warn(f"Path does not exist: {local_path}")
        return False

    scp_cmd = [
        "scp",
        "-P",
        str(conn.port),
        "-i",
        str(conn.key_path),
        "-o",
        "StrictHostKeyChecking=no",
    ]

    if local.is_dir():
        scp_cmd.append("-r")

    scp_cmd.extend([str(local), f"{conn.user}@{conn.host}:~"])

    log(f"Copying {local_path} to {conn.user}@{conn.host}:~")

    try:
        result = subprocess.run(scp_cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            log(f"Successfully copied: {local.name}")
            return True
        warn(f"SCP failed: {result.stderr}")
        return False
    except OSError as exc:
        warn(f"SCP error: {exc}")
        return False


def cmd_stop(args: argparse.Namespace) -> None:
    """Stop a running simulation."""
    air = get_air_client(args.username, args.token)

    log(f"Stopping simulation: {args.stop}")

    try:
        sim = air.simulations.get(args.stop)
    except (ConnectionError, ValueError):
        error(f"Simulation not found: {args.stop}")
        return

    sim_title = sim.title or args.stop
    owner = sim.name

    if owner != args.username:
        error(f"Cannot stop '{sim_title}' - owned by {owner}, not {args.username}")

    log(f"Simulation: {sim_title}")

    if sim.state in ("STORED", "NEW"):
        log(f"Simulation is already stopped (state: {sim.state})")
        return

    if sim.state not in ("RUNNING", "LOADED"):
        error(f"Cannot stop simulation in state: {sim.state}")

    sim.stop()
    log("Simulation stop initiated")

    print()
    print(f"Simulation '{sim_title}' is being stopped.")


def cmd_start(args: argparse.Namespace) -> None:
    """Start an existing simulation."""
    air = get_air_client(args.username, args.token)

    log(f"Starting simulation: {args.start}")

    try:
        sim = air.simulations.get(args.start)
    except (ConnectionError, ValueError):
        error(f"Simulation not found: {args.start}")
        return

    sim_title = sim.title or args.start
    log(f"Simulation: {sim_title}")

    if sim.state in ("RUNNING", "LOADED"):
        log(f"Simulation is already running (state: {sim.state})")
        return

    if sim.state not in ("NEW", "STORED"):
        error(f"Cannot start simulation in state: {sim.state}")

    sim.start()
    log("Simulation start initiated")

    state = wait_for_simulation(air, args.start, ["LOADED", "RUNNING"], max_wait=300)
    log(f"Simulation is ready! State: {state}")

    print()
    print(f"Simulation '{sim_title}' is now running.")
    print(f"To connect: gust --connect {args.start}")


def _get_simulation_ssh_key(key_dir: Path, sim_title: str) -> Path:
    """Get SSH key path for simulation, with fallback."""
    ssh_key = key_dir / sim_title

    if not ssh_key.exists():
        fallback_key = key_dir / "spectrum-x"
        if fallback_key.exists():
            warn(f"Key not found at {ssh_key}, using fallback: {fallback_key}")
            return fallback_key
        error(f"SSH key not found: {ssh_key}")

    return ssh_key


def cmd_connect(args: argparse.Namespace) -> None:
    """Connect to existing simulation."""
    air = get_air_client(args.username, args.token)

    log(f"Getting SSH details for simulation: {args.connect}")

    try:
        sim = air.simulations.get(args.connect)
    except (ConnectionError, ValueError):
        error(f"Simulation not found: {args.connect}")
        return

    sim_title = sim.title or args.connect
    log(f"Simulation: {sim_title}")

    if sim.state not in ("RUNNING", "LOADED"):
        error(
            f"Simulation is not running (state: {sim.state}). "
            f"Use --start {args.connect} first."
        )

    result = get_or_create_ssh_service(air, sim)
    if not result:
        error("Could not find oob-mgmt-server in simulation")
        return

    port, fqdn = result
    ssh_key = _get_simulation_ssh_key(Path(args.key_dir), sim_title)

    conn = SSHConnection(host=fqdn, port=port, key_path=ssh_key, user="ubuntu")

    log("Checking if password change is required...")
    if change_ssh_password(conn, "nvidia", DEFAULT_OOB_PASSWORD):
        log(f"Password set to: {DEFAULT_OOB_PASSWORD}")
    else:
        warn("Password change may have failed")

    if args.copy:
        scp_to_server(conn, args.copy)

    log("Connecting to oob-mgmt-server...")
    print(f"SSH Command: ssh -p {port} -i {ssh_key} ubuntu@{fqdn}")

    os.execvp(
        "ssh",
        [
            "ssh",
            "-p",
            str(port),
            "-i",
            str(ssh_key),
            "-o",
            "StrictHostKeyChecking=no",
            f"ubuntu@{fqdn}",
        ],
    )


def _setup_ssh_key(args: argparse.Namespace, sim_name: str) -> SSHKeyManager:
    """Generate and upload SSH key for simulation."""
    log("Step 3: SSH Key Setup")
    key_path = Path(args.key_dir) / sim_name
    ssh_manager = SSHKeyManager(str(key_path))
    ssh_manager.generate(overwrite=True)

    log("Step 4: GitHub SSH Key Upload")
    if not GitHubKeyManager.is_authenticated():
        error("gh CLI not authenticated - run 'gh auth login' first")
    log("Uploading SSH key to GitHub...")
    if GitHubKeyManager.add_key(ssh_manager.pub_key_path, sim_name):
        log(f"SSH key uploaded to GitHub as '{sim_name}'")
    else:
        error("Failed to upload SSH key to GitHub")

    return ssh_manager


def _add_ssh_key_to_air(air: AirApi, ssh_manager: SSHKeyManager, sim_name: str) -> None:
    """Add SSH key to AIR profile."""
    log("Step 7: Add SSH Key to AIR Profile")
    pub_key = ssh_manager.get_public_key()
    fingerprint = ssh_manager.get_fingerprint()
    if pub_key and fingerprint:
        existing_keys = air.ssh_keys.list()
        key_exists = any(fingerprint in (k.fingerprint or "") for k in existing_keys)

        if key_exists:
            log("SSH key already exists in AIR profile")
        else:
            try:
                air.ssh_keys.create(name=sim_name, public_key=pub_key)
                log("SSH key added to AIR profile")
            except (ConnectionError, ValueError) as exc:
                warn(f"Failed to add SSH key to AIR: {exc}")
    else:
        warn("No public key found to add to AIR profile")


def _get_organization(air: AirApi, org_name: str):
    """Get organization by name."""
    log("Step 8: Get Organization")
    try:
        orgs = air.organizations.list()
        for org in orgs:
            if org.name == org_name:
                log(f"Found organization: {org_name} ({org.id})")
                return org
        warn(f"Organization '{org_name}' not found, creating without organization")
    except (ConnectionError, ValueError) as exc:
        warn(f"Could not fetch organizations: {exc}")
    return None


def _get_github_username() -> str:
    """Get GitHub username from gh CLI or environment."""
    if GitHubKeyManager.is_authenticated():
        username = GitHubKeyManager.get_username()
        if username:
            log(f"GitHub username: {username}")
            return username

    username = os.environ.get("GITHUB_USERNAME")
    if not username:
        username = input("Enter your GitHub username: ").strip()
    log(f"Using GitHub username: {username}")
    return username


def _print_create_success(sim_name: str, sim_id: str) -> None:
    """Print success message after simulation creation."""
    print()
    print("=" * 50)
    print(f"{Colors.green}Simulation Created!{Colors.reset}")
    print("=" * 50)
    print()
    print(f"Simulation: {sim_name}")
    print(f"Simulation ID: {sim_id}")
    print()
    print("Next steps:")
    print(f"  gust --start {sim_id}     # Start the simulation")
    print(f"  gust --connect {sim_id}   # Connect (after starting)")
    print()
    print("=" * 50)


def cmd_create(args: argparse.Namespace) -> None:
    """Create a new simulation."""
    use_default_topology = args.json is None
    json_path = None

    if not use_default_topology:
        json_path = Path(args.json)
        if not json_path.exists():
            error(f"JSON file not found: {json_path}")
        log("Using custom topology file")
    else:
        log("Using default Spectrum-X topology")

    log("Step 1: Get GitHub Username")
    github_username = _get_github_username()

    log("Step 2: Generate Simulation Name")
    sim_name = generate_sim_name(args.username, args.label)
    log(f"Simulation name: {sim_name}")

    ssh_manager = _setup_ssh_key(args, sim_name)

    log("Step 5: Prepare Topology")
    if use_default_topology:
        json_data = update_json_ssh_url(load_default_topology(), github_username)
    else:
        json_data = update_json_ssh_url(json_path, github_username)

    log("Step 6: Authenticate with NVIDIA AIR")
    air = get_air_client(args.username, args.token)
    log("Successfully authenticated with NVIDIA AIR")

    _add_ssh_key_to_air(air, ssh_manager, sim_name)

    org = _get_organization(air, args.org)

    log("Step 9: Create AIR Simulation")
    json_data["title"] = sim_name
    if org:
        json_data["organization"] = str(org.id)

    try:
        sim_id = create_simulation_from_json(air, json_data, start=False)
        log(f"Created simulation: {sim_name} ({sim_id})")
    except ValueError as exc:
        error(f"Failed to create simulation: {exc}")
        return

    _print_create_success(sim_name, sim_id)


def _create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="gust",
        description="Gust - CLI tool for managing NVIDIA AIR Spectrum-X simulations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_get_help_epilog(),
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    cmd_group = parser.add_mutually_exclusive_group()
    cmd_group.add_argument("--list", action="store_true", help="List all simulations")
    cmd_group.add_argument(
        "--delete", metavar="ID", help="Delete simulation(s) by ID (comma-separated)"
    )
    cmd_group.add_argument(
        "--connect",
        metavar="ID",
        help="Connect to oob-mgmt-server of an existing simulation",
    )
    cmd_group.add_argument(
        "--start", metavar="ID", help="Start an existing simulation by ID"
    )
    cmd_group.add_argument(
        "--stop", metavar="ID", help="Stop a running simulation by ID"
    )

    parser.add_argument(
        "--copy",
        metavar="PATH",
        help="File or directory to SCP to oob-mgmt-server (with --connect)",
    )

    parser.add_argument(
        "-u",
        "--username",
        default=os.environ.get("AIR_USERNAME"),
        help="NVIDIA AIR username (email) [env: AIR_USERNAME]",
    )
    parser.add_argument(
        "-t",
        "--token",
        default=os.environ.get("AIR_TOKEN"),
        help="NVIDIA AIR API token [env: AIR_TOKEN]",
    )

    parser.add_argument(
        "-j",
        "--json",
        metavar="FILE",
        help="Path to topology JSON file (default: Spectrum-X topology)",
    )

    default_key_dir = os.environ.get("SSH_KEY_DIR", str(Path.home() / ".ssh"))
    parser.add_argument(
        "-k",
        "--key-dir",
        default=default_key_dir,
        help="Directory for SSH keys [env: SSH_KEY_DIR] (default: ~/.ssh)",
    )
    parser.add_argument("-l", "--label", help="Optional label for simulation name")
    parser.add_argument(
        "-o",
        "--org",
        default="spectrocloud2",
        help="Organization name (default: spectrocloud2)",
    )

    return parser


def _get_help_epilog() -> str:
    """Get help epilog text."""
    return """
Environment Variables:
  AIR_USERNAME     NVIDIA AIR username (email)
  AIR_TOKEN        NVIDIA AIR API token
  SSH_KEY_DIR      Directory for SSH keys (default: ~/.ssh)
  GITHUB_USERNAME  GitHub username for ZTP script

Per-Simulation SSH Keys:
  Each simulation gets its own SSH key named after the simulation.
  Keys are stored in SSH_KEY_DIR (default: ~/.ssh) and uploaded to GitHub.
  When deleting a simulation, the associated key is removed from GitHub and locally.

Examples:
  # Set credentials once via environment
  export AIR_USERNAME="user@example.com"
  export AIR_TOKEN="your-api-token"

  # Create simulation with default Spectrum-X topology
  gust -l "dev-test"

  # Create simulation with custom topology
  gust -j custom-topology.json -l "dev-test"

  # Commands
  gust --list                              # List all simulations
  gust --start SIM_ID                      # Start a simulation
  gust --stop SIM_ID                       # Stop a simulation
  gust --connect SIM_ID                    # Connect to running simulation
  gust --connect SIM_ID --copy ./rcp.tar   # Copy file then connect
  gust --delete SIM_ID                     # Delete sim + GitHub key + local key

Simulation name format: {username_prefix}-{epoch}-{label}
"""


def _route_command(args: argparse.Namespace) -> None:
    """Route to appropriate command handler."""
    if args.list:
        cmd_list(args)
    elif args.delete:
        cmd_delete(args)
    elif args.start:
        cmd_start(args)
    elif args.stop:
        cmd_stop(args)
    elif args.connect:
        cmd_connect(args)
    else:
        cmd_create(args)


def main() -> None:
    """Main entry point for the CLI."""
    parser = _create_parser()
    args = parser.parse_args()

    if args.copy and not args.connect:
        parser.error("--copy requires --connect")

    if not args.username:
        parser.error("Username required: use -u/--username or set AIR_USERNAME env var")
    if not args.token:
        parser.error("Token required: use -t/--token or set AIR_TOKEN env var")

    _route_command(args)


if __name__ == "__main__":
    main()
