"""Shared pytest fixtures for gust tests."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture
def temp_ssh_dir(tmp_path):
    """Create a temporary SSH directory."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    return ssh_dir


@pytest.fixture
def mock_ssh_key_pair(temp_ssh_dir):
    """Create mock SSH key pair files."""
    key_path = temp_ssh_dir / "test-key"
    pub_key_path = temp_ssh_dir / "test-key.pub"

    key_path.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    pub_key_path.write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test-key-comment\n"
    )

    return key_path, pub_key_path


@pytest.fixture
def sample_topology():
    """Return a sample topology dictionary."""
    return {
        "title": "test-sim",
        "ztp": "#!/bin/bash\nSSH_URL=https://github.com/testuser.keys\necho $SSH_URL",
        "nodes": [
            {"name": "oob-mgmt-server", "os": "ubuntu"},
            {"name": "leaf-01", "os": "cumulus"},
        ],
    }


@pytest.fixture
def mock_air_api():
    """Create a mock AirApi instance."""
    mock_api = MagicMock()
    mock_api.client.headers = {"authorization": "Bearer test-token"}
    return mock_api


@pytest.fixture
def mock_simulation():
    """Create a mock simulation object."""
    sim = MagicMock()
    sim.id = "test-sim-id-12345"
    sim.title = "test-simulation"
    sim.state = "RUNNING"
    sim.name = "testuser@example.com"
    sim.created = "2024-01-01T00:00:00Z"
    return sim


@pytest.fixture
def mock_args():
    """Create a mock argparse.Namespace."""
    args = MagicMock()
    args.username = "testuser@example.com"
    args.token = "test-api-token"
    args.key_dir = "/tmp/ssh"
    args.label = "test"
    args.json = None
    args.org = "testorg"
    args.copy = None
    args.list = False
    args.delete = None
    args.connect = None
    args.start = None
    args.stop = None
    return args
