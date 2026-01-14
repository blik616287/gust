"""Tests for the cli module."""

import argparse
import json
import os
import subprocess
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from gust import cli
from gust.cli import (
    Colors,
    SSHConnection,
    log,
    warn,
    error,
    update_json_ssh_url,
    generate_sim_name,
    get_air_client,
    create_simulation_from_json,
    wait_for_simulation,
    get_or_create_ssh_service,
    change_ssh_password,
    cmd_list,
    cmd_delete,
    cmd_stop,
    cmd_start,
    cmd_connect,
    cmd_create,
    scp_to_server,
    main,
    _create_parser,
    _route_command,
    _get_worker_fqdn,
    _handle_password_prompt,
    _delete_simulation_keys,
    _get_simulation_ssh_key,
    _setup_ssh_key,
    _add_ssh_key_to_air,
    _get_organization,
    _get_github_username,
    _print_create_success,
    _get_help_epilog,
)


class TestColors:
    """Tests for Colors dataclass."""

    def test_default_values(self):
        """Test that Colors has correct default values."""
        colors = Colors()

        assert colors.red == "\033[0;31m"
        assert colors.green == "\033[0;32m"
        assert colors.yellow == "\033[1;33m"
        assert colors.cyan == "\033[0;36m"
        assert colors.reset == "\033[0m"


class TestSSHConnection:
    """Tests for SSHConnection dataclass."""

    def test_initialization(self, tmp_path):
        """Test SSHConnection initialization."""
        key_path = tmp_path / "key"
        conn = SSHConnection(
            host="example.com", port=22, key_path=key_path, user="ubuntu"
        )

        assert conn.host == "example.com"
        assert conn.port == 22
        assert conn.key_path == key_path
        assert conn.user == "ubuntu"


class TestLogFunctions:
    """Tests for logging functions."""

    def test_log_prints_info_message(self, capsys):
        """Test log() prints info message."""
        log("Test message")

        captured = capsys.readouterr()
        assert "[INFO]" in captured.out
        assert "Test message" in captured.out

    def test_warn_prints_warning_message(self, capsys):
        """Test warn() prints warning message."""
        warn("Warning message")

        captured = capsys.readouterr()
        assert "[WARN]" in captured.out
        assert "Warning message" in captured.out

    def test_error_prints_and_exits(self, capsys):
        """Test error() prints message and exits."""
        with pytest.raises(SystemExit) as exc_info:
            error("Error message")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "[ERROR]" in captured.out
        assert "Error message" in captured.out


class TestUpdateJsonSshUrl:
    """Tests for update_json_ssh_url function."""

    def test_updates_ztp_url_from_dict(self, sample_topology):
        """Test updating SSH URL in dictionary."""
        result = update_json_ssh_url(sample_topology, "newuser")

        assert "github.com/newuser.keys" in result["ztp"]

    def test_updates_ztp_url_from_file(self, tmp_path, sample_topology):
        """Test updating SSH URL from file path."""
        json_file = tmp_path / "topology.json"
        json_file.write_text(json.dumps(sample_topology))

        result = update_json_ssh_url(json_file, "newuser")

        assert "github.com/newuser.keys" in result["ztp"]

    def test_handles_missing_ztp_key(self):
        """Test handling topology without ztp key."""
        data = {"nodes": []}

        result = update_json_ssh_url(data, "newuser")

        assert "ztp" not in result

    def test_does_not_modify_original_dict(self, sample_topology):
        """Test that original dict is not modified."""
        original_ztp = sample_topology["ztp"]

        update_json_ssh_url(sample_topology, "newuser")

        assert sample_topology["ztp"] == original_ztp


class TestGenerateSimName:
    """Tests for generate_sim_name function."""

    def test_generates_name_without_label(self):
        """Test generating name without label."""
        result = generate_sim_name("user@example.com")

        assert result.startswith("user-")
        assert result.count("-") >= 1

    def test_generates_name_with_label(self):
        """Test generating name with label."""
        result = generate_sim_name("user@example.com", "test")

        assert result.startswith("user-")
        assert result.endswith("-test")

    def test_replaces_dots_in_username(self):
        """Test that dots in username are replaced with dashes."""
        result = generate_sim_name("first.last@example.com")

        assert "first-last-" in result

    def test_includes_epoch_timestamp(self):
        """Test that epoch timestamp is included."""
        result = generate_sim_name("user@example.com")

        parts = result.split("-")
        # Should have username part and epoch
        assert len(parts) >= 2
        # Second part should be numeric (epoch)
        assert parts[1].isdigit()


class TestGetAirClient:
    """Tests for get_air_client function."""

    def test_returns_air_api_instance(self):
        """Test successful API client creation."""
        with patch("gust.cli.AirApi") as mock_api:
            mock_api.return_value = MagicMock()

            result = get_air_client("user@example.com", "token")

            assert result is not None
            mock_api.assert_called_once_with(
                username="user@example.com", password="token"
            )

    def test_exits_on_connection_error(self):
        """Test exit on connection error."""
        with patch("gust.cli.AirApi") as mock_api:
            mock_api.side_effect = ConnectionError("Failed to connect")

            with pytest.raises(SystemExit):
                get_air_client("user@example.com", "token")

    def test_exits_on_value_error(self):
        """Test exit on value error."""
        with patch("gust.cli.AirApi") as mock_api:
            mock_api.side_effect = ValueError("Invalid credentials")

            with pytest.raises(SystemExit):
                get_air_client("user@example.com", "token")


class TestCreateSimulationFromJson:
    """Tests for create_simulation_from_json function."""

    def test_creates_simulation_successfully(self, mock_air_api):
        """Test successful simulation creation."""
        json_data = {"title": "test"}

        with patch("gust.cli.req.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=201, json=lambda: {"id": "sim-123"}
            )

            result = create_simulation_from_json(mock_air_api, json_data)

            assert result == "sim-123"

    def test_raises_on_missing_auth_header(self):
        """Test raises error when auth header missing."""
        mock_api = MagicMock()
        mock_api.client.headers = {}

        with pytest.raises(ValueError, match="No authorization token"):
            create_simulation_from_json(mock_api, {})

    def test_raises_on_api_error(self, mock_air_api):
        """Test raises error on API failure."""
        with patch("gust.cli.req.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=400, text="Bad request")

            with pytest.raises(ValueError, match="API returned 400"):
                create_simulation_from_json(mock_air_api, {})

    def test_sets_start_flag(self, mock_air_api):
        """Test that start flag is set in request."""
        json_data = {"title": "test"}

        with patch("gust.cli.req.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=201, json=lambda: {"id": "sim-123"}
            )

            create_simulation_from_json(mock_air_api, json_data, start=False)

            call_json = mock_post.call_args[1]["json"]
            assert call_json["start"] is False


class TestWaitForSimulation:
    """Tests for wait_for_simulation function."""

    def test_returns_when_target_state_reached(self, mock_air_api):
        """Test returns when simulation reaches target state."""
        mock_sim = MagicMock(state="RUNNING")
        mock_air_api.simulations.get.return_value = mock_sim

        result = wait_for_simulation(mock_air_api, "sim-123", ["RUNNING"])

        assert result == "RUNNING"

    def test_waits_for_state_change(self, mock_air_api):
        """Test waits for simulation state to change."""
        states = ["LOADING", "LOADING", "RUNNING"]
        mock_sims = [MagicMock(state=s) for s in states]
        mock_air_api.simulations.get.side_effect = mock_sims

        with patch("gust.cli.time.sleep"):
            result = wait_for_simulation(
                mock_air_api, "sim-123", ["RUNNING"], max_wait=300
            )

        assert result == "RUNNING"

    def test_exits_on_error_state(self, mock_air_api):
        """Test exits when simulation enters error state."""
        mock_sim = MagicMock(state="ERROR")
        mock_air_api.simulations.get.return_value = mock_sim

        with pytest.raises(SystemExit):
            wait_for_simulation(mock_air_api, "sim-123", ["RUNNING"])

    def test_exits_on_failed_state(self, mock_air_api):
        """Test exits when simulation enters failed state."""
        mock_sim = MagicMock(state="FAILED")
        mock_air_api.simulations.get.return_value = mock_sim

        with pytest.raises(SystemExit):
            wait_for_simulation(mock_air_api, "sim-123", ["RUNNING"])

    def test_exits_on_timeout(self, mock_air_api):
        """Test exits when max wait time exceeded."""
        mock_sim = MagicMock(state="LOADING")
        mock_air_api.simulations.get.return_value = mock_sim

        with patch("gust.cli.time.sleep"):
            with pytest.raises(SystemExit):
                wait_for_simulation(mock_air_api, "sim-123", ["RUNNING"], max_wait=5)


class TestGetWorkerFqdn:
    """Tests for _get_worker_fqdn function."""

    def test_returns_fqdn_from_worker_attribute(self, mock_air_api):
        """Test returns FQDN from worker attribute."""
        node = MagicMock()
        node.worker.fqdn = "worker.example.com"

        result = _get_worker_fqdn(mock_air_api, node)

        assert result == "worker.example.com"

    def test_fetches_worker_when_fqdn_not_attribute(self, mock_air_api):
        """Test fetches worker when FQDN not directly available."""
        # Create a node where worker is just a string ID (not an object with fqdn)
        node = MagicMock(spec=["worker"])
        node.worker = "worker-id-string"  # Just a string, no fqdn attribute

        mock_worker = MagicMock(fqdn="fetched.example.com")
        mock_air_api.workers.get.return_value = mock_worker

        result = _get_worker_fqdn(mock_air_api, node)

        assert result == "fetched.example.com"
        mock_air_api.workers.get.assert_called_once_with("worker-id-string")


class TestGetOrCreateSshService:
    """Tests for get_or_create_ssh_service function."""

    def test_returns_existing_service(self, mock_air_api, mock_simulation):
        """Test returns existing SSH service."""
        mock_service = MagicMock(dest_port=22, src_port=2222)
        mock_service.name = "ssh"  # Set name separately (it's special in MagicMock)
        mock_air_api.services.list.return_value = [mock_service]

        mock_node = MagicMock()
        mock_node.name = "oob-mgmt-server"
        mock_node.worker.fqdn = "worker.example.com"
        mock_air_api.simulation_nodes.list.return_value = [mock_node]

        result = get_or_create_ssh_service(mock_air_api, mock_simulation)

        assert result == (2222, "worker.example.com")

    def test_creates_new_service(self, mock_air_api, mock_simulation):
        """Test creates new SSH service when none exists."""
        mock_air_api.services.list.return_value = []

        mock_node = MagicMock()
        mock_node.name = "oob-mgmt-server"
        mock_node.worker.fqdn = "worker.example.com"
        mock_air_api.simulation_nodes.list.return_value = [mock_node]

        mock_service = MagicMock(src_port=3333)
        mock_simulation.create_service.return_value = mock_service

        result = get_or_create_ssh_service(mock_air_api, mock_simulation)

        assert result == (3333, "worker.example.com")

    def test_returns_none_on_create_error(self, mock_air_api, mock_simulation):
        """Test returns None when service creation fails."""
        mock_air_api.services.list.return_value = []
        mock_simulation.create_service.side_effect = ConnectionError("Failed")

        result = get_or_create_ssh_service(mock_air_api, mock_simulation)

        assert result is None

    def test_returns_none_when_no_oob_server(self, mock_air_api, mock_simulation):
        """Test returns None when oob-mgmt-server not found."""
        mock_service = MagicMock(dest_port=22, src_port=2222)
        mock_service.name = "ssh"
        mock_air_api.services.list.return_value = [mock_service]

        mock_node = MagicMock()
        mock_node.name = "other-node"
        mock_air_api.simulation_nodes.list.return_value = [mock_node]

        result = get_or_create_ssh_service(mock_air_api, mock_simulation)

        assert result is None


class TestHandlePasswordPrompt:
    """Tests for _handle_password_prompt function."""

    def test_handles_successful_password_change(self):
        """Test successful password change handling."""
        mock_child = MagicMock()
        mock_child.expect.return_value = 0  # passwd: password updated successfully

        result = _handle_password_prompt(mock_child, "old", "new")

        assert result is True
        mock_child.sendline.assert_any_call("old")
        mock_child.sendline.assert_any_call("new")

    def test_handles_connection_closed(self):
        """Test handling connection closed."""
        mock_child = MagicMock()
        mock_child.expect.return_value = 1  # Connection closed

        result = _handle_password_prompt(mock_child, "old", "new")

        assert result is True

    def test_handles_shell_prompt(self):
        """Test handling shell prompt."""
        mock_child = MagicMock()
        mock_child.expect.return_value = 2  # Shell prompt

        result = _handle_password_prompt(mock_child, "old", "new")

        assert result is True

    def test_handles_timeout(self):
        """Test handling timeout."""
        mock_child = MagicMock()
        mock_child.expect.return_value = 3  # Timeout

        result = _handle_password_prompt(mock_child, "old", "new")

        assert result is False


class TestChangeSshPassword:
    """Tests for change_ssh_password function."""

    def test_no_password_change_required(self, tmp_path):
        """Test when password change is not required."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.return_value = 2  # Shell prompt
            mock_spawn.return_value = mock_child

            result = change_ssh_password(conn, "old", "new")

            assert result is True
            mock_child.sendline.assert_called_with("exit")

    def test_permission_denied(self, tmp_path):
        """Test handling permission denied."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.return_value = 3  # Permission denied
            mock_spawn.return_value = mock_child

            result = change_ssh_password(conn, "old", "new")

            assert result is False

    def test_timeout_handling(self, tmp_path):
        """Test handling timeout."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.return_value = 4  # Timeout
            mock_spawn.return_value = mock_child

            result = change_ssh_password(conn, "old", "new")

            assert result is False

    def test_password_expired_warning(self, tmp_path):
        """Test handling password expired warning."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            # First expect returns warning, second returns current password prompt
            mock_child.expect.side_effect = [1, None, 0]
            mock_spawn.return_value = mock_child

            with patch("gust.cli._handle_password_prompt", return_value=True):
                result = change_ssh_password(conn, "old", "new")

            assert result is True

    def test_current_password_prompt(self, tmp_path):
        """Test handling current password prompt."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.return_value = 0  # Current password prompt
            mock_spawn.return_value = mock_child

            with patch("gust.cli._handle_password_prompt", return_value=True):
                result = change_ssh_password(conn, "old", "new")

            assert result is True

    def test_pexpect_exception(self, tmp_path):
        """Test handling pexpect exception."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            import pexpect

            mock_spawn.side_effect = pexpect.ExceptionPexpect("Error")

            result = change_ssh_password(conn, "old", "new")

            assert result is False

    def test_unexpected_response_after_password_change(self, tmp_path):
        """Test handling unexpected response after password change."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.return_value = 0
            mock_spawn.return_value = mock_child

            with patch("gust.cli._handle_password_prompt", return_value=False):
                result = change_ssh_password(conn, "old", "new")

            assert result is False


class TestCmdList:
    """Tests for cmd_list function."""

    def test_lists_simulations(self, mock_args, capsys):
        """Test listing simulations."""
        mock_sim = MagicMock()
        mock_sim.id = "sim-123"
        mock_sim.title = "test-sim"
        mock_sim.state = "RUNNING"
        mock_sim.name = "testuser@example.com"
        mock_sim.created = "2024-01-01T00:00:00Z"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.list.return_value = [mock_sim]
            mock_get_client.return_value = mock_api

            cmd_list(mock_args)

            captured = capsys.readouterr()
            assert "sim-123" in captured.out
            assert "test-sim" in captured.out
            assert "RUNNING" in captured.out


class TestCmdDelete:
    """Tests for cmd_delete function."""

    def test_deletes_owned_simulation(self, mock_args, tmp_path):
        """Test deleting an owned simulation."""
        mock_args.delete = "sim-123"
        mock_args.key_dir = str(tmp_path)

        mock_sim = MagicMock()
        mock_sim.name = "testuser@example.com"
        mock_sim.title = "test-sim"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with patch("gust.cli._delete_simulation_keys"):
                cmd_delete(mock_args)

                mock_sim.delete.assert_called_once()

    def test_skips_unowned_simulation(self, mock_args, capsys):
        """Test skipping simulation owned by another user."""
        mock_args.delete = "sim-123"

        mock_sim = MagicMock()
        mock_sim.name = "otheruser@example.com"
        mock_sim.title = "other-sim"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            cmd_delete(mock_args)

            mock_sim.delete.assert_not_called()
            captured = capsys.readouterr()
            assert "Cannot delete" in captured.out

    def test_handles_simulation_not_found(self, mock_args, capsys):
        """Test handling simulation not found."""
        mock_args.delete = "nonexistent"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.side_effect = ConnectionError("Not found")
            mock_get_client.return_value = mock_api

            cmd_delete(mock_args)

            captured = capsys.readouterr()
            assert "not found" in captured.out

    def test_handles_delete_error(self, mock_args, capsys, tmp_path):
        """Test handling delete error."""
        mock_args.delete = "sim-123"
        mock_args.key_dir = str(tmp_path)

        mock_sim = MagicMock()
        mock_sim.name = "testuser@example.com"
        mock_sim.title = "test-sim"
        mock_sim.delete.side_effect = ConnectionError("Delete failed")

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            cmd_delete(mock_args)

            captured = capsys.readouterr()
            assert "Failed to delete" in captured.out

    def test_deletes_multiple_simulations(self, mock_args, tmp_path):
        """Test deleting multiple comma-separated simulations."""
        mock_args.delete = "sim-1,sim-2"
        mock_args.key_dir = str(tmp_path)

        mock_sim1 = MagicMock(title="sim-1")
        mock_sim1.name = "testuser@example.com"  # Set name separately
        mock_sim2 = MagicMock(title="sim-2")
        mock_sim2.name = "testuser@example.com"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.side_effect = [mock_sim1, mock_sim2]
            mock_get_client.return_value = mock_api

            with patch("gust.cli._delete_simulation_keys"):
                cmd_delete(mock_args)

                assert mock_sim1.delete.called
                assert mock_sim2.delete.called


class TestDeleteSimulationKeys:
    """Tests for _delete_simulation_keys function."""

    def test_deletes_github_and_local_keys(self, tmp_path):
        """Test deleting both GitHub and local keys."""
        key_path = tmp_path / "test-sim"
        pub_key_path = tmp_path / "test-sim.pub"
        key_path.write_text("private key")
        pub_key_path.write_text("public key")

        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = True
            mock_gh.delete_key.return_value = True

            _delete_simulation_keys("test-sim", tmp_path)

            mock_gh.delete_key.assert_called_with("test-sim")
            assert not key_path.exists()
            assert not pub_key_path.exists()

    def test_handles_github_not_authenticated(self, tmp_path):
        """Test handling when GitHub is not authenticated."""
        key_path = tmp_path / "test-sim"
        key_path.write_text("private key")

        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = False

            _delete_simulation_keys("test-sim", tmp_path)

            mock_gh.delete_key.assert_not_called()


class TestScpToServer:
    """Tests for scp_to_server function."""

    def test_copies_file_successfully(self, tmp_path):
        """Test successful file copy."""
        local_file = tmp_path / "test.txt"
        local_file.write_text("test content")
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = scp_to_server(conn, str(local_file))

            assert result is True

    def test_copies_directory_with_recursive_flag(self, tmp_path):
        """Test directory copy uses -r flag."""
        local_dir = tmp_path / "testdir"
        local_dir.mkdir()
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = scp_to_server(conn, str(local_dir))

            assert result is True
            call_args = mock_run.call_args[0][0]
            assert "-r" in call_args

    def test_returns_false_for_nonexistent_path(self, tmp_path):
        """Test returns False for nonexistent path."""
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        result = scp_to_server(conn, "/nonexistent/path")

        assert result is False

    def test_returns_false_on_scp_failure(self, tmp_path):
        """Test returns False when scp fails."""
        local_file = tmp_path / "test.txt"
        local_file.write_text("test")
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Error")

            result = scp_to_server(conn, str(local_file))

            assert result is False

    def test_handles_oserror(self, tmp_path):
        """Test handles OSError."""
        local_file = tmp_path / "test.txt"
        local_file.write_text("test")
        conn = SSHConnection(
            host="example.com", port=22, key_path=tmp_path / "key", user="ubuntu"
        )

        with patch("gust.cli.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Command not found")

            result = scp_to_server(conn, str(local_file))

            assert result is False


class TestCmdStop:
    """Tests for cmd_stop function."""

    def test_stops_running_simulation(self, mock_args):
        """Test stopping a running simulation."""
        mock_args.stop = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.name = "testuser@example.com"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            cmd_stop(mock_args)

            mock_sim.stop.assert_called_once()

    def test_skips_already_stopped_simulation(self, mock_args, capsys):
        """Test skipping already stopped simulation."""
        mock_args.stop = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.name = "testuser@example.com"
        mock_sim.state = "STORED"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            cmd_stop(mock_args)

            mock_sim.stop.assert_not_called()
            captured = capsys.readouterr()
            assert "already stopped" in captured.out

    def test_exits_on_invalid_state(self, mock_args):
        """Test exits when simulation in invalid state."""
        mock_args.stop = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.name = "testuser@example.com"
        mock_sim.state = "ERROR"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_stop(mock_args)

    def test_exits_on_not_owned(self, mock_args):
        """Test exits when simulation not owned."""
        mock_args.stop = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.name = "other@example.com"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_stop(mock_args)

    def test_handles_simulation_not_found(self, mock_args):
        """Test handling simulation not found."""
        mock_args.stop = "nonexistent"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.side_effect = ConnectionError("Not found")
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_stop(mock_args)


class TestCmdStart:
    """Tests for cmd_start function."""

    def test_starts_stopped_simulation(self, mock_args):
        """Test starting a stopped simulation."""
        mock_args.start = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "STORED"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with patch("gust.cli.wait_for_simulation", return_value="RUNNING"):
                cmd_start(mock_args)

                mock_sim.start.assert_called_once()

    def test_skips_already_running_simulation(self, mock_args, capsys):
        """Test skipping already running simulation."""
        mock_args.start = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            cmd_start(mock_args)

            mock_sim.start.assert_not_called()
            captured = capsys.readouterr()
            assert "already running" in captured.out

    def test_exits_on_invalid_state(self, mock_args):
        """Test exits when simulation in invalid state."""
        mock_args.start = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "ERROR"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_start(mock_args)

    def test_handles_simulation_not_found(self, mock_args):
        """Test handling simulation not found."""
        mock_args.start = "nonexistent"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.side_effect = ConnectionError("Not found")
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_start(mock_args)


class TestGetSimulationSshKey:
    """Tests for _get_simulation_ssh_key function."""

    def test_returns_existing_key(self, tmp_path):
        """Test returns existing key path."""
        key_path = tmp_path / "test-sim"
        key_path.write_text("private key")

        result = _get_simulation_ssh_key(tmp_path, "test-sim")

        assert result == key_path

    def test_falls_back_to_spectrum_x_key(self, tmp_path, capsys):
        """Test falls back to spectrum-x key."""
        fallback_key = tmp_path / "spectrum-x"
        fallback_key.write_text("private key")

        result = _get_simulation_ssh_key(tmp_path, "nonexistent")

        assert result == fallback_key
        captured = capsys.readouterr()
        assert "using fallback" in captured.out

    def test_exits_when_no_key_found(self, tmp_path):
        """Test exits when no key found."""
        with pytest.raises(SystemExit):
            _get_simulation_ssh_key(tmp_path, "nonexistent")


class TestCmdConnect:
    """Tests for cmd_connect function."""

    def test_connects_to_running_simulation(self, mock_args, tmp_path):
        """Test connecting to a running simulation."""
        mock_args.connect = "sim-123"
        mock_args.key_dir = str(tmp_path)
        mock_args.copy = None

        # Create SSH key file
        key_path = tmp_path / "test-sim"
        key_path.write_text("private key")

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with patch(
                "gust.cli.get_or_create_ssh_service",
                return_value=(2222, "worker.example.com"),
            ):
                with patch("gust.cli.change_ssh_password", return_value=True):
                    with patch("gust.cli.os.execvp") as mock_exec:
                        cmd_connect(mock_args)

                        mock_exec.assert_called_once()

    def test_exits_when_simulation_not_running(self, mock_args):
        """Test exits when simulation is not running."""
        mock_args.connect = "sim-123"

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "STORED"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with pytest.raises(SystemExit):
                cmd_connect(mock_args)

    def test_exits_when_ssh_service_unavailable(self, mock_args, tmp_path):
        """Test exits when SSH service unavailable."""
        mock_args.connect = "sim-123"
        mock_args.key_dir = str(tmp_path)

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with patch("gust.cli.get_or_create_ssh_service", return_value=None):
                with pytest.raises(SystemExit):
                    cmd_connect(mock_args)

    def test_copies_file_when_specified(self, mock_args, tmp_path):
        """Test copies file when --copy specified."""
        mock_args.connect = "sim-123"
        mock_args.key_dir = str(tmp_path)
        mock_args.copy = str(tmp_path / "file.txt")

        # Create files
        key_path = tmp_path / "test-sim"
        key_path.write_text("private key")
        copy_file = tmp_path / "file.txt"
        copy_file.write_text("content")

        mock_sim = MagicMock()
        mock_sim.title = "test-sim"
        mock_sim.state = "RUNNING"

        with patch("gust.cli.get_air_client") as mock_get_client:
            mock_api = MagicMock()
            mock_api.simulations.get.return_value = mock_sim
            mock_get_client.return_value = mock_api

            with patch(
                "gust.cli.get_or_create_ssh_service",
                return_value=(2222, "worker.example.com"),
            ):
                with patch("gust.cli.change_ssh_password", return_value=True):
                    with patch("gust.cli.scp_to_server") as mock_scp:
                        with patch("gust.cli.os.execvp"):
                            cmd_connect(mock_args)

                            mock_scp.assert_called_once()


class TestSetupSshKey:
    """Tests for _setup_ssh_key function."""

    def test_generates_and_uploads_key(self, mock_args, tmp_path):
        """Test generating and uploading SSH key."""
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli.SSHKeyManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager.pub_key_path = tmp_path / "key.pub"
            mock_manager_class.return_value = mock_manager

            with patch("gust.cli.GitHubKeyManager") as mock_gh:
                mock_gh.is_authenticated.return_value = True
                mock_gh.add_key.return_value = True

                result = _setup_ssh_key(mock_args, "test-sim")

                mock_manager.generate.assert_called_once_with(overwrite=True)
                mock_gh.add_key.assert_called_once()

    def test_exits_when_not_authenticated(self, mock_args, tmp_path):
        """Test exits when GitHub not authenticated."""
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli.SSHKeyManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            with patch("gust.cli.GitHubKeyManager") as mock_gh:
                mock_gh.is_authenticated.return_value = False

                with pytest.raises(SystemExit):
                    _setup_ssh_key(mock_args, "test-sim")

    def test_exits_when_upload_fails(self, mock_args, tmp_path):
        """Test exits when upload fails."""
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli.SSHKeyManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager.pub_key_path = tmp_path / "key.pub"
            mock_manager_class.return_value = mock_manager

            with patch("gust.cli.GitHubKeyManager") as mock_gh:
                mock_gh.is_authenticated.return_value = True
                mock_gh.add_key.return_value = False

                with pytest.raises(SystemExit):
                    _setup_ssh_key(mock_args, "test-sim")


class TestAddSshKeyToAir:
    """Tests for _add_ssh_key_to_air function."""

    def test_adds_new_key(self, mock_air_api):
        """Test adding new SSH key to AIR."""
        mock_manager = MagicMock()
        mock_manager.get_public_key.return_value = "ssh-ed25519 test"
        mock_manager.get_fingerprint.return_value = "SHA256:abc123"

        mock_air_api.ssh_keys.list.return_value = []

        _add_ssh_key_to_air(mock_air_api, mock_manager, "test-sim")

        mock_air_api.ssh_keys.create.assert_called_once()

    def test_skips_existing_key(self, mock_air_api, capsys):
        """Test skipping existing SSH key."""
        mock_manager = MagicMock()
        mock_manager.get_public_key.return_value = "ssh-ed25519 test"
        mock_manager.get_fingerprint.return_value = "SHA256:abc123"

        existing_key = MagicMock(fingerprint="SHA256:abc123")
        mock_air_api.ssh_keys.list.return_value = [existing_key]

        _add_ssh_key_to_air(mock_air_api, mock_manager, "test-sim")

        mock_air_api.ssh_keys.create.assert_not_called()
        captured = capsys.readouterr()
        assert "already exists" in captured.out

    def test_handles_no_public_key(self, mock_air_api, capsys):
        """Test handling missing public key."""
        mock_manager = MagicMock()
        mock_manager.get_public_key.return_value = None
        mock_manager.get_fingerprint.return_value = None

        _add_ssh_key_to_air(mock_air_api, mock_manager, "test-sim")

        mock_air_api.ssh_keys.create.assert_not_called()
        captured = capsys.readouterr()
        assert "No public key found" in captured.out

    def test_handles_create_error(self, mock_air_api, capsys):
        """Test handling key creation error."""
        mock_manager = MagicMock()
        mock_manager.get_public_key.return_value = "ssh-ed25519 test"
        mock_manager.get_fingerprint.return_value = "SHA256:abc123"

        mock_air_api.ssh_keys.list.return_value = []
        mock_air_api.ssh_keys.create.side_effect = ConnectionError("Failed")

        _add_ssh_key_to_air(mock_air_api, mock_manager, "test-sim")

        captured = capsys.readouterr()
        assert "Failed to add SSH key" in captured.out


class TestGetOrganization:
    """Tests for _get_organization function."""

    def test_returns_matching_org(self, mock_air_api):
        """Test returns matching organization."""
        mock_org = MagicMock(id="org-123")
        mock_org.name = "testorg"  # Set name separately
        mock_air_api.organizations.list.return_value = [mock_org]

        result = _get_organization(mock_air_api, "testorg")

        assert result == mock_org

    def test_returns_none_when_not_found(self, mock_air_api, capsys):
        """Test returns None when org not found."""
        mock_air_api.organizations.list.return_value = []

        result = _get_organization(mock_air_api, "nonexistent")

        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_handles_api_error(self, mock_air_api, capsys):
        """Test handles API error."""
        mock_air_api.organizations.list.side_effect = ConnectionError("Failed")

        result = _get_organization(mock_air_api, "testorg")

        assert result is None
        captured = capsys.readouterr()
        assert "Could not fetch" in captured.out


class TestGetGithubUsername:
    """Tests for _get_github_username function."""

    def test_returns_username_from_gh(self):
        """Test returns username from gh CLI."""
        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = True
            mock_gh.get_username.return_value = "testuser"

            result = _get_github_username()

            assert result == "testuser"

    def test_returns_username_from_env(self):
        """Test returns username from environment."""
        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = False

            with patch.dict(os.environ, {"GITHUB_USERNAME": "envuser"}):
                result = _get_github_username()

            assert result == "envuser"

    def test_prompts_for_username(self):
        """Test prompts user for username."""
        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = False

            with patch.dict(os.environ, {}, clear=True):
                with patch("builtins.input", return_value="inputuser"):
                    result = _get_github_username()

            assert result == "inputuser"

    def test_returns_none_username_from_gh(self):
        """Test handles None username from gh."""
        with patch("gust.cli.GitHubKeyManager") as mock_gh:
            mock_gh.is_authenticated.return_value = True
            mock_gh.get_username.return_value = None

            with patch.dict(os.environ, {"GITHUB_USERNAME": "fallback"}):
                result = _get_github_username()

            assert result == "fallback"


class TestPrintCreateSuccess:
    """Tests for _print_create_success function."""

    def test_prints_success_message(self, capsys):
        """Test prints success message."""
        _print_create_success("test-sim", "sim-123")

        captured = capsys.readouterr()
        assert "Simulation Created!" in captured.out
        assert "test-sim" in captured.out
        assert "sim-123" in captured.out
        assert "--start" in captured.out
        assert "--connect" in captured.out


class TestCmdCreate:
    """Tests for cmd_create function."""

    def test_creates_simulation_with_default_topology(self, mock_args, tmp_path):
        """Test creating simulation with default topology."""
        mock_args.json = None
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli._get_github_username", return_value="testuser"):
            with patch("gust.cli._setup_ssh_key") as mock_setup:
                mock_setup.return_value = MagicMock()
                with patch(
                    "gust.cli.load_default_topology", return_value={"nodes": []}
                ):
                    with patch(
                        "gust.cli.update_json_ssh_url", return_value={"nodes": []}
                    ):
                        with patch("gust.cli.get_air_client") as mock_get_client:
                            mock_api = MagicMock()
                            mock_api.ssh_keys.list.return_value = []
                            mock_get_client.return_value = mock_api

                            with patch("gust.cli._add_ssh_key_to_air"):
                                with patch(
                                    "gust.cli._get_organization", return_value=None
                                ):
                                    with patch(
                                        "gust.cli.create_simulation_from_json",
                                        return_value="sim-123",
                                    ):
                                        with patch("gust.cli._print_create_success"):
                                            cmd_create(mock_args)

    def test_creates_simulation_with_custom_topology(self, mock_args, tmp_path):
        """Test creating simulation with custom topology file."""
        json_file = tmp_path / "topology.json"
        json_file.write_text('{"nodes": []}')
        mock_args.json = str(json_file)
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli._get_github_username", return_value="testuser"):
            with patch("gust.cli._setup_ssh_key") as mock_setup:
                mock_setup.return_value = MagicMock()
                with patch("gust.cli.update_json_ssh_url", return_value={"nodes": []}):
                    with patch("gust.cli.get_air_client") as mock_get_client:
                        mock_api = MagicMock()
                        mock_api.ssh_keys.list.return_value = []
                        mock_get_client.return_value = mock_api

                        with patch("gust.cli._add_ssh_key_to_air"):
                            with patch("gust.cli._get_organization", return_value=None):
                                with patch(
                                    "gust.cli.create_simulation_from_json",
                                    return_value="sim-123",
                                ):
                                    with patch("gust.cli._print_create_success"):
                                        cmd_create(mock_args)

    def test_exits_on_missing_json_file(self, mock_args):
        """Test exits when JSON file not found."""
        mock_args.json = "/nonexistent/file.json"

        with pytest.raises(SystemExit):
            cmd_create(mock_args)

    def test_exits_on_creation_error(self, mock_args, tmp_path):
        """Test exits when simulation creation fails."""
        mock_args.json = None
        mock_args.key_dir = str(tmp_path)

        with patch("gust.cli._get_github_username", return_value="testuser"):
            with patch("gust.cli._setup_ssh_key") as mock_setup:
                mock_setup.return_value = MagicMock()
                with patch(
                    "gust.cli.load_default_topology", return_value={"nodes": []}
                ):
                    with patch(
                        "gust.cli.update_json_ssh_url", return_value={"nodes": []}
                    ):
                        with patch("gust.cli.get_air_client") as mock_get_client:
                            mock_api = MagicMock()
                            mock_api.ssh_keys.list.return_value = []
                            mock_get_client.return_value = mock_api

                            with patch("gust.cli._add_ssh_key_to_air"):
                                with patch(
                                    "gust.cli._get_organization", return_value=None
                                ):
                                    with patch(
                                        "gust.cli.create_simulation_from_json"
                                    ) as mock_create:
                                        mock_create.side_effect = ValueError(
                                            "API error"
                                        )

                                        with pytest.raises(SystemExit):
                                            cmd_create(mock_args)

    def test_includes_organization_in_request(self, mock_args, tmp_path):
        """Test includes organization in simulation request."""
        mock_args.json = None
        mock_args.key_dir = str(tmp_path)

        mock_org = MagicMock(id="org-123")

        with patch("gust.cli._get_github_username", return_value="testuser"):
            with patch("gust.cli._setup_ssh_key") as mock_setup:
                mock_setup.return_value = MagicMock()
                with patch(
                    "gust.cli.load_default_topology", return_value={"nodes": []}
                ):
                    with patch(
                        "gust.cli.update_json_ssh_url", return_value={"nodes": []}
                    ):
                        with patch("gust.cli.get_air_client") as mock_get_client:
                            mock_api = MagicMock()
                            mock_api.ssh_keys.list.return_value = []
                            mock_get_client.return_value = mock_api

                            with patch("gust.cli._add_ssh_key_to_air"):
                                with patch(
                                    "gust.cli._get_organization", return_value=mock_org
                                ):
                                    with patch(
                                        "gust.cli.create_simulation_from_json",
                                        return_value="sim-123",
                                    ) as mock_create:
                                        with patch("gust.cli._print_create_success"):
                                            cmd_create(mock_args)

                                            call_json = mock_create.call_args[0][1]
                                            assert (
                                                call_json["organization"] == "org-123"
                                            )


class TestCreateParser:
    """Tests for _create_parser function."""

    def test_creates_parser_with_all_options(self):
        """Test parser has all expected options."""
        parser = _create_parser()

        # Test parser was created
        assert parser is not None
        assert parser.prog == "gust"

    def test_mutually_exclusive_commands(self):
        """Test mutually exclusive command group."""
        parser = _create_parser()

        # These should work individually
        args1 = parser.parse_args(["--list", "-u", "user", "-t", "token"])
        assert args1.list is True

        args2 = parser.parse_args(["--delete", "sim-123", "-u", "user", "-t", "token"])
        assert args2.delete == "sim-123"

    def test_default_values(self):
        """Test default argument values."""
        with patch.dict(os.environ, {}, clear=True):
            parser = _create_parser()
            args = parser.parse_args(["-u", "user", "-t", "token"])

            assert args.org == "spectrocloud2"
            assert args.label is None
            assert args.json is None


class TestGetHelpEpilog:
    """Tests for _get_help_epilog function."""

    def test_returns_help_text(self):
        """Test returns help text."""
        result = _get_help_epilog()

        assert "Environment Variables" in result
        assert "AIR_USERNAME" in result
        assert "Examples" in result


class TestRouteCommand:
    """Tests for _route_command function."""

    def test_routes_to_list(self, mock_args):
        """Test routes to cmd_list."""
        mock_args.list = True

        with patch("gust.cli.cmd_list") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)

    def test_routes_to_delete(self, mock_args):
        """Test routes to cmd_delete."""
        mock_args.delete = "sim-123"

        with patch("gust.cli.cmd_delete") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)

    def test_routes_to_start(self, mock_args):
        """Test routes to cmd_start."""
        mock_args.start = "sim-123"

        with patch("gust.cli.cmd_start") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)

    def test_routes_to_stop(self, mock_args):
        """Test routes to cmd_stop."""
        mock_args.stop = "sim-123"

        with patch("gust.cli.cmd_stop") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)

    def test_routes_to_connect(self, mock_args):
        """Test routes to cmd_connect."""
        mock_args.connect = "sim-123"

        with patch("gust.cli.cmd_connect") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)

    def test_routes_to_create_by_default(self, mock_args):
        """Test routes to cmd_create by default."""
        with patch("gust.cli.cmd_create") as mock_cmd:
            _route_command(mock_args)
            mock_cmd.assert_called_once_with(mock_args)


class TestMain:
    """Tests for main function."""

    def test_main_with_list_command(self):
        """Test main with --list command."""
        with patch(
            "sys.argv", ["gust", "--list", "-u", "user@test.com", "-t", "token"]
        ):
            with patch("gust.cli.cmd_list") as mock_cmd:
                main()
                mock_cmd.assert_called_once()

    def test_main_requires_username(self):
        """Test main requires username."""
        with patch("sys.argv", ["gust", "--list", "-t", "token"]):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(SystemExit):
                    main()

    def test_main_requires_token(self):
        """Test main requires token."""
        with patch("sys.argv", ["gust", "--list", "-u", "user@test.com"]):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(SystemExit):
                    main()

    def test_main_copy_requires_connect(self):
        """Test --copy requires --connect."""
        with patch(
            "sys.argv", ["gust", "--copy", "/path", "-u", "user", "-t", "token"]
        ):
            with pytest.raises(SystemExit):
                main()

    def test_main_uses_env_vars(self):
        """Test main uses environment variables."""
        with patch("sys.argv", ["gust", "--list"]):
            with patch.dict(
                os.environ, {"AIR_USERNAME": "env@test.com", "AIR_TOKEN": "envtoken"}
            ):
                with patch("gust.cli.cmd_list") as mock_cmd:
                    main()
                    mock_cmd.assert_called_once()
