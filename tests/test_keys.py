"""Tests for the keys module."""

import os
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from gust.keys import SSHKeyManager, GitHubKeyManager


class TestSSHKeyManager:
    """Tests for SSHKeyManager class."""

    def test_init_with_custom_path(self, tmp_path):
        """Test initialization with custom key path."""
        key_path = tmp_path / "custom-key"
        manager = SSHKeyManager(str(key_path))

        assert manager.key_path == key_path
        assert manager.pub_key_path == Path(str(key_path) + ".pub")

    def test_init_with_default_path(self):
        """Test initialization with default path."""
        with patch.dict(os.environ, {}, clear=True):
            manager = SSHKeyManager()

            expected_path = Path.home() / ".ssh" / "spectrum-x"
            assert manager.key_path == expected_path

    def test_init_with_env_var(self, tmp_path):
        """Test initialization with SSH_KEY_PATH environment variable."""
        env_path = str(tmp_path / "env-key")
        with patch.dict(os.environ, {"SSH_KEY_PATH": env_path}):
            manager = SSHKeyManager()

            assert manager.key_path == Path(env_path)

    def test_exists_returns_true_when_both_files_exist(self, mock_ssh_key_pair):
        """Test exists() returns True when both key files exist."""
        key_path, _ = mock_ssh_key_pair
        manager = SSHKeyManager(str(key_path))

        assert manager.exists() is True

    def test_exists_returns_false_when_private_key_missing(self, temp_ssh_dir):
        """Test exists() returns False when private key is missing."""
        key_path = temp_ssh_dir / "missing-key"
        pub_key_path = temp_ssh_dir / "missing-key.pub"
        pub_key_path.write_text("ssh-ed25519 test")

        manager = SSHKeyManager(str(key_path))

        assert manager.exists() is False

    def test_exists_returns_false_when_public_key_missing(self, temp_ssh_dir):
        """Test exists() returns False when public key is missing."""
        key_path = temp_ssh_dir / "missing-pub"
        key_path.write_text("private key content")

        manager = SSHKeyManager(str(key_path))

        assert manager.exists() is False

    def test_generate_creates_new_key_pair(self, temp_ssh_dir):
        """Test generate() creates a new SSH key pair."""
        key_path = temp_ssh_dir / "new-key"
        manager = SSHKeyManager(str(key_path))

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = manager.generate()

            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "ssh-keygen" in call_args
            assert "-t" in call_args
            assert "ed25519" in call_args

    def test_generate_returns_false_when_exists_and_no_overwrite(
        self, mock_ssh_key_pair
    ):
        """Test generate() returns False when key exists and overwrite=False."""
        key_path, _ = mock_ssh_key_pair
        manager = SSHKeyManager(str(key_path))

        result = manager.generate(overwrite=False)

        assert result is False

    def test_generate_overwrites_existing_keys(self, mock_ssh_key_pair):
        """Test generate() overwrites existing keys when overwrite=True."""
        key_path, pub_key_path = mock_ssh_key_pair
        manager = SSHKeyManager(str(key_path))

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = manager.generate(overwrite=True)

            assert result is True
            # Files should have been unlinked
            assert not key_path.exists()
            assert not pub_key_path.exists()

    def test_generate_returns_false_on_subprocess_error(self, temp_ssh_dir):
        """Test generate() returns False when ssh-keygen fails."""
        key_path = temp_ssh_dir / "fail-key"
        manager = SSHKeyManager(str(key_path))

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "ssh-keygen")

            result = manager.generate()

            assert result is False

    def test_get_public_key_returns_content(self, mock_ssh_key_pair):
        """Test get_public_key() returns the public key content."""
        key_path, pub_key_path = mock_ssh_key_pair
        manager = SSHKeyManager(str(key_path))

        result = manager.get_public_key()

        assert result is not None
        assert "ssh-ed25519" in result

    def test_get_public_key_returns_none_when_missing(self, temp_ssh_dir):
        """Test get_public_key() returns None when file doesn't exist."""
        key_path = temp_ssh_dir / "nonexistent"
        manager = SSHKeyManager(str(key_path))

        result = manager.get_public_key()

        assert result is None

    def test_get_fingerprint_returns_fingerprint(self, mock_ssh_key_pair):
        """Test get_fingerprint() returns the key fingerprint."""
        key_path, _ = mock_ssh_key_pair
        manager = SSHKeyManager(str(key_path))

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="256 SHA256:abc123fingerprint test-key (ED25519)\n", returncode=0
            )

            result = manager.get_fingerprint()

            assert result == "SHA256:abc123fingerprint"

    def test_get_fingerprint_returns_none_on_error(self, temp_ssh_dir):
        """Test get_fingerprint() returns None when ssh-keygen fails."""
        key_path = temp_ssh_dir / "no-key"
        manager = SSHKeyManager(str(key_path))

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "ssh-keygen")

            result = manager.get_fingerprint()

            assert result is None


class TestGitHubKeyManager:
    """Tests for GitHubKeyManager class."""

    def test_delete_key_success(self):
        """Test delete_key() successfully deletes a key."""
        with patch("gust.keys.subprocess.run") as mock_run:
            # First call lists keys
            mock_run.side_effect = [
                MagicMock(
                    returncode=0, stdout="test-key\tSHA256:xxx\t2024-01-01\t12345\n"
                ),
                MagicMock(returncode=0),  # Delete call
            ]

            result = GitHubKeyManager.delete_key("test-key")

            assert result is True

    def test_delete_key_not_found(self):
        """Test delete_key() returns False when key not found."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="other-key\tSHA256:xxx\t2024-01-01\t12345\n"
            )

            result = GitHubKeyManager.delete_key("nonexistent")

            assert result is False

    def test_delete_key_list_fails(self):
        """Test delete_key() returns False when list fails."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = GitHubKeyManager.delete_key("test-key")

            assert result is False

    def test_delete_key_empty_lines(self):
        """Test delete_key() handles empty lines in output."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="\n\n")

            result = GitHubKeyManager.delete_key("test-key")

            assert result is False

    def test_delete_key_oserror(self):
        """Test delete_key() handles OSError."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Command not found")

            result = GitHubKeyManager.delete_key("test-key")

            assert result is False

    def test_delete_key_insufficient_parts(self):
        """Test delete_key() handles lines with insufficient parts."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="test-key\tonly-two-parts\n"
            )

            result = GitHubKeyManager.delete_key("test-key")

            assert result is False

    def test_is_authenticated_returns_true(self):
        """Test is_authenticated() returns True when gh is authenticated."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = GitHubKeyManager.is_authenticated()

            assert result is True

    def test_is_authenticated_returns_false(self):
        """Test is_authenticated() returns False when not authenticated."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = GitHubKeyManager.is_authenticated()

            assert result is False

    def test_is_authenticated_file_not_found(self):
        """Test is_authenticated() returns False when gh not installed."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            result = GitHubKeyManager.is_authenticated()

            assert result is False

    def test_get_username_success(self):
        """Test get_username() returns username."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="testuser\n", returncode=0)

            result = GitHubKeyManager.get_username()

            assert result == "testuser"

    def test_get_username_failure(self):
        """Test get_username() returns None on failure."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "gh")

            result = GitHubKeyManager.get_username()

            assert result is None

    def test_list_keys_success(self):
        """Test list_keys() returns list of keys."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="key1\tfingerprint1\nkey2\tfingerprint2\n", returncode=0
            )

            result = GitHubKeyManager.list_keys()

            assert len(result) == 2
            assert "key1" in result[0]

    def test_list_keys_empty(self):
        """Test list_keys() returns empty list when no keys."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=0)

            result = GitHubKeyManager.list_keys()

            assert result == []

    def test_list_keys_failure(self):
        """Test list_keys() returns empty list on failure."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "gh")

            result = GitHubKeyManager.list_keys()

            assert result == []

    def test_refresh_permissions_success(self):
        """Test refresh_permissions() returns True on success."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = GitHubKeyManager.refresh_permissions()

            assert result is True

    def test_refresh_permissions_failure(self):
        """Test refresh_permissions() returns False on failure."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = GitHubKeyManager.refresh_permissions()

            assert result is False

    def test_refresh_permissions_oserror(self):
        """Test refresh_permissions() handles OSError."""
        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = OSError()

            result = GitHubKeyManager.refresh_permissions()

            assert result is False

    def test_add_key_success(self, tmp_path):
        """Test add_key() successfully adds a key."""
        pub_key = tmp_path / "test.pub"
        pub_key.write_text("ssh-ed25519 test")

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = GitHubKeyManager.add_key(pub_key, "test-key")

            assert result is True

    def test_add_key_needs_permission_refresh(self, tmp_path):
        """Test add_key() refreshes permissions when needed."""
        pub_key = tmp_path / "test.pub"
        pub_key.write_text("ssh-ed25519 test")

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stderr="admin:public_key scope required"),
                MagicMock(returncode=0),  # refresh_permissions
                MagicMock(returncode=0),  # retry add_key
            ]

            result = GitHubKeyManager.add_key(pub_key, "test-key")

            assert result is True

    def test_add_key_permission_refresh_fails(self, tmp_path):
        """Test add_key() returns False when permission refresh fails."""
        pub_key = tmp_path / "test.pub"
        pub_key.write_text("ssh-ed25519 test")

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stderr="admin:public_key scope required"),
                MagicMock(returncode=1),  # refresh_permissions fails
            ]

            result = GitHubKeyManager.add_key(pub_key, "test-key")

            assert result is False

    def test_add_key_other_error(self, tmp_path):
        """Test add_key() returns False on other errors."""
        pub_key = tmp_path / "test.pub"
        pub_key.write_text("ssh-ed25519 test")

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="other error")

            result = GitHubKeyManager.add_key(pub_key, "test-key")

            assert result is False

    def test_add_key_oserror(self, tmp_path):
        """Test add_key() handles OSError."""
        pub_key = tmp_path / "test.pub"

        with patch("gust.keys.subprocess.run") as mock_run:
            mock_run.side_effect = OSError()

            result = GitHubKeyManager.add_key(pub_key, "test-key")

            assert result is False

    def test_key_exists_true(self):
        """Test key_exists() returns True when fingerprint found."""
        with patch.object(GitHubKeyManager, "list_keys") as mock_list:
            mock_list.return_value = ["key1\tSHA256:abc123", "key2\tSHA256:xyz789"]

            result = GitHubKeyManager.key_exists("SHA256:abc123")

            assert result is True

    def test_key_exists_false(self):
        """Test key_exists() returns False when fingerprint not found."""
        with patch.object(GitHubKeyManager, "list_keys") as mock_list:
            mock_list.return_value = ["key1\tSHA256:abc123"]

            result = GitHubKeyManager.key_exists("SHA256:notfound")

            assert result is False
