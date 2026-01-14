"""
SSH key management for Gust.

Provides classes for managing local SSH keys and GitHub SSH keys.
"""

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


class SSHKeyManager:
    """Manage SSH keys for simulation access."""

    def __init__(self, key_path: Optional[str] = None):
        """
        Initialize SSH key manager.

        Args:
            key_path: Path to SSH key file. Defaults to ~/.ssh/spectrum-x
        """
        if key_path:
            self.key_path = Path(key_path)
        else:
            default_path = os.environ.get(
                "SSH_KEY_PATH", str(Path.home() / ".ssh" / "spectrum-x")
            )
            self.key_path = Path(default_path)
        self.pub_key_path = Path(str(self.key_path) + ".pub")

    def exists(self) -> bool:
        """Check if key pair exists.

        Returns:
            True if both private and public key files exist.
        """
        return self.key_path.exists() and self.pub_key_path.exists()

    def generate(self, overwrite: bool = False) -> bool:
        """
        Generate new SSH key pair.

        Args:
            overwrite: If True, overwrite existing keys

        Returns:
            True if key was generated successfully
        """
        if self.exists() and not overwrite:
            return False

        try:
            if self.key_path.exists():
                self.key_path.unlink()
            if self.pub_key_path.exists():
                self.pub_key_path.unlink()

            key_name = self.key_path.stem
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            comment = f"{key_name}-{timestamp}"

            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "ed25519",
                    "-f",
                    str(self.key_path),
                    "-N",
                    "",
                    "-C",
                    comment,
                ],
                check=True,
                capture_output=True,
            )

            return True
        except subprocess.CalledProcessError:
            return False

    def get_public_key(self) -> Optional[str]:
        """Read public key content.

        Returns:
            Public key content as string, or None if not found.
        """
        if self.pub_key_path.exists():
            return self.pub_key_path.read_text(encoding="utf-8").strip()
        return None

    def get_fingerprint(self) -> Optional[str]:
        """Get key fingerprint.

        Returns:
            SSH key fingerprint string, or None on failure.
        """
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", str(self.pub_key_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.split()[1]
        except subprocess.CalledProcessError:
            return None


class GitHubKeyManager:
    """Manage GitHub SSH keys via gh CLI."""

    @staticmethod
    def delete_key(title: str) -> bool:
        """
        Delete SSH key from GitHub by title.

        Args:
            title: Title of the SSH key to delete

        Returns:
            True if key was deleted successfully
        """
        try:
            result = subprocess.run(
                ["gh", "ssh-key", "list"], capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                return False

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 4 and parts[0] == title:
                    key_id = parts[3]
                    del_result = subprocess.run(
                        ["gh", "api", "-X", "DELETE", f"/user/keys/{key_id}"],
                        capture_output=True,
                        check=False,
                    )
                    return del_result.returncode == 0
            return False
        except OSError:
            return False

    @staticmethod
    def is_authenticated() -> bool:
        """Check if gh CLI is authenticated.

        Returns:
            True if gh CLI is authenticated with GitHub.
        """
        try:
            result = subprocess.run(
                ["gh", "auth", "status"], capture_output=True, text=True, check=False
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    def get_username() -> Optional[str]:
        """Get GitHub username.

        Returns:
            GitHub username string, or None on failure.
        """
        try:
            result = subprocess.run(
                ["gh", "api", "user", "-q", ".login"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    @staticmethod
    def list_keys() -> list:
        """List SSH key fingerprints on GitHub.

        Returns:
            List of SSH key lines from GitHub.
        """
        try:
            result = subprocess.run(
                ["gh", "ssh-key", "list"], capture_output=True, text=True, check=True
            )
            if result.stdout.strip():
                return result.stdout.strip().split("\n")
            return []
        except subprocess.CalledProcessError:
            return []

    @staticmethod
    def refresh_permissions() -> bool:
        """Refresh gh auth to add admin:public_key scope.

        Returns:
            True if permissions were refreshed successfully.
        """
        try:
            result = subprocess.run(
                ["gh", "auth", "refresh", "-h", "github.com", "-s", "admin:public_key"],
                capture_output=False,
                check=False,
            )
            return result.returncode == 0
        except OSError:
            return False

    @staticmethod
    def add_key(pub_key_path: Path, title: str) -> bool:
        """
        Add SSH key to GitHub, requesting permissions if needed.

        Args:
            pub_key_path: Path to public key file
            title: Title for the SSH key

        Returns:
            True if key was added successfully
        """
        try:
            result = subprocess.run(
                ["gh", "ssh-key", "add", str(pub_key_path), "--title", title],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return True

            if "admin:public_key" in result.stderr:
                if GitHubKeyManager.refresh_permissions():
                    retry = subprocess.run(
                        ["gh", "ssh-key", "add", str(pub_key_path), "--title", title],
                        capture_output=True,
                        check=False,
                    )
                    return retry.returncode == 0
            return False
        except OSError:
            return False

    @classmethod
    def key_exists(cls, fingerprint: str) -> bool:
        """Check if key with fingerprint exists on GitHub.

        Args:
            fingerprint: SSH key fingerprint to search for.

        Returns:
            True if key with matching fingerprint exists.
        """
        keys = cls.list_keys()
        return any(fingerprint in key for key in keys)
