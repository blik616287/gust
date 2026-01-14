"""Tests for the topology module."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

from gust.topology import get_default_topology, load_default_topology


class TestGetDefaultTopology:
    """Tests for get_default_topology function."""

    def test_loads_topology_from_package_data(self):
        """Test that topology is loaded from default_topology.json."""
        # Clear the cache to ensure fresh load
        get_default_topology.cache_clear()

        topology = get_default_topology()

        assert isinstance(topology, dict)
        assert "nodes" in topology or "title" in topology or len(topology) > 0

    def test_returns_cached_result_on_subsequent_calls(self):
        """Test that lru_cache caches the result."""
        get_default_topology.cache_clear()

        first_call = get_default_topology()
        second_call = get_default_topology()

        # Should be the same object due to caching
        assert first_call is second_call

    def test_raises_on_missing_file(self, tmp_path):
        """Test error when topology file doesn't exist."""
        get_default_topology.cache_clear()

        nonexistent_file = tmp_path / "nonexistent.json"

        with patch("gust.topology.Path") as mock_path_class:
            # Make Path(__file__) return a mock whose parent / "default_topology.json"
            # returns our nonexistent file path
            mock_file_path = MagicMock()
            mock_file_path.parent.__truediv__ = lambda self, x: nonexistent_file
            mock_path_class.return_value = mock_file_path

            with pytest.raises(FileNotFoundError):
                get_default_topology()

    def test_raises_on_invalid_json(self, tmp_path):
        """Test error when topology file contains invalid JSON."""
        get_default_topology.cache_clear()

        invalid_json_file = tmp_path / "invalid.json"
        invalid_json_file.write_text("{ invalid json }")

        with patch("gust.topology.Path") as mock_path_class:
            mock_file_path = MagicMock()
            mock_file_path.parent.__truediv__ = lambda self, x: invalid_json_file
            mock_path_class.return_value = mock_file_path

            with pytest.raises(json.JSONDecodeError):
                get_default_topology()


class TestLoadDefaultTopology:
    """Tests for load_default_topology function."""

    def test_returns_same_as_get_default_topology(self):
        """Test that load_default_topology returns the same result."""
        get_default_topology.cache_clear()

        result1 = get_default_topology()
        result2 = load_default_topology()

        assert result1 == result2

    def test_backward_compatibility(self):
        """Test that load_default_topology maintains backward compatibility."""
        get_default_topology.cache_clear()

        result = load_default_topology()

        assert isinstance(result, dict)
