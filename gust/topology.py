"""
Default topology configurations for Gust.

Provides functions to load the default Spectrum-X topology from package data.
"""

import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_default_topology() -> dict:
    """Load the default Spectrum-X topology from package data.

    Returns:
        Dictionary containing the default topology configuration.
    """
    topology_file = Path(__file__).parent / "default_topology.json"
    with open(topology_file, encoding="utf-8") as file:
        return json.load(file)


def load_default_topology() -> dict:
    """Load default topology (for backward compatibility).

    Returns:
        Dictionary containing the default topology configuration.
    """
    return get_default_topology()
