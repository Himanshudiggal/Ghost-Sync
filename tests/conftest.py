"""Shared test fixtures for Ghost Sync tests."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a temporary directory for test data."""
    return tmp_path


@pytest.fixture
def identity_path(tmp_dir):
    """Path for a temporary identity file."""
    return tmp_dir / "identity.key"


@pytest.fixture
def trust_store_path(tmp_dir):
    """Path for a temporary trust store file."""
    return tmp_dir / "trust_store.json.enc"
