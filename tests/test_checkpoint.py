"""Tests for checkpointing functionality."""

import pytest
from chaos_kitten.utils.checkpoint import (
    CheckpointData,
    save_checkpoint,
    load_checkpoint,
    clean_checkpoint,
    calculate_config_hash
)

@pytest.fixture
def tmp_checkpoint_path(tmp_path):
    return tmp_path / "test_checkpoint.json"

@pytest.fixture
def sample_data():
    return CheckpointData(
        target_url="http://test.com",
        config_hash="abc123hash",
        completed_profiles=["sql_injection"],
        vulnerabilities=[{"type": "sqli", "severity": "high"}],
        timestamp=1234567890.0
    )

def test_calculate_config_hash():
    config1 = {"target": {"url": "http://a.com"}, "param": 1}
    config2 = {"param": 1, "target": {"url": "http://a.com"}}
    config3 = {"target": {"url": "http://b.com"}, "param": 1}
    
    # Hash should be consistent regardless of key order
    assert calculate_config_hash(config1) == calculate_config_hash(config2)
    # Hash should change if content changes
    assert calculate_config_hash(config1) != calculate_config_hash(config3)

def test_save_and_load_checkpoint(tmp_checkpoint_path, sample_data):
    # Save
    save_checkpoint(sample_data, tmp_checkpoint_path)
    assert tmp_checkpoint_path.exists()
    
    # Load
    loaded = load_checkpoint(tmp_checkpoint_path)
    assert loaded is not None
    assert loaded.target_url == sample_data.target_url
    assert loaded.config_hash == sample_data.config_hash
    assert loaded.completed_profiles == sample_data.completed_profiles
    assert loaded.vulnerabilities == sample_data.vulnerabilities
    assert loaded.timestamp == sample_data.timestamp

def test_load_nonexistent_checkpoint(tmp_checkpoint_path):
    loaded = load_checkpoint(tmp_checkpoint_path)
    assert loaded is None

def test_load_corrupted_checkpoint(tmp_checkpoint_path):
    with open(tmp_checkpoint_path, "w") as f:
        f.write("{invalid json")
    
    loaded = load_checkpoint(tmp_checkpoint_path)
    assert loaded is None

def test_clean_checkpoint(tmp_checkpoint_path, sample_data):
    save_checkpoint(sample_data, tmp_checkpoint_path)
    assert tmp_checkpoint_path.exists()
    
    clean_checkpoint(tmp_checkpoint_path)
    assert not tmp_checkpoint_path.exists()

def test_clean_nonexistent_checkpoint(tmp_checkpoint_path):
    # Should not raise error
    clean_checkpoint(tmp_checkpoint_path)
