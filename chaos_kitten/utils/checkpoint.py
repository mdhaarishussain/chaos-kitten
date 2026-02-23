"""Checkpoint utility for saving and restoring scan state."""

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict, field

@dataclass
class CheckpointData:
    """Data structure for a scan checkpoint."""
    target_url: str
    config_hash: str
    completed_profiles: List[str]
    vulnerabilities: List[Dict[str, Any]]
    timestamp: float
    recon_results: Dict[str, Any] = field(default_factory=dict)

def calculate_config_hash(config: Dict[str, Any]) -> str:
    """Calculate a hash of the configuration to ensure consistency."""
    # Convert config to a consistent JSON string for hashing
    config_str = json.dumps(config, sort_keys=True, default=str)
    return hashlib.sha256(config_str.encode()).hexdigest()

def save_checkpoint(data: CheckpointData, path: Union[str, Path]) -> None:
    """Save checkpoint data to a file atomically.
    
    Args:
        data: The checkpoint data to save
        path: Path to the checkpoint file
    """
    path = Path(path)
    temp_path = path.with_suffix(".tmp")
    try:
        with open(temp_path, "w") as f:
            json.dump(asdict(data), f, indent=2)
            f.flush()
            import os
            os.fsync(f.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

def load_checkpoint(path: Union[str, Path]) -> Optional[CheckpointData]:
    """Load checkpoint data from a file.
    
    Args:
        path: Path to the checkpoint file
        
    Returns:
        CheckpointData if file exists and is valid, None otherwise
    """
    path = Path(path)
    if not path.exists():
        return None
        
    try:
        with open(path, "r") as f:
            data = json.load(f)
            return CheckpointData(**data)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None

def clean_checkpoint(path: Union[str, Path]) -> None:
    """Remove the checkpoint file.
    
    Args:
        path: Path to the checkpoint file
    """
    path = Path(path)
    if path.exists():
        path.unlink()
