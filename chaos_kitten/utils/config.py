"""Configuration loader and validator."""

from pathlib import Path
from typing import Any
import yaml
import os


class Config:
    """Load and validate chaos-kitten.yaml configuration."""
    
    def __init__(self, config_path: str | Path = "chaos-kitten.yaml") -> None:
        """Initialize config loader.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self._config: dict[str, Any] = {}
    
    def load(self) -> dict[str, Any]:
        """Load and validate configuration.
        
        Returns:
            Validated configuration dictionary
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If configuration is invalid
        """
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}\n"
                "Run 'chaos-kitten init' to create one."
            )
        
        with open(self.config_path, encoding="utf-8") as f:
            self._config = yaml.safe_load(f)
        
        if self._config is None:
            self._config = {}
            
        if not isinstance(self._config, dict):
            raise ValueError("Configuration root must be a mapping/object")
        
        # Expand environment variables
        self._expand_env_vars(self._config)
        
        # Validate required fields
        self._validate()
        
        return self._config
    
    def _expand_env_vars(self, obj: Any) -> None:
        """Recursively expand ${VAR} environment variables."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                    env_var = value[2:-1]
                    obj[key] = os.environ.get(env_var, "")
                elif isinstance(value, (dict, list)):
                    self._expand_env_vars(value)
        elif isinstance(obj, list):
            for item in obj:
                self._expand_env_vars(item)
    
    def _validate(self) -> None:
        """Validate configuration."""
        required = ["target"]
        for field in required:
            if field not in self._config:
                raise ValueError(f"Missing required configuration field: {field}")
        
        target = self._config.get("target", {})
        target_type = target.get("type", "rest")
        
        if target_type == "graphql":
            if "graphql_endpoint" not in target and "graphql_schema" not in target:
                raise ValueError("GraphQL target requires either 'graphql_endpoint' or 'graphql_schema'")
        else:
            # Default to REST behavior
            if "base_url" not in target:
                raise ValueError("Missing required field: target.base_url")
    
    @property
    def target(self) -> dict[str, Any]:
        """Get target configuration."""
        return self._config.get("target", {})
    
    @property
    def agent(self) -> dict[str, Any]:
        """Get agent configuration."""
        return self._config.get("agent", {})
    
    @property
    def executor(self) -> dict[str, Any]:
        """Get executor configuration."""
        return self._config.get("executor", {})
    
    @property
    def safety(self) -> dict[str, Any]:
        """Get safety configuration."""
        return self._config.get("safety", {})
    
    @property
    def retry(self) -> dict[str, Any]:
        """Get retry configuration.
        
        Returns:
            Retry configuration with sensible defaults:
            - max_attempts: Maximum number of retry attempts (default: 5)
            - initial_backoff_ms: Initial backoff in milliseconds (default: 100)
            - max_backoff_ms: Maximum backoff in milliseconds (default: 32000)
            - backoff_multiplier: Exponential multiplier (default: 2.0)
            - jitter_factor: Jitter as fraction of backoff (default: 0.1)
            - strategy: Retry strategy - exponential|linear|fixed|adaptive (default: exponential)
            - respect_retry_after: Use Retry-After header (default: true)
            - retry_on_status_codes: List of status codes to retry on (default: [429, 500, 502, 503, 504])
        """
        defaults = {
            "max_attempts": 5,
            "initial_backoff_ms": 100,
            "max_backoff_ms": 32000,
            "backoff_multiplier": 2.0,
            "jitter_factor": 0.1,
            "strategy": "exponential",
            "respect_retry_after": True,
            "retry_on_status_codes": [429, 500, 502, 503, 504],
        }
        
        retry_config = self._config.get("retry", {})
        
        # Merge defaults with user config
        for key, default_value in defaults.items():
            if key not in retry_config:
                retry_config[key] = default_value
        
        return retry_config
