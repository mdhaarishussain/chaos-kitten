import os
import tempfile

import pytest

from chaos_kitten.utils.config import Config


class TestConfigValidation:

    def create_temp_config(self, content):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_empty_config_file(self):
        """Test that an empty config file raises a clear ValueError about missing fields, not TypeError."""
        config_path = self.create_temp_config("")
        try:
            config = Config(config_path)
            with pytest.raises(
                ValueError, match="Missing required configuration field: target"
            ):
                config.load()
        finally:
            os.remove(config_path)

    def test_invalid_root_list(self):
        """Test that a list root raises ValueError."""
        config_path = self.create_temp_config("- item1\n- item2")
        try:
            config = Config(config_path)
            with pytest.raises(
                ValueError, match="Configuration root must be a mapping/object"
            ):
                config.load()
        finally:
            os.remove(config_path)

    def test_invalid_root_string(self):
        """Test that a string root raises ValueError."""
        config_path = self.create_temp_config("just a string")
        try:
            config = Config(config_path)
            with pytest.raises(
                ValueError, match="Configuration root must be a mapping/object"
            ):
                config.load()
        finally:
            os.remove(config_path)

    def test_valid_config(self):
        """Test that a valid config loads correctly."""
        valid_yaml = """
target:
  base_url: "http://example.com"
"""
        config_path = self.create_temp_config(valid_yaml)
        try:
            config = Config(config_path)
            loaded = config.load()
            assert loaded["target"]["base_url"] == "http://example.com"
        finally:
            os.remove(config_path)
