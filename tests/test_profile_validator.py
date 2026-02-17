import pytest
import yaml
import os
from chaos_kitten.validators.profile_validator import AttackProfileValidator, ValidationReport

class TestAttackProfileValidator:
    @pytest.fixture
    def validator(self):
        return AttackProfileValidator()

    def create_profile(self, tmp_path, filename, content):
        p = tmp_path / filename
        with open(p, 'w') as f:
            yaml.dump(content, f)
        return str(p)

    def test_valid_profile(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'high',
            'payloads': ['1 OR 1=1'],
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'valid.yaml', content)
        report = validator.validate_profile(path)
        assert report.is_valid
        assert not report.errors

    def test_missing_required_field(self, validator, tmp_path):
        content = {
            'category': 'sql_injection',
            # missing name
            'severity': 'high',
            'payloads': ['1 OR 1=1'],
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'missing_name.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert any("Missing required field: 'name'" in e for e in report.errors)

    def test_invalid_severity(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'super_critical', # Invalid
            'payloads': ['1 OR 1=1'],
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'invalid_severity.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert any("Invalid severity" in e for e in report.errors)

    def test_empty_payloads(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'high',
            'payloads': [], # Empty
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'empty_payloads.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert "Field 'payloads' cannot be empty" in report.errors

    def test_malformed_payload(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'high',
            'payloads': [{'wrong_key': 'val'}], # Missing 'value'
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'malformed_payload.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert any("missing 'value' field" in e for e in report.errors)

    def test_missing_success_indicators(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'high',
            'payloads': ['payload'],
            # missing success_indicators
        }
        path = self.create_profile(tmp_path, 'missing_indicators.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert any("Missing required field: 'success_indicators'" in e for e in report.errors)

    def test_invalid_success_indicators_type(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'sql_injection',
            'severity': 'high',
            'payloads': ['payload'],
            'success_indicators': ['should be dict'] # Invalid type
        }
        path = self.create_profile(tmp_path, 'invalid_indicators.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert "Field 'success_indicators' must be a dictionary" in report.errors

    def test_file_not_found(self, validator):
        report = validator.validate_profile("non_existent_file.yaml")
        assert not report.is_valid
        assert any("File not found" in e for e in report.errors)

    def test_invalid_yaml_syntax(self, validator, tmp_path):
        p = tmp_path / "invalid.yaml"
        with open(p, 'w') as f:
            f.write("key: [unclosed list")
        report = validator.validate_profile(str(p))
        assert not report.is_valid
        assert any("Invalid YAML syntax" in e for e in report.errors)

    def test_unknown_category_warning(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'unknown_category',
            'severity': 'high',
            'payloads': ['payload'],
            'success_indicators': {'status_codes': [200]}
        }
        path = self.create_profile(tmp_path, 'unknown_cat.yaml', content)
        report = validator.validate_profile(path)
        assert report.is_valid # Should still be valid, just warning
        assert any("Unknown category" in w for w in report.warnings)

    def test_validate_all_profiles(self, validator, tmp_path):
        # Create 2 valid profiles
        self.create_profile(tmp_path, 'p1.yaml', {
            'name': 'P1', 'category': 'xss', 'severity': 'low', 
            'payloads': ['p1'], 'success_indicators': {'a': 1}
        })
        self.create_profile(tmp_path, 'p2.yaml', {
            'name': 'P2', 'category': 'xss', 'severity': 'low', 
            'payloads': ['p2'], 'success_indicators': {'a': 1}
        })
        
        results = validator.validate_all_profiles(str(tmp_path))
        assert len(results) == 2
        assert results['p1.yaml'].is_valid
        assert results['p2.yaml'].is_valid

    def test_cwe_format_warning(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'xss',
            'severity': 'high',
            'payloads': ['p'],
            'success_indicators': {'a': 1},
            'references': ['https://cwe.mitre.org/data/definitions/bad_format'] # No CWE-XXX
        }
        path = self.create_profile(tmp_path, 'cwe_warn.yaml', content)
        report = validator.validate_profile(path)
        assert report.is_valid
        assert any("CWE format" in w for w in report.warnings)

    def test_invalid_references_type(self, validator, tmp_path):
        content = {
            'name': 'Test Profile',
            'category': 'xss',
            'severity': 'high',
            'payloads': ['p'],
            'success_indicators': {'a': 1},
            'references': 'not-a-list'
        }
        path = self.create_profile(tmp_path, 'inval_ref.yaml', content)
        report = validator.validate_profile(path)
        assert not report.is_valid
        assert "Field 'references' must be a list" in report.errors
