"""Tests for the core SafeDisclosure functionality."""

import unittest
import tempfile
import json
import os

from safe_disclosure import SafeDisclosure


class TestSafeDisclosure(unittest.TestCase):
    """Test cases for SafeDisclosure class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sd = SafeDisclosure()
        self.sample_text = """
        Hello John Doe, your email is john.doe@example.com and phone is 555-123-4567.
        Please contact Jane Smith at jane.smith@company.org or call 555-987-6543.
        The server IP is 192.168.1.100 and SSN is 123-45-6789.
        """
    
    def test_redaction_for_public_role(self):
        """Test that public role sees no sensitive information."""
        redacted, tokens = self.sd.redact_document(self.sample_text, 'public')
        
        # Public should see no real data
        self.assertNotIn('john.doe@example.com', redacted)
        self.assertNotIn('555-123-4567', redacted)
        self.assertNotIn('John Doe', redacted)
        self.assertNotIn('192.168.1.100', redacted)
        
        # Should contain tokens
        self.assertIn('TOKEN_', redacted)
    
    def test_redaction_for_internal_role(self):
        """Test that internal role can see names but not other data."""
        redacted, tokens = self.sd.redact_document(self.sample_text, 'internal')
        
        # Internal should see names
        self.assertIn('John Doe', redacted)
        self.assertIn('Jane Smith', redacted)
        
        # But not emails, phones, etc.
        self.assertNotIn('john.doe@example.com', redacted)
        self.assertNotIn('555-123-4567', redacted)
    
    def test_redaction_for_manager_role(self):
        """Test that manager role can see names and emails."""
        redacted, tokens = self.sd.redact_document(self.sample_text, 'manager')
        
        # Manager should see names and emails
        self.assertIn('John Doe', redacted)
        self.assertIn('john.doe@example.com', redacted)
        
        # But not phones, SSN, etc.
        self.assertNotIn('555-123-4567', redacted)
        self.assertNotIn('123-45-6789', redacted)
    
    def test_token_generation(self):
        """Test that tokens are generated consistently."""
        redacted1, tokens1 = self.sd.redact_document(self.sample_text, 'public')
        redacted2, tokens2 = self.sd.redact_document(self.sample_text, 'public')
        
        # Tokens should be consistent (same tokenizer instance)
        self.assertEqual(redacted1, redacted2)
    
    def test_restoration(self):
        """Test restoration of redacted content."""
        redacted, tokens = self.sd.redact_document(self.sample_text, 'public')
        
        # Security role should be able to restore everything
        restored = self.sd.restore_document(redacted, tokens, 'security')
        
        # Should contain original data
        self.assertIn('john.doe@example.com', restored)
        self.assertIn('555-123-4567', restored)
        self.assertIn('John Doe', restored)
    
    def test_custom_entities(self):
        """Test redaction with custom entities."""
        custom_entities = {
            'secret_code': ['ALPHA-123', 'BETA-456']
        }
        
        text_with_custom = self.sample_text + " Secret codes: ALPHA-123 and BETA-456"
        
        redacted, tokens = self.sd.redact_document(text_with_custom, 'public', custom_entities)
        
        # Custom entities should be redacted
        self.assertNotIn('ALPHA-123', redacted)
        self.assertNotIn('BETA-456', redacted)
    
    def test_config_loading(self):
        """Test loading configuration from file."""
        config_data = {
            'patterns': {
                'test_pattern': r'TEST-\\d{3}'
            },
            'roles': {
                'test_role': {
                    'allowed_entities': ['email'],
                    'can_restore': True,
                    'description': 'Test role'
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            sd = SafeDisclosure(config_path)
            
            # Should have loaded custom pattern
            self.assertIn('test_pattern', sd.entity_patterns)
            
            # Should have loaded custom role
            self.assertIn('test_role', sd.role_manager.list_roles())
            
        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    unittest.main()