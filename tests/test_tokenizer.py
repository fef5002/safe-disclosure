"""Tests for the Tokenizer class."""

import unittest

from safe_disclosure.tokenizer import Tokenizer


class TestTokenizer(unittest.TestCase):
    """Test cases for Tokenizer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tokenizer = Tokenizer()
    
    def test_token_generation(self):
        """Test basic token generation."""
        token = self.tokenizer.generate_token('email', 'test@example.com')
        
        self.assertTrue(token.startswith('TOKEN_EMAIL_'))
        self.assertTrue(len(token) > len('TOKEN_EMAIL_'))
    
    def test_deterministic_tokens(self):
        """Test that same entity generates same token within session."""
        email = 'test@example.com'
        token1 = self.tokenizer.generate_token('email', email)
        token2 = self.tokenizer.generate_token('email', email)
        
        self.assertEqual(token1, token2)
    
    def test_different_entities_different_tokens(self):
        """Test that different entities generate different tokens."""
        token1 = self.tokenizer.generate_token('email', 'test1@example.com')
        token2 = self.tokenizer.generate_token('email', 'test2@example.com')
        
        self.assertNotEqual(token1, token2)
    
    def test_entity_type_extraction(self):
        """Test extraction of entity type from token."""
        token = self.tokenizer.generate_token('phone', '555-123-4567')
        entity_type = self.tokenizer.get_entity_type_from_token(token)
        
        self.assertEqual(entity_type, 'phone')
    
    def test_original_value_retrieval(self):
        """Test retrieval of original value from token."""
        original_value = 'test@example.com'
        token = self.tokenizer.generate_token('email', original_value)
        retrieved_value = self.tokenizer.get_original_value(token)
        
        self.assertEqual(retrieved_value, original_value)
    
    def test_token_clearing(self):
        """Test clearing of all tokens."""
        self.tokenizer.generate_token('email', 'test@example.com')
        self.tokenizer.generate_token('phone', '555-123-4567')
        
        self.assertEqual(len(self.tokenizer.entity_tokens), 2)
        
        self.tokenizer.clear_tokens()
        
        self.assertEqual(len(self.tokenizer.entity_tokens), 0)
        self.assertEqual(len(self.tokenizer.token_entities), 0)


if __name__ == '__main__':
    unittest.main()