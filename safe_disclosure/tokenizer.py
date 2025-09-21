"""Token generation and management for safe disclosure."""

import hashlib
import secrets
from typing import Dict


class Tokenizer:
    """Handles token generation and management for redacted entities."""
    
    def __init__(self, token_prefix: str = "TOKEN_"):
        """Initialize tokenizer with optional prefix."""
        self.token_prefix = token_prefix
        self.token_counter = 0
        self.entity_tokens = {}  # entity_value -> token
        self.token_entities = {}  # token -> (entity_type, entity_value)
    
    def generate_token(self, entity_type: str, entity_value: str) -> str:
        """
        Generate a token for an entity value.
        
        Args:
            entity_type: Type of entity (e.g., 'email', 'name')
            entity_value: Actual value to tokenize
        
        Returns:
            Generated token string
        """
        # Check if we already have a token for this entity
        if entity_value in self.entity_tokens:
            return self.entity_tokens[entity_value]
        
        # Generate deterministic but secure token
        entity_hash = hashlib.sha256(
            f"{entity_type}:{entity_value}:{secrets.token_hex(8)}".encode()
        ).hexdigest()[:12]
        
        token = f"{self.token_prefix}{entity_type.upper()}_{entity_hash}"
        
        # Store mappings
        self.entity_tokens[entity_value] = token
        self.token_entities[token] = (entity_type, entity_value)
        
        return token
    
    def get_entity_type_from_token(self, token: str) -> str:
        """Extract entity type from token."""
        if token in self.token_entities:
            return self.token_entities[token][0]
        
        # Fallback: parse from token structure
        if token.startswith(self.token_prefix):
            parts = token[len(self.token_prefix):].split('_')
            if len(parts) >= 2:
                return parts[0].lower()
        
        return "unknown"
    
    def get_original_value(self, token: str) -> str:
        """Get original value for a token."""
        if token in self.token_entities:
            return self.token_entities[token][1]
        return token
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        self.entity_tokens.clear()
        self.token_entities.clear()
        self.token_counter = 0