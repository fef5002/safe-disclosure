"""Core functionality for safe disclosure."""

import json
import re
from typing import Dict, List, Optional, Set, Tuple
from .tokenizer import Tokenizer
from .roles import RoleManager


class SafeDisclosure:
    """Main class for handling safe disclosure of sensitive information."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize SafeDisclosure with optional configuration."""
        self.tokenizer = Tokenizer()
        self.role_manager = RoleManager()
        self.entity_patterns = self._load_default_patterns()
        
        if config_path:
            self.load_config(config_path)
    
    def _load_default_patterns(self) -> Dict[str, str]:
        """Load default regex patterns for common sensitive entities."""
        return {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'name': r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Simple name pattern
        }
    
    def load_config(self, config_path: str) -> None:
        """Load configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                if 'patterns' in config:
                    self.entity_patterns.update(config['patterns'])
                if 'roles' in config:
                    self.role_manager.load_roles(config['roles'])
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in configuration file: {config_path}")
    
    def redact_document(self, text: str, target_role: str, 
                       custom_entities: Optional[Dict[str, List[str]]] = None) -> Tuple[str, Dict[str, str]]:
        """
        Redact sensitive information from text based on role permissions.
        
        Args:
            text: Input text to redact
            target_role: Role for which the document is being prepared
            custom_entities: Additional entities to redact (entity_type -> list of values)
        
        Returns:
            Tuple of (redacted_text, token_mapping)
        """
        # Get allowed entities for the role
        allowed_entities = self.role_manager.get_allowed_entities(target_role)
        
        # Find all entities in the text
        entities_found = self._find_entities(text, custom_entities)
        
        # Generate tokens and redact
        redacted_text = text
        token_mapping = {}
        
        for entity_type, matches in entities_found.items():
            if entity_type not in allowed_entities:
                for match in matches:
                    token = self.tokenizer.generate_token(entity_type, match)
                    redacted_text = redacted_text.replace(match, token)
                    token_mapping[token] = match
        
        return redacted_text, token_mapping
    
    def _find_entities(self, text: str, custom_entities: Optional[Dict[str, List[str]]] = None) -> Dict[str, Set[str]]:
        """Find entities in text using patterns and custom entities."""
        entities_found = {}
        
        # Find entities using regex patterns
        for entity_type, pattern in self.entity_patterns.items():
            matches = set(re.findall(pattern, text))
            if matches:
                entities_found[entity_type] = matches
        
        # Add custom entities
        if custom_entities:
            for entity_type, entity_list in custom_entities.items():
                found_custom = set()
                for entity in entity_list:
                    if entity in text:
                        found_custom.add(entity)
                if found_custom:
                    entities_found.setdefault(entity_type, set()).update(found_custom)
        
        return entities_found
    
    def restore_document(self, redacted_text: str, token_mapping: Dict[str, str], 
                        requester_role: str) -> str:
        """
        Restore original entities based on requester's role permissions.
        
        Args:
            redacted_text: Text with tokens
            token_mapping: Mapping of tokens to original values
            requester_role: Role of the entity requesting restoration
        
        Returns:
            Text with allowed entities restored
        """
        if not self.role_manager.can_restore(requester_role):
            return redacted_text
        
        allowed_entities = self.role_manager.get_allowed_entities(requester_role)
        restored_text = redacted_text
        
        for token, original_value in token_mapping.items():
            entity_type = self.tokenizer.get_entity_type_from_token(token)
            if entity_type in allowed_entities:
                restored_text = restored_text.replace(token, original_value)
        
        return restored_text