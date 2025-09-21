"""Role-based access control for safe disclosure."""

from typing import Dict, List, Set


class RoleManager:
    """Manages role-based access control for entity disclosure."""
    
    def __init__(self):
        """Initialize with default roles."""
        self.roles = self._load_default_roles()
    
    def _load_default_roles(self) -> Dict[str, Dict]:
        """Load default role configurations."""
        return {
            'public': {
                'allowed_entities': [],
                'can_restore': False,
                'description': 'Public audience - no sensitive data visible'
            },
            'internal': {
                'allowed_entities': ['name'],
                'can_restore': False,
                'description': 'Internal team - names visible but other data redacted'
            },
            'manager': {
                'allowed_entities': ['name', 'email'],
                'can_restore': True,
                'description': 'Management level - names and emails visible'
            },
            'admin': {
                'allowed_entities': ['name', 'email', 'phone', 'ip_address'],
                'can_restore': True,
                'description': 'Admin level - most entities visible except highly sensitive'
            },
            'security': {
                'allowed_entities': ['name', 'email', 'phone', 'ip_address', 'ssn', 'credit_card'],
                'can_restore': True,
                'description': 'Security team - all entities visible'
            }
        }
    
    def load_roles(self, roles_config: Dict[str, Dict]) -> None:
        """Load role configuration from external source."""
        self.roles.update(roles_config)
    
    def add_role(self, role_name: str, allowed_entities: List[str], 
                 can_restore: bool = False, description: str = "") -> None:
        """Add or update a role."""
        self.roles[role_name] = {
            'allowed_entities': allowed_entities,
            'can_restore': can_restore,
            'description': description
        }
    
    def get_allowed_entities(self, role_name: str) -> Set[str]:
        """Get set of entities that a role can see."""
        if role_name not in self.roles:
            return set()  # Default to no access for unknown roles
        
        return set(self.roles[role_name]['allowed_entities'])
    
    def can_restore(self, role_name: str) -> bool:
        """Check if a role can restore redacted content."""
        if role_name not in self.roles:
            return False
        
        return self.roles[role_name].get('can_restore', False)
    
    def get_role_description(self, role_name: str) -> str:
        """Get description of a role."""
        if role_name not in self.roles:
            return f"Unknown role: {role_name}"
        
        return self.roles[role_name].get('description', '')
    
    def list_roles(self) -> List[str]:
        """List all available roles."""
        return list(self.roles.keys())
    
    def role_hierarchy_check(self, requester_role: str, target_role: str) -> bool:
        """
        Check if requester role has sufficient permissions compared to target role.
        Higher permission roles can access content prepared for lower permission roles.
        """
        role_levels = {
            'public': 0,
            'internal': 1,
            'manager': 2,
            'admin': 3,
            'security': 4
        }
        
        requester_level = role_levels.get(requester_role, -1)
        target_level = role_levels.get(target_role, 0)
        
        return requester_level >= target_level