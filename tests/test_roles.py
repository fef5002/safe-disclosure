"""Tests for the RoleManager class."""

import unittest

from safe_disclosure.roles import RoleManager


class TestRoleManager(unittest.TestCase):
    """Test cases for RoleManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.role_manager = RoleManager()
    
    def test_default_roles_loaded(self):
        """Test that default roles are loaded."""
        roles = self.role_manager.list_roles()
        
        expected_roles = ['public', 'internal', 'manager', 'admin', 'security']
        for role in expected_roles:
            self.assertIn(role, roles)
    
    def test_public_role_permissions(self):
        """Test public role has no access."""
        allowed = self.role_manager.get_allowed_entities('public')
        can_restore = self.role_manager.can_restore('public')
        
        self.assertEqual(len(allowed), 0)
        self.assertFalse(can_restore)
    
    def test_security_role_permissions(self):
        """Test security role has full access."""
        allowed = self.role_manager.get_allowed_entities('security')
        can_restore = self.role_manager.can_restore('security')
        
        self.assertTrue(len(allowed) > 0)
        self.assertTrue(can_restore)
        self.assertIn('email', allowed)
        self.assertIn('ssn', allowed)
    
    def test_manager_role_permissions(self):
        """Test manager role has intermediate access."""
        allowed = self.role_manager.get_allowed_entities('manager')
        can_restore = self.role_manager.can_restore('manager')
        
        self.assertTrue(can_restore)
        self.assertIn('name', allowed)
        self.assertIn('email', allowed)
        self.assertNotIn('ssn', allowed)  # Should not have access to SSN
    
    def test_add_custom_role(self):
        """Test adding a custom role."""
        self.role_manager.add_role(
            'custom_role',
            ['email', 'phone'],
            can_restore=True,
            description='Custom test role'
        )
        
        roles = self.role_manager.list_roles()
        self.assertIn('custom_role', roles)
        
        allowed = self.role_manager.get_allowed_entities('custom_role')
        self.assertIn('email', allowed)
        self.assertIn('phone', allowed)
        
        self.assertTrue(self.role_manager.can_restore('custom_role'))
    
    def test_unknown_role(self):
        """Test behavior with unknown role."""
        allowed = self.role_manager.get_allowed_entities('nonexistent')
        can_restore = self.role_manager.can_restore('nonexistent')
        
        self.assertEqual(len(allowed), 0)
        self.assertFalse(can_restore)
    
    def test_role_hierarchy(self):
        """Test role hierarchy checks."""
        # Security should have access to public content
        self.assertTrue(self.role_manager.role_hierarchy_check('security', 'public'))
        
        # Security should have access to manager content
        self.assertTrue(self.role_manager.role_hierarchy_check('security', 'manager'))
        
        # Public should not have access to security content
        self.assertFalse(self.role_manager.role_hierarchy_check('public', 'security'))
        
        # Manager should have access to internal content
        self.assertTrue(self.role_manager.role_hierarchy_check('manager', 'internal'))
    
    def test_load_roles_config(self):
        """Test loading roles from configuration."""
        roles_config = {
            'test_role': {
                'allowed_entities': ['custom_entity'],
                'can_restore': False,
                'description': 'Test role from config'
            }
        }
        
        self.role_manager.load_roles(roles_config)
        
        roles = self.role_manager.list_roles()
        self.assertIn('test_role', roles)
        
        allowed = self.role_manager.get_allowed_entities('test_role')
        self.assertIn('custom_entity', allowed)


if __name__ == '__main__':
    unittest.main()