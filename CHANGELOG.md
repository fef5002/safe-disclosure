# Changelog

## [0.1.0] - 2025-01-01

### Added
- Initial release of Safe Disclosure Kit
- Core redaction functionality with token-based entity replacement
- Role-based access control system with predefined roles (public, internal, manager, admin, security)
- Support for multiple entity types: email, phone, SSN, credit card, IP addresses, names
- Command line interface with redact, restore, list-roles, and generate-config commands
- Configurable regex patterns for custom entity detection
- JSON-based configuration system
- Comprehensive test suite
- Example configuration file

### Features
- Secure token generation using cryptographic hashing
- Role hierarchy support for access control
- Custom entity patterns via configuration
- Token mapping for restoration capabilities
- CLI tools for easy integration into workflows