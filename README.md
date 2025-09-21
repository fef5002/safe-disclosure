# Safe Disclosure Kit

A Python toolkit to safely redact sensitive information from documents, emails, and other communications. The kit uses token-based redaction and role-based access control to customize what information is visible to different audiences while keeping all original data secure with the user.

## Features

- **Token-based redaction**: Replace sensitive information with secure tokens
- **Role-based access control**: Different roles see different levels of information
- **Configurable patterns**: Define custom regex patterns for entity detection
- **CLI interface**: Easy-to-use command line tools
- **Restoration capabilities**: Authorized roles can restore original content
- **Secure by default**: Original data never leaves your control

## Installation

```bash
pip install -e .
```

## Quick Start

### Basic Usage

```python
from safe_disclosure import SafeDisclosure

# Initialize the disclosure kit
sd = SafeDisclosure()

# Sample document with sensitive information
document = """
Dear John Doe,
Your account john.doe@example.com has been updated.
Please call us at 555-123-4567 if you have questions.
Server logs show access from 192.168.1.100.
"""

# Redact for public audience
redacted_doc, tokens = sd.redact_document(document, 'public')
print("Public version:")
print(redacted_doc)

# Redact for internal team (names visible)
internal_doc, _ = sd.redact_document(document, 'internal')
print("\nInternal version:")
print(internal_doc)

# Security team can restore full content
if sd.role_manager.can_restore('security'):
    restored = sd.restore_document(redacted_doc, tokens, 'security')
    print("\nRestored by security:")
    print(restored)
```

### Command Line Usage

```bash
# Redact a document for public consumption
safe-disclosure redact input.txt public_output.txt --role public --save-tokens tokens.json

# Restore content for authorized personnel
safe-disclosure restore public_output.txt tokens.json restored.txt --role security

# List available roles
safe-disclosure list-roles

# Generate sample configuration
safe-disclosure generate-config config.json
```

## Default Roles

- **public**: No sensitive data visible
- **internal**: Names visible, other data redacted  
- **manager**: Names and emails visible
- **admin**: Most entities visible except highly sensitive data
- **security**: All entities visible

## Configuration

Create a JSON configuration file to customize patterns and roles:

```json
{
  "patterns": {
    "employee_id": "\\bEMP-\\d{6}\\b",
    "api_key": "\\bapi_[a-f0-9]{32}\\b"
  },
  "roles": {
    "contractor": {
      "allowed_entities": ["name"],
      "can_restore": false,
      "description": "External contractor - minimal access"
    }
  }
}
```

## Supported Entity Types

- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers
- IP addresses
- Names (basic pattern)
- Custom patterns via configuration

## Security Considerations

- Tokens are generated using cryptographic hashing
- Original data is never stored in tokens
- Role-based access prevents unauthorized data exposure
- Token mappings should be stored securely
- Consider encryption for token mapping files in production

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Project Structure

```
safe_disclosure/
├── __init__.py          # Package initialization
├── core.py              # Main SafeDisclosure class
├── tokenizer.py         # Token generation and management
├── roles.py             # Role-based access control
└── cli.py               # Command line interface
```

## License

MIT License - see LICENSE file for details.
