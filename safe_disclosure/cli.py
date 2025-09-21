"""Command line interface for safe-disclosure."""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from . import SafeDisclosure


@click.group()
@click.version_option()
def main():
    """Safe Disclosure Kit - Securely redact sensitive information using tokens and roles."""
    pass


@main.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--role', required=True, help='Target role for the redacted document')
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
@click.option('--entities', help='Custom entities JSON file')
@click.option('--save-tokens', type=click.Path(), help='Save token mapping to file')
def redact(input_file: str, output_file: str, role: str, 
           config: Optional[str], entities: Optional[str], save_tokens: Optional[str]):
    """Redact sensitive information from a document for a specific role."""
    try:
        # Initialize SafeDisclosure
        sd = SafeDisclosure(config)
        
        # Read input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Load custom entities if provided
        custom_entities = None
        if entities:
            with open(entities, 'r', encoding='utf-8') as f:
                custom_entities = json.load(f)
        
        # Perform redaction
        redacted_content, token_mapping = sd.redact_document(content, role, custom_entities)
        
        # Write redacted content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(redacted_content)
        
        # Save token mapping if requested
        if save_tokens:
            with open(save_tokens, 'w', encoding='utf-8') as f:
                json.dump(token_mapping, f, indent=2)
        
        click.echo(f"Document redacted for role '{role}' and saved to {output_file}")
        if save_tokens:
            click.echo(f"Token mapping saved to {save_tokens}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('tokens_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--role', required=True, help='Requester role for restoration')
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
def restore(input_file: str, tokens_file: str, output_file: str, 
            role: str, config: Optional[str]):
    """Restore redacted content based on role permissions."""
    try:
        # Initialize SafeDisclosure
        sd = SafeDisclosure(config)
        
        # Read redacted content
        with open(input_file, 'r', encoding='utf-8') as f:
            redacted_content = f.read()
        
        # Read token mapping
        with open(tokens_file, 'r', encoding='utf-8') as f:
            token_mapping = json.load(f)
        
        # Restore content
        restored_content = sd.restore_document(redacted_content, token_mapping, role)
        
        # Write restored content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(restored_content)
        
        click.echo(f"Document restored for role '{role}' and saved to {output_file}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
def list_roles(config: Optional[str]):
    """List available roles and their permissions."""
    try:
        sd = SafeDisclosure(config)
        
        click.echo("Available roles:")
        click.echo("-" * 50)
        
        for role in sd.role_manager.list_roles():
            entities = sd.role_manager.get_allowed_entities(role)
            can_restore = sd.role_manager.can_restore(role)
            description = sd.role_manager.get_role_description(role)
            
            click.echo(f"Role: {role}")
            click.echo(f"  Description: {description}")
            click.echo(f"  Allowed entities: {', '.join(sorted(entities)) if entities else 'None'}")
            click.echo(f"  Can restore: {can_restore}")
            click.echo()
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('output_file', type=click.Path())
def generate_config(output_file: str):
    """Generate a sample configuration file."""
    sample_config = {
        "patterns": {
            "custom_id": r"\\bID-\\d{6}\\b",
            "account_number": r"\\bACC-\\d{8}\\b"
        },
        "roles": {
            "contractor": {
                "allowed_entities": ["name"],
                "can_restore": False,
                "description": "External contractor - limited access"
            },
            "analyst": {
                "allowed_entities": ["name", "email", "custom_id"],
                "can_restore": True,
                "description": "Data analyst - medium access"
            }
        }
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sample_config, f, indent=2)
    
    click.echo(f"Sample configuration saved to {output_file}")


if __name__ == '__main__':
    main()