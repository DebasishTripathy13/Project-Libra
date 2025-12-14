"""
CLI Entry Point for ProjectLibra.

Allows running: python -m src.cli [command]
"""

from .commands import cli

if __name__ == "__main__":
    cli()
