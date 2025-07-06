import click
from scanner import run_scan

@click.command()
@click.argument('target_url')
@click.option('--verbose', is_flag=True, help="Enable verbose output.")
def cli(target_url, verbose):
    """Scan a remote MCP server for common vulnerabilities."""
    run_scan(target_url, verbose)

if __name__ == '__main__':
    cli()
