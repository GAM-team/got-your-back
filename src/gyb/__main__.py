"""Allow invoking GYB via ``python -m gyb``."""

from __future__ import annotations

from gyb.cli.main import cli


def main() -> None:
    """Entrypoint for ``python -m gyb``."""
    cli()


if __name__ == "__main__":
    main()
