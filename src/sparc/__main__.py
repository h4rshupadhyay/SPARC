"""Command-line diagnostics for SPARC."""

import argparse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import platform
import sys

from .identity import load_identity
from .models import SparcError
from .storage import resolve_data_dir


def _distribution_version(distribution: str) -> str:
    try:
        return version(distribution)
    except PackageNotFoundError:
        return "not installed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sparc")
    parser.add_argument("--check", action="store_true", help="print local diagnostic versions and identity fingerprint")
    parser.add_argument("--data-dir", type=Path, help="use an explicit SPARC data directory")
    args = parser.parse_args(argv)

    if not args.check:
        print(
            "The graphical interface is not available yet. Run `python -m sparc --check` "
            "for diagnostics.",
            file=sys.stderr,
        )
        return 2

    try:
        data_dir = resolve_data_dir(args.data_dir)
        identity = load_identity(data_dir)
    except SparcError as exc:
        print(f"SPARC check failed: {exc.message}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"SPARC check failed: {exc}", file=sys.stderr)
        return 1

    print(f"SPARC: {_distribution_version('sparc')}")
    print(f"Python: {platform.python_version()}")
    print(f"cryptography: {_distribution_version('cryptography')}")
    print(f"psutil: {_distribution_version('psutil')}")
    print(f"PyCryptodome: {_distribution_version('pycryptodome')}")
    print(f"PyShark: {_distribution_version('pyshark')}")
    print(f"Public fingerprint: {identity.fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
