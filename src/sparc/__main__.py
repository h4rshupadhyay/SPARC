"""Command-line diagnostics for SPARC."""

import argparse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import platform
import sys

from .identity import inspect_identity
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

    if args.check:
        try:
            data_dir = resolve_data_dir(args.data_dir)
            identity = inspect_identity(data_dir)
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
        if identity.status == "absent":
            print("Identity: absent")
            print("Public fingerprint: unavailable (identity absent)")
        elif identity.status == "legacy_unencrypted":
            print("Identity: legacy unencrypted; migration required; private key not verified")
            print(
                "Public fingerprint (unverified stored metadata): "
                f"{identity.fingerprint}"
            )
        else:
            print("Identity: encrypted; locked; private key not verified")
            print(
                "Public fingerprint (unverified stored metadata): "
                f"{identity.fingerprint}"
            )
        return 0

    try:
        data_dir = resolve_data_dir(args.data_dir)
        # Import the GUI only for normal launch so --check stays Tk-free.
        from .gui.app import launch

        launch(data_dir)
    except ImportError as exc:
        if getattr(exc, "name", None) not in {"tkinter", "_tkinter"}:
            raise
        print(
            "SPARC GUI requires Tk. Install python3-tk on Debian or Ubuntu, or install "
            "CPython for Windows with Tcl/Tk support, then run `python -m sparc` again.",
            file=sys.stderr,
        )
        return 2
    except SparcError as exc:
        if exc.code == "identity_unlock_cancelled":
            print("SPARC launch canceled.", file=sys.stderr)
            return 130
        if exc.code == "gui_unavailable":
            print(f"SPARC GUI unavailable: {exc.message}", file=sys.stderr)
            return 2
        print(f"SPARC launch failed: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
