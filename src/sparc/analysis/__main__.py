"""Command-line entry point for standalone synthetic analysis tools."""

import argparse
from pathlib import Path
import sys

from ..models import SparcError
from .benchmark import run_local_benchmarks
from .export import export_benchmark, export_lab
from .sensitivity import run_sensitivity


def _parse_seed(value: str) -> int:
    """Parse an arbitrarily large signed decimal seed without large int() calls."""
    text = value.strip()
    sign = 1
    if text[:1] in ("+", "-"):
        if text[0] == "-":
            sign = -1
        text = text[1:]

    # Normalize the decimal digits and separators accepted by int. Defer
    # malformed values to int so argparse reports its usual conversion error.
    digits = []
    for index, character in enumerate(text):
        if character == "_":
            if (
                index == 0
                or index == len(text) - 1
                or not text[index - 1].isdecimal()
                or not text[index + 1].isdecimal()
            ):
                return int(value)
            continue
        if not character.isdecimal():
            return int(value)
        digits.append(str(int(character)))

    if not digits:
        return int(value)

    number = 0
    normalized = "".join(digits)
    for start in range(0, len(normalized), 9):
        chunk = normalized[start : start + 9]
        number = number * (10 ** len(chunk)) + int(chunk)
    return sign * number


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sparc.analysis")
    commands = parser.add_subparsers(dest="command", required=True)

    sensitivity = commands.add_parser("sensitivity", help="run the synthetic AES sensitivity laboratory")
    sensitivity.add_argument("--seed", type=_parse_seed, default=42, help="integer seed for reproducible operands")
    sensitivity.add_argument("--output", type=Path, required=True, help="directory for trial and summary CSV files")

    benchmark = commands.add_parser("benchmark", help="measure local synthetic cryptographic operations")
    benchmark.add_argument("--output", type=Path, required=True, help="destination CSV file")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one standalone analysis command and return its process status."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "sensitivity":
            result = run_sensitivity(seed=args.seed)
            paths = export_lab(result, args.output)
            if not result.complete:
                print("Incomplete sensitivity run; partial results were exported.", file=sys.stderr)
                for path in paths:
                    print(path, file=sys.stderr)
                return 1
            print("Complete sensitivity run.")
            for path in paths:
                print(path)
            return 0

        result = run_local_benchmarks()
        export_benchmark(result, args.output)
        if not result.complete:
            print("Incomplete benchmark run; partial results were exported.", file=sys.stderr)
            print(args.output, file=sys.stderr)
            return 1
        print("Complete benchmark run.")
        print(args.output)
        return 0
    except (SparcError, OSError, ValueError) as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
