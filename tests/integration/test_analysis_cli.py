from collections import Counter
from importlib import import_module
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sparc.analysis.models import BenchmarkResult
from sparc.analysis.sensitivity import run_sensitivity


def _cli_module():
    try:
        cli = import_module("sparc.analysis.__main__")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.__main__":
            raise
        pytest.fail("sparc.analysis CLI must be implemented")
    assert callable(getattr(cli, "main", None)), "analysis CLI main(argv) must be implemented"
    return cli


def _subprocess_environment():
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    source_path = str(project_root / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    return project_root, environment


def _read_csv(path):
    import csv

    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _benchmark_fixture():
    operations = ("hash", "sign", "encrypt", "decrypt", "recompute_hash", "verify")
    samples = [
        {"operation": operation, "payload_bytes": 64, "elapsed_ns": index + 1, "success": True}
        for index, operation in enumerate(operations)
    ]
    summaries = [
        {
            "operation": operation,
            "payload_bytes": 64,
            "count": 1,
            "mean_ns": index + 1.0,
            "median_ns": index + 1.0,
            "p95_ns": index + 1,
            "throughput_bytes_s": 64 * 1_000_000_000 / (index + 1),
        }
        for index, operation in enumerate(operations)
    ]
    return BenchmarkResult(
        metadata={"run_id": "stub-local-run", "evidence_mode": "synthetic_local"},
        samples=samples,
        summary=summaries,
        complete=True,
    )


def test_sensitivity_cli_exports_expected_default_counts(tmp_path):
    project_root, environment = _subprocess_environment()
    command = [
        sys.executable,
        "-m",
        "sparc.analysis",
        "sensitivity",
        "--seed",
        "42",
        "--output",
        str(tmp_path),
    ]
    result = subprocess.run(
        command,
        cwd=project_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Complete" in result.stdout
    trial_rows = _read_csv(tmp_path / "sensitivity_trials.csv")
    summary_rows = _read_csv(tmp_path / "sensitivity_summary.csv")
    assert Counter(row["mode"] for row in trial_rows) == {"plaintext": 6400, "key": 12800}
    assert len(summary_rows) == 6
    assert {"synthetic_key_hex", "synthetic_modified_key_hex"} <= set(trial_rows[0])
    metadata = json.loads(trial_rows[0]["metadata_json"])
    assert metadata["seed"] == "42"
    assert metadata["synthetic_operands"] is True
    assert all(row["complete"] == "true" for row in trial_rows + summary_rows)


def test_benchmark_cli_uses_default_workload_and_exports_six_operations(tmp_path, monkeypatch):
    cli = _cli_module()
    benchmark_module = import_module("sparc.analysis.benchmark")
    result = _benchmark_fixture()
    calls = []

    def runner(sizes=(64, 1024, 16384), warmups=10, repetitions=1000, **kwargs):
        calls.append((sizes, warmups, repetitions))
        return result

    monkeypatch.setattr(benchmark_module, "run_local_benchmarks", runner)
    if hasattr(cli, "run_local_benchmarks"):
        monkeypatch.setattr(cli, "run_local_benchmarks", runner)

    destination = tmp_path / "local.csv"
    exit_code = cli.main(["benchmark", "--output", str(destination)])

    assert exit_code == 0
    assert calls == [((64, 1024, 16384), 10, 1000)]
    rows = _read_csv(destination)
    sample_rows = [row for row in rows if row["row_type"] == "sample"]
    summary_rows = [row for row in rows if row["row_type"] == "summary"]
    assert Counter(row["operation"] for row in sample_rows) == {
        operation: 1 for operation in ("hash", "sign", "encrypt", "decrypt", "recompute_hash", "verify")
    }
    assert len(summary_rows) == 6
    assert json.loads(rows[0]["metadata_json"])["run_id"] == "stub-local-run"


def test_bad_arguments_and_output_path_fail_without_completed_output(tmp_path, monkeypatch, capsys):
    project_root, environment = _subprocess_environment()
    output = tmp_path / "bad-input-output"
    invalid = subprocess.run(
        [
            sys.executable,
            "-m",
            "sparc.analysis",
            "sensitivity",
            "--seed",
            "not-an-integer",
            "--output",
            str(output),
        ],
        cwd=project_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert invalid.returncode != 0
    assert "Complete" not in invalid.stdout
    assert not output.exists()

    cli = _cli_module()
    benchmark_module = import_module("sparc.analysis.benchmark")
    stub_result = _benchmark_fixture()
    monkeypatch.setattr(benchmark_module, "run_local_benchmarks", lambda **_kwargs: stub_result)
    if hasattr(cli, "run_local_benchmarks"):
        monkeypatch.setattr(cli, "run_local_benchmarks", lambda **_kwargs: stub_result)

    blocker = tmp_path / "regular-file"
    blocker.write_text("keep", encoding="utf-8")
    exit_code = cli.main(["benchmark", "--output", str(blocker / "output.csv")])
    output_text = capsys.readouterr()
    assert exit_code != 0
    assert "Complete" not in output_text.out
    assert blocker.read_text(encoding="utf-8") == "keep"
    assert not (blocker / "output.csv").exists()


@pytest.mark.parametrize("negative", [False, True])
def test_cli_preserves_unbounded_integer_seed_in_export_metadata(tmp_path, monkeypatch, negative):
    cli = _cli_module()
    seed_text = ("-" if negative else "") + "1" + "0" * 5000
    expected_seed = -(10**5000) if negative else 10**5000
    seen_seeds = []
    real_runner = run_sensitivity

    def one_case_runner(seed=42, **_kwargs):
        seen_seeds.append(seed)
        return real_runner(seed=seed, cases=1)

    monkeypatch.setattr(cli, "run_sensitivity", one_case_runner)
    output = tmp_path / ("negative" if negative else "positive")

    exit_code = cli.main(["sensitivity", "--seed", seed_text, "--output", str(output)])

    assert exit_code == 0
    assert seen_seeds == [expected_seed]
    rows = _read_csv(output / "sensitivity_trials.csv")
    metadata = json.loads(rows[0]["metadata_json"])
    assert metadata["seed"] == seed_text


def test_standalone_cli_imports_no_gui_socket_service_or_packet_tools(tmp_path):
    project_root, environment = _subprocess_environment()
    destination = tmp_path / "isolated.csv"
    script = r'''
import builtins
import importlib
import sys

blocked = ("socket", "tkinter", "sparc.gui", "sparc.peer.service", "pyshark", "sparc.traffic")
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if any(name == item or name.startswith(item + ".") for item in blocked):
        raise AssertionError("unexpected standalone CLI import: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import

cli = importlib.import_module("sparc.analysis.__main__")
benchmark = importlib.import_module("sparc.analysis.benchmark")
from sparc.analysis.models import BenchmarkResult

def stub_runner(**kwargs):
    return BenchmarkResult(
        metadata={"run_id": "isolated", "evidence_mode": "synthetic_local"},
        samples=[], summary=[], complete=True,
    )

benchmark.run_local_benchmarks = stub_runner
if hasattr(cli, "run_local_benchmarks"):
    cli.run_local_benchmarks = stub_runner
assert cli.main(["benchmark", "--output", sys.argv[1]]) == 0
for name in tuple(sys.modules):
    assert not any(name == item or name.startswith(item + ".") for item in blocked), name
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(destination)],
        cwd=project_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert destination.exists()
