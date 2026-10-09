"""Real spawn-process races for F1b identity compare-and-publish."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
from pathlib import Path
import secrets

import pytest


def _storage():
    from importlib import import_module

    try:
        module = import_module("sparc.identity_storage")
    except ModuleNotFoundError as error:
        if error.name != "sparc.identity_storage":
            raise
        pytest.fail("the F1b identity storage API must be implemented")
    assert callable(getattr(module, "publish_identity", None))
    return module


def _identity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.models import Identity

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _encrypted(identity):
    from sparc.identity_codec import encode_identity

    return encode_identity(identity, secrets.token_hex(32).encode("ascii"))


def _publish_racer(path_value, expected, candidate, barrier, result_queue):
    from sparc.identity_storage import publish_identity
    from sparc.models import SparcError

    try:
        barrier.wait(timeout=8)
        publish_identity(Path(path_value), expected=expected, candidate=candidate)
    except SparcError as error:
        result_queue.put((error.code, None))
    except BaseException as error:
        result_queue.put(("unexpected", type(error).__name__))
    else:
        result_queue.put(("committed", None))


def _race_pair(ctx, directory, path, expected, candidates):
    result_queue = ctx.Queue()
    barrier = ctx.Barrier(2)
    processes = [
        ctx.Process(
            target=_publish_racer,
            args=(str(path), expected, candidate, barrier, result_queue),
        )
        for candidate in candidates
    ]
    try:
        for process in processes:
            process.start()
        outcomes = [result_queue.get(timeout=12) for _ in processes]
        for process in processes:
            process.join(timeout=4)
        assert all(not process.is_alive() for process in processes)
        assert all(process.exitcode == 0 for process in processes)
        assert sorted(outcome for outcome, _detail in outcomes) == [
            "committed", "identity_changed"
        ]
        assert path.read_bytes() in candidates
        assert (directory / ".identity.lock").is_file()
        return outcomes
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        result_queue.close()
        result_queue.join_thread()


def test_two_process_create_and_migrate_compare_expected(tmp_path):
    _storage()
    ctx = multiprocessing.get_context("spawn")
    create_dir = tmp_path / "create-race"
    create_dir.mkdir(mode=0o700)
    os.chmod(create_dir, 0o700)
    create_path = create_dir / "identity.json"
    create_candidates = (_encrypted(_identity()), _encrypted(_identity()))
    create_outcomes = _race_pair(
        ctx, create_dir, create_path, None, create_candidates
    )
    assert sum(outcome == "committed" for outcome, _ in create_outcomes) == 1
    assert sum(outcome == "identity_changed" for outcome, _ in create_outcomes) == 1

    migrate_dir = tmp_path / "migrate-race"
    migrate_dir.mkdir(mode=0o700)
    os.chmod(migrate_dir, 0o700)
    migrate_path = migrate_dir / "identity.json"
    # This source snapshot is deliberately nonsecret test text. Worker args
    # carry only encrypted candidates and never passphrases or private keys.
    old_snapshot = b"public migration compare-and-publish snapshot"
    migrate_path.write_bytes(old_snapshot)
    old_identity = _identity()
    migrate_candidates = (_encrypted(old_identity), _encrypted(old_identity))
    migrate_outcomes = _race_pair(
        ctx, migrate_dir, migrate_path, old_snapshot, migrate_candidates
    )
    assert sum(outcome == "committed" for outcome, _ in migrate_outcomes) == 1
    assert sum(outcome == "identity_changed" for outcome, _ in migrate_outcomes) == 1
