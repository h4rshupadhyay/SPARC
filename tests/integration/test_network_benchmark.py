import json
from importlib import import_module
from threading import Event

import pytest

from sparc.audit import verify_log
from sparc.audit_format import verify_peer_evidence
from sparc.models import SparcError


def _network_module():
    try:
        network = import_module("sparc.analysis.network")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.network":
            raise
        pytest.fail("sparc.analysis.network must be implemented")
    assert callable(getattr(network, "run_network_benchmark", None)), (
        "run_network_benchmark must be implemented"
    )
    return network


def _audit_rows(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


class RecordingService:
    def __init__(self, service, text_transform=None):
        self._service = service
        self._text_transform = text_transform
        self.message_ids = []

    def send_text(self, text, *, run_id=None):
        if self._text_transform is not None:
            text = self._text_transform(text)
        message_id = self._service.send_text(text, run_id=run_id)
        self.message_ids.append(message_id)
        return message_id

    def __getattr__(self, name):
        return getattr(self._service, name)


def test_network_benchmark_uses_verified_audited_receipts(peer_pair):
    network = _network_module()
    sender, receiver = peer_pair.alice, peer_pair.bob
    recording_sender = RecordingService(sender)

    result = network.run_network_benchmark(
        recording_sender,
        sizes=(64,),
        warmups=2,
        repetitions=3,
        evidence_mode="paired_test",
    )

    assert result.complete is True
    assert len(recording_sender.message_ids) == 5
    assert len(set(recording_sender.message_ids)) == 5
    assert len(result.samples) == 3
    measured_ids = [row["message_id"] for row in result.samples]
    assert measured_ids == recording_sender.message_ids[2:]
    assert len(set(measured_ids)) == 3
    assert all(row["success"] is True for row in result.samples)
    assert all(row["operation"] == "network_round_trip" for row in result.samples)
    assert all(row["payload_bytes"] == 64 for row in result.samples)
    assert all(row["characters"] == 64 for row in result.samples)
    assert all(row["frame_bytes"] > row["payload_bytes"] for row in result.samples)
    assert all(row["finished_ns"] > row["started_ns"] for row in result.samples)

    summary = next(row for row in result.summary if row["payload_bytes"] == 64)
    assert summary["confirmed_count"] == 3
    assert summary["count"] == 3
    assert summary["throughput_bytes_s"] is None
    expected_interval = result.samples[-1]["finished_ns"] - result.samples[0]["started_ns"]
    assert summary["elapsed_interval_ns"] == expected_interval
    assert summary["goodput_bytes_s"] == pytest.approx(192 * 1_000_000_000 / expected_interval)

    run_id = result.metadata["run_id"]
    receiver_receipts = [
        row
        for row in _audit_rows(receiver)
        if row["event"] == "verified_receipt" and row["metadata"].get("run_id") == run_id
    ]
    sent_ids = set(recording_sender.message_ids)
    sender_deliveries = [
        row
        for row in _audit_rows(sender)
        if row["event"] == "verified_delivery"
        and row["metadata"].get("message_id") in sent_ids
    ]
    assert len(receiver_receipts) == 5
    assert len(sender_deliveries) == 5
    for service, records in ((receiver, receiver_receipts), (sender, sender_deliveries)):
        for record in records:
            verify_peer_evidence(record["metadata"])
        report = verify_log(
            service.data_dir / "audit.jsonl",
            service._identity.public_bytes,
            service._audit.checkpoint_path,
        )
        assert report.valid


def test_disconnect_marks_benchmark_incomplete_and_clears_goodput(peer_pair):
    network = _network_module()
    sender = peer_pair.alice

    class CloseAfterFirstReceipt(RecordingService):
        def __init__(self, service):
            super().__init__(service)
            self._closed_after_receipt = False

        def wait_for_receipt(self, *args, **kwargs):
            receipt = self._service.wait_for_receipt(*args, **kwargs)
            if not self._closed_after_receipt:
                self._closed_after_receipt = True
                self._service.close()
            return receipt

    disconnecting_sender = CloseAfterFirstReceipt(sender)
    result = network.run_network_benchmark(
        disconnecting_sender,
        sizes=(64,),
        warmups=0,
        repetitions=3,
        evidence_mode="paired_test",
    )

    assert result.complete is False
    assert result.samples
    summaries = [row for row in result.summary if row["operation"] == "network_round_trip"]
    assert summaries
    assert all(row["goodput_bytes_s"] is None for row in summaries)
    assert all(row["characters_s"] is None for row in summaries)


def test_character_rate_counts_receipt_codepoints(peer_pair):
    network = _network_module()
    sender = RecordingService(peer_pair.alice, text_transform=lambda _text: "é" * 32)

    result = network.run_network_benchmark(
        sender,
        sizes=(64,),
        warmups=0,
        repetitions=2,
        evidence_mode="paired_test",
    )

    assert result.complete is True
    assert len(result.samples) == 2
    assert all(row["payload_bytes"] == 64 for row in result.samples)
    assert all(row["characters"] == 32 for row in result.samples)
    summary = result.summary[0]
    interval = result.samples[-1]["finished_ns"] - result.samples[0]["started_ns"]
    assert summary["characters_s"] == pytest.approx(64 * 1_000_000_000 / interval)


def test_cancel_during_summary_clears_rates_from_all_workloads(peer_pair, monkeypatch):
    network = _network_module()
    cancel = Event()
    summarize = network.summarize
    summary_calls = 0

    def cancel_on_second_summary(*args, **kwargs):
        nonlocal summary_calls
        summary_calls += 1
        if summary_calls == 2:
            cancel.set()
        return summarize(*args, **kwargs)

    monkeypatch.setattr(network, "summarize", cancel_on_second_summary)
    result = network.run_network_benchmark(
        RecordingService(peer_pair.alice),
        sizes=(64, 1024),
        warmups=0,
        repetitions=1,
        cancel=cancel,
        evidence_mode="paired_test",
    )

    assert summary_calls == 2
    assert result.complete is False
    assert len(result.samples) == 2
    assert all(row["success"] is True for row in result.samples)
    assert all(row["goodput_bytes_s"] is None for row in result.summary)
    assert all(row["characters_s"] is None for row in result.summary)


@pytest.mark.parametrize(
    "overrides",
    [
        {"sizes": ()},
        {"sizes": (64, 64)},
        {"sizes": (32,)},
        {"sizes": (64, 1024, 16384, 64)},
        {"warmups": -1},
        {"warmups": 11},
        {"warmups": True},
        {"warmups": 0.5},
        {"repetitions": 0},
        {"repetitions": 101},
        {"repetitions": False},
        {"repetitions": 1.5},
    ],
)
def test_network_benchmark_rejects_out_of_bounds_workloads(overrides):
    network = _network_module()
    with pytest.raises(SparcError):
        network.run_network_benchmark(object(), **overrides)
