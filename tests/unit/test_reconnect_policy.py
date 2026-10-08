"""Finite automatic reconnect eligibility and delay policy."""

import pytest

from sparc.models import Limits
from sparc.peer.policy import ReconnectPolicy


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.mark.parametrize("error_code", ["tcp_loss", "delivery_timeout", "peer_inactivity"])
def test_eligible_loss_delays_exactly_1_2_4(error_code):
    policy = ReconnectPolicy(FakeClock())

    assert policy.delays(error_code, explicit_stop=False) == (1.0, 2.0, 4.0)


@pytest.mark.parametrize(
    ("error_code", "explicit_stop"),
    [
        ("changed_identity", False),
        ("signature_invalid", False),
        ("audit_storage_failed", False),
        ("operation_cancelled", False),
        ("tcp_loss", True),
        ("delivery_unconfirmed", False),
        ("protocol_error", False),
    ],
)
def test_auth_changed_audit_or_stop_never_retries(error_code, explicit_stop):
    policy = ReconnectPolicy(FakeClock())

    assert policy.delays(error_code, explicit_stop=explicit_stop) == ()


def test_reconnect_policy_uses_configured_finite_delays():
    policy = ReconnectPolicy(
        FakeClock(), limits=Limits(reconnect_delays=(0.25, 0.5))
    )

    assert policy.delays("tcp_loss", explicit_stop=False) == (0.25, 0.5)
    assert policy.delays("tcp_loss", explicit_stop=True) == ()


@pytest.mark.parametrize("bad_code", [None, 1, ""])
def test_reconnect_policy_rejects_invalid_error_category(bad_code):
    policy = ReconnectPolicy(FakeClock())

    with pytest.raises((TypeError, ValueError)):
        policy.delays(bad_code, explicit_stop=False)
