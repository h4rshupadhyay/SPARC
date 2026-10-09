"""Fictional, memory-only data for the visual prototype. No SPARC imports."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address


OWN_FINGERPRINT = "7d9fa621c308b45e" * 4
PEER_FINGERPRINT = "a62c09e1f45bd738" * 4


@dataclass
class Message:
    id: int
    direction: str
    text: str
    timestamp: str
    status: str


def _conversation() -> list[Message]:
    return [
        Message(1, "incoming", "Hey Alice. Ready to try the new connection?", "10:42", "Sample · verified"),
        Message(2, "outgoing", "Ready. I've checked your fingerprint against the one you shared.", "10:43", "Sample · delivered"),
        Message(3, "incoming", "Great. Let's send a few messages and take a look at the audit trail.", "10:43", "Sample · verified"),
        Message(4, "outgoing", "Sounds good. I'll keep the analysis results open too.", "10:44", "Sample · delivered"),
    ]


@dataclass
class DemoState:
    connected: bool = True
    listening: bool = False
    messages: list[Message] = field(default_factory=_conversation)
    pairing: str = "pending"
    endpoint: str = "192.0.2.24:47655"
    analysis_run: int = 0
    audit_verified: bool = False
    analysis_result: dict = field(default_factory=dict)

    def send(self, text: str) -> Message | None:
        if not self.connected or not text.strip():
            return None
        message = Message(len(self.messages) + 1, "outgoing", text, "Now", "Sample · delivered")
        self.messages.append(message)
        return message

    def connect(self, host: str, port: str) -> None:
        try:
            address = IPv4Address(host.strip())
        except ValueError as error:
            raise ValueError("Enter an IPv4 address, for example 192.0.2.24.") from error
        value = port.strip()
        if not value.isascii() or not value.isdecimal() or len(value) > 5 or not 1 <= int(value) <= 65535:
            raise ValueError("Enter a port between 1 and 65535.")
        self.endpoint = f"{address}:{int(value)}"
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def set_listening(self, active: bool) -> None:
        self.listening = active

    def respond_to_pairing(self, approve: bool) -> None:
        self.pairing = "approved" if approve else "rejected"

    def verify_audit(self) -> dict:
        self.audit_verified = True
        return {"sample": True, "valid": True, "verified_records": 24, "writer_head": 26}

    def run_analysis(self) -> dict:
        self.analysis_run += 1
        samples = [(50.4, 0.18, 3.2, 42.1), (49.8, 0.21, 3.8, 42.4), (50.1, 0.19, 3.4, 42.2)]
        sensitivity, latency, cpu, memory = samples[(self.analysis_run - 1) % len(samples)]
        self.analysis_result = {
            "sample": True, "run": self.analysis_run, "sensitivity": sensitivity,
            "encrypt_ms": latency, "cpu_percent": cpu, "memory_mb": memory,
        }
        return dict(self.analysis_result)
