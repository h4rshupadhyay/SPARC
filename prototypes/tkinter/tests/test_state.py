"""Behavior checks for the prototype's local interactions."""

import unittest

from state import DemoState


class DemoStateTests(unittest.TestCase):
    def test_send_requires_connection_and_nonempty_text(self):
        state = DemoState()
        before = len(state.messages)
        self.assertIsNone(state.send("  \n"))
        state.disconnect()
        self.assertIsNone(state.send("hello"))
        self.assertEqual(len(state.messages), before)
        state.connect("192.0.2.24", "47655")
        message = state.send("hello\nworld")
        self.assertEqual(message.text, "hello\nworld")
        self.assertEqual(message.direction, "outgoing")
        self.assertEqual(len(state.messages), before + 1)

    def test_invalid_endpoint_preserves_state(self):
        state = DemoState()
        for host, port in [("invalid", "47655"), ("192.0.2.24", "abc"),
                           ("192.0.2.24", "0"), ("192.0.2.24", "65536")]:
            with self.subTest(host=host, port=port):
                before = (state.connected, state.endpoint)
                with self.assertRaises(ValueError):
                    state.connect(host, port)
                self.assertEqual((state.connected, state.endpoint), before)
        state.connect("192.0.2.24", "47655")
        self.assertEqual(state.endpoint, "192.0.2.24:47655")

    def test_demo_transitions_are_local_and_repeatable(self):
        state = DemoState()
        state.set_listening(True)
        self.assertTrue(state.listening)
        state.set_listening(False)
        self.assertFalse(state.listening)
        state.respond_to_pairing(True)
        self.assertEqual(state.pairing, "approved")
        state.respond_to_pairing(False)
        self.assertEqual(state.pairing, "rejected")
        self.assertTrue(state.verify_audit()["sample"])
        first, second = state.run_analysis(), state.run_analysis()
        self.assertTrue(first["sample"] and second["sample"])
        self.assertEqual(second["run"], first["run"] + 1)
        other = DemoState()
        self.assertEqual(first, other.run_analysis())


if __name__ == "__main__":
    unittest.main()
