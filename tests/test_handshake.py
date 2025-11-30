"""
Minimal unit tests for the Terrapin-style SSH demo.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from src.utils import (
    Direction,
    apply_drop_indices,
    compute_sequence_numbers,
    filter_visible_packets,
    load_packet_trace,
)


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class HandshakeDemoTests(unittest.TestCase):
    def test_load_packet_trace(self) -> None:
        trace_path = DATA_DIR / "sample_trace.json"
        packets = load_packet_trace(trace_path)
        self.assertEqual(len(packets), 10)

        self.assertEqual(packets[0].direction, Direction.CLIENT_TO_SERVER)
        self.assertEqual(packets[1].direction, Direction.SERVER_TO_CLIENT)
        self.assertEqual(packets[0].msg_type, "KEXINIT")

    def test_sequence_numbers_baseline(self) -> None:
        trace_path = DATA_DIR / "sample_trace.json"
        packets = load_packet_trace(trace_path)
        baseline = compute_sequence_numbers(packets)

        c2s_packets = [p for p in baseline if p.direction == Direction.CLIENT_TO_SERVER]
        c2s_seq = [p.seq_no for p in c2s_packets]
        self.assertEqual(c2s_seq, [0, 1, 2, 3, 4])

        s2c_packets = [p for p in baseline if p.direction == Direction.SERVER_TO_CLIENT]
        s2c_seq = [p.seq_no for p in s2c_packets]
        self.assertEqual(s2c_seq, [0, 1, 2, 3, 4])

    def test_sequence_numbers_after_drop(self) -> None:
        trace_path = DATA_DIR / "sample_trace.json"
        packets = load_packet_trace(trace_path)
        baseline = compute_sequence_numbers(packets)

        attacked = apply_drop_indices(baseline, drop_indices=[2])
        visible = filter_visible_packets(attacked)
        visible_with_seq = compute_sequence_numbers(visible)

        c2s_packets = [p for p in visible_with_seq if p.direction == Direction.CLIENT_TO_SERVER]
        c2s_seq = [p.seq_no for p in c2s_packets]
        self.assertEqual(c2s_seq, [0, 1, 2, 3])


if __name__ == "__main__":
    unittest.main()
