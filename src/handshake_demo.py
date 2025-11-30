"""
handshake_demo.py

Entry point for a simple "baseline" handshake demonstration.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .utils import compute_sequence_numbers, load_packet_trace, print_packet_table


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Baseline handshake demo: load a simplified SSH-like trace, "
            "compute implicit sequence numbers, and print the results."
        )
    )
    parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help=(
            "Path to the JSON file containing the demo packet trace. "
            "Despite the flag name, this is NOT a real PCAP file."
        ),
    )
    return parser.parse_args()


def run_handshake_demo(trace_path: str | Path) -> None:
    trace_path = Path(trace_path)
    packets = load_packet_trace(trace_path)
    packets_with_seq = compute_sequence_numbers(packets)
    print_packet_table(packets_with_seq, title="Baseline handshake (no attack)")


def main() -> None:
    args = parse_args()
    run_handshake_demo(args.pcap)


if __name__ == "__main__":
    main()
