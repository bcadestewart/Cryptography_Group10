"""
cli.py

High-level command-line interface for the Terrapin-style SSH demo.

Subcommands
-----------
- baseline : show sequence numbers for a clean handshake (no attack)
- attack   : run the configured Terrapin-style packet-drop demo
- explore  : try random packet drops from the client side
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import List

from . import handshake_demo
from .attack_proxy import run_demo
from .utils import (
    Direction,
    apply_drop_indices,
    compute_sequence_numbers,
    filter_visible_packets,
    load_packet_trace,
    print_packet_table,
    print_sequence_diff,
)


def _add_common_trace_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        help="Path to the JSON file containing the synthetic packet trace.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Terrapin-style SSH demo CLI with multiple subcommands.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_baseline = subparsers.add_parser(
        "baseline",
        help="Show sequence numbers for a clean handshake (no attack).",
    )
    _add_common_trace_arg(p_baseline)

    p_attack = subparsers.add_parser(
        "attack",
        help="Run the configured Terrapin-style packet-drop demo using a YAML config.",
    )
    p_attack.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to the YAML configuration file (e.g., data/demo_config.yaml).",
    )
    p_attack.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory where JSON logs of before/after traces will be written.",
    )

    p_explore = subparsers.add_parser(
        "explore",
        help="Explore random packet drops on the client side.",
    )
    _add_common_trace_arg(p_explore)
    p_explore.add_argument(
        "--random-drop",
        type=int,
        default=1,
        help="Number of client-side packets to drop randomly (default: 1).",
    )
    p_explore.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Random seed for reproducible drops (0 means non-deterministic).",
    )

    return parser


def cmd_baseline(pcap: str) -> None:
    handshake_demo.run_handshake_demo(pcap)


def cmd_attack(config: str, log_dir: str) -> None:
    run_demo(config_path=config, log_dir=log_dir)


def cmd_explore(pcap: str, random_drop: int, seed: int) -> None:
    trace_path = Path(pcap)
    packets = load_packet_trace(trace_path)

    baseline = compute_sequence_numbers(packets)
    print_packet_table(baseline, title="Baseline handshake (no attack)")

    client_indices: List[int] = [
        pkt.index
        for pkt in baseline
        if pkt.direction == Direction.CLIENT_TO_SERVER
    ]

    if not client_indices:
        print("[!] No client-side packets found to drop.")
        return

    if seed != 0:
        random.seed(seed)

    k = max(0, min(random_drop, len(client_indices)))
    if k == 0:
        print("[*] random_drop is 0 or no droppable packets; nothing to drop.")
        return

    chosen = sorted(random.sample(client_indices, k=k))
    print(f"[*] Randomly dropping client packet indices: {chosen}")

    attacked = apply_drop_indices(baseline, drop_indices=chosen)
    visible_after_attack = filter_visible_packets(attacked)
    visible_after_attack = compute_sequence_numbers(visible_after_attack)

    print_packet_table(
        visible_after_attack,
        title="Post-attack visible handshake (explore mode)",
    )

    print_sequence_diff(
        baseline,
        visible_after_attack,
        title="Sequence number diff (baseline vs explore mode)",
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "baseline":
        cmd_baseline(args.pcap)
    elif args.command == "attack":
        cmd_attack(args.config, args.log_dir)
    elif args.command == "explore":
        cmd_explore(args.pcap, args.random_drop, args.seed)
    else:
        parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
