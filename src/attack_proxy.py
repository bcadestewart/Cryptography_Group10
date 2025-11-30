"""
attack_proxy.py

Educational "attack proxy" demo for Terrapin-style sequence number
manipulation in SSH-like protocols.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml  # type: ignore[import-untyped]

from .utils import (
    apply_drop_indices,
    compute_sequence_numbers,
    filter_visible_packets,
    load_packet_trace,
    print_packet_table,
    print_sequence_diff,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Terrapin-style attack proxy demo. Loads a synthetic SSH-like "
            "trace, applies a simple packet-drop 'attack', and shows how "
            "sequence numbers shift as a result."
        )
    )
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to the YAML configuration file (e.g., data/demo_config.yaml).",
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory where JSON logs of before/after traces will be written.",
    )
    return parser.parse_args()


def load_config(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f)  # type: ignore[no-untyped-call]
    if not isinstance(config, dict):
        raise ValueError(f"Configuration in {path} must be a mapping")
    return config


def select_drop_indices(config: Dict[str, Any]) -> Tuple[List[int], str]:
    profiles = config.get("profiles")
    active_profile = config.get("active_profile")

    if isinstance(profiles, dict) and isinstance(active_profile, str):
        profile = profiles.get(active_profile)
        if not isinstance(profile, dict):
            raise ValueError(f"Profile '{active_profile}' not found or not a mapping")

        drop_indices = profile.get("drop_indices", [])
        if not isinstance(drop_indices, list):
            raise ValueError(f"Profile '{active_profile}' has invalid 'drop_indices'")

        description = profile.get("description", f"profile '{active_profile}'")
        return [int(i) for i in drop_indices], description

    drop_indices = config.get("drop_indices", [])
    if not isinstance(drop_indices, list):
        raise ValueError("Config key 'drop_indices' must be a list of integers")

    description = "top-level drop_indices"
    return [int(i) for i in drop_indices], description


def serialize_packets_to_json(path: Path, packets: List[Any]) -> None:
    data = []
    for pkt in packets:
        data.append(
            {
                "index": pkt.index,
                "direction": pkt.direction.value,
                "payload_len": pkt.payload_len,
                "msg_type": pkt.msg_type,
                "seq_no": pkt.seq_no,
                "dropped": pkt.dropped,
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_demo(config_path: str | Path, log_dir: str | Path) -> None:
    config = load_config(config_path)
    try:
        pcap_file = config["pcap_file"]
    except KeyError as exc:
        raise ValueError(f"Missing required config key: {exc!s}") from exc

    drop_indices, desc = select_drop_indices(config)

    print(f"[*] Loading demo trace from: {pcap_file}")
    packets = load_packet_trace(pcap_file)

    baseline = compute_sequence_numbers(packets)
    print_packet_table(baseline, title="Baseline handshake (no attack)")

    print(f"[*] Applying simulated attack using {desc}, dropping packet indices: {drop_indices}")
    attacked = apply_drop_indices(baseline, drop_indices=drop_indices)

    visible_after_attack = filter_visible_packets(attacked)
    visible_after_attack = compute_sequence_numbers(visible_after_attack)

    print_packet_table(
        visible_after_attack,
        title="Post-attack visible handshake (after dropping packets)",
    )

    print_sequence_diff(
        baseline,
        visible_after_attack,
        title="Sequence number diff (baseline vs post-attack)",
    )

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = Path(log_dir)

    baseline_log = log_dir / f"baseline_trace_{timestamp}.json"
    attacked_log = log_dir / f"post_attack_trace_{timestamp}.json"

    serialize_packets_to_json(baseline_log, baseline)
    serialize_packets_to_json(attacked_log, visible_after_attack)

    print(f"[*] Baseline trace written to: {baseline_log}")
    print(f"[*] Post-attack trace written to: {attacked_log}")
    print("[*] Demo complete.")


def main() -> None:
    args = parse_args()
    run_demo(config_path=args.config, log_dir=args.log_dir)


if __name__ == "__main__":
    main()
