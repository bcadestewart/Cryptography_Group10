"""
web_app.py

Small Flask web app that wraps the Terrapin SSH demo.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure the project root (where src/ lives) is on sys.path
ROOT = Path(__file__).resolve().parent
if (ROOT / "src").exists():
    sys.path.insert(0, str(ROOT))
elif (ROOT.parent / "src").exists():
    sys.path.insert(0, str(ROOT.parent))

from flask import Flask, jsonify, render_template, request

from src.utils import (
    Direction,
    Packet,
    apply_drop_indices,
    compute_sequence_numbers,
    filter_visible_packets,
    load_packet_trace,
)
from src.attack_proxy import load_config, select_drop_indices

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

TRACE_PATH = Path("data/sample_trace.json")
CONFIG_PATH = Path("data/demo_config.yaml")


def packet_to_dict(pkt: Packet) -> Dict[str, Any]:
    return {
        "index": pkt.index,
        "direction": pkt.direction.value,
        "msg_type": pkt.msg_type,
        "payload_len": pkt.payload_len,
        "seq_no": pkt.seq_no,
        "dropped": pkt.dropped,
    }


def build_diff(
    baseline: List[Packet],
    after_attack: List[Packet],
) -> List[Dict[str, Any]]:
    base_seq_by_index: Dict[int, int] = {}
    for pkt in baseline:
        if pkt.seq_no is not None:
            base_seq_by_index[pkt.index] = pkt.seq_no

    diff_rows: List[Dict[str, Any]] = []
    for pkt in after_attack:
        seq_before = base_seq_by_index.get(pkt.index)
        seq_after = pkt.seq_no
        changed = (
            seq_before is not None
            and seq_after is not None
            and seq_before != seq_after
        )
        diff_rows.append(
            {
                "index": pkt.index,
                "direction": pkt.direction.value,
                "msg_type": pkt.msg_type,
                "seq_before": seq_before,
                "seq_after": seq_after,
                "changed": changed,
            }
        )
    return diff_rows


@app.route("/")
def index() -> Any:
    return render_template("index.html")


@app.route("/api/run", methods=["POST"])
def api_run() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "baseline")

    packets = load_packet_trace(TRACE_PATH)
    baseline = compute_sequence_numbers(packets)

    if mode == "baseline":
        return jsonify(
            {
                "mode": "baseline",
                "baseline": [packet_to_dict(p) for p in baseline],
                "after": [packet_to_dict(p) for p in baseline],
                "diff": build_diff(baseline, baseline),
            }
        )

    if mode == "attack":
        config = load_config(CONFIG_PATH)
        drop_indices, desc = select_drop_indices(config)

        attacked = apply_drop_indices(baseline, drop_indices=drop_indices)
        visible = filter_visible_packets(attacked)
        visible_with_seq = compute_sequence_numbers(visible)

        return jsonify(
            {
                "mode": "attack",
                "description": desc,
                "drop_indices": drop_indices,
                "baseline": [packet_to_dict(p) for p in baseline],
                "after": [packet_to_dict(p) for p in visible_with_seq],
                "diff": build_diff(baseline, visible_with_seq),
            }
        )

    if mode == "explore":
        import random

        random_drop = int(data.get("random_drop", 1))
        seed = int(data.get("seed", 0))

        client_indices = [
            p.index
            for p in baseline
            if p.direction == Direction.CLIENT_TO_SERVER
        ]
        if not client_indices or random_drop <= 0:
            return jsonify(
                {
                    "mode": "explore",
                    "error": "No client packets or random_drop <= 0",
                    "baseline": [packet_to_dict(p) for p in baseline],
                    "after": [packet_to_dict(p) for p in baseline],
                    "diff": build_diff(baseline, baseline),
                }
            )

        if seed != 0:
            random.seed(seed)

        k = max(0, min(random_drop, len(client_indices)))
        chosen = sorted(random.sample(client_indices, k=k))

        attacked = apply_drop_indices(baseline, drop_indices=chosen)
        visible = filter_visible_packets(attacked)
        visible_with_seq = compute_sequence_numbers(visible)

        return jsonify(
            {
                "mode": "explore",
                "chosen_indices": chosen,
                "baseline": [packet_to_dict(p) for p in baseline],
                "after": [packet_to_dict(p) for p in visible_with_seq],
                "diff": build_diff(baseline, visible_with_seq),
            }
        )

    return jsonify({"error": f"Unknown mode '{mode}'"}), 400


if __name__ == "__main__":
    app.run(debug=True)
