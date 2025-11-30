"""
utils.py

Shared data structures and helper functions for the Terrapin-style SSH demo.

This module is deliberately high-level and educational. It does NOT implement
a real SSH stack. Instead, it uses a simplified "packet" model to illustrate:

- Directions (client -> server, server -> client)
- Implicit per-direction sequence numbers
- How dropping packets early in the handshake can shift sequence numbers
  and change the meaning of later packets.

The goal is to support small, self-contained demos that can be reproduced
easily from the data files shipped with this project.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, List, TextIO, Dict


class Direction(str, Enum):
    """
    Direction of an SSH Binary Packet Protocol message.

    In real SSH, each direction has its own implicit sequence number counter
    that starts at 0 and increments by 1 for every packet sent in that
    direction. Here we only model this behavior at a high level.
    """

    CLIENT_TO_SERVER = "C->S"
    SERVER_TO_CLIENT = "S->C"


@dataclass
class Packet:
    """
    A single simplified "SSH packet" used in this demonstration.

    Attributes
    ----------
    index : int
        Logical index of this packet in the trace (0-based in this demo).
    direction : Direction
        Whether the packet flows from client to server or server to client.
    payload_len : int
        Length of the packet payload in bytes (simplified for demo purposes).
    msg_type : str
        Human-readable label for the message type (e.g., "KEXINIT", "NEWKEYS").
    seq_no : int | None
        Implicit per-direction sequence number. This is populated by calling
        `compute_sequence_numbers`. Until then it may be None.
    dropped : bool
        Whether this packet was dropped by the simulated attack. Dropped packets
        will still be visible in the "before" view but may be filtered out in
        the "after" view.
    """

    index: int
    direction: Direction
    payload_len: int
    msg_type: str
    seq_no: int | None = None
    dropped: bool = False


def load_packet_trace(path: str | Path) -> List[Packet]:
    """
    Load a demo packet trace from a JSON file and return a list of Packet objects.

    The JSON file is expected to contain a list of objects with fields:
    - "direction": string, one of "C->S" or "S->C"
    - "payload_len": integer number of bytes
    - "msg_type": string label

    Parameters
    ----------
    path : str or pathlib.Path
        Path to the JSON file containing the packet trace.

    Returns
    -------
    List[Packet]
        List of Packet objects with indices assigned in order.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        raw_packets = json.load(f)

    packets: List[Packet] = []
    for idx, item in enumerate(raw_packets):
        direction_str = item["direction"]
        try:
            direction = Direction(direction_str)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid direction '{direction_str}' in {path}") from exc

        packets.append(
            Packet(
                index=idx,
                direction=direction,
                payload_len=int(item["payload_len"]),
                msg_type=str(item["msg_type"]),
            )
        )

    return packets


def compute_sequence_numbers(packets: Iterable[Packet]) -> List[Packet]:
    """
    Compute implicit per-direction sequence numbers for the given packets.

    In SSH, each direction (client->server, server->client) has its own
    sequence number counter that starts at 0 and increments by 1 for each
    packet. This function simulates that behavior.

    Parameters
    ----------
    packets : Iterable[Packet]
        Sequence of packets in chronological order.

    Returns
    -------
    List[Packet]
        New list of Packet objects with `seq_no` fields populated.
    """
    seq_c2s = 0  # client-to-server sequence number
    seq_s2c = 0  # server-to-client sequence number

    result: List[Packet] = []

    for pkt in packets:
        # Create a shallow copy so we do not mutate the caller's objects.
        pkt_copy = Packet(
            index=pkt.index,
            direction=pkt.direction,
            payload_len=pkt.payload_len,
            msg_type=pkt.msg_type,
            seq_no=pkt.seq_no,
            dropped=pkt.dropped,
        )

        if pkt_copy.direction == Direction.CLIENT_TO_SERVER:
            pkt_copy.seq_no = seq_c2s
            seq_c2s += 1
        else:
            pkt_copy.seq_no = seq_s2c
            seq_s2c += 1

        result.append(pkt_copy)

    return result


def apply_drop_indices(packets: Iterable[Packet], drop_indices: Iterable[int]) -> List[Packet]:
    """
    Mark packets at the specified indices as dropped and return a new list.

    This simulates a simple prefix truncation / packet-drop attack by removing
    selected packets from the trace. In a real Terrapin attack, the choices of
    which packets to drop and how to manipulate sequence numbers are more
    subtle and protocol-specific; here we only show the basic idea.

    Parameters
    ----------
    packets : Iterable[Packet]
        Original packet sequence.
    drop_indices : Iterable[int]
        Indices (0-based) of packets to drop.

    Returns
    -------
    List[Packet]
        New list of Packet objects. The `dropped` flag is set on the packets
        that were dropped from the "post-attack" visible trace.
    """
    drop_set = set(drop_indices)
    result: List[Packet] = []

    for pkt in packets:
        pkt_copy = Packet(
            index=pkt.index,
            direction=pkt.direction,
            payload_len=pkt.payload_len,
            msg_type=pkt.msg_type,
            seq_no=pkt.seq_no,
            dropped=pkt.dropped,
        )

        if pkt_copy.index in drop_set:
            pkt_copy.dropped = True
        result.append(pkt_copy)

    return result


def filter_visible_packets(packets: Iterable[Packet]) -> List[Packet]:
    """
    Filter out dropped packets to produce the "visible" post-attack trace.

    Parameters
    ----------
    packets : Iterable[Packet]
        Packet list that may contain dropped packets.

    Returns
    -------
    List[Packet]
        List of only non-dropped packets in chronological order.
    """
    return [pkt for pkt in packets if not pkt.dropped]


def print_packet_table(
    packets: Iterable[Packet],
    title: str | None = None,
    file: TextIO | None = None,
) -> None:
    """
    Pretty-print a simple text table summarizing the packet sequence.

    Columns:
    - idx: logical index in the original capture
    - dir: direction ("C->S" or "S->C")
    - type: message type label
    - len: payload length in bytes
    - seq: implicit per-direction sequence number
    - dropped: "yes" or "no"
    """
    if file is None:
        file = sys.stdout

    packets_list = list(packets)

    if title:
        print(f"\n=== {title} ===", file=file)

    header = f"{'idx':>3}  {'dir':>4}  {'type':<16}  {'len':>5}  {'seq':>5}  {'dropped':>7}"
    print(header, file=file)
    print("-" * len(header), file=file)

    for pkt in packets_list:
        seq_str = "?" if pkt.seq_no is None else str(pkt.seq_no)
        dropped_str = "yes" if pkt.dropped else "no"
        print(
            f"{pkt.index:>3}  {pkt.direction.value:>4}  {pkt.msg_type:<16}  "
            f"{pkt.payload_len:>5}  {seq_str:>5}  {dropped_str:>7}",
            file=file,
        )

    print(file=file)


def print_sequence_diff(
    baseline: Iterable[Packet],
    after_attack: Iterable[Packet],
    title: str | None = None,
    file: TextIO | None = None,
) -> None:
    """
    Print a compact diff showing how sequence numbers changed after an attack.

    For each packet that is still visible after the attack, we display:

    - original index
    - direction
    - message type
    - sequence number before the attack
    - sequence number after the attack
    - a marker indicating whether the sequence number changed
    """
    if file is None:
        file = sys.stdout

    base_list = list(baseline)
    after_list = list(after_attack)

    base_seq_by_index: Dict[int, int] = {}
    for pkt in base_list:
        if pkt.seq_no is not None:
            base_seq_by_index[pkt.index] = pkt.seq_no

    if title:
        print(f"\n=== {title} ===", file=file)

    header = f"{'idx':>3}  {'dir':>4}  {'type':<16}  {'seq_before':>10}  {'seq_after':>10}  {'changed':>8}"
    print(header, file=file)
    print("-" * len(header), file=file)

    for pkt in after_list:
        seq_before = base_seq_by_index.get(pkt.index, None)
        seq_after = pkt.seq_no
        before_str = "?" if seq_before is None else str(seq_before)
        after_str = "?" if seq_after is None else str(seq_after)
        changed = "yes" if (seq_before is not None and seq_after is not None and seq_before != seq_after) else "no"
        print(
            f"{pkt.index:>3}  {pkt.direction.value:>4}  {pkt.msg_type:<16}  "
            f"{before_str:>10}  {after_str:>10}  {changed:>8}",
            file=file,
        )

    print(file=file)
