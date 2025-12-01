# Terrapin Attack SSH Demo (with Web UI)

This repository contains a small demo implementation inspired by the
Terrapin attack on SSH sequence number handling.

It includes:

- A fully commented Python simulator (CLI + attack profiles).
- Synthetic data in `data/` so the demo is fully reproducible.
- A Flask-based web UI to visualize baseline vs post-attack sequences.

## Setup

```bash
git clone https://github.com/bcadestewart/Cryptography_Group10.git
cd Cryptography_Group10

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Baseline demo

```bash
python3 -m src.handshake_demo --pcap data/sample_trace.json
```

## Attack demo (YAML config + profiles)

```bash
python3 -m src.attack_proxy --config data/demo_config.yaml --log-dir logs
```

## CLI with subcommands

```bash
python3 -m src.cli baseline --pcap data/sample_trace.json
python3 -m src.cli attack   --config data/demo_config.yaml --log-dir logs
python3 -m src.cli explore  --pcap data/sample_trace.json --random-drop 2 --seed 123
```

## Web UI

```bash
python3 web_app.py
```

Then open http://127.0.0.1:5000/ in your browser to interact with the
simulator from an HTML page that shows baseline, post-attack, and diff
tables.

## Data

All data required to run the demo is in the `data/` directory:

- `sample_trace.json`: synthetic SSH-like handshake trace.
- `demo_config.yaml`: config with attack profiles.

## Functionality

- Baseline simulation: Displays normal SSH handshake with proper sequence number assignment for all packets
-  Two pre-configured attack scenarios:
- `drop_ext_info`: Drops client EXT_INFO message (index 2) to mimic Terrapin's extension stripping
- `drop_client_kexinit`: Drops initial client KEXINIT (index 0) to demonstrate aggressive prefix truncation
- Web visualization: Interactive Flask-based UI with tables and line graphs showing sequence number manipulation
- Random exploration mode: Test arbitrary packet drop combinations with configurable random seeds
- Diff generation: Automatic side-by-side comparison highlighting which sequence numbers changed (color-coded: green = unchanged, red = manipulated)


## Academic References



**Ylonen, T., & Lonvick, C. (Eds.). (2006).** *The Secure Shell (SSH) Protocol Architecture* (RFC 4251). Internet Engineering Task Force. https://doi.org/10.17487/RFC4251

This RFC defines the fundamental SSH protocol architecture, including the Binary Packet Protocol and the implicit per-direction sequence number mechanism that the Terrapin attack exploits. It establishes the baseline security model, key exchange procedures, and handshake protocols that subsequent SSH implementations follow. Understanding this foundational specification is essential for comprehending how sequence number manipulation can compromise SSH security.



**Bäumer, F., Brinkrolf, J., & Kunze, G. (2023).** *Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation*. arXiv preprint arXiv:2312.12422. https://arxiv.org/abs/2312.12422

This paper presents the Terrapin attack, discovered in 2023, which demonstrates how prefix truncation during the SSH handshake can manipulate sequence numbers to bypass security extensions like strict key exchange. The research directly builds upon the RFC 4251 protocol specification to identify previously unknown vulnerabilities in widely-deployed SSH implementations including OpenSSH, PuTTY, and other major clients/servers. The attack affects the integrity of encrypted SSH connections and has led to security updates across the industry.





