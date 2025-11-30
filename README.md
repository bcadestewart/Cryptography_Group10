# Terrapin Attack SSH Demo (with Web UI)

This repository contains a small demo implementation inspired by the
Terrapin attack on SSH sequence number handling.

It includes:

- A fully commented Python simulator (CLI + attack profiles).
- Synthetic data in `data/` so the demo is fully reproducible.
- A Flask-based web UI to visualize baseline vs post-attack sequences.

## Setup

```bash
git clone YOUR_REPO_URL.git
cd terrapin_ssh_demo_full_web

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

