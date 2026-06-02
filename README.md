# Cloudflare Edge Scanner

- [English](README.md)
- [فارسی](README.fa.md)

A command-line and Textual TUI utility for scanning VLESS/VMess/Trojan proxy configs, finding Cloudflare edge IPs, and evaluating connection performance.

## What This Does

- Parses proxy config URIs from files, subscriptions, or templates
- Resolves domain names to Cloudflare IPs
- Measures latency, TLS handshake time, and download speed against Cloudflare endpoints
- Ranks candidate IPs and exports results to CSV and JSON files
- Supports an interactive TUI or non-interactive headless mode
- Includes Cloudflare "clean IP" subnet scanning and Xray config/testing helpers

## Quick Start

1. Install Python 3.11+ and required packages.
2. From the project root:

```bash
python3 main.py -i config.txt
```

3. For headless mode without the TUI:

```bash
python3 main.py -i config.txt --no-tui
```

## Project Structure

```
.
├── README.md
├── config.txt                # Example input config file
├── docs/                     # Generated documentation
│   ├── architecture.md
│   └── usage.md
├── main.py                   # CLI entrypoint and execution flow
├── results/                  # Scan results and logs are written here
├── src/                      # Application source modules
│   ├── app.py                # Textual TUI implementation
│   ├── config_parse.py       # URI parsing and input loading
│   ├── constants.py          # Defaults, Cloudflare ranges, presets
│   ├── core.py               # Scan orchestration and export logic
│   ├── deploy_utils.py       # Linux Xray deployment helpers
│   ├── models.py             # Data models and score calculations
│   ├── rate_limiter.py       # Cloudflare request rate limiting
│   ├── speed_test.py         # Latency and throughput tests
│   ├── tui.py                # Textual views and UI actions
│   ├── utils.py              # Console helpers and utilities
│   └── xray_utils.py         # Xray config generation and URI builders
```

## Documentation

- `docs/architecture.md` — architecture and module interaction
- `docs/usage.md` — command usage, input formats, examples

## Notes

- The app writes results and debug logs to `results/`
- Supported input file formats: `.txt`, `.json`, `.conf`, `.lst`
- `config.txt` is a sample config file with VLESS/Trojan URIs
