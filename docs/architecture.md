# Architecture Overview

## What this project is

This repository implements a Cloudflare-aware proxy config scanner with both an interactive Textual user interface and a non-interactive headless mode.

It is designed to:

- parse VLESS / VMess / Trojan config URIs
- resolve domain names to Cloudflare IPs
- test connectivity and performance
- produce ranked results for use in proxy clients
- optionally scan Cloudflare subnets for clean IPs
- optionally generate and test Xray configurations

## High-level design

### Entry point

- `main.py` is the application entry point.
- It parses CLI arguments and decides between:
  - `run_tui()` for the interactive Textual UI
  - `run_headless()` for normal scans without UI
  - `run_headless_clean()` for clean IP subnet scanning

### Core workflow

1. Load configs from file, subscription, or template
2. Resolve domains to IPv4 addresses (`resolve_all`)
3. Build an IP map and result objects
4. Run latency + TLS/connect checks (`phase1`)
5. Run speed tests in funnel rounds (`phase2_round`)
6. Calculate scores and export results

## Module responsibilities

### `src/config_parse.py`

Responsible for loading config inputs and parsing proxy URIs:

- `parse_vless`, `parse_vmess`, `parse_trojan`
- `parse_vless_full`, `parse_vmess_full` for richer URI parsing
- `load_input()` supports:
  - plaintext URIs line by line
  - JSON arrays of `{"domain": ..., "ipv4": ...}` objects
- `fetch_sub()` downloads subscription data from HTTP(S)
- `generate_from_template()` creates configs from a template and address list

### `src/core.py`

Orchestrates the scan pipeline:

- `build_dynamic_rounds()` computes speed-test funnel parameters
- `resolve_all()` resolves domains concurrently over DNS
- `run_scan()` runs latency and speed phases, applies configurable presets, and exports results
- `save_csv()` writes ranked data to CSV files

### `src/speed_test.py`

Implements the actual network tests used by the scanner:

- latency and TLS connection probes
- download speed measurement
- phased speed testing across selected candidate IPs

### `src/models.py`

Defines core data models and scoring logic:

- `ConfigEntry` — parsed config item
- `RoundCfg` — speed-test round size and keep-count
- `Result` — per-IP metrics and score
- `State` — scan state, progress, and results
- `XrayTestState`, `PipelineConfig`, `DeployState`, `CleanScanState`

Scoring weights are computed in `calc_scores()` based on
latency, speed, and TTFB.

### `src/app.py` and `src/tui.py`

Provide the interactive Textual UI:

- `CFEdgeApp` hosts the dashboard, scanner, clean IP search, Xray test, and deploy views
- `Dashboard`, `ScannerView`, `CleanIPView`, `XrayView`, `DeployView` define UI panels
- Buttons and table widgets connect user actions to scan logic

### `src/xray_utils.py`

Contains Xray helper logic for:

- building Xray JSON configs from parsed URIs
- reconstructing VLESS / VMess URIs with new SNI tags
- fragment preset handling
- transport switching for `ws`, `grpc`, `h2`, `xhttp`, etc.

### `src/deploy_utils.py`

Supports Linux deployment checks and Xray server config generation:

- verifies root and systemd on Linux
- checks ports and public IP detection
- generates REALITY keys and Xray inbound/outbound settings
- builds a systemd unit for Xray service deployment

### `src/utils.py`

Utility helpers for:

- ANSI terminal output and safe logging
- terminal size detection
- keyboard input handling
- result path creation

## Data flow

```text
main.py
  ├─> src/config_parse.py  (input parse/load)
  ├─> src/core.py          (resolve, scan, export)
  │     └─> src/speed_test.py
  ├─> src/tui.py           (interactive UI)
  │     └─> src/app.py
  ├─> src/xray_utils.py    (Xray URI/config helpers)
  └─> src/deploy_utils.py (Linux deployment helpers)
```

## Output and persistence

- Scan results are saved under `results/`
- Debug logging is written to `results/debug.log`
- Export paths can be overridden with CLI options

## Key design decisions

- `main.py` chooses execution mode first, then delegates to either TUI or headless flows.
- The scanner uses a dynamic funnel approach to test many IPs first by latency and then narrow to the best subset for speed targets.
- Parsing is intentionally permissive: it supports plain URIs, JSON domain lists, and subscription payloads.
- Xray support is implemented as a separate helper layer, keeping scanning and config generation distinct.
