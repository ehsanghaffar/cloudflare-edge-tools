# Usage Guide

## Running the scanner

From the project root:

```bash
python3 main.py [options]
```

## Common workflows

### Interactive TUI mode

```bash
python3 main.py
```

This opens a Textual dashboard with:

- config source selection
- scan controls
- live results table
- clean IP search
- Xray testing and deploy views

### Headless scan mode

```bash
python3 main.py -i config.txt --no-tui
```

This runs a non-interactive scan and prints summary results on the console.

### Clean Cloudflare IP scan

```bash
python3 main.py --find-clean --no-tui --clean-mode normal
```

This mode scans Cloudflare subnet ranges to find "clean" IPs.

## Input formats

Supported file inputs:

- `.txt`, `.conf`, `.lst` — one URI per line
- `.json` — array of objects, e.g. `[{"domain":"example.com","ipv4":"1.2.3.4"}]`

Supported URI types:

- `vless://...`
- `vmess://...`
- `trojan://...`

### Subscription URLs

Use `--sub` to fetch remote subscription data:

```bash
python3 main.py --sub https://example.com/sub --no-tui
```

The subscription body may be base64-encoded or plain text.

### Template generation

Use `--template` with an address file or list to expand a template URI:

```bash
python3 main.py --template "vless://..." -i addrs.json --no-tui
```

## Command options

- `-i`, `--input` — config file path
- `--sub` — subscription URL
- `--template` — VLESS/VMess/Trojan template URI
- `-m`, `--mode` — scan mode: `normal`, `fast`, `mega`, `xtreme`
- `-w`, `--workers` — latency test worker count
- `-s`, `--speed-workers` — speed test worker count
- `-t`, `--timeout` — latency timeout seconds
- `--speed-timeout` — speed test timeout seconds
- `--top` — number of top configs to save (`0` = all)
- `--rounds` — custom speed-test rounds, e.g. `2M:100,1M:50,100K:keep`
- `--skip-download` — latency-only scan
- `--no-tui` — run without the Textual interface
- `--find-clean` — perform a Cloudflare clean IP scan
- `--clean-mode` — clean scan mode: `quick`, `normal`, `full`, `mega`
- `--clean-ports` — ports for clean scan
- `--clean-workers` — workers for clean scan
- `--clean-scan-per-24` — IPs per /24 during clean scan
- `--subnets` — explicit subnets to scan for clean IPs
- `--xray-bin` — path to an existing Xray binary
- `--output-csv` — override default CSV export path
- `--output-configs` — override exported config path

## Example commands

Run a normal scan from `config.txt`:

```bash
python3 main.py -i config.txt --no-tui
```

Run a fast scan with more latency workers:

```bash
python3 main.py -i config.txt --no-tui -m fast -w 100
```

Fetch configs from a subscription and run the scan:

```bash
python3 main.py --sub https://example.com/sub --no-tui
```

Scan a VLESS template against a list of addresses:

```bash
python3 main.py --template "vless://..." -i addrs.json --no-tui
```

Search for clean Cloudflare IPs:

```bash
python3 main.py --find-clean --no-tui --clean-mode normal
```

## Results

- Exported files are written to `results/`
- Debug logs are saved to `results/debug.log`
- The scanner prints the loaded config count, resolved IP count, and scan status

## Notes & troubleshooting

- Ensure Python 3.11+ is installed
- The TUI depends on `textual`; install it separately if needed
- If no configs load, verify your input file contains valid VLESS/VMess/Trojan URIs
- For remote subscriptions, check connectivity and URL correctness
- Use `--skip-download` to diagnose connection issues without speed tests
