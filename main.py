# Cloudflare Edge Scanner v1.1 - Test VLESS/VMess proxy configs

import asyncio
import argparse
import csv
import os
import signal
import time
from typing import List, Tuple

from src.constants import (
    CF_HTTPS_PORTS,
    CLEAN_MODES,
    DEBUG_LOG,
    LATENCY_TIMEOUT,
    LATENCY_WORKERS,
    PRESETS,
    SPEED_TIMEOUT,
    SPEED_WORKERS,
    _CF_NETS,
)
from src.clean_finder import generate_cf_ips, scan_clean_ips
from src.config_parse import (
    fetch_sub,
    generate_from_template,
    load_addresses,
    load_input,
    parse_rounds_str,
)
from src.models import (
    ConfigEntry,
    Result,
    RoundCfg,
    State,
    calc_scores,
    sorted_alive,
)
from src.utils import (
    _dbg,
    _results_path,
)
from src.core import (
    build_dynamic_rounds,
    do_export,
    resolve_all,
    run_scan,
)


def load_configs_from_args(args) -> Tuple[List[ConfigEntry], str]:
    if args.sub:
        configs = fetch_sub(args.sub)
        return configs, args.sub
    if args.template and args.input:
        addrs = load_addresses(args.input)
        configs = generate_from_template(args.template, addrs)
        return configs, args.input
    if args.input:
        configs = load_input(args.input)
        return configs, args.input
    return [], ""


def run_tui(args, deploy_mode=False):
    from src.app import CFEdgeApp
    app = CFEdgeApp()
    app.run()


async def run_headless(args):
    st = State()
    st.mode = args.mode
    st.top = args.top
    if args.rounds:
        st.rounds = parse_rounds_str(args.rounds)
    elif args.skip_download:
        st.rounds = []
    configs, source = load_configs_from_args(args)
    if not configs:
        print("No configs loaded.")
        return
    st.configs = configs
    st.input_file = source
    print(f"Loaded {len(configs)} configs from {source}")
    print(
        f"Mode: {st.mode}, Latency workers: {args.workers}, Speed workers: {args.speed_workers}"
    )
    print(f"Latency timeout: {args.timeout}s, Speed timeout: {args.speed_timeout}s")
    print("Resolving DNS...")
    await resolve_all(st)
    print(f"  {len(st.ips)} unique IPs")
    if not st.ips:
        return
    scan_task = asyncio.ensure_future(
        run_scan(st, args.workers, args.speed_workers, args.timeout, args.speed_timeout)
    )
    old_sigint = signal.getsignal(signal.SIGINT)

    def _sig(sig, frame):
        st.interrupted = True
        st.finished = True
        scan_task.cancel()

    signal.signal(signal.SIGINT, _sig)
    try:
        await scan_task
    except asyncio.CancelledError:
        st.interrupted = True
        st.finished = True
        calc_scores(st)
        print("\n  Interrupted! Exporting partial results...")
    signal.signal(signal.SIGINT, old_sigint)
    if st.finished:
        csv_path, cfg_path, full_path = do_export(st, source, top=st.top)
        print(f"\nResults saved to:")
        print(f"  CSV:     {csv_path}")
        print(f"  Configs: {cfg_path}")
        print(f"  All:     {full_path}")
    else:
        print("\nScan did not complete.")


async def run_headless_clean(args):
    mode = args.clean_mode
    start_time = time.time()
    if mode not in CLEAN_MODES:
        print(f"Unknown clean mode: {mode}. Available: {list(CLEAN_MODES.keys())}")
        return
    subnets = []
    if args.subnets:
        for s in args.subnets:
            s = s.strip()
            if "/" in s:
                subnets.append(s)
            else:
                subnets.append(s + "/24")
    else:
        subnets = [str(n) for n in _CF_NETS]
    cf_ips = generate_cf_ips(subnets, args.clean_scan_per_24)
    print(f"Testing {len(cf_ips)} IPs across {len(subnets)} subnets in {mode} mode")
    results = await scan_clean_ips(cf_ips, workers=args.clean_workers, ports=args.clean_ports)
    if results:
        elapsed = time.time() - start_time
        print(f"\nFound {len(results)} clean IPs in {elapsed:.1f}s:")
        for ip, tls_ms in results[:20]:
            print(f"  {ip:15s}  {tls_ms:.0f}ms")
        if len(results) > 20:
            print(f"  ... and {len(results) - 20} more")
    else:
        print("No clean IPs found.")


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Edge Scanner v1.1 - Test VLESS/VMess proxy configs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Modes (sort by latency first, then speed-test the best):
  normal     Funnel: 2M->8Mx100%% -> 1M->50%% -> 100K->keep   [balanced]
  fast       300K->keep                                         [quick check]
  mega       2M->8Mx100%% -> 2M->50%% -> 200K->25%% -> keep   [deep scan]
  xtreme     2M->8Mx100%% -> 2M->50%% -> 200K->25%% -> 50K->keep  [maximum]

Examples:
  python3 scanner.py                                    # Interactive TUI
  python3 scanner.py -i configs.txt -m mega             # Mega mode from file
  python3 scanner.py --sub https://example.com/sub      # From subscription
  python3 scanner.py --template "vless://..." -i addrs  # From template
  python3 scanner.py --find-clean --clean-mode normal   # Clean IP finder
""",
    )
    parser.add_argument("-i", "--input", help="Config file (txt/json/conf/lst)")
    parser.add_argument("--sub", help="Subscription URL")
    parser.add_argument("--template", help="VLESS config template URI")
    parser.add_argument(
        "-m",
        "--mode",
        default="normal",
        choices=["normal", "fast", "mega", "xtreme"],
        help="Scan mode (default: normal)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=LATENCY_WORKERS,
        help=f"Latency test workers (default: {LATENCY_WORKERS})",
    )
    parser.add_argument(
        "-s",
        "--speed-workers",
        type=int,
        default=SPEED_WORKERS,
        help=f"Speed test workers (default: {SPEED_WORKERS})",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=LATENCY_TIMEOUT,
        help=f"Latency timeout seconds (default: {LATENCY_TIMEOUT})",
    )
    parser.add_argument(
        "--speed-timeout",
        type=float,
        default=SPEED_TIMEOUT,
        help=f"Speed test timeout seconds (default: {SPEED_TIMEOUT})",
    )
    parser.add_argument(
        "--top", type=int, default=50, help="Top N configs to save (default: 50, 0=all)"
    )
    parser.add_argument(
        "--rounds", help="Custom round sizes: 2M:100%%|1M:50%%|100K:keep"
    )
    parser.add_argument(
        "--skip-download", action="store_true", help="Skip speed test, latency only"
    )
    parser.add_argument("--no-tui", action="store_true", help="Non-interactive mode")
    parser.add_argument(
        "--find-clean", action="store_true", help="Scan for clean Cloudflare IPs"
    )
    parser.add_argument(
        "--clean-mode",
        default="normal",
        choices=list(CLEAN_MODES.keys()),
        help="Clean IP scan mode",
    )
    parser.add_argument(
        "--clean-ports",
        nargs="*",
        type=int,
        default=CF_HTTPS_PORTS,
        help="Ports for clean scan (default: 443 8443)",
    )
    parser.add_argument(
        "--clean-workers",
        type=int,
        default=500,
        help="Workers for clean scan (default: 500)",
    )
    parser.add_argument(
        "--clean-scan-per-24",
        type=int,
        default=0,
        help="Random IPs per /24 subnet (0=all)",
    )
    parser.add_argument(
        "--subnets", nargs="*", help="Subnets for clean scan (default: all CF ranges)"
    )
    parser.add_argument("--xray-bin", help="Path to xray binary")
    parser.add_argument("--output-csv", help="Override CSV output path")
    parser.add_argument("--output-configs", help="Override configs output path")

    args = parser.parse_args()
    args._mode_set = args.mode != "normal"

    if args.find_clean and args.no_tui:
        asyncio.run(run_headless_clean(args))
    elif args.no_tui or args.input or args.sub or args.template:
        asyncio.run(run_headless(args))
    else:
        deploy_mode = False
        run_tui(args, deploy_mode)


if __name__ == "__main__":
    main()
