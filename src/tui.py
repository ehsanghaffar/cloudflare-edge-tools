import asyncio
import csv
import glob
import json
import os
import signal
import statistics
import sys
import time
from typing import Dict, List, Optional, Tuple

from src.constants import (A, ANSI, CLEAN_MODES, RESULTS_DIR, SPEED_HOST,
                           XRAY_BIN_DIR, XRAY_TMP_DIR, _CF_NETS, _CF_PREFLIGHT_IPS,
                           _generate_random_cf_ips, _is_cf_address, _resolve_is_cf,
                           CDN_FALLBACK, CF_SUBNETS, CF_HTTPS_PORTS, LATENCY_TIMEOUT,
                           LATENCY_WORKERS, SPEED_TIMEOUT, SPEED_WORKERS, PRESETS,
                           VERSION, DEBUG_LOG, XRAY_FRAG_PRESETS, XRAY_CONFIG_TEMPLATE,
                           XRAY_CONNECT_TIMEOUT, XRAY_HOME, XRAY_PROFILES_DIR,
                           XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT, XRAY_SPEED_SIZE,
                           XRAY_SPEED_TIMEOUT, XRAY_BASE_PORT, XRAY_BIN_DIR,
                           CF_TEST_IPS)
from src.clean_finder import _split_to_24s, _tls_probe, generate_cf_ips, scan_clean_ips
from src.config_parse import (fetch_sub, generate_from_template, load_addresses,
                              load_input, parse_config, parse_rounds_str, parse_size,
                              parse_vless_full, parse_vmess_full)
from src.models import (CleanScanState, ConfigEntry, DeployState, PipelineConfig,
                        Result, RoundCfg, State, XrayTestState, XrayVariation)
from src.rate_limiter import CFRateLimiter
from src.speed_test import _dl_one, _lat_one, phase1, phase2_round
from src.utils import (_dbg, _fmt_elapsed, _flush_stdin, _prompt_number,
                       _read_key_blocking, _read_key_nb, _restore_console_input,
                       _vl, _w, _fl, _wait_any_key, enable_ansi, term_size)
from src.xray_utils import (_build_uri, _extract_vless_ws_params, _find_free_ports,
                            _test_single_variation, _vless_ws_read_tunnel,
                            _vless_ws_speed_test, _xray_calc_scores,
                            _xray_speed_test_blocking, build_vless_uri,
                            build_vmess_uri, build_xray_config, expand_custom_ips,
                            generate_pipeline_variations, generate_xray_variations,
                            switch_transport, xray_find_binary, xray_install,
                            xray_pipeline_test, xray_speed_test, XrayProcess)


def _results_path(filename: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, filename)


def calc_scores(st: State):
    has_speed = any(r.best_mbps > 0 for r in st.res.values())
    for r in st.res.values():
        if not r.alive:
            r.score = 0
            continue
        lat = max(0, 100 - r.tls_ms / 10) if r.tls_ms > 0 else 0
        spd = min(100, r.best_mbps * 20) if r.best_mbps > 0 else 0
        ttfb = max(0, 100 - r.ttfb_ms / 5) if r.ttfb_ms > 0 else 0
        if r.best_mbps > 0:
            r.score = round(lat * 0.35 + spd * 0.50 + ttfb * 0.15, 1)
        elif has_speed:
            r.score = round(lat * 0.35, 1)
        else:
            r.score = round(lat, 1)


def sorted_alive(st: State, key: str = "score") -> List[Result]:
    alive = [r for r in st.res.values() if r.alive]
    if key == "score":
        alive.sort(key=lambda r: r.score, reverse=True)
    elif key == "latency":
        alive.sort(key=lambda r: r.tls_ms)
    elif key == "speed":
        alive.sort(key=lambda r: r.best_mbps, reverse=True)
    return alive


def sorted_all(st: State, key: str = "score") -> List[Result]:
    alive = sorted_alive(st, key)
    dead = [r for r in st.res.values() if not r.alive]
    dead.sort(key=lambda r: r.ip)
    return alive + dead


def find_config_files() -> List[Tuple[str, str, int]]:
    results: List[Tuple[str, str, int]] = []
    for ext, ftype in [("*.txt", "txt"), ("*.json", "json"), ("*.conf", "config"), ("*.lst", "list")]:
        for path in glob.glob(ext):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    count = sum(1 for line in f if line.strip() and not line.startswith("#"))
            except OSError:
                count = 0
            results.append((path, ftype, count))
    results.sort(key=lambda x: os.path.getmtime(x[0]) if os.path.isfile(x[0]) else 0, reverse=True)
    return results


def draw_menu_header(cols: int) -> List[str]:
    W = cols - 2
    lines = []
    lines.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
    t = f" {A.BOLD}{A.WHT}CF Config Scanner{A.RST} {A.DIM}v{VERSION}{A.RST}"
    lines.append(f"{A.CYN}║{A.RST}" + t + " " * (W - _vl(t)) + f"{A.CYN}║{A.RST}")
    lines.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    return lines


def draw_box_line(content: str, cols: int) -> str:
    W = cols - 2
    vl = _vl(content)
    pad = " " * max(0, W - vl)
    return f"{A.CYN}║{A.RST}{content}{pad}{A.CYN}║{A.RST}"


def draw_box_sep(cols: int) -> str:
    return f"{A.CYN}╠{'═' * (cols - 2)}╣{A.RST}"


def draw_box_bottom(cols: int) -> str:
    return f"{A.CYN}╚{'═' * (cols - 2)}╝{A.RST}"


def _help_show_page(title: str, content: List[str]):
    scroll = 0
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        W = cols - 2
        visible = max(3, rows - 8)
        page = content[scroll:scroll + visible]
        max_scroll = max(0, len(content) - visible)

        out: List[str] = []
        _cpos = f"\033[{W + 2}G"
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        t = f" {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{t}{' ' * max(0, W - _vl(t))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        ttl = f" {A.BOLD}{A.WHT}{title}{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{ttl}{' ' * max(0, W - _vl(ttl))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        for line in page:
            vl = _vl(line)
            out.append(f"{A.CYN}|{A.RST}{line}{' ' * max(0, W - vl)}{_cpos}{A.CYN}|{A.RST}")
        for _ in range(visible - len(page)):
            out.append(f"{A.CYN}|{A.RST}{' ' * W}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        if max_scroll > 0:
            pct = scroll * 100 // max_scroll if max_scroll else 100
            nav = f" {A.DIM}[j/k] Scroll  [{pct}%]  [b] Back{A.RST}"
        else:
            nav = f" {A.DIM}[b] Back to help menu{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{nav}{' ' * max(0, W - _vl(nav))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()
        key = _read_key_blocking()
        if key in ("q", "esc", "b", "ctrl-c", "h"):
            _w(A.SHOW)
            return
        if key in ("j", "down") and scroll < max_scroll:
            scroll += 1
        elif key in ("k", "up") and scroll > 0:
            scroll -= 1
        elif key in ("n", "pagedown"):
            scroll = min(max_scroll, scroll + visible)
        elif key in ("p", "pageup"):
            scroll = max(0, scroll - visible)


def _help_getting_started() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is cfray?{A.RST}",
        f"   A Cloudflare config scanner, speed tester, and Xray server",
        f"   deployer. Finds the fastest CF edge IPs and the best proxy",
        f"   configurations for your connection.",
        "",
        f" {A.BOLD}{A.CYN}How to launch{A.RST}",
        f"   {A.WHT}Interactive TUI:{A.RST}  python3 scanner.py",
        f"   {A.WHT}Headless mode:{A.RST}    python3 scanner.py -i file.txt --no-tui",
        f"   {A.WHT}Show CLI help:{A.RST}    python3 scanner.py --help",
        "",
        f" {A.BOLD}{A.CYN}Basic workflow{A.RST}",
        f"   {A.WHT}1.{A.RST} Choose an input source from the main menu",
        f"   {A.WHT}2.{A.RST} cfray resolves domains to Cloudflare edge IPs",
        f"   {A.WHT}3.{A.RST} Tests TCP+TLS latency on all IPs (fast filter)",
        f"   {A.WHT}4.{A.RST} Speed tests the top IPs through progressive rounds",
        f"   {A.WHT}5.{A.RST} Results dashboard shows ranked results live",
        f"   {A.WHT}6.{A.RST} Export best configs — ready to use in your client",
        "",
        f" {A.BOLD}{A.CYN}Scoring formula{A.RST}",
        f"   Score = {A.WHT}latency (35%){A.RST} + {A.WHT}speed (50%){A.RST} + {A.WHT}TTFB (15%){A.RST}",
        f"   Higher score = better overall performance (0-100 scale)",
        "",
        f" {A.BOLD}{A.CYN}What gets exported{A.RST}",
        f"   {A.WHT}CSV file:{A.RST}         IP, latency, speed, score, colo, domains",
        f"   {A.WHT}Top N configs:{A.RST}    Best VLESS/VMess URIs ready to import",
        f"   {A.WHT}Full sorted:{A.RST}      ALL alive configs, best to worst",
        f"   Files saved to {A.WHT}results/{A.RST} directory",
        "",
        f" {A.BOLD}{A.CYN}Main menu keys{A.RST}",
        f"   {A.WHT}1-9{A.RST}  Select a local config file",
        f"   {A.WHT} s {A.RST}  Load from subscription URL",
        f"   {A.WHT} p {A.RST}  Enter a custom file path",
        f"   {A.WHT} t {A.RST}  Template + address list mode",
        f"   {A.WHT} f {A.RST}  Find clean Cloudflare IPs",
        f"   {A.WHT} x {A.RST}  Xray pipeline test (fragment + transport)",
        *([ f"   {A.WHT} d {A.RST}  Deploy Xray on a Linux VPS"] if sys.platform == "linux" else []),
        f"   {A.WHT} o {A.RST}  Worker Proxy (fresh workers.dev SNI)",
        *([ f"   {A.WHT} c {A.RST}  Connection Manager"] if sys.platform == "linux" else []),
        f"   {A.WHT} h {A.RST}  This help menu",
        f"   {A.WHT} q {A.RST}  Quit",
        "",
    ]


def _help_scan_modes() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}Local Files (auto-detected){A.RST}",
        f"   Place config files in the directory where you run cfray.",
        f"   Supported formats: {A.WHT}.txt  .json  .conf  .lst{A.RST}",
        f"   They appear automatically in the {A.WHT}LOCAL FILES{A.RST} section.",
        "",
        f"   {A.BOLD}Text files (.txt):{A.RST}",
        f"   One VLESS or VMess URI per line:",
        f"     {A.GRN}vless://uuid@domain:443?type=ws&host=sni.com#name{A.RST}",
        f"     {A.GRN}vmess://base64-encoded-json{A.RST}",
        "",
        f"   {A.BOLD}JSON files (.json):{A.RST}",
        f'   Domain list: {A.GRN}{{"data":[{{"domain":"x.ir","ipv4":"1.2.3.4"}}]}}{A.RST}',
        "",
        f" {A.BOLD}{A.CYN}[P] Enter File Path{A.RST}",
        f"   Load a config file from any location on disk.",
        f"   Type the full path when prompted.",
        f"   {A.GRN}Example:{A.RST} /home/user/configs/my_vless.txt",
        "",
        f" {A.BOLD}{A.CYN}[S] Subscription URL{A.RST}",
        f"   Fetches VLESS/VMess configs from a remote URL.",
        f"   Supports both plain text and base64-encoded content.",
        f"   {A.GRN}Example:{A.RST} https://example.com/sub.txt",
        "",
        f"   {A.BOLD}How to use:{A.RST}",
        f"   1. Press {A.WHT}s{A.RST} in the main menu",
        f"   2. Paste your subscription URL",
        f"   3. cfray fetches and parses the configs automatically",
        "",
        f" {A.BOLD}{A.CYN}[T] Template + Address List{A.RST}",
        f"   Have one working config but want to test many IPs?",
        f"   This mode takes your config and a file of IPs/domains,",
        f"   replaces the address in the config for each one, and",
        f"   tests them all to find the fastest.",
        "",
        f"   {A.BOLD}How to use:{A.RST}",
        f"   1. Press {A.WHT}t{A.RST} in the main menu",
        f"   2. Paste your VLESS/VMess URI (the template)",
        f"   3. Enter path to a .txt file with one IP per line",
        f"   4. cfray generates a config for each IP and scans all",
        "",
        f"   {A.BOLD}CLI equivalent:{A.RST}",
        f"   {A.GRN}python3 scanner.py --template 'vless://...' -i addrs.txt{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}Scan rounds{A.RST}",
        f"   {A.WHT}Quick:{A.RST}     1 round (small download, fast)",
        f"   {A.WHT}Normal:{A.RST}    3 rounds (progressive: small -> large)",
        f"   {A.WHT}Thorough:{A.RST}  5 rounds (most accurate, slower)",
        f"   In each round, bottom performers are eliminated.",
        f"   Survivors move to the next round with a bigger download.",
        "",
    ]


def _help_xray_test() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is Xray Pipeline Test?{A.RST}",
        f"   Tests your config through a {A.WHT}real Xray-core proxy tunnel{A.RST}.",
        f"   Unlike basic scanning, this actually routes traffic through",
        f"   your VPN/proxy — measuring real-world speed and latency.",
        "",
        f"   The pipeline generates variations of your config with",
        f"   different fragment settings and transports, then tests",
        f"   each one to find the best combination.",
        "",
        f" {A.BOLD}{A.CYN}3-Stage Pipeline{A.RST}",
        f"   {A.WHT}Stage 1 — IP Scan:{A.RST}",
        f"     TLS probes on Cloudflare IPs to find live edges",
        f"   {A.WHT}Stage 2 — Base Connectivity:{A.RST}",
        f"     Tests your original config on discovered live IPs",
        f"   {A.WHT}Stage 3 — Expansion:{A.RST}",
        f"     Generates fragment + transport variations on working IPs",
        f"     and speed-tests each one to find the fastest combo",
        "",
        f" {A.BOLD}{A.CYN}[X] Xray Pipeline Test — step by step{A.RST}",
        f"   1. Press {A.WHT}x{A.RST} in the main menu",
        f"   2. Paste your working VLESS/VMess URI",
        f"   3. Choose fragment preset:",
        f"      {A.WHT}none{A.RST}:   no fragmentation",
        f"      {A.WHT}light{A.RST}:  gentle DPI bypass (length 100-200)",
        f"      {A.WHT}medium{A.RST}: moderate bypass (2 settings)",
        f"      {A.WHT}heavy{A.RST}:  aggressive bypass (3 settings)",
        f"      {A.WHT}all{A.RST}:    tests all fragment combos",
        f"   4. Choose IP source (auto CF scan or custom IPs)",
        f"   5. Pipeline runs all 3 stages automatically",
        f"   6. Results ranked by real proxy speed",
        "",
        f" {A.BOLD}{A.CYN}What are fragments?{A.RST}",
        f"   TLS Client Hello fragmentation splits the initial TLS",
        f"   handshake into small pieces. This can bypass DPI (Deep",
        f"   Packet Inspection) that filters traffic based on SNI.",
        "",
        f"   {A.WHT}packets:{A.RST}   tlshello (fragment the Client Hello)",
        f"   {A.WHT}length:{A.RST}    size of each fragment (e.g. 100-200 bytes)",
        f"   {A.WHT}interval:{A.RST}  delay between fragments (e.g. 10-20 ms)",
        "",
        f"   Heavier fragments = more likely to bypass DPI but slower.",
        f"   Let cfray test all presets to find the best one for you.",
        "",
        f" {A.BOLD}{A.CYN}Xray binary{A.RST}",
        f"   Xray-core is auto-installed to {A.WHT}~/.cfray/bin/xray{A.RST}",
        f"   Does NOT touch your system xray installation.",
        f"   Use {A.WHT}--xray-install{A.RST} to force reinstall.",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --xray 'vless://...' --xray-frag all{A.RST}",
        "",
    ]


def _help_clean_finder() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is the Clean IP Finder?{A.RST}",
        f"   Scans Cloudflare's IP ranges to find edge servers that",
        f"   are reachable from your network. These 'clean' IPs can be",
        f"   used as the address in your proxy configs for better",
        f"   performance and reliability.",
        "",
        f" {A.BOLD}{A.CYN}How to use{A.RST}",
        f"   1. Press {A.WHT}f{A.RST} in the main menu",
        f"   2. Pick a scan mode:",
        "",
        f"      {A.WHT}Quick{A.RST}    ~4,000 IPs     (fast, samples each /24)",
        f"      {A.WHT}Normal{A.RST}   ~12,000 IPs    (recommended, good coverage)",
        f"      {A.WHT}Full{A.RST}     ~1.5M IPs      (every IP in CF ranges)",
        f"      {A.WHT}Mega{A.RST}     ~3M tests      (all IPs x ports 443+8443)",
        "",
        f"   3. cfray tests TCP+TLS connectivity to each IP",
        f"   4. Results show reachable IPs sorted by latency",
        f"   5. Save clean IPs to a file, or continue to template scan",
        "",
        f" {A.BOLD}{A.CYN}What happens with the results?{A.RST}",
        f"   After the scan completes, you can:",
        f"   - {A.WHT}Save{A.RST} the clean IPs to a text file",
        f"   - {A.WHT}Use with template{A.RST}: pick a config URI and test each IP",
        f"   - {A.WHT}Use with Xray test{A.RST}: full proxy speed test on clean IPs",
        "",
        f" {A.BOLD}{A.CYN}Custom subnets{A.RST}",
        f"   By default cfray scans all official Cloudflare ranges.",
        f"   You can limit to specific subnets:",
        f"   {A.GRN}python3 scanner.py --find-clean --subnets 104.16.0.0/12{A.RST}",
        f"   Or provide a file with one CIDR per line:",
        f"   {A.GRN}python3 scanner.py --find-clean --subnets subnets.txt{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}Validation{A.RST}",
        f"   cfray verifies each IP actually serves Cloudflare by",
        f"   checking for the {A.WHT}server: cloudflare{A.RST} response header.",
        f"   This filters out non-CF IPs within CF ranges.",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --no-tui{A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --clean-mode mega --no-tui{A.RST}",
        "",
    ]


def _help_deploy() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}[D] Deploy Xray Server{A.RST}",
        f"   Install and configure Xray on a Linux VPS in minutes.",
        f"   Generates a full server config + client URI automatically.",
        "",
        f" {A.BOLD}{A.CYN}How to deploy{A.RST}",
        f"   1. Press {A.WHT}d{A.RST} in the main menu",
        f"   2. Choose protocol: {A.WHT}VLESS{A.RST} or {A.WHT}VMess{A.RST}",
        f"   3. Choose transport: {A.WHT}TCP{A.RST}, {A.WHT}WebSocket{A.RST}, {A.WHT}gRPC{A.RST}, {A.WHT}H2{A.RST}, or {A.WHT}XHTTP{A.RST}",
        f"   4. Choose security:",
        f"      {A.WHT}REALITY{A.RST}  Best for censored networks (no domain needed)",
        f"      {A.WHT}TLS{A.RST}      Standard TLS (needs domain + certificate)",
        f"      {A.WHT}None{A.RST}     No encryption (not recommended)",
        f"   5. cfray installs Xray, generates UUID + keys",
        f"   6. Outputs a ready-to-use client URI — just copy it!",
        "",
        f" {A.BOLD}{A.CYN}Multiple configs{A.RST}",
        f"   After creating the first config, the wizard asks if you",
        f"   want to add another. This lets you deploy e.g.:",
        f"   - {A.WHT}TCP + REALITY{A.RST} on port 443 (direct, fast)",
        f"   - {A.WHT}WS + TLS{A.RST} on port 444 (CDN-compatible)",
        f"   REALITY keys and TLS certs are reused across configs.",
        "",
        f" {A.BOLD}{A.CYN}Requirements{A.RST}",
        f"   - Linux VPS (Ubuntu/Debian/CentOS/Fedora)",
        f"   - Run as {A.WHT}root{A.RST}",
        f"   - Port 443 open (or your chosen port)",
        "",
        f" {A.BOLD}{A.CYN}[C] Connection Manager{A.RST}",
        f"   After deploying, use the Connection Manager to manage",
        f"   your server's inbounds and users.",
        "",
        f"   {A.BOLD}Keys:{A.RST}",
        f"   {A.WHT}A{A.RST}  Add a new inbound (new protocol/port)",
        f"   {A.WHT}U{A.RST}  Add a user to an existing inbound",
        f"   {A.WHT}S{A.RST}  Show all client URIs",
        f"   {A.WHT}V{A.RST}  View inbound details (config JSON)",
        f"   {A.WHT}X{A.RST}  Delete an inbound",
        f"   {A.WHT}R{A.RST}  Restart Xray service",
        f"   {A.WHT}L{A.RST}  View Xray logs",
        f"   {A.WHT}D{A.RST}  Uninstall Xray completely",
        f"   {A.WHT}B{A.RST}  Back to main menu",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-security reality{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-protocol vmess \\{A.RST}",
        f"   {A.GRN}  --deploy-transport ws --deploy-security tls{A.RST}",
        "",
    ]


def _help_worker_proxy() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is Worker Proxy?{A.RST}",
        f"   Creates a Cloudflare Worker that proxies your traffic,",
        f"   giving your VLESS config a fresh {A.WHT}*.workers.dev{A.RST} SNI.",
        "",
        f"   This is useful when your current SNI is blocked or slow.",
        f"   The Worker acts as a middleman on Cloudflare's CDN,",
        f"   routing traffic to your origin through a new hostname.",
        "",
        f" {A.BOLD}{A.CYN}How to use{A.RST}",
        f"   1. Press {A.WHT}o{A.RST} in the main menu",
        f"   2. Paste your VLESS URI (must use {A.WHT}WebSocket{A.RST} transport)",
        f"   3. cfray generates a Worker script (JavaScript)",
        f"   4. Deploy it on {A.WHT}dash.cloudflare.com{A.RST} -> Workers & Pages",
        f"   5. Enter your Worker URL (e.g. {A.WHT}my-proxy.user.workers.dev{A.RST})",
        f"   6. cfray builds a new URI with the Worker as address/SNI",
        f"   7. Optionally run a pipeline test on the new config",
        "",
        f" {A.BOLD}{A.CYN}Requirements{A.RST}",
        f"   - Your config must use {A.WHT}WebSocket (ws){A.RST} transport",
        f"   - Free Cloudflare account (100K requests/day free tier)",
        f"   - TCP, gRPC, H2 transports are NOT supported by Workers",
        "",
        f" {A.BOLD}{A.CYN}How it works{A.RST}",
        f"   {A.WHT}Client{A.RST} -> {A.CYN}CF Worker{A.RST} -> {A.WHT}Origin server{A.RST}",
        f"   The Worker receives your WebSocket connection and forwards",
        f"   it to your origin, setting the correct Host header.",
        f"   Your ISP only sees a connection to {A.WHT}*.workers.dev{A.RST}.",
        "",
    ]


def _help_cli_reference() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}Input options{A.RST}",
        f"   {A.WHT}-i, --input FILE{A.RST}     Input file (VLESS URIs or domains.json)",
        f"   {A.WHT}--sub URL{A.RST}             Subscription URL (fetches configs)",
        f"   {A.WHT}--template URI{A.RST}        Base VLESS/VMess URI (use with -i)",
        "",
        f" {A.BOLD}{A.CYN}Scan settings{A.RST}",
        f"   {A.WHT}-m, --mode MODE{A.RST}      quick / normal / thorough",
        f"   {A.WHT}--rounds SPEC{A.RST}         Custom, e.g. '1MB:200,5MB:50,20MB:20'",
        f"   {A.WHT}-w, --workers N{A.RST}      Latency workers (default: 300)",
        f"   {A.WHT}--speed-workers N{A.RST}     Download workers (default: 10)",
        f"   {A.WHT}--timeout SEC{A.RST}         Latency timeout (default: 3)",
        f"   {A.WHT}--speed-timeout SEC{A.RST}   Download timeout (default: 10)",
        f"   {A.WHT}--skip-download{A.RST}       Latency only, no speed test",
        "",
        f" {A.BOLD}{A.CYN}Output options{A.RST}",
        f"   {A.WHT}--top N{A.RST}              Export top N configs (0 = all)",
        f"   {A.WHT}--no-tui{A.RST}             Headless mode (plain text output)",
        f"   {A.WHT}-o, --output FILE{A.RST}    CSV output path",
        f"   {A.WHT}--output-configs FILE{A.RST} Save top URIs to file",
        "",
        f" {A.BOLD}{A.CYN}Clean IP Finder{A.RST}",
        f"   {A.WHT}--find-clean{A.RST}         Find clean Cloudflare IPs",
        f"   {A.WHT}--clean-mode MODE{A.RST}    quick / normal / full / mega",
        f"   {A.WHT}--subnets CIDRS{A.RST}      Custom subnets (file or comma-sep)",
        "",
        f" {A.BOLD}{A.CYN}Xray Pipeline Test{A.RST}",
        f"   {A.WHT}--xray URI{A.RST}           VLESS/VMess URI to test",
        f"   {A.WHT}--xray-frag PRESET{A.RST}   none / light / medium / heavy / all",
        f"   {A.WHT}--xray-bin PATH{A.RST}      Path to Xray binary",
        f"   {A.WHT}--xray-install{A.RST}       Force install Xray binary",
        f"   {A.WHT}--xray-keep N{A.RST}        Keep top N results (default: 10)",
        "",
        f" {A.BOLD}{A.CYN}Deploy{A.RST}",
        f"   {A.WHT}--deploy{A.RST}             Deploy Xray on this server",
        f"   {A.WHT}--deploy-port N{A.RST}      Port (default: 443)",
        f"   {A.WHT}--deploy-protocol P{A.RST}  vless / vmess",
        f"   {A.WHT}--deploy-transport T{A.RST} tcp / ws / grpc / h2",
        f"   {A.WHT}--deploy-security S{A.RST}  reality / tls / none",
        f"   {A.WHT}--deploy-sni DOMAIN{A.RST}  SNI domain for REALITY/TLS",
        f"   {A.WHT}--deploy-cert PATH{A.RST}   TLS certificate file",
        f"   {A.WHT}--deploy-key PATH{A.RST}    TLS private key file",
        f"   {A.WHT}--deploy-ip IP{A.RST}       Server IP (auto-detected)",
        f"   {A.WHT}--uninstall{A.RST}          Remove everything cfray installed",
        "",
        f" {A.BOLD}{A.CYN}Examples{A.RST}",
        "",
        f"   {A.DIM}# Scan a config file (headless){A.RST}",
        f"   {A.GRN}python3 scanner.py -i configs.txt --no-tui{A.RST}",
        "",
        f"   {A.DIM}# Subscription URL, export top 20{A.RST}",
        f"   {A.GRN}python3 scanner.py --sub https://example.com/sub --top 20{A.RST}",
        "",
        f"   {A.DIM}# Template scan: one config, many IPs{A.RST}",
        f"   {A.GRN}python3 scanner.py --template 'vless://...' -i ips.txt{A.RST}",
        "",
        f"   {A.DIM}# Xray test with all fragment presets{A.RST}",
        f"   {A.GRN}python3 scanner.py --xray 'vless://...' --xray-frag all{A.RST}",
        "",
        f"   {A.DIM}# Find clean IPs (mega mode, headless){A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --clean-mode mega --no-tui{A.RST}",
        "",
        f"   {A.DIM}# Deploy VLESS + REALITY on port 443{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-security reality{A.RST}",
        "",
        f"   {A.DIM}# Deploy VMess + WebSocket + TLS{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-protocol vmess \\{A.RST}",
        f"   {A.GRN}  --deploy-transport ws --deploy-security tls{A.RST}",
        "",
    ]


def tui_show_guide():
    pages = [
        ("Getting Started",            "First steps, basic workflow, scoring",     _help_getting_started),
        ("Scan & Test Modes",          "File scan, subscription, template",        _help_scan_modes),
        ("Xray Pipeline Test",         "Fragment + transport pipeline testing",    _help_xray_test),
        ("Clean IP Finder",            "Find reachable Cloudflare edge IPs",      _help_clean_finder),
        *([ ("Deploy & Server Management", "Install Xray on VPS, manage connections", _help_deploy)] if sys.platform == "linux" else []),
        ("Worker Proxy",               "Fresh workers.dev SNI for any config",    _help_worker_proxy),
        ("CLI Reference",              "All command-line flags and examples",      _help_cli_reference),
    ]
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        W = cols - 2

        out: List[str] = []
        _cpos = f"\033[{W + 2}G"
        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}|{A.RST}{c}{pad}{_cpos}{A.CYN}|{A.RST}")

        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        t = f" {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        bx(t)
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        bx(f" {A.BOLD}{A.WHT}Help & Guide{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        bx("")

        icons = ["🚀", "📡", "⚡", "🔍", "🛠", "☁", "💻"]
        for i, (title, desc, _) in enumerate(pages):
            num = f"  {A.CYN}{A.BOLD}{i + 1}{A.RST}"
            bx(f"{num}.  {icons[i]} {A.BOLD}{A.WHT}{title}{A.RST}")
            bx(f"      {A.DIM}{desc}{A.RST}")
            bx("")

        bx(f" {A.DIM}{'─' * (W - 2)}{A.RST}")
        bx(f" {A.DIM}[1-{len(pages)}] Open topic    [q] Back to menu{A.RST}")
        bx("")
        bx(f" {A.BOLD}{A.WHT}Made By Sam — SamNet Technologies{A.RST}")
        bx(f" {A.DIM}https://github.com/SamNet-dev/cfray{A.RST}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()
        key = _read_key_blocking()
        if key in ("q", "b", "esc", "ctrl-c"):
            _w(A.SHOW)
            return
        if key.isdigit() and 1 <= int(key) <= len(pages):
            title, _, fn = pages[int(key) - 1]
            _help_show_page(title, fn())
            continue


def _clean_pick_mode() -> Optional[str]:
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Find Clean Cloudflare IPs{A.RST}", cols))
        lines.append(draw_box_line(f" {A.DIM}Scans Cloudflare IP ranges to find reachable edge IPs{A.RST}", cols))
        lines.append(draw_box_line("", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.BOLD}Select scan scope:{A.RST}", cols))
        lines.append(draw_box_line("", cols))

        for name, key in [("quick", "1"), ("normal", "2"), ("full", "3"), ("mega", "4")]:
            cfg = CLEAN_MODES[name]
            num = f"{A.CYN}{A.BOLD}{key}{A.RST}"
            lbl = f"{A.BOLD}{cfg['label']}{A.RST}"
            if name == "normal":
                lbl += f" {A.GRN}(recommended){A.RST}"
            lines.append(draw_box_line(f"   {num}  {lbl}", cols))
            desc = cfg["desc"]
            if len(cfg.get("ports", [])) > 1:
                desc += f"  (ports: {', '.join(str(p) for p in cfg['ports'])})"
            lines.append(draw_box_line(f"      {A.DIM}{desc}{A.RST}", cols))
            lines.append(draw_box_line("", cols))

        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}[1-4] Select   [B] Back   [Q] Quit{A.RST}", cols))
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c"):
            return None
        if key in ("b", "esc"):
            return "__back__"
        if key == "1":
            return "quick"
        if key == "2" or key == "enter":
            return "normal"
        if key == "3":
            return "full"
        if key == "4":
            return "mega"


def _draw_clean_progress(cs: CleanScanState):
    cols, rows = term_size()
    W = cols - 2
    out: List[str] = []

    def bx(c: str):
        out.append(f"{A.CYN}║{A.RST}" + c + " " * max(0, W - _vl(c)) + f"{A.CYN}║{A.RST}")

    out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
    elapsed = _fmt_elapsed(time.monotonic() - cs.start_time) if cs.start_time else "0s"
    title = f" {A.BOLD}{A.WHT}Finding Clean Cloudflare IPs{A.RST}"
    right = f"{A.DIM}{elapsed}  |  ^C stop{A.RST}"
    bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

    pct = cs.done * 100 // max(1, cs.total)
    bw = max(1, min(30, W - 40))
    filled = int(bw * pct / 100)
    bar = f"{A.GRN}{'█' * filled}{A.DIM}{'░' * (bw - filled)}{A.RST}"
    bx(f" Probing [{bar}] {cs.done:,}/{cs.total:,}  {pct}%")

    found_line = f" {A.GRN}Found: {cs.found:,} clean IPs{A.RST}"
    if cs.results:
        best_lat = cs.results[0][1]
        found_line += f"   {A.DIM}Best: {best_lat:.0f}ms{A.RST}"
    bx(found_line)

    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    bx(f" {A.BOLD}Top IPs found (by latency):{A.RST}")

    vis = min(15, rows - 12)
    if cs.results:
        for i, (ip, lat) in enumerate(cs.results[:vis]):
            bx(f"   {A.CYN}{i+1:>3}.{A.RST} {ip:<22} {A.GRN}{lat:>6.0f}ms{A.RST}")
    else:
        bx(f"   {A.DIM}Scanning...{A.RST}")

    used = len(cs.results[:vis]) if cs.results else 1
    for _ in range(vis - used):
        bx("")

    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    bx(f" {A.DIM}Press Ctrl+C to stop early and show results{A.RST}")
    out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

    _w(A.HOME)
    _w("\n".join(out) + "\n")
    _fl()


def _clean_show_results(results: List[Tuple[str, float]], elapsed: str) -> Optional[str]:
    MAX_SHOW = 300
    display = results[:MAX_SHOW]
    offset = 0

    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        lines = draw_menu_header(cols)

        if results:
            lines.append(draw_box_line(
                f" {A.BOLD}{A.GRN}Scan Complete!{A.RST}  "
                f"Found {A.BOLD}{len(results):,}{A.RST} clean IPs in {elapsed}", cols))
        else:
            lines.append(draw_box_line(f" {A.YEL}Scan Complete — no clean IPs found.{A.RST}", cols))
        lines.append(draw_box_sep(cols))

        if display:
            vis = max(5, rows - 13)
            end = min(len(display), offset + vis)

            hdr = f" {A.BOLD}{'#':>4}  {'Address':<22} {'Latency':>8}{A.RST}"
            if len(display) > vis:
                pos = f"{A.DIM}[{offset+1}-{end} of {len(display)}"
                if len(results) > MAX_SHOW:
                    pos += f", {len(results):,} total"
                pos += f"]{A.RST}"
                hdr += " " * max(1, cols - 2 - _vl(hdr) - _vl(pos) - 1) + pos
            lines.append(draw_box_line(hdr, cols))
            lines.append(draw_box_line(
                f" {A.DIM}{'─'*4}  {'─'*22} {'─'*8}{A.RST}", cols))

            for i in range(offset, end):
                ip, lat = display[i]
                lines.append(draw_box_line(
                    f" {i+1:>4}  {ip:<22} {A.GRN}{lat:>6.0f}ms{A.RST}", cols))

        lines.append(draw_box_line("", cols))
        lines.append(draw_box_sep(cols))
        ft = ""
        if results:
            ft += f" {A.CYN}[S]{A.RST} Save all  {A.CYN}[T]{A.RST} Template+SpeedTest  "
        ft += f" {A.CYN}[B]{A.RST} Back"
        lines.append(draw_box_line(ft, cols))
        if display and len(display) > vis:
            lines.append(draw_box_line(
                f" {A.DIM}j/↓ down  k/↑ up  n/p page down/up{A.RST}", cols))
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("b", "esc", "q", "ctrl-c"):
            return "back"
        if key in ("j", "down"):
            vis = max(5, rows - 13)
            offset = min(offset + 1, max(0, len(display) - vis))
            continue
        if key in ("k", "up"):
            offset = max(0, offset - 1)
            continue
        if key == "n":
            vis = max(5, rows - 13)
            offset = min(offset + vis, max(0, len(display) - vis))
            continue
        if key == "p":
            vis = max(5, rows - 13)
            offset = max(0, offset - vis)
            continue
        if key == "s" and results:
            return "save"
        if key == "t" and results:
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Speed Test with Clean IPs{A.RST}\n")
            _w(f" {A.DIM}Paste a VLESS/VMess config URI. The address in it will be{A.RST}\n")
            _w(f" {A.DIM}replaced with each clean IP, then all configs get speed-tested.{A.RST}\n\n")
            _restore_console_input()
            _w(f" {A.CYN}Template:{A.RST} ")
            _fl()
            try:
                tpl = input().strip()
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            if not tpl or not parse_config(tpl):
                _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            return f"template:{tpl}"


async def tui_run_clean_finder() -> Optional[Tuple[str, str]]:
    mode = _clean_pick_mode()
    if mode is None:
        return None
    if mode == "__back__":
        return ("__back__", "")

    scan_cfg = CLEAN_MODES[mode]

    _w(A.CLR + A.HOME)
    cols, _ = term_size()
    lines = draw_menu_header(cols)
    lines.append(draw_box_line(
        f" {A.BOLD}Generating IPs from {len(CF_SUBNETS)} Cloudflare ranges...{A.RST}", cols))
    lines.append(draw_box_bottom(cols))
    _w("\n".join(lines) + "\n")
    _fl()

    ips = generate_cf_ips(CF_SUBNETS, scan_cfg["sample"])
    ports = scan_cfg.get("ports", [443])
    _dbg(f"CLEAN: Generated {len(ips):,} IPs × {len(ports)} port(s), sample={scan_cfg['sample']}")

    cs = CleanScanState()
    scan_task = asyncio.ensure_future(
        scan_clean_ips(
            ips, workers=scan_cfg["workers"], timeout=5.0,
            validate=scan_cfg["validate"], cs=cs, ports=ports,
        )
    )

    old_sigint = signal.getsignal(signal.SIGINT)
    _loop = asyncio.get_running_loop()
    def _sig(sig, frame):
        cs.interrupted = True
        _loop.call_soon_threadsafe(scan_task.cancel)
    signal.signal(signal.SIGINT, _sig)

    _w(A.CLR + A.HIDE)
    try:
        while not scan_task.done():
            _draw_clean_progress(cs)
            await asyncio.sleep(0.3)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        _dbg(f"CLEAN: progress loop error: {e}")
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    try:
        results = await scan_task
    except asyncio.CancelledError:
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])
    except Exception as e:
        _dbg(f"CLEAN: scan_task error: {e}")
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])

    elapsed = _fmt_elapsed(time.monotonic() - cs.start_time) if cs.start_time > 0 else "0s"
    _dbg(f"CLEAN: Done in {elapsed}. Found {len(results):,} / {len(ips):,}")

    action = _clean_show_results(results, elapsed)

    if action is None or action == "back":
        return ("__back__", "")

    if action == "save":
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = os.path.abspath(_results_path("clean_ips.txt"))
            with open(path, "w", encoding="utf-8") as f:
                for ip, lat in results:
                    f.write(f"{ip}\n")
            _w(f"\n {A.GRN}Saved {len(results):,} IPs to {path}{A.RST}\n")
        except OSError as e:
            _w(f"\n {A.RED}Save error: {e}{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _wait_any_key()
        return ("__back__", "")

    if action.startswith("template:"):
        template_uri = action[9:]
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = os.path.abspath(_results_path("clean_ips.txt"))
            with open(path, "w", encoding="utf-8") as f:
                for ip, lat in results:
                    f.write(f"{ip}\n")
        except OSError as e:
            _w(f"\n {A.RED}Save error: {e}{A.RST}\n")
            _fl()
            time.sleep(2)
            return ("__back__", "")
        return ("template", f"{template_uri}|||{path}")

    return None


def _tui_prompt_text(label: str) -> Optional[str]:
    _w(A.SHOW)
    _restore_console_input()
    _w(f"\n {A.CYN}{label}{A.RST} ")
    _fl()
    try:
        val = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    return val if val else None


def tui_pick_file() -> Optional[Tuple[str, str]]:
    enable_ansi()
    files = find_config_files()

    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        W = cols - 2

        out: List[str] = []
        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}║{A.RST}{c}{pad}\033[{W + 2}G{A.CYN}║{A.RST}")

        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        title = f" ⚡ {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        subtitle = f"{A.DIM}Cloudflare Config Scanner{A.RST}"
        bx(title + "  " + subtitle)
        bx("")

        bx(f" {A.DIM}── {A.BOLD}{A.WHT}📁 LOCAL FILES{A.RST} {A.DIM}{'─' * max(1, W - 19)}{A.RST}")
        if files:
            for i, (path, ftype, count) in enumerate(files[:9]):
                num = f" {A.CYN}{A.BOLD}{i + 1}{A.RST}."
                name = os.path.basename(path)
                desc = f"{A.DIM}{ftype}, {count} entries{A.RST}"
                bx(f" {num}  📄 {name:<28} {desc}")
        else:
            bx(f"    {A.DIM}No config files found in current directory{A.RST}")
            bx(f"    {A.DIM}Drop .txt or .json files here, or use options below{A.RST}")
        bx("")

        bx(f" {A.DIM}── {A.BOLD}{A.WHT}🌐 REMOTE SOURCES{A.RST} {A.DIM}{'─' * max(1, W - 22)}{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}s{A.RST}.  🔗 {A.WHT}Subscription URL{A.RST}        {A.DIM}Fetch configs from remote URL{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}p{A.RST}.  📂 {A.WHT}Enter File Path{A.RST}         {A.DIM}Load from custom file path{A.RST}")
        bx("")

        bx(f" {A.DIM}── {A.BOLD}{A.WHT}🔧 TOOLS{A.RST} {A.DIM}{'─' * max(1, W - 13)}{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}t{A.RST}.  🧩 {A.WHT}Template + Addresses{A.RST}    {A.DIM}Test one config against many IPs{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}f{A.RST}.  🔍 {A.WHT}Clean IP Finder{A.RST}         {A.DIM}Scan Cloudflare IP ranges{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}x{A.RST}.  ⚡ {A.WHT}Xray Pipeline Test{A.RST}    {A.DIM}Smart: probe → validate → expand → speed{A.RST}")
        if sys.platform == "linux":
            bx(f"  {A.CYN}{A.BOLD}d{A.RST}.  🚀 {A.WHT}Deploy Xray Server{A.RST}    {A.DIM}Install Xray on Linux VPS{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}o{A.RST}.  ☁  {A.WHT}Worker Proxy{A.RST}          {A.DIM}Fresh workers.dev SNI for any VLESS config{A.RST}")
        if sys.platform == "linux":
            bx(f"  {A.CYN}{A.BOLD}c{A.RST}.  🔧 {A.WHT}Connection Manager{A.RST}    {A.DIM}Manage existing Xray server configs{A.RST}")
        bx("")
        bx(f" {A.DIM}{'─' * (W - 2)}{A.RST}")
        bx(f" {A.DIM}[h] ❓ Help    [q] 🚪 Quit{A.RST}")
        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c", "esc"):
            _w(A.SHOW)
            _fl()
            return None
        if key == "h":
            tui_show_guide()
            files = find_config_files()
            continue
        if key == "p":
            path = _tui_prompt_text("Enter file path:")
            if path is None:
                continue
            if os.path.isfile(path):
                return ("file", path)
            _w(f" {A.RED}File not found.{A.RST}\n")
            _fl()
            time.sleep(1)
            continue
        if key == "s":
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Subscription URL{A.RST}\n")
            _w(f" {A.DIM}Paste a URL that contains VLESS/VMess configs (plain text or base64).{A.RST}\n")
            _w(f" {A.DIM}Example: https://example.com/sub.txt{A.RST}\n\n")
            _fl()
            url = _tui_prompt_text("URL:")
            if url is None:
                continue
            if not url.lower().startswith(("http://", "https://")):
                _w(f" {A.RED}URL must start with http:// or https://{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            return ("sub", url)
        if key == "t":
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Template + Address List{A.RST}\n")
            _w(f" {A.DIM}This mode takes ONE working config and a list of Cloudflare IPs/domains.{A.RST}\n")
            _w(f" {A.DIM}It replaces the address in your config with each IP from the list,{A.RST}\n")
            _w(f" {A.DIM}then tests all of them to find the fastest.{A.RST}\n\n")
            _w(f" {A.BOLD}Step 1:{A.RST} {A.CYN}Paste your VLESS/VMess config URI:{A.RST}\n")
            _w(f" {A.DIM}(a full vless://... or vmess://... URI){A.RST}\n ")
            _restore_console_input()
            _fl()
            try:
                tpl = input().strip()
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            if not tpl or not parse_config(tpl):
                _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            _w(f"\n {A.BOLD}Step 2:{A.RST} {A.CYN}Enter path to address list file:{A.RST}\n")
            _w(f" {A.DIM}(a .txt file with one IP or domain per line){A.RST}\n")
            _fl()
            addr_path = _tui_prompt_text("Path:")
            if addr_path is None:
                continue
            if not os.path.isfile(addr_path):
                _w(f" {A.RED}File not found.{A.RST}\n")
                _fl()
                time.sleep(1)
                continue
            return ("template", f"{tpl}|||{addr_path}")
        if key == "f":
            return ("find_clean", "")
        if key == "x":
            return ("pipeline", "")
        if key == "d" and sys.platform == "linux":
            return ("deploy", "")
        if key == "o":
            return ("worker_proxy", "")
        if key == "c" and sys.platform == "linux":
            return ("connection_manager", "")
        if key.isdigit() and 1 <= int(key) <= len(files):
            return ("file", files[int(key) - 1][0])


def tui_pick_mode() -> Optional[str]:
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Select scan mode:{A.RST}", cols))
        lines.append(draw_box_line("", cols))

        modes = [("quick", "1"), ("normal", "2"), ("thorough", "3")]
        for name, key in modes:
            p = PRESETS[name]
            num = f"{A.CYN}{A.BOLD}{key}{A.RST}"
            lbl = f"{A.BOLD}{p['label']}{A.RST}"
            if name == "normal":
                lbl += f" {A.GRN}(recommended){A.RST}"
            lines.append(draw_box_line(f"   {num}  {lbl}", cols))
            lines.append(
                draw_box_line(f"      {A.DIM}{p['desc']}{A.RST}", cols)
            )
            lines.append(
                draw_box_line(
                    f"      {A.DIM}Data: {p['data']}  |  Est. time: {p['time']}{A.RST}",
                    cols,
                )
            )
            lines.append(draw_box_line("", cols))

        lines.append(draw_box_sep(cols))
        lines.append(
            draw_box_line(
                f" {A.DIM}[1-3] Select   [B] Back   [Q] Quit{A.RST}", cols
            )
        )
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c"):
            _w(A.SHOW)
            _fl()
            return None
        if key == "b":
            return "__back__"
        if key == "1":
            return "quick"
        if key == "2" or key == "enter":
            return "normal"
        if key == "3":
            return "thorough"


class XrayDashboard:
    """TUI dashboard for xray proxy test progress."""

    def __init__(self, xst: XrayTestState):
        self.xst = xst
        self.sort = "score"
        self.offset = 0

    def _bar(self, cur: int, tot: int, w: int = 24) -> str:
        if tot == 0:
            return "░" * w
        p = min(1.0, cur / tot)
        f = int(w * p)
        return f"{A.GRN}{'█' * f}{A.DIM}{'░' * (w - f)}{A.RST}"

    def draw(self):
        cols, rows = term_size()
        W = cols - 2
        xst = self.xst

        for _v in xst.variations:
            if _v.alive and _v.score == 0 and _v.connect_ms > 0:
                cms = _v.connect_ms if _v.connect_ms >= 0 else 1000
                tms = _v.ttfb_ms if _v.ttfb_ms >= 0 else 1000
                _lat = max(0.0, 100.0 - cms / 10.0)
                _ttfb = max(0.0, 100.0 - tms / 5.0)
                if _v.native_tested or _v.speed_mbps < 0.01:
                    _v.score = round(_lat * 0.55 + _ttfb * 0.45, 1)
                else:
                    _spd = min(100.0, _v.speed_mbps * 20.0)
                    _v.score = round(_lat * 0.35 + _spd * 0.50 + _ttfb * 0.15, 1)

        out: List[str] = []

        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}║{A.RST}{c}{pad}\033[{W + 2}G{A.CYN}║{A.RST}")

        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        elapsed = _fmt_elapsed(time.monotonic() - xst.start_time) if xst.start_time else "0s"
        _pipeline = getattr(xst, 'pipeline_mode', False)
        title = f" {A.BOLD}{A.WHT}Xray Pipeline Test{A.RST}" if _pipeline else f" {A.BOLD}{A.WHT}Xray Proxy Test{A.RST}"
        right = f"{A.DIM}{elapsed}  |  ^C stop{A.RST}"
        bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        src = xst.source_uri[:60] + "..." if len(xst.source_uri) > 60 else xst.source_uri
        bx(f" {A.DIM}Config:{A.RST} {src}")
        bx(f" {A.DIM}Variations:{A.RST} {len(xst.variations)}  "
           f"{A.GRN}{xst.alive_count} alive{A.RST}  "
           f"{A.RED}{xst.dead_count} dead{A.RST}")
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        bw = max(1, min(24, W - 50))
        _is_pipeline = getattr(xst, 'pipeline_mode', False)

        if _is_pipeline:
            stage_stats = {
                "ip_scan": f"{len(xst.live_ips)} CF confirmed" if xst.live_ips else "",
                "base_test": (f"{len(xst.working_ips)} working" if xst.working_ips
                              else f"0 working" if xst.pipeline_stages[1]["status"] in ("done", "interrupted")
                              else ""),
                "expansion": (f"{xst.quick_passed} alive" if xst.quick_passed
                              else f"{xst.alive_count} alive" if xst.alive_count
                              else f"0 alive" if xst.pipeline_stages[2]["status"] in ("done", "interrupted")
                              else ""),
            }
            for i, stage in enumerate(xst.pipeline_stages):
                st = stage["status"]
                label = f"{stage['label']:<18}"
                stat = stage_stats.get(stage["name"], "")
                if st == "done":
                    stat_color = A.RED if stat.startswith("0 ") else A.GRN
                    bx(f" {A.GRN}v{A.RST} {label} {stat_color}{stat}{A.RST}")
                elif st == "active":
                    pct = xst.done_count * 100 // max(1, xst.total) if xst.total > 0 else 0
                    bx(f" {A.GRN}>{A.RST} {A.BOLD}{label}{A.RST}"
                       f"[{self._bar(xst.done_count, xst.total, bw)}] "
                       f"{xst.done_count}/{xst.total}  {pct}%")
                elif st == "interrupted":
                    bx(f" {A.YEL}!{A.RST} {label} {A.YEL}interrupted{A.RST}")
                else:
                    bx(f" {A.DIM}o {label} waiting...{A.RST}")
            _pf_warn = getattr(xst, 'preflight_warning', '')
            if _pf_warn:
                _pf_text = _pf_warn[:W - 6] if len(_pf_warn) > W - 6 else _pf_warn
                bx(f" {A.YEL}! {_pf_text}{A.RST}")
        elif xst.finished and xst.interrupted:
            if xst.phase == "quick_filter":
                bx(f" {A.YEL}!{A.RST} Quick Filter   {A.YEL}interrupted ({xst.alive_count} passed){A.RST}")
            elif xst.phase == "speed_test":
                qp = xst.quick_passed or xst.alive_count
                bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
                bx(f" {A.YEL}!{A.RST} Speed Test     {A.YEL}interrupted{A.RST}")
            else:
                bx(f" {A.YEL}!{A.RST} Quick Filter   {A.YEL}interrupted before starting{A.RST}")
        elif xst.finished:
            qp = xst.quick_passed or xst.alive_count
            bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
            if xst.phase == "speed_test":
                bx(f" {A.GRN}v{A.RST} Speed Test     {A.GRN}done{A.RST}")
        elif xst.phase == "quick_filter":
            pct = xst.done_count * 100 // max(1, xst.total)
            bx(f" {A.GRN}>{A.RST} {A.BOLD}Quick Filter{A.RST}   [{self._bar(xst.done_count, xst.total, bw)}] "
               f"{xst.done_count}/{xst.total}  {pct}%")
        elif xst.phase == "speed_test":
            qp = xst.quick_passed or xst.alive_count
            bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
            pct = xst.done_count * 100 // max(1, xst.total)
            bx(f" {A.GRN}>{A.RST} {A.BOLD}Speed Test{A.RST}     [{self._bar(xst.done_count, xst.total, bw)}] "
               f"{xst.done_count}/{xst.total}  {pct}%")
        else:
            bx(f" {A.DIM}o Quick Filter   starting...{A.RST}")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        _multi_ip = any(v.tag.count("|") >= 2 for v in xst.variations[:3])
        if _multi_ip:
            hdr = (f" {A.BOLD}{'#':>3}  {'IP':<18} {'SNI':<20} {'Frag':>8}  "
                   f"{'Conn':>6}  {'TTFB':>6}  {'Score':>5}{A.RST}")
            bx(hdr)
            bx(f" {A.DIM}{'─'*3}  {'─'*18} {'─'*20} {'─'*8}  {'─'*6}  {'─'*6}  {'─'*5}{A.RST}")
        else:
            hdr = (f" {A.BOLD}{'#':>3}  {'SNI':<26} {'Fragment':>10}  "
                   f"{'Conn':>6}  {'TTFB':>6}  {'Score':>5}{A.RST}")
            bx(hdr)
            bx(f" {A.DIM}{'─'*3}  {'─'*26} {'─'*10}  {'─'*6}  {'─'*6}  {'─'*5}{A.RST}")

        sorted_vars = sorted(
            xst.variations,
            key=lambda v: (
                -v.score if self.sort == "score"
                else (v.connect_ms if v.connect_ms > 0 else 9999)
            ),
        )

        vis = max(3, rows - 18)
        page = sorted_vars[self.offset:self.offset + vis]

        for rank, v in enumerate(page, self.offset + 1):
            frag_s = "none" if v.fragment is None else v.fragment.get("length", "?")
            if _multi_ip:
                _parts = v.tag.split("|", 2)
                _raw_ip = _parts[0] if len(_parts) >= 3 else ""
                _ip_s = (_raw_ip[:16] + "..") if len(_raw_ip) > 18 else _raw_ip[:18]
                sni_short = v.sni[:20]
                _name_col = f"{_ip_s:<18} {sni_short:<20} {frag_s:>8}"
            else:
                sni_short = v.sni[:26]
                _name_col = f"{sni_short:<26} {frag_s:>10}"
            if not v.alive and v.error:
                _err_s = v.error[:31] if v.error else "dead"
                _pad = max(0, 31 - len(_err_s))
                row = (f" {A.DIM}{rank:>3}  {_name_col}  "
                       f"{A.RED}{_err_s}{A.RST}{A.DIM}{' '*_pad}{A.RST}")
            elif not v.alive and not v.error and v.connect_ms <= 0 and v.score <= 0:
                row = (f" {A.DIM}{rank:>3}  {_name_col}  "
                       f"{'--':>6}  {'--':>6}  {'--':>5}{A.RST}")
            else:
                conn_s = f"{v.connect_ms:6.0f}" if v.connect_ms > 0 else f"{'--':>6}"
                ttfb_s = f"{v.ttfb_ms:6.0f}" if v.ttfb_ms > 0 else f"{'--':>6}"
                if v.score >= 70:
                    sc_s = f"{A.GRN}{v.score:5.1f}{A.RST}"
                elif v.score >= 40:
                    sc_s = f"{A.YEL}{v.score:5.1f}{A.RST}"
                elif v.score > 0:
                    sc_s = f"{v.score:5.1f}"
                else:
                    sc_s = f"{'--':>5}"
                row = (f" {rank:>3}  {_name_col}  "
                       f"{conn_s}  {ttfb_s}  {sc_s}")
            bx(row)

        for _ in range(vis - len(page)):
            bx("")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
        if xst.finished:
            if W >= 100:
                footer = (f" {A.CYN}[S]{A.RST} Sort  {A.CYN}[E]{A.RST} Export  "
                          f"{A.CYN}[C]{A.RST} View URI  "
                          f"{A.CYN}[J/K]{A.RST} Scroll  {A.CYN}[N/P]{A.RST} Page  "
                          f"{A.CYN}[B]{A.RST} Back  {A.CYN}[Q]{A.RST} Quit")
                bx(footer)
            else:
                bx(f" {A.CYN}[S]{A.RST}ort {A.CYN}[E]{A.RST}xp {A.CYN}[C]{A.RST}URI {A.CYN}[B]{A.RST}ack {A.CYN}[Q]{A.RST}uit")
                bx(f" {A.CYN}[J/K]{A.RST} Scroll  {A.CYN}[N/P]{A.RST} Page")
            if xst.export_error:
                bx(f" {A.RED}{xst.export_error}{A.RST}")
        else:
            bx(f" {A.DIM}{xst.phase_label}  |  Press Ctrl+C to stop{A.RST}")
        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w(A.CLR + A.HIDE)
        _w("\n".join(out) + "\n")
        _fl()

    def handle(self, key: str) -> Optional[str]:
        sorts = ["score", "latency"]
        if key == "s":
            idx = sorts.index(self.sort) if self.sort in sorts else 0
            self.sort = sorts[(idx + 1) % len(sorts)]
            self.offset = 0
        elif key in ("j", "down"):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = min(self.offset + 1, max(0, len(self.xst.variations) - vis))
        elif key in ("k", "up"):
            self.offset = max(0, self.offset - 1)
        elif key in ("n",):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = min(self.offset + vis, max(0, len(self.xst.variations) - vis))
        elif key in ("p",):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = max(0, self.offset - vis)
        elif key == "e" and self.xst.finished:
            return "export"
        elif key == "c" and self.xst.finished:
            return "view_uri"
        elif key == "b":
            return "back"
        elif key in ("q", "ctrl-c"):
            return "quit"
        return None


def xray_save_results(xst: XrayTestState, top: int = 10) -> Tuple[str, str]:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    sorted_vars = sorted(
        [v for v in xst.variations if v.alive],
        key=lambda v: v.score, reverse=True,
    )

    csv_path = _results_path(f"xray_{ts}_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Rank", "Tag", "SNI", "Fragment", "Connect_ms", "TTFB_ms",
                     "Speed_MBps", "Score", "Error", "URI"])
        for rank, v in enumerate(sorted_vars, 1):
            frag_s = json.dumps(v.fragment) if v.fragment else ""
            w.writerow([
                rank, v.tag, v.sni, frag_s,
                f"{v.connect_ms:.0f}" if v.connect_ms > 0 else "",
                f"{v.ttfb_ms:.0f}" if v.ttfb_ms > 0 else "",
                f"{v.speed_mbps:.3f}" if v.speed_mbps > 0 else "",
                f"{v.score:.1f}", v.error, v.result_uri,
            ])

    uri_path = _results_path(f"xray_{ts}_top{top}.txt")
    with open(uri_path, "w", encoding="utf-8") as f:
        count = 0
        for v in sorted_vars:
            if count >= top:
                break
            if v.result_uri:
                f.write(v.result_uri + "\n")
                count += 1

    return csv_path, uri_path


async def _run_pipeline_core(
    xst: "XrayTestState", pcfg: "PipelineConfig", xray_bin: str,
) -> "XrayDashboard":
    xst.source_uri = pcfg.uri
    xst.xray_bin = xray_bin

    xdash = XrayDashboard(xst)

    async def _pipeline_refresh():
        while not xst.finished:
            try:
                xdash.draw()
            except (OSError, ValueError):
                pass
            await asyncio.sleep(0.3)

    _w(A.CLR + A.HOME + A.HIDE)
    refresh_task = asyncio.create_task(_pipeline_refresh())
    pipeline_task = asyncio.ensure_future(xray_pipeline_test(xst, pcfg))

    old_sigint = signal.getsignal(signal.SIGINT)
    _loop_pl = asyncio.get_running_loop()

    def _sig(sig, frame):
        xst.interrupted = True
        xst.finished = True
        _loop_pl.call_soon_threadsafe(pipeline_task.cancel)
    signal.signal(signal.SIGINT, _sig)

    try:
        await pipeline_task
    except (asyncio.CancelledError, KeyboardInterrupt):
        xst.interrupted = True
        xst.finished = True
        _xray_calc_scores(xst)
    except Exception as e:
        _dbg(f"pipeline exception: {e}")
        xst.interrupted = True
        xst.finished = True
        _xray_calc_scores(xst)
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    refresh_task.cancel()
    try:
        await refresh_task
    except asyncio.CancelledError:
        pass

    return xdash


async def _post_pipeline_results(
    xst: "XrayTestState", xdash: "XrayDashboard", args,
) -> None:
    top_n = getattr(args, "xray_keep", 10)
    csv_p = uri_p = ""

    if any(v.alive for v in xst.variations):
        try:
            csv_p, uri_p = xray_save_results(xst, top=top_n)
        except OSError as e:
            csv_p = uri_p = ""
            xst.export_error = f"Export failed: {e}"

    xdash.draw()

    try:
        while True:
            key = _read_key_nb(0.1)
            if key is None:
                continue
            act = xdash.handle(key)
            if act in ("quit", "back"):
                break
            elif act == "export":
                try:
                    csv_p, uri_p = xray_save_results(xst, top=top_n)
                    _n_alive = sum(1 for v in xst.variations if v.alive)
                    xst.export_error = f"Exported {_n_alive} configs -> {uri_p}"
                except OSError as e:
                    xst.export_error = f"Export failed: {e}"
            elif act == "view_uri":
                alive = sorted(
                    [v for v in xst.variations if v.alive],
                    key=lambda v: v.score, reverse=True,
                )
                if alive and alive[0].result_uri:
                    while True:
                        _w(A.CLR + A.HOME + A.SHOW)
                        _w(f"\n {A.BOLD}Top configs ({len(alive)} alive):{A.RST}\n\n")
                        for _vi, _vv in enumerate(alive[:10], 1):
                            _vc = A.GRN if _vi == 1 else A.CYN
                            _conn_s = f"conn={_vv.connect_ms:.0f}ms" if _vv.connect_ms > 0 else ""
                            _w(f"  {A.BOLD}#{_vi:<3}{A.RST} "
                               f"{_vc}{_vv.sni:<28}{A.RST} "
                               f"score={_vv.score:<6.1f} "
                               f"{_conn_s}\n")
                        if len(alive) > 10:
                            _w(f"  {A.DIM}... +{len(alive) - 10} more{A.RST}\n")
                        _w(f"\n")
                        if csv_p:
                            _w(f" {A.DIM}Full results: {csv_p}{A.RST}\n")
                        if uri_p:
                            _w(f" {A.DIM}Top URIs:     {uri_p}{A.RST}\n")
                        _w(f"\n {A.YEL}Enter #{A.RST} to view full URI"
                           f" {A.DIM}(or press Enter to go back):{A.RST} ")
                        _fl()
                        try:
                            _choice = input().strip()
                        except (EOFError, KeyboardInterrupt, OSError):
                            _choice = ""
                        if not _choice:
                            break
                        try:
                            _idx = int(_choice.lstrip("#")) - 1
                            if 0 <= _idx < len(alive) and alive[_idx].result_uri:
                                _conn_s2 = f"conn={alive[_idx].connect_ms:.0f}ms" if alive[_idx].connect_ms > 0 else ""
                                _w(f"\n {A.BOLD}#{_idx + 1} "
                                   f"(score={alive[_idx].score:.1f}"
                                   f"{', ' + _conn_s2 if _conn_s2 else ''}):"
                                   f"{A.RST}\n\n")
                                _w(f" {A.GRN}{alive[_idx].result_uri}{A.RST}\n")
                            else:
                                _w(f"\n {A.RED}No config #{_choice} "
                                   f"(1-{len(alive)} available){A.RST}\n")
                        except ValueError:
                            _w(f"\n {A.RED}Enter a number 1-{len(alive)}{A.RST}\n")
                        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
                        _fl()
                        _read_key_blocking()
                    _w(A.HIDE)
                else:
                    xst.export_error = "No alive configs to view"
            xdash.draw()
    except (KeyboardInterrupt, EOFError, OSError):
        pass
    _w(A.SHOW)


def tui_pipeline_input(configless: bool = False) -> Optional[PipelineConfig]:
    _w(A.SHOW)

    _w(f"\n {A.BOLD}{A.CYN}Xray Pipeline Test{A.RST}\n")
    _w(f" {A.YEL}For:{A.RST} You have a working config {A.WHT}behind Cloudflare{A.RST} and want to find the fastest IPs and fragment settings.\n")
    _w(f" {A.DIM}Smart: probe IPs -> validate config -> expand (IPs x fragments){A.RST}\n\n")

    _restore_console_input()
    _w(f" {A.BOLD}Step 1:{A.RST} {A.CYN}Paste your VLESS/VMess config URI:{A.RST}\n")
    _w(f" {A.DIM}(must be behind Cloudflare -- CDN, Tunnel, or Workers){A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    parsed = parse_vless_full(uri) or parse_vmess_full(uri)
    if not parsed:
        _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n"); _fl()
        time.sleep(1.5); return None

    _proto = parsed.get("protocol", "vless")
    _net = parsed.get("type") or parsed.get("net") or "tcp"
    _sec = parsed.get("security") or "none"
    _addr = parsed.get("address", "?")
    _port = parsed.get("port", "?")
    _is_reality = _sec == "reality"
    _no_tls = _sec in ("none", "")
    _is_cf = _is_cf_address(_addr)
    if not _is_cf and not _is_reality and not _no_tls:
        _is_cf = _resolve_is_cf(_addr)

    _mode_label = "Cloudflare" if _is_cf else ("REALITY" if _is_reality else "Direct")
    _w(f" {A.GRN}OK{A.RST} {_proto}/{_net}/{_sec} @ {_addr}:{_port}"
       f" {A.DIM}({_mode_label}){A.RST}\n")
    _fl()

    if not _is_cf and not _is_reality:
        _w(f"\n {A.RED}{'─' * 50}{A.RST}\n")
        _w(f" {A.BOLD}{A.RED}Server is not behind Cloudflare{A.RST}\n")
        _w(f" {A.RED}{'─' * 50}{A.RST}\n\n")
        _w(f" {A.DIM}The pipeline scanner works by rotating Cloudflare IPs, SNIs,{A.RST}\n")
        _w(f" {A.DIM}and fragment settings. This only works when your server is{A.RST}\n")
        _w(f" {A.DIM}behind the Cloudflare CDN.{A.RST}\n\n")
        _w(f" {A.DIM}Press any key to go back...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return None

    if _is_reality:
        _w(f"\n {A.DIM}REALITY config -- testing with original SNI, no fragments.{A.RST}\n")
        _w(f" {A.DIM}Pipeline will validate connectivity on the original server.{A.RST}\n")
        _fl()
        return PipelineConfig(
            uri=uri, parsed=parsed,
            sni_pool=[], frag_preset="none",
            transport_variants=[],
        )

    sni_pool = []

    _w(f"\n {A.BOLD}Step 2:{A.RST} {A.CYN}Fragment settings (DPI bypass):{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. All presets (none + light + medium + heavy) {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. No fragmentation\n")
    _w(f"  {A.CYN}3{A.RST}. Light only\n")
    _w(f"  {A.CYN}4{A.RST}. Heavy only\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        frag_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    frag_map = {"1": "all", "2": "none", "3": "light", "4": "heavy"}
    frag_preset = frag_map.get(frag_ch, "all")

    transport_variants = []
    _w(f"\n {A.DIM}Transport: {A.WHT}{_net}{A.RST}{A.DIM} (from config -- only testing {_net}){A.RST}\n")

    _w(f"\n {A.BOLD}Step 3:{A.RST} {A.CYN}IP source:{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. Random CF IPs ({len(CF_TEST_IPS)} IPs across all ranges) {A.GRN}(recommended){A.RST}\n")
    _clean_ip_path = os.path.join(RESULTS_DIR, "clean_ips.txt")
    _clean_count = 0
    if os.path.isfile(_clean_ip_path):
        try:
            with open(_clean_ip_path, "r") as _cf:
                _clean_count = sum(1 for l in _cf if l.strip() and not l.startswith("#"))
        except OSError:
            pass
    if _clean_count > 0:
        _w(f"  {A.CYN}2{A.RST}. Clean IP Finder results ({_clean_count} IPs from {_clean_ip_path})\n")
    else:
        _w(f"  {A.CYN}2{A.RST}. Clean IP Finder results {A.DIM}(none found -- run [f] first){A.RST}\n")
    _w(f"  {A.CYN}3{A.RST}. Load from file path\n")
    _w(f"  {A.CYN}4{A.RST}. Enter IPs/CIDRs manually\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        ip_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt, OSError):
        return None

    custom_ips: List[str] = []
    if ip_ch == "2":
        if _clean_count > 0:
            custom_ips = expand_custom_ips(_clean_ip_path)
            if custom_ips:
                _w(f" {A.GRN}Loaded {len(custom_ips)} IPs from clean_ips.txt{A.RST}\n")
                _fl()
            else:
                _w(f" {A.RED}Failed to read clean_ips.txt{A.RST}\n"); _fl()
                time.sleep(1); return None
        else:
            _w(f" {A.RED}No clean IPs found. Run Clean IP Finder [f] from the main menu first.{A.RST}\n")
            _fl(); time.sleep(2); return None
    elif ip_ch == "3":
        _w(f" {A.CYN}Enter file path:{A.RST}\n ")
        _w(f" {A.DIM}e.g. results/clean_ips.txt or /path/to/ips.txt{A.RST}\n ")
        _fl()
        try:
            raw_ips = input().strip()
        except (EOFError, KeyboardInterrupt, OSError):
            return None
        if raw_ips:
            custom_ips = expand_custom_ips(raw_ips)
            if not custom_ips:
                _w(f" {A.RED}No valid IPs found in file.{A.RST}\n"); _fl()
                time.sleep(1); return None
            _w(f" {A.GRN}Loaded {len(custom_ips)} IPs{A.RST}\n")
            _fl()
        else:
            _w(f" {A.RED}No path entered.{A.RST}\n"); _fl()
            time.sleep(1); return None
    elif ip_ch == "4":
        _w(f" {A.CYN}Enter IPs, CIDRs (comma-separated):{A.RST}\n ")
        _w(f" {A.DIM}e.g. 104.16.0.0/24, 172.67.1.1{A.RST}\n ")
        _fl()
        try:
            raw_ips = input().strip()
        except (EOFError, KeyboardInterrupt, OSError):
            return None
        if raw_ips:
            custom_ips = expand_custom_ips(raw_ips)
            if not custom_ips:
                _w(f" {A.RED}No valid IPs found.{A.RST}\n"); _fl()
                time.sleep(1); return None
            _w(f" {A.GRN}Expanded to {len(custom_ips)} IPs{A.RST}\n")
            _fl()
        else:
            _w(f" {A.RED}No IPs entered.{A.RST}\n"); _fl()
            time.sleep(1); return None

    _orig_port = int(parsed.get("port", 443))
    _w(f"\n {A.BOLD}Step 4:{A.RST} {A.CYN}Ports to scan per IP:{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. Original port ({_orig_port}) only {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. All CF HTTPS ports (443, 8443, 2053, 2083, 2087, 2096)\n")
    _w(f"  {A.CYN}3{A.RST}. Custom ports\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        port_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt, OSError):
        return None

    if port_ch == "2":
        probe_ports = list(CF_HTTPS_PORTS)
        if _orig_port not in probe_ports:
            probe_ports.insert(0, _orig_port)
    elif port_ch == "3":
        _w(f" {A.CYN}Enter ports (comma-separated):{A.RST} ")
        _fl()
        try:
            raw_ports = input().strip()
        except (EOFError, KeyboardInterrupt, OSError):
            return None
        probe_ports = []
        for p in raw_ports.split(","):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                probe_ports.append(int(p))
        if not probe_ports:
            _w(f" {A.RED}No valid ports. Using {_orig_port}.{A.RST}\n"); _fl()
            probe_ports = [_orig_port]
    else:
        probe_ports = [_orig_port]

    _n_frags = len(XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS.get("all", [])))
    _potential = 120 * max(1, _n_frags)
    _w(f"\n {A.BOLD}Step 5:{A.RST} {A.CYN}Test intensity:{A.RST}\n")
    _w(f" {A.DIM}How many IP x fragment combinations to test in expansion.{A.RST}\n")
    _w(f" {A.DIM}More = better coverage but takes longer.{A.RST}\n\n")
    _w(f"  {A.CYN}1{A.RST}. {A.WHT}Quick{A.RST}      500 variations   {A.DIM}~2-3 min{A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. {A.WHT}Normal{A.RST}    1,500 variations   {A.DIM}~5-8 min{A.RST} {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}3{A.RST}. {A.WHT}Thorough{A.RST}  3,000 variations   {A.DIM}~10-15 min{A.RST}\n")
    _w(f"  {A.CYN}4{A.RST}. {A.WHT}Maximum{A.RST}   7,500 variations   {A.DIM}~25-40 min{A.RST}\n")
    _w(f"\n Choice [2]: ")
    _fl()
    try:
        _int_ch = input().strip() or "2"
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    _int_map = {"1": 500, "2": 1500, "3": 3000, "4": 7500}
    max_expansion = _int_map.get(_int_ch, 1500)
    _w(f" {A.GRN}-> Up to {max_expansion:,} variations{A.RST}\n")

    return PipelineConfig(
        uri=uri, parsed=parsed,
        sni_pool=sni_pool,
        frag_preset=frag_preset,
        transport_variants=transport_variants,
        custom_ips=custom_ips,
        probe_ports=probe_ports,
        max_expansion=max_expansion,
    )


async def _tui_run_pipeline(args, cli_uri: str = ""):
    if cli_uri:
        parsed = parse_vless_full(cli_uri) or parse_vmess_full(cli_uri)
        if not parsed:
            _w(A.SHOW)
            print(f"  Invalid VLESS/VMess URI: {cli_uri[:60]}...")
            time.sleep(2)
            return
        _addr = parsed.get("address", "")
        _sec = parsed.get("security") or "none"
        _is_cf_smart = _is_cf_address(_addr) or (
            _sec not in ("reality", "none", "") and _resolve_is_cf(_addr))
        if not _is_cf_smart and _sec != "reality":
            _w(A.SHOW)
            _w(f"\n {A.RED}Server is not behind Cloudflare.{A.RST}\n")
            _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            return
        sni_pool = []
        if getattr(args, "xray_sni", None):
            sni_pool = [s.strip() for s in args.xray_sni.split(",") if s.strip()]
        frag_preset = getattr(args, "xray_frag", "all")
        if _sec == "reality":
            frag_preset = "none"
            transport_vars = []
        else:
            transport_vars = ["ws", "xhttp"]
        pcfg = PipelineConfig(
            uri=cli_uri, parsed=parsed,
            sni_pool=sni_pool, frag_preset=frag_preset,
            transport_variants=transport_vars,
            max_expansion=1500,
        )
    else:
        pcfg = tui_pipeline_input()
        if pcfg is None:
            return

    _w(A.SHOW)
    _w(f"\n {A.DIM}Looking for xray-core binary...{A.RST}\n")
    _fl()
    xray_bin = xray_find_binary(getattr(args, "xray_bin", None))
    if not xray_bin:
        _w(f" {A.YEL}Xray not found. Installing to ~/.cfray/bin/...{A.RST}\n")
        _fl()
        xray_bin = xray_install()
        if not xray_bin:
            _w(f" {A.RED}ERROR: Could not install xray-core.{A.RST}\n")
            _fl()
            time.sleep(3)
            return
    _w(f" {A.GRN}OK{A.RST} Using {xray_bin}\n")
    _fl()

    xst = XrayTestState()
    xdash = await _run_pipeline_core(xst, pcfg, xray_bin)
    await _post_pipeline_results(xst, xdash, args)


class Dashboard:
    def __init__(self, st: State):
        self.st = st
        self.sort = "score"
        self.offset = 0
        self.show_domains = False

    def _bar(self, cur: int, tot: int, w: int = 24) -> str:
        if tot == 0:
            return "░" * w
        p = min(1.0, cur / tot)
        f = int(w * p)
        return f"{A.GRN}{'█' * f}{A.DIM}{'░' * (w - f)}{A.RST}"

    def _cscore(self, v: float) -> str:
        if v >= 70:
            return f"{A.GRN}{v:5.1f}{A.RST}"
        if v >= 40:
            return f"{A.YEL}{v:5.1f}{A.RST}"
        if v > 0:
            return f"{A.RED}{v:5.1f}{A.RST}"
        return f"{A.DIM}    -{A.RST}"

    def _speed_str(self, v: float) -> str:
        if v <= 0:
            return f"{A.DIM}     -{A.RST}"
        if v >= 1:
            return f"{A.GRN}{v:5.1f}{A.RST}"
        return f"{A.YEL}{v * 1000:4.0f}K{A.RST}"

    def draw(self):
        cols, rows = term_size()
        W = cols - 2
        s = self.st
        vis = max(3, rows - 18 - len(s.rounds))
        out: List[str] = []

        def bx(c: str):
            out.append(f"{A.CYN}║{A.RST}" + c + " " * max(0, W - _vl(c)) + f"{A.CYN}║{A.RST}")

        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        elapsed = _fmt_elapsed(time.monotonic() - s.start_time) if s.start_time else "0s"
        title = f" {A.BOLD}{A.WHT}CF Config Scanner{A.RST}"
        right = f"{A.DIM}{elapsed}  |  {s.mode}  |  ^C stop{A.RST}"
        bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        fname = os.path.basename(s.input_file)
        info = f" {A.DIM}File:{A.RST} {fname}   {A.DIM}Configs:{A.RST} {len(s.configs)}   {A.DIM}Unique IPs:{A.RST} {len(s.ips)}"
        if s.latency_cut_n > 0:
            info += f"   {A.DIM}Cut:{A.RST} {s.latency_cut_n}"
        bx(info)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        bw = min(24, W - 55)

        if s.phase == "latency":
            pct = s.done_count * 100 // max(1, s.total)
            bx(f" {A.GRN}▶{A.RST} {A.BOLD}Latency{A.RST}          [{self._bar(s.done_count, s.total, bw)}] {s.done_count}/{s.total}  {pct}%")
        elif s.alive_n > 0:
            cut_info = f"  {A.DIM}cut {s.latency_cut_n}{A.RST}" if s.latency_cut_n > 0 else ""
            bx(f" {A.GRN}✓{A.RST} Latency          {A.GRN}{s.alive_n} alive{A.RST}  {A.DIM}{s.dead_n} dead{A.RST}{cut_info}")
        else:
            bx(f" {A.DIM}○ Latency          waiting...{A.RST}")

        for i, rc in enumerate(s.rounds):
            rn = i + 1
            lbl = f"Speed R{rn} ({rc.label}x{rc.keep})"
            if s.cur_round == rn and s.phase.startswith("speed") and not s.finished:
                pct = s.done_count * 100 // max(1, s.total)
                bx(f" {A.GRN}▶{A.RST} {A.BOLD}{lbl:<18}{A.RST}[{self._bar(s.done_count, s.total, bw)}] {s.done_count}/{s.total}  {pct}%")
            elif s.cur_round > rn or (s.cur_round >= rn and s.finished):
                bx(f" {A.GRN}✓{A.RST} {lbl:<18}{A.GRN}done{A.RST}")
            else:
                bx(f" {A.DIM}○ {lbl:<18}waiting...{A.RST}")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
        parts = []
        if s.alive_n > 0:
            alats = [r.tls_ms for r in s.res.values() if r.alive and r.tls_ms > 0]
            avg_lat = statistics.mean(alats) if alats else 0
            parts.append(f"{A.GRN}● {s.alive_n}{A.RST} alive")
            parts.append(f"{A.RED}● {s.dead_n}{A.RST} dead")
            if avg_lat:
                parts.append(f"{A.DIM}avg latency:{A.RST} {avg_lat:.0f}ms")
            if s.best_speed > 0:
                parts.append(f"{A.CYN}best:{A.RST} {s.best_speed:.2f} MB/s")
        bx(" " + "   ".join(parts) if parts else " ")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        hdr = f" {A.BOLD}{'#':>3}  {'IP':<16} {'Dom':>3}  {'Ping':>6}  {'Conn':>6}"
        for i, rc in enumerate(s.rounds):
            hdr += f"  {'R' + str(i + 1):>5}"
        hdr += f"  {'Colo':>4}  {'Score':>5}{A.RST}"
        bx(hdr)

        sep = f" {'─' * 3}  {'─' * 16} {'─' * 3}  {'─' * 6}  {'─' * 6}"
        for _ in s.rounds:
            sep += f"  {'─' * 5}"
        sep += f"  {'─' * 4}  {'─' * 5}"
        bx(f"{A.DIM}{sep}{A.RST}")

        results = sorted_all(s, self.sort)
        total_results = len(results)
        page = results[self.offset : self.offset + vis]

        for rank, r in enumerate(page, self.offset + 1):
            if not r.alive:
                row = f" {A.DIM}{rank:>3}  {r.ip:<16} {len(r.domains):>3}  {A.RED}{'dead':>6}{A.RST}{A.DIM}  {'':>6}"
                for j in range(len(s.rounds)):
                    row += f"  {'':>5}"
                row += f"  {'':>4}  {A.RED}{'--':>5}{A.RST}"
                bx(row)
                continue
            tcp = f"{r.tcp_ms:6.0f}" if r.tcp_ms > 0 else f"{A.DIM}     -{A.RST}"
            tls = f"{r.tls_ms:6.0f}" if r.tls_ms > 0 else f"{A.DIM}     -{A.RST}"
            row = f" {rank:>3}  {r.ip:<16} {len(r.domains):>3}  {tcp}  {tls}"
            for j in range(len(s.rounds)):
                if j < len(r.speeds) and r.speeds[j] > 0:
                    row += f"  {self._speed_str(r.speeds[j])}"
                else:
                    row += f"  {A.DIM}    -{A.RST}"
            if r.colo:
                cl = f"{r.colo:>4}"
            else:
                cl = f"{A.DIM}   -{A.RST}"
            row += f"  {cl}  {self._cscore(r.score)}"
            bx(row)

        for _ in range(vis - len(page)):
            bx("")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        if s.notify and time.monotonic() < s.notify_until:
            bx(f" {A.GRN}{A.BOLD}{s.notify}{A.RST}")
        elif s.finished:
            sort_hint = f"sort:{A.BOLD}{self.sort}{A.RST}"
            page_hint = f"{self.offset + 1}-{min(self.offset + vis, total_results)}/{total_results}"
            ft = (
                f" {A.CYN}[S]{A.RST} {sort_hint}  "
                f"{A.CYN}[E]{A.RST} Export  "
                f"{A.CYN}[A]{A.RST} ExportAll  "
                f"{A.CYN}[C]{A.RST} Configs  "
                f"{A.CYN}[D]{A.RST} Domains  "
                f"{A.CYN}[H]{A.RST} Help  "
                f"{A.CYN}[J/K]{A.RST}"
            )
            ft2 = (
                f" Scroll  {A.CYN}[N/P]{A.RST} Page ({page_hint})  "
                f"{A.CYN}[B]{A.RST} Back  "
                f"{A.CYN}[Q]{A.RST} Quit"
            )
            bx(ft)
            bx(ft2)
        else:
            bx(f" {A.DIM}{s.phase_label}...  Press Ctrl+C to stop and export partial results{A.RST}")

        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w(A.HOME)
        _w("\n".join(out) + "\n")
        _fl()

    def draw_domain_popup(self, r: Result):
        _w(A.CLR)
        cols, rows = term_size()
        vis = min(len(r.domains), rows - 10)
        lines = []
        lines.append(f"{A.CYN}╔{'═' * (cols - 2)}╗{A.RST}")
        lines.append(draw_box_line(f" {A.BOLD}Domains for {r.ip}  ({len(r.domains)} total){A.RST}", cols))
        ping_s = f"{r.tcp_ms:.0f}ms" if r.tcp_ms > 0 else "-"
        conn_s = f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-"
        lines.append(draw_box_line(f" {A.DIM}Score: {r.score:.1f}  |  Ping: {ping_s}  |  Conn: {conn_s}{A.RST}", cols))
        lines.append(draw_box_sep(cols))
        for d in r.domains[:vis]:
            lines.append(draw_box_line(f"  {d}", cols))
        if len(r.domains) > vis:
            lines.append(draw_box_line(f"  {A.DIM}...and {len(r.domains) - vis} more{A.RST}", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}Press any key to go back{A.RST}", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)

    def draw_config_popup(self, r: Result):
        _w(A.CLR)
        cols, rows = term_size()
        lines = []
        lines.append(f"{A.CYN}╔{'═' * (cols - 2)}╗{A.RST}")
        lines.append(draw_box_line(f" {A.BOLD}Configs for {r.ip}  ({len(r.uris)} URIs){A.RST}", cols))
        ping_s = f"{r.tcp_ms:.0f}ms" if r.tcp_ms > 0 else "-"
        conn_s = f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-"
        speed_s = f"{r.best_mbps:.1f} MB/s" if r.best_mbps > 0 else "-"
        lines.append(draw_box_line(
            f" {A.DIM}Score: {r.score:.1f}  |  Ping: {ping_s}  |  Conn: {conn_s}  |  Speed: {speed_s}{A.RST}", cols
        ))
        lines.append(draw_box_sep(cols))
        if r.uris:
            max_show = rows - 10
            for i, uri in enumerate(r.uris[:max_show]):
                tag = f" {A.CYN}{i+1}.{A.RST} "
                max_uri = cols - 8
                display = uri if len(uri) <= max_uri else uri[:max_uri - 3] + "..."
                lines.append(draw_box_line(f"{tag}{A.GRN}{display}{A.RST}", cols))
            if len(r.uris) > max_show:
                lines.append(draw_box_line(f"  {A.DIM}...and {len(r.uris) - max_show} more{A.RST}", cols))
        else:
            lines.append(draw_box_line(f"  {A.DIM}No VLESS/VMess URIs stored for this IP{A.RST}", cols))
            lines.append(draw_box_line(f"  {A.DIM}(only available when loaded from URIs or subscriptions){A.RST}", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}Press any key to go back{A.RST}", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)

    def draw_help_popup(self):
        _w(A.CLR)
        cols, rows = term_size()
        W = min(64, cols - 4)
        lines = []
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Keyboard Shortcuts{A.RST}")
        lines.append(f"  {A.CYN}{'-' * W}{A.RST}")
        help_items = [
            ("S", "Cycle sort order: score / latency / speed"),
            ("E", "Export results (CSV + top N configs)"),
            ("A", "Export ALL configs sorted best to worst"),
            ("C", "View VLESS/VMess URIs for an IP (enter rank #)"),
            ("D", "View domains for an IP (enter rank #)"),
            ("J / K", "Scroll down / up one row"),
            ("N / P", "Page down / up"),
            ("B", "Back to main menu (new scan)"),
            ("H", "Show this help screen"),
            ("Q", "Quit (results auto-saved on exit)"),
        ]
        for key, desc in help_items:
            lines.append(f"  {A.CYN}{key:<10}{A.RST} {desc}")
        lines.append("")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Column Guide{A.RST}")
        lines.append(f"  {A.CYN}{'-' * W}{A.RST}")
        col_items = [
            ("#", "Rank (sorted by current sort order)"),
            ("IP", "Cloudflare edge IP address"),
            ("Dom", "How many domains share this IP"),
            ("Ping", "TCP connect time in ms (like ping)"),
            ("Conn", "Full connection time in ms (TCP + TLS handshake)"),
            ("R1,R2..", "Download speed per round (MB/s or KB/s)"),
            ("Colo", "CF datacenter code (e.g. FRA, IAH, MRS)"),
            ("Score", "Combined score (0-100, higher = better)"),
        ]
        for key, desc in col_items:
            lines.append(f"  {A.CYN}{key:<10}{A.RST} {desc}")
        lines.append("")
        lines.append(f"  {A.DIM}Score = Conn latency (35%) + speed (50%) + TTFB (15%){A.RST}")
        lines.append(f"  {A.DIM}'-' means not tested yet (only top IPs get speed tested){A.RST}")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Made By Sam - SamNet Technologies{A.RST}")
        lines.append(f"  {A.DIM}  https://github.com/SamNet-dev/cfray{A.RST}")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.DIM}Press any key to go back{A.RST}")

        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)

    def handle(self, key: str) -> Optional[str]:
        sorts = ["score", "latency", "speed"]
        if key == "s":
            idx = sorts.index(self.sort) if self.sort in sorts else 0
            self.sort = sorts[(idx + 1) % len(sorts)]
        elif key in ("j", "down"):
            self.offset = min(self.offset + 1, max(0, len(sorted_all(self.st, self.sort)) - 3))
        elif key in ("k", "up"):
            self.offset = max(0, self.offset - 1)
        elif key == "n":
            _, rows = term_size()
            page = max(3, rows - 18 - len(self.st.rounds))
            self.offset = min(self.offset + page, max(0, len(sorted_all(self.st, self.sort)) - 3))
        elif key == "p":
            _, rows = term_size()
            page = max(3, rows - 18 - len(self.st.rounds))
            self.offset = max(0, self.offset - page)
        elif key == "e":
            return "export"
        elif key == "a":
            return "export-all"
        elif key == "c":
            return "configs"
        elif key == "d":
            return "domains"
        elif key == "h":
            return "help"
        elif key == "b":
            return "back"
        elif key in ("q", "ctrl-c"):
            return "quit"
        return None


async def _refresh_loop(dash: Dashboard, st: State):
    while not st.finished:
        try:
            dash.draw()
        except Exception:
            pass
        await asyncio.sleep(0.3)
