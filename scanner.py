#!/usr/bin/env python3
#
# ┌─────────────────────────────────────────────────────────────────┐
# │                                                                 │
# │   ⚡  CF CONFIG SCANNER v1.1                                    │
# │                                                                 │
# │   Test VLESS/VMess proxy configs for latency + download speed   │
# │                                                                 │
# │   • Latency test (TCP + TLS) all IPs in seconds                 │
# │   • Download speed test via progressive funnel                  │
# │   • Live TUI dashboard with real-time results                   │
# │   • Smart rate limiting with CDN fallback                       │
# │   • Clean IP Finder — scan all Cloudflare ranges (up to 3M)     │
# │   • Multi-port scanning (443, 8443) for maximum coverage        │
# │   • Zero dependencies — Python 3.8+ stdlib only                 │
# │   • Xray Pipeline Test — smart probe → expand → speed test      │
# │   • Deploy Xray Server — full VPS setup with systemd + certs    │
# │   • Worker Proxy — fresh workers.dev SNI for any VLESS config   │
# │                                                                 │
# │                                                                 │
# └─────────────────────────────────────────────────────────────────┘
#
# Usage:
#   python3 scanner.py                              Interactive TUI
#   python3 scanner.py -i configs.txt               Normal mode
#   python3 scanner.py --sub https://example.com/sub Fetch from subscription
#   python3 scanner.py --template "vless://..." -i addrs.json  Generate + test
#   python3 scanner.py --find-clean --no-tui --clean-mode mega  Clean IP scan
#

import asyncio
import argparse
import base64
import csv
import glob as globmod
import json
import os
import platform as _platform
import random
import re
import secrets
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.parse
import zipfile
from typing import Dict, List, Optional, Tuple

from src.constants import (A, ANSI, CDN_FALLBACK, CF_HTTPS_PORTS, CF_SUBNETS,
                           CF_TEST_IPS, CLEAN_MODES, DEBUG_LOG, DEPLOY_SYSTEMD_UNIT,
                           DEPLOY_XRAY_BACKUP_DIR, DEPLOY_XRAY_BIN, DEPLOY_XRAY_CONFIG,
                           DEPLOY_XRAY_CONFIG_DIR, DEPLOY_XRAY_SERVICE, DEPLOY_XRAY_SHARE,
                           LATENCY_TIMEOUT, LATENCY_WORKERS, LOG_MAX_BYTES, PRESETS,
                           RESULTS_DIR, SPEED_HOST, SPEED_PATH, SPEED_TIMEOUT, SPEED_WORKERS,
                           VERSION, XRAY_BASE_PORT, XRAY_BIN_DIR, XRAY_CONFIG_TEMPLATE,
                           XRAY_CONNECT_TIMEOUT, XRAY_FRAG_PRESETS, XRAY_HOME,
                           XRAY_PROFILES_DIR, XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT,
                           XRAY_SPEED_SIZE, XRAY_SPEED_TIMEOUT, XRAY_TMP_DIR,
                           _CF_NETS, _CF_PREFLIGHT_IPS, _generate_random_cf_ips,
                           _is_cf_address, _resolve_is_cf)
from src.clean_finder import _split_to_24s, _tls_probe, generate_cf_ips, scan_clean_ips
from src.config_parse import (_infer_orig_sni, fetch_sub, generate_from_template,
                              load_addresses, load_input, parse_config,
                              parse_rounds_str, parse_size, parse_vless_full,
                              parse_vmess_full)
from src.models import (CleanScanState, ConfigEntry, DeployState,
                        PipelineConfig, Result, RoundCfg, State,
                        XrayTestState, XrayVariation)
from src.rate_limiter import CFRateLimiter
from src.speed_test import _dl_one, _lat_one, phase1, phase2_round
from src.tui import (Dashboard, XrayDashboard, _clean_pick_mode, _clean_show_results,
                     _draw_clean_progress, _help_clean_finder, _help_cli_reference,
                     _help_deploy, _help_getting_started, _help_scan_modes,
                     _help_show_page, _help_worker_proxy, _help_xray_test,
                     _post_pipeline_results, _refresh_loop, _run_pipeline_core,
                     _tui_prompt_text, _tui_run_pipeline, calc_scores, draw_box_bottom,
                     draw_box_line, draw_box_sep, draw_menu_header, find_config_files,
                     sorted_alive, sorted_all, tui_pick_file, tui_pick_mode,
                     tui_pipeline_input, tui_run_clean_finder, tui_show_guide,
                     xray_save_results, _results_path)
from src.xray_utils import (_build_uri, _extract_vless_ws_params, _find_free_ports,
                            _test_single_variation, _vless_ws_read_tunnel,
                            _vless_ws_speed_test, _xray_calc_scores,
                            _xray_speed_test_blocking, build_vless_uri,
                            build_vmess_uri, build_xray_config, expand_custom_ips,
                            generate_pipeline_variations, generate_xray_variations,
                            switch_transport, xray_find_binary, xray_install,
                            xray_pipeline_test, xray_speed_test, XrayProcess)
from src.utils import (_dbg, _WsFrameParser, _char_width, _fl, _flush_stdin,
                       _fmt_elapsed, _prompt_number, _read_key_blocking,
                       _read_key_nb, _restore_console_input, _vl, _w,
                       _wait_any_key, _ws_frame_encode, enable_ansi, term_size)
from src.deploy_utils import (
    _build_single_inbound, _cm_build_client_uri, _parse_inbound_summary,
    _read_server_config, _restart_xray_service, _tui_connection_manager,
    _tui_deploy_detect_ip, _tui_deploy_fresh_wizard, _tui_deploy_from_file,
    _tui_deploy_from_uri, _tui_deploy_handle_security, _tui_run_deploy,
    _uninstall_all, _write_server_config, build_client_uri_for_server,
    build_server_config, deploy_check_port, deploy_check_prerequisites,
    deploy_detect_server_ip, deploy_fresh_config, deploy_generate_reality_keys,
    deploy_generate_short_id, deploy_generate_uuid, deploy_install_xray_system,
    deploy_run_pipeline, deploy_save_results, deploy_setup_certbot,
    deploy_systemd_service, deploy_validate_config, deploy_write_config,
    generate_configless_base, tui_deploy_input,
)


def build_dynamic_rounds(mode: str, alive_count: int) -> List[RoundCfg]:
    """Build round configs dynamically based on mode and alive IP count."""
    preset = PRESETS.get(mode, PRESETS["normal"])
    if not preset.get("dynamic"):
        return [RoundCfg(1_000_000, alive_count)]
    sizes = preset["round_sizes"]
    pcts = preset["round_pcts"]
    mins = preset["round_min"]
    maxs = preset["round_max"]
    small_set = alive_count <= 50
    rounds = []
    for size, pct, mn, mx in zip(sizes, pcts, mins, maxs):
        if small_set:
            keep = alive_count
        else:
            keep = int(alive_count * pct / 100) if pct < 100 else alive_count
            if mn > 0:
                keep = max(mn, keep)
            if mx > 0:
                keep = min(mx, keep)
        keep = min(keep, alive_count)
        if keep > 0:
            rounds.append(RoundCfg(size, keep))
    return rounds


def load_configs_from_args(args) -> Tuple[List[ConfigEntry], str]:
    """Load configs based on CLI args. Returns (configs, source_label)."""
    if getattr(args, "sub", None):
        configs = fetch_sub(args.sub)
        return configs, args.sub
    if getattr(args, "template", None):
        if not getattr(args, "input", None):
            return [], "ERROR: --template requires -i (address list file)"
        addrs = load_addresses(args.input)
        configs = generate_from_template(args.template, addrs)
        return configs, f"{args.input} ({len(addrs)} addresses)"
    if getattr(args, "input", None):
        configs = load_input(args.input)
        return configs, args.input
    return [], ""


def _worker_proxy_generate_script(origin_host: str, origin_port: int,
                                   origin_security: str = "tls") -> str:
    """Generate CF Worker script to proxy WS to an origin behind CF CDN.

    Unlike _cdn_generate_worker_script (which targets a raw IP you own),
    this targets an existing CF-backed host domain.  The Worker rewrites
    the Host header so CF routes the internal fetch to the real origin.
    """
    scheme = "https" if origin_security in ("tls", "reality") else "http"
    port_part = ("" if (scheme == "https" and origin_port == 443)
                      or (scheme == "http" and origin_port == 80)
                 else f":{origin_port}")
    return f"""\
// CFray Worker Proxy — route ANY SNI to origin
// Deploy: dash.cloudflare.com → Workers & Pages → Create → Deploy
// Free tier: 100K requests/day

export default {{
  async fetch(request) {{
    const url = new URL(request.url);
    const origin = "{scheme}://{origin_host}{port_part}" + url.pathname;
    const headers = new Headers(request.headers);
    headers.set("Host", "{origin_host}");
    return fetch(origin, {{
      method: request.method,
      headers: headers,
    }});
  }}
}};"""


async def _tui_worker_proxy(args):
    """Worker Proxy — paste any VLESS URI, deploy a CF Worker, run pipeline
    with ALL CF SNIs enabled.

    CF enforces zone matching (SNI must match Host domain's zone), so a
    random VLESS config only works with the original SNI.  A CF Worker
    sits in its own zone (*.workers.dev); the Worker rewrites Host to the
    origin domain and proxies internally.  Result: every CF SNI works.
    """
    enable_ansi()
    _w(A.CLR + A.HOME + A.SHOW)
    cols, _ = term_size()
    W = cols - 2

    _w(f"\n{A.CYN}{'=' * (W + 2)}{A.RST}\n")
    _w(f"{A.CYN}|{A.RST} {A.BOLD}{A.WHT}Worker Proxy -- Fresh SNI for Any VLESS Config{A.RST}" +
       " " * max(0, W - 50) + f"{A.CYN}|{A.RST}\n")
    _w(f"{A.CYN}{'=' * (W + 2)}{A.RST}\n\n")

    _w(f" {A.DIM}If the original domain's SNI is blocked by DPI, a CF Worker gives{A.RST}\n")
    _w(f" {A.DIM}you a fresh *.workers.dev SNI. The Worker proxies to the original{A.RST}\n")
    _w(f" {A.DIM}server, so your configs work with a different (unblocked) SNI.{A.RST}\n\n")

    _restore_console_input()
    _w(f" {A.BOLD}{A.CYN}[1/3]{A.RST} {A.BOLD}Paste your VLESS config URI:{A.RST}\n")
    _w(f" {A.DIM}(a full vless://... URI){A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return
    if not uri:
        _w(f"\n {A.RED}Cancelled.{A.RST}\n")
        time.sleep(1)
        return

    parsed = parse_vless_full(uri)
    if not parsed:
        _w(f"\n {A.RED}Invalid VLESS URI.{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    if parsed.get("type") not in ("ws", "websocket"):
        _w(f"\n {A.RED}Only WebSocket (ws) transport is supported for Worker proxy.{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    origin_host = parsed.get("host") or parsed.get("sni") or parsed.get("address", "")
    origin_port = parsed.get("port", 443)
    ws_path = parsed.get("path", "/")
    uuid_val = parsed.get("uuid", "")
    security = parsed.get("security", "tls")

    _w(f"\n   {A.GRN}Protocol: VLESS  |  Transport: WS  |  Security: {security}{A.RST}\n")
    _w(f"   {A.GRN}Origin host: {origin_host}:{origin_port}  |  Path: {ws_path}{A.RST}\n")
    _w(f"   {A.GRN}UUID: {uuid_val[:8]}...{A.RST}\n\n")

    _w(f" {A.BOLD}{A.CYN}[2/3]{A.RST} {A.BOLD}Worker script generated:{A.RST}\n\n")
    script = _worker_proxy_generate_script(origin_host, origin_port, security)
    _w(f" {A.DIM}{'-' * (W - 2)}{A.RST}\n")
    for line in script.split("\n"):
        _w(f" {A.WHT}{line}{A.RST}\n")
    _w(f" {A.DIM}{'-' * (W - 2)}{A.RST}\n\n")

    _w(f" {A.BOLD}Deploy instructions:{A.RST}\n\n")
    _w(f"   {A.WHT}1.{A.RST} Go to {A.CYN}dash.cloudflare.com{A.RST} -> Workers & Pages -> Create\n")
    _w(f"   {A.WHT}2.{A.RST} Click {A.WHT}\"Create Worker\"{A.RST}, name it anything\n")
    _w(f"   {A.WHT}3.{A.RST} Click {A.WHT}\"Deploy\"{A.RST}, then {A.WHT}\"Edit Code\"{A.RST}\n")
    _w(f"   {A.WHT}4.{A.RST} Delete all default code, paste the script above\n")
    _w(f"   {A.WHT}5.{A.RST} Click {A.WHT}\"Deploy\"{A.RST} again\n")
    _w(f"   {A.WHT}6.{A.RST} Copy your Worker URL (e.g. {A.GRN}my-proxy.username.workers.dev{A.RST})\n\n")

    _flush_stdin()
    _restore_console_input()
    _w(f" {A.BOLD}{A.CYN}[3/3]{A.RST} {A.YEL}Enter your Worker URL when deployed{A.RST} (or Enter to skip): ")
    _fl()
    try:
        worker_url = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return
    if not worker_url:
        _w(f"\n {A.DIM}Skipped. Deploy the Worker first, then come back.{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    worker_url = worker_url.replace("https://", "").replace("http://", "").rstrip("/")
    _m = re.search(r'[a-zA-Z]', worker_url)
    if _m and _m.start() > 0 and ".workers.dev" in worker_url:
        worker_url = worker_url[_m.start():]

    _w(f"\n   {A.GRN}Worker URL: {worker_url}{A.RST}\n")
    new_parsed = dict(parsed)
    new_parsed["address"] = worker_url
    new_parsed["host"] = worker_url
    new_parsed["sni"] = worker_url
    new_parsed["port"] = 443
    new_parsed["security"] = "tls"
    new_uri = build_vless_uri(new_parsed, worker_url, "Worker-Proxy")

    _w(f"\n {A.BOLD}New config URI:{A.RST}\n")
    _w(f" {A.GRN}{new_uri}{A.RST}\n\n")
    _w(f" {A.BOLD}{A.CYN}How it works:{A.RST}\n")
    _w(f"   {A.DIM}Client -> any CF IP (SNI={worker_url}) -> CF routes to Worker{A.RST}\n")
    _w(f"   {A.DIM}Worker -> Host={origin_host} -> CF routes to original server{A.RST}\n")
    _w(f"   {A.DIM}Result: fresh *.workers.dev SNI instead of original domain!{A.RST}\n\n")

    _w(f" {A.YEL}Run pipeline test with ALL SNIs?{A.RST} [Y/n]: ")
    _fl()
    try:
        ans = input().strip().lower()
    except (EOFError, KeyboardInterrupt, OSError):
        ans = "n"
    if ans in ("", "y", "yes"):
        re_parsed = parse_vless_full(new_uri)
        if re_parsed:
            pcfg = PipelineConfig(
                uri=new_uri, parsed=re_parsed,
                sni_pool=[],
                frag_preset="all",
                transport_variants=[],
                max_expansion=1500,
            )
            xray_bin = xray_find_binary(getattr(args, "xray_bin", None))
            if not xray_bin:
                _w(f" {A.YEL}Xray not found. Installing...{A.RST}\n")
                _fl()
                xray_bin = xray_install()
            if xray_bin:
                xst = XrayTestState()
                xdash = await _run_pipeline_core(xst, pcfg, xray_bin)
                await _post_pipeline_results(xst, xdash, args)
                return
            else:
                _w(f"   {A.RED}Could not find/install xray-core{A.RST}\n")
        else:
            _w(f"   {A.RED}Failed to parse generated URI{A.RST}\n")
    _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
    _fl()
    _read_key_blocking()


def save_csv(st: State, path: str, sort_by: str = "score"):
    results = sorted_alive(st, sort_by)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        hdr = ["Rank", "IP", "Domains", "Domain_Count", "Ping_ms", "Conn_ms", "TTFB_ms"]
        for i, rc in enumerate(st.rounds):
            hdr.append(f"R{i + 1}_{rc.label}_MBps")
        hdr += ["Best_MBps", "Colo", "Score", "Error"]
        w.writerow(hdr)
        for rank, r in enumerate(results, 1):
            row = [
                rank, r.ip,
                "|".join(r.domains[:5]), len(r.domains),
                f"{r.tcp_ms:.1f}" if r.tcp_ms > 0 else "",
                f"{r.tls_ms:.1f}" if r.tls_ms > 0 else "",
                f"{r.ttfb_ms:.1f}" if r.ttfb_ms > 0 else "",
            ]
            for i in range(len(st.rounds)):
                row.append(
                    f"{r.speeds[i]:.3f}"
                    if i < len(r.speeds) and r.speeds[i] > 0
                    else ""
                )
            row += [
                f"{r.best_mbps:.3f}" if r.best_mbps > 0 else "",
                r.colo, f"{r.score:.1f}", r.error,
            ]
            w.writerow(row)


def save_configs(st: State, path: str, top: int = 50, sort_by: str = "score"):
    """Save top configs. Use top=0 for ALL configs sorted best to worst."""
    results = sorted_alive(st, sort_by)
    has_uris = any(r.uris for r in results)
    limit = top if top > 0 else len(results)
    with open(path, "w", encoding="utf-8") as f:
        n = 0
        for r in results:
            if n >= limit:
                break
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
                    n += 1
                    if n >= limit:
                        break
            else:
                doms = ", ".join(r.domains[:3])
                extra = f" (+{len(r.domains) - 3} more)" if len(r.domains) > 3 else ""
                f.write(f"{r.ip}  # score={r.score:.1f} domains={doms}{extra}\n")
                n += 1


def save_all_configs_sorted(st: State, path: str, sort_by: str = "score"):
    """Save ALL raw configs (every URI) sorted by their IP's score, best to worst."""
    results = sorted_alive(st, sort_by)
    dead = [r for r in st.res.values() if not r.alive]
    has_uris = any(r.uris for r in results)
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
            else:
                doms = ", ".join(r.domains[:3])
                extra = f" (+{len(r.domains) - 3} more)" if len(r.domains) > 3 else ""
                f.write(f"{r.ip}  # score={r.score:.1f} domains={doms}{extra}\n")
        for r in dead:
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
            else:
                doms = ", ".join(r.domains[:3])
                f.write(f"{r.ip}  # DEAD domains={doms}\n")


def do_export(st: State, base_path: str, sort_by: str = "score", top: int = 50,
              output_csv: str = "", output_configs: str = ""):
    stem = os.path.basename(base_path).rsplit(".", 1)[0] if base_path else "scan"
    csv_path = output_csv if output_csv else _results_path(stem + "_results.csv")
    if output_configs:
        cfg_path = output_configs
    elif top <= 0:
        cfg_path = _results_path(stem + "_all_sorted.txt")
    else:
        cfg_path = _results_path(stem + f"_top{top}.txt")
    full_path = _results_path(stem + "_full_sorted.txt")
    save_csv(st, csv_path, sort_by)
    save_configs(st, cfg_path, top, sort_by)
    save_all_configs_sorted(st, full_path, sort_by)
    st.saved = True
    return csv_path, cfg_path, full_path


async def _resolve(e: ConfigEntry, sem: asyncio.Semaphore, counter: List[int]) -> ConfigEntry:
    if e.ip:
        counter[0] += 1
        return e
    async with sem:
        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(e.address, 443, family=socket.AF_INET)
            if info:
                e.ip = info[0][4][0]
        except Exception:
            e.ip = ""
        counter[0] += 1
    return e


async def resolve_all(st: State, workers: int = 100):
    sem = asyncio.Semaphore(workers)
    counter = [0]
    total = len(st.configs)

    async def _progress():
        spin = "|/-\\"
        i = 0
        while counter[0] < total:
            s = spin[i % len(spin)]
            pct = counter[0] * 100 // max(1, total)
            _w(f"\r  {A.CYN}{s}{A.RST} Resolving DNS... {counter[0]}/{total}  ({pct}%)  ")
            _fl()
            i += 1
            await asyncio.sleep(0.15)
        _w(f"\r  {A.GRN}OK{A.RST} Resolved {total} domains -> {len(set(c.ip for c in st.configs if c.ip))} unique IPs\n")
        _fl()

    prog_task = asyncio.create_task(_progress())
    try:
        st.configs = list(await asyncio.gather(*[_resolve(c, sem, counter) for c in st.configs]))
    finally:
        prog_task.cancel()
        try:
            await prog_task
        except asyncio.CancelledError:
            pass
    for c in st.configs:
        if c.ip:
            st.ip_map[c.ip].append(c)
    st.ips = list(st.ip_map.keys())
    for ip in st.ips:
        cs = st.ip_map[ip]
        st.res[ip] = Result(
            ip=ip,
            domains=[c.address for c in cs],
            uris=[c.original_uri for c in cs if c.original_uri],
        )


async def run_scan(st: State, workers: int, speed_workers: int, timeout: float, speed_timeout: float):
    try:
        os.makedirs("results", exist_ok=True)
        with open(DEBUG_LOG, "w") as f:
            f.write(f"=== Scan started {time.strftime('%Y-%m-%d %H:%M:%S')} mode={st.mode} ===\n")
    except OSError:
        pass
    st.start_time = time.monotonic()
    # Build IP map from configs
    if not st.ips and st.configs:
        seen = set()
        st.ip_map.clear()
        for c in st.configs:
            ip = (c.ip if c.ip else c.address).strip()
            if not ip:
                continue
            st.ip_map[ip].append(c)
            if ip not in seen:
                seen.add(ip)
                st.ips.append(ip)
                st.res[ip] = Result(ip=ip)
    _dbg(f"=== Built IP map: {len(st.ips)} unique IPs from {len(st.configs)} configs ===")
    if not st.interrupted:
        await phase1(st, workers, timeout)
    if st.interrupted or st.alive_n == 0:
        st.finished = True
        calc_scores(st)
        return
    preset = PRESETS.get(st.mode, PRESETS["normal"])
    alive = sorted(
        (ip for ip, r in st.res.items() if r.alive),
        key=lambda ip: st.res[ip].tls_ms,
    )
    cut_pct = preset.get("latency_cut", 0)
    if cut_pct > 0 and len(alive) > 50:
        cut_n = max(1, int(len(alive) * cut_pct / 100))
        alive = alive[:-cut_n]
        st.latency_cut_n = cut_n
        _dbg(f"=== Latency cut: removed bottom {cut_pct}% = {cut_n} IPs, {len(alive)} remaining ===")
    if not st.rounds:
        st.rounds = build_dynamic_rounds(st.mode, len(alive))
        _dbg(f"=== Dynamic rounds: {[(r.label, r.keep) for r in st.rounds]} ===")
    if not st.interrupted and st.rounds:
        rlim = CFRateLimiter()
        cands = list(alive)
        cdn_host = SPEED_HOST
        cdn_path = ""
        for i, rc in enumerate(st.rounds):
            if st.interrupted:
                break
            st.cur_round = i + 1
            st.phase = f"speed_r{i + 1}"
            actual_count = min(rc.keep, len(cands))
            st.phase_label = f"Speed R{i + 1} ({rc.label} x {actual_count})"
            _dbg(f"=== Round R{i+1}: {rc.size}B x {actual_count} IPs, workers={speed_workers}, timeout={speed_timeout}s, budget={rlim.BUDGET - rlim.count} left ===")
            if i > 0:
                calc_scores(st)
                cands = sorted(cands, key=lambda ip: st.res[ip].score, reverse=True)
            cands = cands[:rc.keep]
            await phase2_round(st, rc, cands, speed_workers, speed_timeout,
                               rlim=rlim, cdn_host=cdn_host, cdn_path=cdn_path)
            calc_scores(st)
    st.finished = True
    calc_scores(st)


async def run_tui(args, deploy_mode=False):
    enable_ansi()
    input_method = None
    input_value = None
    if deploy_mode:
        input_method, input_value = "deploy", ""
    if getattr(args, "sub", None):
        input_method, input_value = "sub", args.sub
    elif getattr(args, "template", None):
        if getattr(args, "input", None):
            input_method, input_value = "template", f"{args.template}|||{args.input}"
        else:
            print("Error: --template requires -i (address list file)")
            return
    elif getattr(args, "find_clean", False):
        input_method, input_value = "find_clean", ""
    elif getattr(args, "input", None):
        input_method, input_value = "file", args.input
    while True:
        interactive = input_method is None
        while True:
            if input_method is None:
                pick = tui_pick_file()
                if not pick:
                    _w(A.SHOW)
                    return
                input_method, input_value = pick
            if input_method == "pipeline":
                await _tui_run_pipeline(args, cli_uri=input_value or "")
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return
            if input_method == "deploy":
                await _tui_run_deploy(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return
            if input_method == "worker_proxy":
                await _tui_worker_proxy(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return
            if input_method == "connection_manager":
                await _tui_connection_manager(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return
            if input_method == "find_clean":
                result = await tui_run_clean_finder()
                if result is None:
                    _w(A.SHOW)
                    return
                if result[0] == "__back__":
                    input_method = None
                    input_value = None
                    continue
                input_method, input_value = result
            mode = args.mode
            if not getattr(args, "_mode_set", False) and interactive:
                picked = tui_pick_mode()
                if not picked:
                    _w(A.SHOW)
                    return
                if picked == "__back__":
                    input_method = None
                    input_value = None
                    continue
                mode = picked
            break
        st = State()
        st.mode = mode
        st.top = args.top
        if args.rounds:
            st.rounds = parse_rounds_str(args.rounds)
        elif args.skip_download:
            st.rounds = []
        if input_method == "sub":
            load_label = input_value.split("/")[-1][:40] or "subscription"
        elif input_method == "template":
            parts = input_value.split("|||", 1)
            load_label = os.path.basename(parts[1]) if len(parts) > 1 else "template"
        else:
            load_label = os.path.basename(input_value)
        _w(A.CLR + A.HOME)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Starting scan...{A.RST}", cols))
        lines.append(draw_box_line("", cols))
        lines.append(draw_box_line(f" {A.CYN}>{A.RST} Loading {load_label}...", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()
        if input_method == "sub":
            st.configs = fetch_sub(input_value)
            st.input_file = input_value
        elif input_method == "template":
            parts = input_value.split("|||", 1)
            template_uri = parts[0]
            addrs = load_addresses(parts[1])
            st.configs = generate_from_template(template_uri, addrs)
            st.input_file = parts[1]
        elif input_method == "file":
            st.configs = load_input(input_value)
            st.input_file = input_value
        elif input_method == "find_clean":
            st.configs = []
            st.input_file = ""
        if not st.configs and input_method not in ("find_clean",):
            _w(f"\n {A.RED}No configs loaded.{A.RST}\n")
            _w(f" {A.DIM}Press any key...{A.RST}\n")
            _fl()
            _read_key_blocking()
            input_method = None
            input_value = None
            continue
        st.phase = "dns"
        st.phase_label = "Resolving DNS"
        try:
            await resolve_all(st)
        except Exception as e:
            _w(A.SHOW + "\n")
            print(f"DNS resolution error: {e}")
            return
        if not st.ips:
            _w(A.SHOW + "\n")
            print("No IPs resolved — check network or config addresses.")
            return
        dash = Dashboard(st)
        refresh = asyncio.create_task(_refresh_loop(dash, st))
        scan_task = asyncio.ensure_future(
            run_scan(st, args.workers, args.speed_workers,
                     args.timeout, args.speed_timeout))
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
        signal.signal(signal.SIGINT, old_sigint)
        if refresh:
            refresh.cancel()
            try:
                await refresh
            except asyncio.CancelledError:
                pass
        if st.interrupted and not st.finished:
            _w(f"\n {A.YEL}Scan interrupted. Press any key for menu...{A.RST}\n")
            _fl()
            _read_key_blocking()
            input_method = None
            input_value = None
            continue
        csv_p, cfg_p, full_p = do_export(st, input_value, dash.sort, st.top)
        _w(A.CLR + A.HOME + A.SHOW)
        _w(f"\n{A.CYN}{'=' * (cols - 2)}{A.RST}\n")
        _w(f" {A.BOLD}{A.GRN}Scan Complete{A.RST}\n")
        _w(f" {A.CYN}Results saved:{A.RST}\n")
        _w(f"   {A.WHT}CSV:{A.RST} {csv_p}\n")
        _w(f"   {A.WHT}Configs:{A.RST} {cfg_p}\n")
        _w(f"   {A.WHT}All sorted:{A.RST} {full_p}\n")
        _w(f"{A.CYN}{'=' * (cols - 2)}{A.RST}\n\n")
        _w(f" {A.YEL}What next?{A.RST}\n")
        _w(f"   {A.WHT}[1]{A.RST} Start new scan\n")
        _w(f"   {A.WHT}[2]{A.RST} View help\n")
        _w(f"   {A.WHT}[3]{A.RST} Deploy to VPS\n")
        _w(f"   {A.WHT}[4]{A.RST} Worker proxy\n")
        _w(f"   {A.WHT}[5]{A.RST} Connection manager\n")
        _w(f"   {A.WHT}[6]{A.RST} Clean IP finder\n")
        _w(f"   {A.WHT}[7]{A.RST} Export settings\n")
        _w(f"   {A.WHT}[q]{A.RST} Quit\n\n")
        _w(f" {A.BOLD}Choice: {A.RST}")
        _fl()
        _restore_console_input()
        try:
            ch = input().strip().lower()
        except (EOFError, KeyboardInterrupt, OSError):
            ch = "q"
        if ch == "1":
            input_method = None
            input_value = None
        elif ch == "2":
            tui_show_guide()
            input_method = None
            input_value = None
        elif ch == "3":
            await _tui_run_deploy(args)
            input_method = None
            input_value = None
        elif ch == "4":
            await _tui_worker_proxy(args)
            input_method = None
            input_value = None
        elif ch == "5":
            await _tui_connection_manager(args)
            input_method = None
            input_value = None
        elif ch == "6":
            result = await tui_run_clean_finder()
            if result and result[0] != "__back__":
                input_method, input_value = result
            else:
                input_method = None
                input_value = None
        elif ch == "7":
            _flush_stdin()
            _restore_console_input()
            _w(f"\n {A.BOLD}Sort by (score/latency/speed) [{dash.sort}]: {A.RST}")
            _fl()
            try:
                inp = input().strip().lower()
                if inp in ("score", "latency", "speed"):
                    dash.sort = inp
                else:
                    _w(f" {A.DIM}Keeping: {dash.sort}{A.RST}\n")
            except (EOFError, KeyboardInterrupt, OSError):
                pass
            _w(f" {A.BOLD}Top N [{st.top}]: {A.RST}")
            _fl()
            try:
                inp = input().strip()
                if inp:
                    try:
                        st.top = max(1, int(inp))
                    except ValueError:
                        pass
            except (EOFError, KeyboardInterrupt, OSError):
                pass
            csv_p, cfg_p, full_p = do_export(st, input_value, dash.sort, st.top)
            _w(f"\n {A.GRN}Exported: {cfg_p}{A.RST}\n")
            _w(f" {A.DIM}Press any key...{A.RST}\n")
            _fl()
            _read_key_blocking()
            input_method = None
            input_value = None
        else:
            break


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
    print(f"Mode: {st.mode}, Latency workers: {args.workers}, Speed workers: {args.speed_workers}")
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
        csv_p, cfg_p, full_p = do_export(st, source, top=st.top)
        print(f"\nResults saved to:")
        print(f"  CSV:     {csv_p}")
        print(f"  Configs: {cfg_p}")
        print(f"  All:     {full_p}")
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
        subnets = list(_CF_NETS)
    cf_ips = generate_cf_ips(subnets, args.clean_scan_per_24)
    print(f"Testing {len(cf_ips)} IPs across {len(subnets)} subnets in {mode} mode")
    results = await scan_clean_ips(cf_ips, mode, args.clean_ports, args.clean_workers)
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
        description="CF Config Scanner v1.1 - Test VLESS/VMess proxy configs",
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
""")
    parser.add_argument("-i", "--input", help="Config file (txt/json/conf/lst)")
    parser.add_argument("--sub", help="Subscription URL")
    parser.add_argument("--template", help="VLESS config template URI")
    parser.add_argument("-m", "--mode", default="normal",
                        choices=["normal", "fast", "mega", "xtreme"],
                        help="Scan mode (default: normal)")
    parser.add_argument("-w", "--workers", type=int, default=LATENCY_WORKERS,
                        help=f"Latency test workers (default: {LATENCY_WORKERS})")
    parser.add_argument("-s", "--speed-workers", type=int, default=SPEED_WORKERS,
                        help=f"Speed test workers (default: {SPEED_WORKERS})")
    parser.add_argument("-t", "--timeout", type=float, default=LATENCY_TIMEOUT,
                        help=f"Latency timeout seconds (default: {LATENCY_TIMEOUT})")
    parser.add_argument("--speed-timeout", type=float, default=SPEED_TIMEOUT,
                        help=f"Speed test timeout seconds (default: {SPEED_TIMEOUT})")
    parser.add_argument("--top", type=int, default=50,
                        help="Top N configs to save (default: 50, 0=all)")
    parser.add_argument("--rounds", help="Custom round sizes: 2M:100%%|1M:50%%|100K:keep")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip speed test, latency only")
    parser.add_argument("--no-tui", action="store_true",
                        help="Non-interactive mode")
    parser.add_argument("--find-clean", action="store_true",
                        help="Scan for clean Cloudflare IPs")
    parser.add_argument("--clean-mode", default="normal",
                        choices=list(CLEAN_MODES.keys()),
                        help="Clean IP scan mode")
    parser.add_argument("--clean-ports", nargs="*", type=int, default=CF_HTTPS_PORTS,
                        help="Ports for clean scan (default: 443 8443)")
    parser.add_argument("--clean-workers", type=int, default=500,
                        help="Workers for clean scan (default: 500)")
    parser.add_argument("--clean-scan-per-24", type=int, default=0,
                        help="Random IPs per /24 subnet (0=all)")
    parser.add_argument("--subnets", nargs="*",
                        help="Subnets for clean scan (default: all CF ranges)")
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
        asyncio.run(run_tui(args, deploy_mode))


if __name__ == "__main__":
    main()
