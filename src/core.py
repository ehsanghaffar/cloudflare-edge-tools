import asyncio
import csv
import json
import os
import socket
import time
from typing import List, Tuple, Optional

from src.constants import (
    DEBUG_LOG,
    PRESETS,
    SPEED_HOST,
    RESULTS_DIR,
)
from src.models import (
    ConfigEntry,
    Result,
    RoundCfg,
    State,
    XrayTestState,
    calc_scores,
    sorted_alive,
)
from src.rate_limiter import CFRateLimiter
from src.speed_test import phase1, phase2_round
from src.utils import _dbg, _w, _fl, A, _results_path

def build_dynamic_rounds(mode: str, alive_count: int) -> List[RoundCfg]:
    """Build round configs dynamically based on mode and alive IP count."""
    preset = PRESETS.get(mode, PRESETS["normal"])
    if not preset.get("dynamic"):
        return [RoundCfg(1_000_000, alive_count)]
    sizes = preset["round_sizes"]
    percentages = preset["round_pcts"]
    mins = preset["round_min"]
    maxs = preset["round_max"]
    small_set = alive_count <= 50
    rounds = []
    for size, pct, min_keep, max_keep in zip(sizes, percentages, mins, maxs):
        if small_set:
            keep = alive_count
        else:
            keep = int(alive_count * pct / 100) if pct < 100 else alive_count
            if min_keep > 0:
                keep = max(min_keep, keep)
            if max_keep > 0:
                keep = min(max_keep, keep)
        keep = min(keep, alive_count)
        if keep > 0:
            rounds.append(RoundCfg(size, keep))
    return rounds


async def _resolve(
    entry: ConfigEntry, semaphore: asyncio.Semaphore, counter: List[int], st: State
) -> ConfigEntry:
    if st.interrupted:
        return entry
    if entry.ip:
        counter[0] += 1
        return entry
    async with semaphore:
        if st.interrupted:
            return entry
        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(entry.address, 443, family=socket.AF_INET)
            if info:
                entry.ip = info[0][4][0]
        except Exception:
            entry.ip = ""
        counter[0] += 1
    return entry


async def resolve_all(st: State, workers: int = 100):
    semaphore = asyncio.Semaphore(workers)
    counter = [0]
    total = len(st.configs)

    async def _progress():
        spin = "|/-\\"
        i = 0
        while counter[0] < total and not st.interrupted:
            s = spin[i % len(spin)]
            pct = counter[0] * 100 // max(1, total)
            _w(
                f"\r  {A.CYN}{s}{A.RST} Resolving DNS... {counter[0]}/{total}  ({pct}%)  "
            )
            _fl()
            i += 1
            await asyncio.sleep(0.15)
        if not st.interrupted:
            _w(
                f"\r  {A.GRN}OK{A.RST} Resolved {total} domains -> {len(set(config.ip for config in st.configs if config.ip))} unique IPs\n"
            )
            _fl()

    prog_task = asyncio.create_task(_progress())
    try:
        st.configs = list(
            await asyncio.gather(
                *[_resolve(config, semaphore, counter, st) for config in st.configs]
            )
        )
    finally:
        prog_task.cancel()
        try:
            await prog_task
        except asyncio.CancelledError:
            pass
    for config in st.configs:
        if config.ip:
            st.ip_map[config.ip].append(config)
    st.ips = list(st.ip_map.keys())
    for ip in st.ips:
        config_entries = st.ip_map[ip]
        st.res[ip] = Result(
            ip=ip,
            domains=[config.address for config in config_entries],
            uris=[
                config.original_uri for config in config_entries if config.original_uri
            ],
        )


async def run_scan(
    st: State, workers: int, speed_workers: int, timeout: float, speed_timeout: float
):
    try:
        os.makedirs("results", exist_ok=True)
        with open(DEBUG_LOG, "w") as f:
            f.write(
                f"=== Scan started {time.strftime('%Y-%m-%d %H:%M:%S')} mode={st.mode} ===\n"
            )
    except OSError:
        pass
    st.start_time = time.monotonic()
    # Build IP map from configs
    if not st.ips and st.configs:
        seen = set()
        st.ip_map.clear()
        for config in st.configs:
            ip = (config.ip if config.ip else config.address).strip()
            if not ip:
                continue
            st.ip_map[ip].append(config)
            if ip not in seen:
                seen.add(ip)
                st.ips.append(ip)
                st.res[ip] = Result(ip=ip)
    _dbg(
        f"=== Built IP map: {len(st.ips)} unique IPs from {len(st.configs)} configs ==="
    )
    if not st.interrupted:
        await phase1(st, workers, timeout)
    if st.interrupted or st.alive_n == 0:
        st.finished = True
        calc_scores(st)
        return
    preset = PRESETS.get(st.mode, PRESETS["normal"])
    alive = sorted(
        (ip for ip, result in st.res.items() if result.alive),
        key=lambda ip: st.res[ip].tls_ms,
    )
    cut_pct = preset.get("latency_cut", 0)
    if cut_pct > 0 and len(alive) > 50:
        cut_n = max(1, int(len(alive) * cut_pct / 100))
        alive = alive[:-cut_n]
        st.latency_cut_n = cut_n
        _dbg(
            f"=== Latency cut: removed bottom {cut_pct}% = {cut_n} IPs, {len(alive)} remaining ==="
        )
    if not st.rounds:
        st.rounds = build_dynamic_rounds(st.mode, len(alive))
        _dbg(f"=== Dynamic rounds: {[(r.label, r.keep) for r in st.rounds]} ===")
    if not st.interrupted and st.rounds:
        rate_limiter = CFRateLimiter()
        candidates = list(alive)
        cdn_host = SPEED_HOST
        cdn_path = ""
        for i, round_cfg in enumerate(st.rounds):
            if st.interrupted:
                break
            st.cur_round = i + 1
            st.phase = f"speed_r{i + 1}"
            actual_count = min(round_cfg.keep, len(candidates))
            st.phase_label = f"Speed R{i + 1} ({round_cfg.label} x {actual_count})"
            _dbg(
                f"=== Round R{i+1}: {round_cfg.size}B x {actual_count} IPs, workers={speed_workers}, timeout={speed_timeout}s, budget={rate_limiter.BUDGET - rate_limiter.count} left ==="
            )
            if i > 0:
                calc_scores(st)
                candidates = sorted(
                    candidates, key=lambda ip: st.res[ip].score, reverse=True
                )
            candidates = candidates[: round_cfg.keep]
            await phase2_round(
                st,
                round_cfg,
                candidates,
                speed_workers,
                speed_timeout,
                rate_limiter=rate_limiter,
                cdn_host=cdn_host,
                cdn_path=cdn_path,
            )
            calc_scores(st)
    st.finished = True
    calc_scores(st)


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
                rank,
                r.ip,
                "|".join(r.domains[:5]),
                len(r.domains),
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
                r.colo,
                f"{r.score:.1f}",
                r.error,
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


def do_export(
    st: State, base_path: str, sort_by: str = "score", top: int = 50,
    output_csv: str = "", output_configs: str = "",
) -> Tuple[str, str, str]:
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


def xray_save_results(xst: XrayTestState, top: int = 10) -> Tuple[str, str]:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    sorted_vars = sorted(
        [v for v in xst.variations if v.alive],
        key=lambda v: v.score,
        reverse=True,
    )

    csv_path = _results_path(f"xray_{ts}_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "Rank",
                "Tag",
                "SNI",
                "Fragment",
                "Connect_ms",
                "TTFB_ms",
                "Speed_MBps",
                "Score",
                "Error",
                "URI",
            ]
        )
        for rank, v in enumerate(sorted_vars, 1):
            frag_s = json.dumps(v.fragment) if v.fragment else ""
            w.writerow(
                [
                    rank,
                    v.tag,
                    v.sni,
                    frag_s,
                    f"{v.connect_ms:.0f}" if v.connect_ms > 0 else "",
                    f"{v.ttfb_ms:.0f}" if v.ttfb_ms > 0 else "",
                    f"{v.speed_mbps:.3f}" if v.speed_mbps > 0 else "",
                    f"{v.score:.1f}",
                    v.error,
                    v.result_uri,
                ]
            )

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
