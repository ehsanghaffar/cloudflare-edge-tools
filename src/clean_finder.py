import asyncio
import ipaddress
import random
import re
import ssl
import time
from typing import List, Optional, Tuple

from src.constants import CF_SUBNETS, SPEED_HOST, _is_cf_address
from src.models import CleanScanState
from src.utils import _dbg


def split_to_24_blocks(subnets: List[str]) -> list:
    """Split CIDR subnets into /24 blocks, deduplicate."""
    seen = set()
    blocks = []
    for sub in subnets:
        try:
            net = ipaddress.IPv4Network(sub.strip(), strict=False)
            if net.prefixlen <= 24:
                for block in net.subnets(new_prefix=24):
                    key = int(block.network_address)
                    if key not in seen:
                        seen.add(key)
                        blocks.append(block)
            else:
                key = int(net.network_address)
                if key not in seen:
                    seen.add(key)
                    blocks.append(net)
        except (ValueError, TypeError):
            continue
    return blocks


def generate_cf_ips(subnets: List[str], sample_per_24: int = 0) -> List[str]:
    """Generate IPs from CIDR subnets. sample_per_24=0 means all hosts."""
    blocks = split_to_24_blocks(subnets)
    random.shuffle(blocks)
    ips = []
    for net in blocks:
        hosts = [str(ip) for ip in net.hosts()]
        if sample_per_24 > 0 and sample_per_24 < len(hosts):
            hosts = random.sample(hosts, sample_per_24)
        ips.extend(hosts)
    return ips


async def probe_tls_handshake(
    ip: str, sni: str, timeout: float, validate: bool = True, port: int = 443,
) -> Tuple[float, bool, str]:
    """TLS probe with optional Cloudflare header validation.
    Returns (latency_ms, is_cloudflare, error)."""
    w = None
    cf_err = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        tls_ms = (time.monotonic() - t0) * 1000

        is_cf = True
        htxt = ""
        if validate:
            is_cf = False
            try:
                safe_sni = sni.replace("\r", "").replace("\n", "")
                req = f"GET / HTTP/1.1\r\nHost: {safe_sni}\r\nConnection: close\r\n\r\n"
                w.write(req.encode())
                await w.drain()
                hdr = await asyncio.wait_for(r.read(2048), timeout=min(timeout, 3))
                htxt = hdr.decode("latin-1", errors="replace").lower()
                is_cf = "server: cloudflare" in htxt or "cf-ray:" in htxt
            except OSError:
                pass

        if is_cf:
            status_line = htxt.split("\r\n", 1)[0] if "\r\n" in htxt else ""
            status_match = re.search(r'http/\S+\s+(\d{3})', status_line)
            if status_match:
                status_code = int(status_match.group(1))
                if status_code >= 400:
                    cf_err = f"cf-origin-{status_code}"

        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        w = None
        return tls_ms, is_cf, cf_err
    except asyncio.TimeoutError:
        return -1, False, "timeout"
    except OSError as e:
        return -1, False, str(e)[:40]
    finally:
        if w:
            try:
                w.close()
            except OSError:
                pass


async def scan_clean_ips(
    ips: List[str],
    sni: str = SPEED_HOST,
    workers: int = 500,
    timeout: float = 3.0,
    validate: bool = True,
    scan_state: Optional[CleanScanState] = None,
    ports: Optional[List[int]] = None,
) -> List[Tuple[str, float]]:
    """Scan IPs for TLS + optional CF validation. Returns [(addr, latency_ms)] sorted.
    addr is 'ip' for port 443, or 'ip:port' for other ports."""
    if ports is None:
        ports = [443]
    sem = asyncio.Semaphore(workers)
    results: List[Tuple[str, float]] = []
    lock = asyncio.Lock()

    total_probes = len(ips) * len(ports)
    if scan_state:
        scan_state.total = total_probes
        scan_state.done = 0
        scan_state.found = 0
        scan_state.start_time = time.monotonic()

    async def probe(ip: str, port: int):
        if scan_state and scan_state.interrupted:
            return
        async with sem:
            if scan_state and scan_state.interrupted:
                return
            lat, is_cf, _err = await probe_tls_handshake(ip, sni, timeout, validate, port)
            if lat > 0 and is_cf:
                addr = ip if port == 443 else f"{ip}:{port}"
                async with lock:
                    results.append((addr, lat))
                    if scan_state:
                        scan_state.found += 1
                        scan_state.all_results = results  # full reference for Ctrl+C recovery
                        if scan_state.found % 10 == 0 or scan_state.found <= 20:
                            scan_state.results = sorted(results, key=lambda x: x[1])[:20]
            if scan_state:
                scan_state.done += 1

    # Build flat list of (ip, port) pairs
    probes = [(ip, p) for ip in ips for p in ports]
    random.shuffle(probes)  # spread ports across batches for better coverage

    BATCH = 50_000
    for i in range(0, len(probes), BATCH):
        if scan_state and scan_state.interrupted:
            break
        batch = probes[i : i + BATCH]
        tasks = [asyncio.ensure_future(probe(ip, port)) for ip, port in batch]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            break
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

    results.sort(key=lambda x: x[1])
    return results
