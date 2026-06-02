import asyncio
import ssl
import statistics
import time
from typing import List, Optional, Tuple

from src.constants import CDN_FALLBACK, SPEED_HOST, SPEED_PATH
from src.models import RoundCfg, State
from src.rate_limiter import CFRateLimiter
from src.utils import _dbg


async def _lat_one(ip: str, sni: str, timeout: float) -> Tuple[float, float, str]:
    try:
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, 443), timeout=timeout
        )
        tcp = (time.monotonic() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
    except asyncio.TimeoutError:
        return -1, -1, "tcp-timeout"
    except (OSError, asyncio.TimeoutError) as e:
        return -1, -1, f"tcp:{str(e)[:50]}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        tls_full = (time.monotonic() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        return tcp, tls_full, ""
    except asyncio.TimeoutError:
        return tcp, -1, "tls-timeout"
    except (OSError, ssl.SSLError) as e:
        return tcp, -1, f"tls:{str(e)[:50]}"


async def phase1(st: State, workers: int, timeout: float):
    st.phase = "latency"
    st.phase_label = "Testing latency"
    st.total = len(st.ips)
    st.done_count = 0
    sem = asyncio.Semaphore(workers)

    async def go(ip: str):
        async with sem:
            if st.interrupted:
                return
            res = st.res[ip]
            tcp, tls, err = await _lat_one(ip, SPEED_HOST, timeout)
            res.tcp_ms = tcp
            res.tls_ms = tls
            res.error = err
            res.alive = tls > 0
            st.done_count += 1
            if res.alive:
                st.alive_n += 1
            else:
                st.dead_n += 1

    tasks = [asyncio.ensure_future(go(ip)) for ip in st.ips]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


async def _dl_one(
    ip: str, size: int, timeout: float,
    host: str = "", path: str = "",
) -> Tuple[float, float, int, str, str]:
    if not host:
        host = SPEED_HOST
    if not path:
        path = f"{SPEED_PATH}?bytes={size}"

    dl_timeout = max(timeout, 30 + (size / 1_000_000) * 2)
    conn_timeout = min(timeout, 15)

    w = None
    total = 0
    dl_start = 0.0
    ttfb = 0.0
    colo = ""

    def _cleanup():
        nonlocal w
        if w is not None:
            try:
                w.close()
            except OSError:
                pass
            w = None

    try:
        ctx = ssl.create_default_context()
        t_start = time.monotonic()
        try:
            t0 = t_start
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=host),
                timeout=conn_timeout,
            )
        except ssl.SSLCertVerificationError:
            _cleanup()
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            t0 = time.monotonic()
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, 443, ssl=ctx2, server_hostname=host
                ),
                timeout=conn_timeout,
            )
        conn_ms = (time.monotonic() - t0) * 1000

        range_hdr = ""
        if "bytes=" not in path:
            range_hdr = f"Range: bytes=0-{size - 1}\r\n"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120\r\n"
            f"Accept: */*\r\n"
            f"{range_hdr}"
            f"Connection: close\r\n\r\n"
        )
        w.write(req.encode())
        await w.drain()

        hbuf = b""
        while b"\r\n\r\n" not in hbuf:
            ch = await asyncio.wait_for(r.read(4096), timeout=min(conn_timeout, 10))
            if not ch:
                _dbg(f"DL {ip} {size}: empty response (no headers)")
                return -1, 0, 0, "", "empty"
            hbuf += ch
            if len(hbuf) > 65536:
                _dbg(f"DL {ip} {size}: header too big")
                return -1, 0, 0, "", "hdr-too-big"

        sep = hbuf.index(b"\r\n\r\n") + 4
        htxt = hbuf[:sep].decode("latin-1", errors="replace")
        body0 = hbuf[sep:]

        status_line = htxt.split("\r\n")[0]
        status_parts = status_line.split(None, 2)
        status_code = status_parts[1] if len(status_parts) >= 2 else ""
        if status_code == "429":
            ra = ""
            for line in htxt.split("\r\n"):
                if line.lower().startswith("retry-after:"):
                    ra = line.split(":", 1)[1].strip()
                    break
            _dbg(f"DL {ip} {size}: 429 rate-limited (retry-after={ra})")
            return -1, 0, 0, "", f"429:{ra}"
        if status_code not in ("200", "206"):
            _dbg(f"DL {ip} {size}: HTTP error: {status_line[:80]}")
            return -1, 0, 0, "", f"http:{status_line[:40]}"

        for line in htxt.split("\r\n"):
            if line.lower().startswith("cf-ray:"):
                ray = line.split(":", 1)[1].strip()
                if "-" in ray:
                    colo = ray.rsplit("-", 1)[-1]
                break

        ttfb = (time.monotonic() - t0) * 1000 - conn_ms
        dl_start = time.monotonic()
        total = len(body0)

        sample_interval = 1_000_000 if size >= 5_000_000 else size + 1
        next_sample = sample_interval
        samples: List[Tuple[int, float]] = []

        min_for_stable = min(size // 2, 20_000_000) if size >= 5_000_000 else size
        min_samples = 5 if size >= 10_000_000 else 3

        while True:
            try:
                elapsed_total = time.monotonic() - t_start
                left = max(1.0, dl_timeout - elapsed_total)
                ch = await asyncio.wait_for(r.read(65536), timeout=min(left, 10))
                if not ch:
                    break
                total += len(ch)
                if total >= next_sample:
                    elapsed = time.monotonic() - dl_start
                    samples.append((total, elapsed))
                    next_sample += sample_interval
                    if len(samples) >= min_samples and total >= min_for_stable:
                        recent = samples[-4:]
                        sp = []
                        for j in range(1, len(recent)):
                            db = recent[j][0] - recent[j - 1][0]
                            dt = recent[j][1] - recent[j - 1][1]
                            if dt > 0:
                                sp.append(db / dt)
                        if len(sp) >= 2:
                            mn = statistics.mean(sp)
                            if mn > 0:
                                try:
                                    sd = statistics.stdev(sp)
                                    if sd / mn < 0.10:
                                        break
                                except statistics.StatisticsError:
                                    pass
            except asyncio.TimeoutError:
                break
            except (OSError, ssl.SSLError):
                break

        dl_t = time.monotonic() - dl_start
        mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
        _dbg(f"DL {ip} {size}: OK {mbps:.2f}MB/s total={total} dt={dl_t:.1f}s host={host}")
        return ttfb, mbps, total, colo, ""

    except asyncio.TimeoutError:
        if total > 0 and dl_start > 0:
            dl_t = time.monotonic() - dl_start
            mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
            _dbg(f"DL {ip} {size}: TIMEOUT partial={total}B mbps={mbps:.2f} dt={dl_t:.1f}s")
            if mbps > 0:
                return ttfb, mbps, total, colo, ""
        _dbg(f"DL {ip} {size}: TIMEOUT no data total={total}")
        return -1, 0, 0, "", "timeout"
    except Exception as e:
        if total > 0 and dl_start > 0:
            dl_t = time.monotonic() - dl_start
            mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
            _dbg(f"DL {ip} {size}: ERR partial={total}B mbps={mbps:.2f} err={e}")
            if mbps > 0:
                return ttfb, mbps, total, colo, ""
        _dbg(f"DL {ip} {size}: ERR no data err={e}")
        return -1, 0, 0, "", str(e)[:60]
    finally:
        _cleanup()


async def phase2_round(
    st: State,
    rcfg: RoundCfg,
    candidates: List[str],
    workers: int,
    timeout: float,
    rlim: Optional[CFRateLimiter] = None,
    cdn_host: str = "",
    cdn_path: str = "",
):
    st.total = len(candidates)
    st.done_count = 0
    if rcfg.size >= 50_000_000:
        workers = min(workers, 6)
    elif rcfg.size >= 10_000_000:
        workers = min(workers, 8)
    sem = asyncio.Semaphore(workers)

    max_retries = 2

    async def go(ip: str):
        best_mbps_this = 0.0
        best_ttfb = -1.0
        best_colo = ""
        last_err = ""
        force_cdn = False

        for attempt in range(max_retries):
            if st.interrupted:
                break

            use_host = cdn_host
            use_path = cdn_path
            if force_cdn and CDN_FALLBACK:
                use_host, use_path = CDN_FALLBACK
                _dbg(f"DL {ip}: forced fallback CDN {use_host}")
            elif rlim and rlim.would_block() and CDN_FALLBACK:
                use_host, use_path = CDN_FALLBACK
                _dbg(f"DL {ip}: using fallback CDN {use_host}")
            elif rlim:
                await rlim.acquire(st)

            await sem.acquire()
            try:
                if st.interrupted:
                    break
                ttfb, mbps, _total, colo, err = await _dl_one(
                    ip, rcfg.size, timeout, use_host, use_path
                )
            finally:
                sem.release()

            if err == "429" or err.startswith("429:"):
                ra = 0
                if ":" in err:
                    try:
                        ra = int(err.split(":", 1)[1])
                    except (ValueError, IndexError):
                        ra = 60
                if rlim:
                    rlim.report_429(ra)
                if CDN_FALLBACK:
                    force_cdn = True
                    _dbg(f"DL {ip}: retrying with CDN fallback (attempt {attempt + 1})")
                    continue
                last_err = "429"
                break
            elif err and "timeout" in err and attempt < max_retries - 1:
                last_err = err
                _dbg(f"DL {ip}: retry after {err} (attempt {attempt + 1})")
                continue
            elif err:
                last_err = err
                break
            else:
                if mbps > best_mbps_this:
                    best_mbps_this = mbps
                    best_ttfb = ttfb
                    best_colo = colo
                break

        res = st.res[ip]
        if best_mbps_this > 0:
            res.ttfb_ms = best_ttfb if best_ttfb > 0 else res.ttfb_ms
            res.best_mbps = max(res.best_mbps, best_mbps_this)
            res.colo = best_colo or res.colo
            res.error = ""
            res.speeds.append(best_mbps_this)
            st.best_speed = max(st.best_speed, best_mbps_this)
        else:
            if not res.error:
                res.error = last_err or "dl-failed"

        st.done_count += 1

    tasks = [asyncio.ensure_future(go(ip)) for ip in candidates]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
