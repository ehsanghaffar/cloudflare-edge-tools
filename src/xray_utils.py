import asyncio
import base64
import copy
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import zipfile
from typing import Dict, List, Optional, Tuple

from src.constants import (SPEED_HOST, SPEED_PATH, XRAY_BASE_PORT, XRAY_BIN_DIR,
                           XRAY_CONFIG_TEMPLATE, XRAY_CONNECT_TIMEOUT, XRAY_FRAG_PRESETS,
                            XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT,
                             XRAY_TMP_DIR,
                            _CF_PREFLIGHT_IPS, _is_cf_address)
from src.config_parse import parse_vless_full, parse_vmess_full, _infer_orig_sni
from src.models import ( PipelineConfig, XrayTestState, XrayVariation)
from src.rate_limiter import CFRateLimiter
from src.utils import _dbg, _WsFrameParser, _ws_frame_encode


def build_xray_config(parsed: dict, sni: str, fragment: Optional[dict], port: int,
                      address_override: str = "") -> dict:
    """Build a complete Xray JSON config from parsed URI fields."""
    cfg = copy.deepcopy(XRAY_CONFIG_TEMPLATE)
    cfg["inbounds"][0]["port"] = port

    is_vmess = parsed.get("protocol") == "vmess"
    protocol = "vmess" if is_vmess else "vless"
    _addr = address_override or parsed["address"]

    outbound = cfg["outbounds"][0]
    outbound["protocol"] = protocol

    if is_vmess:
        outbound["settings"] = {"vnext": [{
            "address": _addr,
            "port": parsed["port"],
            "users": [{
                "id": parsed["uuid"],
                "alterId": parsed.get("aid", 0),
                "security": parsed.get("scy", "auto"),
            }],
        }]}
    else:
        user = {
            "id": parsed["uuid"],
            "encryption": parsed.get("encryption", "none"),
        }
        flow = parsed.get("flow", "")
        if flow:
            user["flow"] = flow
        outbound["settings"] = {"vnext": [{
            "address": _addr,
            "port": parsed["port"],
            "users": [user],
        }]}

    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "tls")
    host = parsed.get("host") or sni

    stream: dict = {"network": net, "security": sec}

    if sec == "tls":
        tls_cfg: dict = {
            "serverName": sni,
            "allowInsecure": False,
        }
        _fp = parsed.get("fp", "")
        if _fp:
            tls_cfg["fingerprint"] = _fp
        if parsed.get("alpn"):
            tls_cfg["alpn"] = parsed["alpn"].split(",")
        stream["tlsSettings"] = tls_cfg
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": parsed.get("fp", "chrome"),
            "publicKey": parsed.get("pbk", ""),
            "shortId": parsed.get("sid", ""),
            "spiderX": parsed.get("spx", ""),
        }

    if net == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("path", "/"),
            "host": host,
            "headers": {"Host": host},
        }
    elif net == "grpc":
        grpc_cfg: dict = {
            "serviceName": parsed.get("serviceName") or (parsed.get("path", "") if parsed.get("path", "") != "/" else ""),
        }
        if host:
            grpc_cfg["authority"] = host
        stream["grpcSettings"] = grpc_cfg
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "host": [host],
            "path": parsed.get("path", "/"),
        }
    elif net == "tcp":
        htype = parsed.get("headerType", "")
        if htype == "http":
            stream["tcpSettings"] = {"header": {
                "type": "http",
                "request": {
                    "path": [parsed.get("path", "/")],
                    "headers": {"Host": [host]},
                },
            }}
    elif net in ("xhttp", "splithttp"):
        xhttp_cfg = {"path": parsed.get("path", "/xhttp")}
        if host:
            xhttp_cfg["host"] = host
        mode = parsed.get("mode", "auto")
        if mode and mode != "auto":
            xhttp_cfg["mode"] = mode
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = xhttp_cfg

    if fragment:
        sockopt: dict = {
            "dialerProxy": "fragment",
            "tcpKeepAliveIdle": 300,
        }
        if sys.platform == "linux":
            sockopt["mark"] = 255
        stream["sockopt"] = sockopt
        cfg["outbounds"].append({
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {"fragment": fragment},
        })

    outbound["streamSettings"] = stream
    return cfg


def build_vless_uri(parsed: dict, sni: str, tag: str) -> str:
    """Reconstruct a VLESS URI with a specific SNI domain."""
    security = parsed.get("security", "tls")
    params = {
        "type": parsed.get("type", "tcp"),
        "security": security,
        "sni": sni,
    }
    _fp = parsed.get("fp", "")
    if _fp:
        params["fp"] = _fp
    if (parsed.get("type") in ("ws", "h2", "http", "xhttp", "splithttp", "grpc")
            or (parsed.get("type") == "tcp" and parsed.get("headerType") == "http")
            or parsed.get("host")):
        params["host"] = parsed.get("host") or sni
    if parsed.get("path") and parsed["path"] != "/":
        params["path"] = parsed["path"]
    if parsed.get("flow"):
        params["flow"] = parsed["flow"]
    if parsed.get("alpn"):
        params["alpn"] = parsed["alpn"]
    if parsed.get("encryption") and parsed["encryption"] != "none":
        params["encryption"] = parsed["encryption"]
    if parsed.get("pbk"):
        params["pbk"] = parsed["pbk"]
    if parsed.get("sid"):
        params["sid"] = parsed["sid"]
    if parsed.get("spx"):
        params["spx"] = parsed["spx"]
    sn = parsed.get("serviceName") or ""
    if not sn and parsed.get("type") == "grpc":
        sn = parsed.get("path", "")
        if sn == "/":
            sn = ""
    if sn:
        params["serviceName"] = sn
    if parsed.get("headerType") and parsed["headerType"] != "none":
        params["headerType"] = parsed["headerType"]
    if parsed.get("mode") and parsed["mode"] != "auto":
        params["mode"] = parsed["mode"]
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    name = urllib.parse.quote(tag)
    addr = parsed["address"]
    if ":" in addr:
        addr = f"[{addr}]"
    return f"vless://{parsed['uuid']}@{addr}:{parsed['port']}?{qs}#{name}"


def build_vmess_uri(parsed: dict, sni: str, tag: str) -> str:
    """Reconstruct a VMess base64 URI with a specific SNI domain."""
    obj = {
        "v": "2",
        "ps": tag,
        "add": parsed["address"],
        "port": str(parsed["port"]),
        "id": parsed["uuid"],
        "aid": str(parsed.get("aid", 0)),
        "scy": parsed.get("scy", "auto"),
        "net": parsed.get("type", "tcp"),
        "type": parsed.get("headerType") or "none",
        "host": parsed.get("host") or sni,
        "path": parsed.get("path", "/"),
        "tls": "tls" if parsed.get("security", "") == "tls" else "",
        "sni": sni,
        "alpn": parsed.get("alpn", ""),
        "fp": parsed.get("fp", ""),
    }
    if parsed.get("type") in ("xhttp", "splithttp"):
        obj["mode"] = parsed.get("mode", "auto")
    if parsed.get("type") == "grpc":
        obj["path"] = parsed.get("serviceName") or parsed.get("path", "grpc")
    raw = json.dumps(obj, separators=(",", ":"))
    b64 = base64.b64encode(raw.encode()).decode()
    return f"vmess://{b64}"


def _build_uri(parsed: dict, sni: str, tag: str) -> str:
    """Build VLESS or VMess URI based on the protocol field in parsed dict."""
    if parsed.get("protocol") == "vmess":
        return build_vmess_uri(parsed, sni, tag)
    return build_vless_uri(parsed, sni, tag)


def switch_transport(parsed: dict, new_transport: str, path: str = "") -> dict:
    """Clone parsed config and change its transport type."""
    new = copy.deepcopy(parsed)

    # Only carry over path if it looks custom (not a transport default)
    _default_paths = {"/", "/ws", "/xhttp", "/h2", "/grpc", "grpc"}
    old_path = parsed.get("path", "/")
    carry_path = old_path if old_path not in _default_paths else ""

    # XTLS flow (e.g. xtls-rprx-vision) only works with TCP — clear for others
    if new_transport != "tcp" and new.get("flow"):
        new["flow"] = ""

    if new_transport == "ws":
        new["type"] = "ws"
        new["path"] = path or carry_path or "/ws"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
    elif new_transport in ("xhttp", "splithttp"):
        new["type"] = "xhttp"
        new["path"] = path or carry_path or "/xhttp"
        new["mode"] = parsed.get("mode", "auto")
        new["headerType"] = ""
        new.pop("serviceName", None)
    elif new_transport == "grpc":
        new["type"] = "grpc"
        svc = path or parsed.get("serviceName") or "grpc"
        if svc.startswith("/"):
            svc = svc[1:]
        new["serviceName"] = svc
        new["path"] = ""
        new["headerType"] = ""
        new.pop("mode", None)
    elif new_transport in ("h2", "http"):
        new["type"] = "h2"
        new["path"] = path or carry_path or "/h2"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
    elif new_transport == "tcp":
        new["type"] = "tcp"
        new["path"] = "/"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
        # VLESS+REALITY+TCP requires XTLS flow
        if (new.get("security") == "reality"
                and new.get("protocol", "vless") == "vless"
                and not new.get("flow")):
            new["flow"] = "xtls-rprx-vision"
    else:
        return new

    return new


def xray_find_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """Find xray binary. Search order: custom_path > PATH > ~/.cfray/bin/xray."""
    if custom_path and os.path.isfile(custom_path):
        return os.path.abspath(custom_path)
    xray_name = "xray.exe" if sys.platform == "win32" else "xray"
    found = shutil.which(xray_name)
    if found:
        return found
    local_bin = os.path.join(XRAY_BIN_DIR, xray_name)
    if os.path.isfile(local_bin):
        return local_bin
    return None


def xray_install() -> Optional[str]:
    """Download xray-core to ~/.cfray/bin/. Returns binary path or None."""
    os.makedirs(XRAY_BIN_DIR, exist_ok=True)
    machine = _platform.machine().lower()
    if sys.platform == "win32":
        if "aarch64" in machine or "arm64" in machine:
            asset_name = "Xray-windows-arm64-v8a.zip"
        elif "64" in machine or "amd64" in machine:
            asset_name = "Xray-windows-64.zip"
        else:
            asset_name = "Xray-windows-32.zip"
    elif sys.platform == "darwin":
        if "arm" in machine or "aarch64" in machine:
            asset_name = "Xray-macos-arm64-v8a.zip"
        else:
            asset_name = "Xray-macos-64.zip"
    else:
        if "aarch64" in machine or "arm64" in machine:
            asset_name = "Xray-linux-arm64-v8a.zip"
        elif "arm" in machine:
            asset_name = "Xray-linux-arm32-v7a.zip"
        else:
            asset_name = "Xray-linux-64.zip"

    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset_name}"
    zip_path = os.path.join(XRAY_BIN_DIR, asset_name)

    print(f"  Downloading {asset_name}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except (OSError, ValueError, http.client.HTTPException) as e:
        print(f"  Download failed: {e}")
        try:
            os.remove(zip_path)
        except OSError:
            pass
        return None

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            real_base = os.path.realpath(XRAY_BIN_DIR)
            for info in zf.infolist():
                target = os.path.realpath(os.path.join(XRAY_BIN_DIR, info.filename))
                if target != real_base and not target.startswith(real_base + os.sep):
                    print(f"  Bad zip entry (path traversal): {info.filename}")
                    return None
            zf.extractall(XRAY_BIN_DIR)
    except (zipfile.BadZipFile, OSError) as e:
        print(f"  Extract failed: {e}")
        return None
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass

    xray_name = "xray.exe" if sys.platform == "win32" else "xray"
    bin_path = os.path.join(XRAY_BIN_DIR, xray_name)
    if sys.platform != "win32":
        try:
            os.chmod(bin_path, 0o755)
        except OSError:
            pass
    if os.path.isfile(bin_path):
        print(f"  Installed to {bin_path}")
        return bin_path
    return None


def _find_free_ports(base: int, count: int) -> List[int]:
    """Find `count` free TCP ports starting from `base`."""
    ports: List[int] = []
    port = base
    while len(ports) < count and port <= 65535:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            ports.append(port)
        except OSError:
            pass
        finally:
            s.close()
        port += 1
    return ports


class XrayProcess:
    """Manages a single xray-core subprocess."""

    def __init__(self, binary: str, config_path: str, socks_port: int):
        self.binary = binary
        self.config_path = config_path
        self.socks_port = socks_port
        self.proc: Optional[subprocess.Popen] = None
        self.last_error: str = ""

    def _read_stderr_file(self):
        """Read last error from stderr temp file (tail)."""
        try:
            p = self.config_path + ".err"
            if not os.path.isfile(p):
                self.last_error = "no-stderr-file"
                return
            sz = os.path.getsize(p)
            if sz == 0:
                self.last_error = "xray-stderr-empty"
                return
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                # Read last 32KB to capture debug-level output
                if sz > 32768:
                    f.seek(sz - 32768)
                    f.readline()  # skip partial first line
                lines = f.read().strip().splitlines()
            if not lines:
                self.last_error = f"xray-stderr-{sz}B-no-lines"
                return
            # Search backward for meaningful error lines
            for line in reversed(lines):
                lo = line.lower()
                if any(kw in lo for kw in (
                    "error", "fail", "reject", "refused", "timeout",
                    "closed", "reset", "eof", "tls:", "dial",
                    "handshake", "certificate", "invalid")):
                    self.last_error = line.strip()[-120:]
                    return
            # No keyword match — show last non-empty line + file stats
            self.last_error = f"[{sz}B/{len(lines)}L] {lines[-1].strip()[-80:]}"
        except OSError:
            pass

    def start(self) -> bool:
        """Start xray process. Returns True if SOCKS5 port becomes reachable."""
        err_path = self.config_path + ".err"
        try:
            err_fd = os.open(err_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            kwargs: dict = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": err_fd,
            }
            if sys.platform == "win32":
                kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
            self.proc = subprocess.Popen(
                [self.binary, "run", "-c", self.config_path],
                **kwargs,
            )
            os.close(err_fd)
        except (OSError, ValueError, subprocess.SubprocessError):
            try:
                os.close(err_fd)
            except (OSError, UnboundLocalError):
                pass
            return False

        deadline = time.monotonic() + XRAY_CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self._read_stderr_file()
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", self.socks_port))
                s.close()
                return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                s.close()
                time.sleep(0.3)
        self._read_stderr_file()
        self.stop()
        return False

    def stop(self):
        """Terminate xray process and cleanup."""
        if self.proc:
            self._read_stderr_file()
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            self.proc = None

    def cleanup(self):
        """Remove temp config and stderr files."""
        for p in (self.config_path, self.config_path + ".err"):
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass


def _xray_speed_test_blocking(
    socks_port: int, size: int, timeout: float,
) -> Tuple[float, float, float, str]:
    """Blocking SOCKS5 + TLS + HTTP download. Returns (connect_ms, ttfb_ms, speed_mbps, error)."""
    sock = None
    tls_sock = None
    try:
        t0 = time.monotonic()

        # 1) Connect to SOCKS5 proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", socks_port))

        def _recv_exact(s, n):
            """Receive exactly n bytes from socket."""
            buf = bytearray()
            while len(buf) < n:
                chunk = s.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("connection closed during recv")
                buf.extend(chunk)
            return bytes(buf)

        # SOCKS5 handshake (no auth)
        sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp != b"\x05\x00":
            return -1, -1, 0, f"socks5-auth:{resp.hex()}"

        # SOCKS5 CONNECT to speed.cloudflare.com:443
        host = SPEED_HOST.encode("ascii")
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big")
        sock.sendall(req)
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            return -1, -1, 0, f"socks5-connect:{head[1]}"
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            dlen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, dlen + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return -1, -1, 0, f"socks5-bad-atyp:{atyp}"

        # 2) TLS upgrade
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=SPEED_HOST)
        sock = None  # tls_sock now owns the socket
        connect_ms = (time.monotonic() - t0) * 1000

        # 3) HTTP request
        http_req = (
            f"GET {SPEED_PATH}?bytes={size} HTTP/1.0\r\n"
            f"Host: {SPEED_HOST}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode()
        tls_sock.sendall(http_req)

        # Read headers
        hbuf = b""
        hdr_deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in hbuf:
            if time.monotonic() > hdr_deadline:
                return connect_ms, -1, 0, "hdr-timeout"
            ch = tls_sock.recv(4096)
            if not ch:
                return connect_ms, -1, 0, "empty-headers"
            hbuf += ch
            if len(hbuf) > 65536:
                return connect_ms, -1, 0, "hdr-too-big"

        sep_idx = hbuf.index(b"\r\n\r\n") + 4
        htxt = hbuf[:sep_idx].decode("latin-1", errors="replace")
        body0 = hbuf[sep_idx:]

        status_parts = htxt.split("\r\n")[0].split(None, 2)
        status_code = status_parts[1] if len(status_parts) >= 2 else ""
        if status_code not in ("200", "206"):
            return connect_ms, -1, 0, f"http:{status_code}"

        ttfb_ms = (time.monotonic() - t0) * 1000 - connect_ms

        # 4) Download body (seed with body bytes already in header buffer)
        dl_start = time.monotonic()
        dl_deadline = dl_start + timeout
        total = len(body0)
        while True:
            try:
                if time.monotonic() > dl_deadline:
                    break
                ch = tls_sock.recv(65536)
                if not ch:
                    break
                total += len(ch)
            except socket.timeout:
                break
            except ssl.SSLWantReadError:
                continue
            except (OSError, ssl.SSLError):
                break

        dl_t = time.monotonic() - dl_start
        if total < min(size * 0.05, 4096):
            return connect_ms, ttfb_ms, 0, f"incomplete:{total}"
        mbps = (total / 1_000_000) / dl_t if dl_t > 0.001 else 0
        return connect_ms, ttfb_ms, mbps, ""

    except socket.timeout:
        return -1, -1, 0, "timeout"
    except (OSError, ssl.SSLError) as e:
        return -1, -1, 0, str(e)[:60]
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except OSError:
                pass
        if sock:
            try:
                sock.close()
            except OSError:
                pass


async def xray_speed_test(
    socks_port: int, size: int, timeout: float,
) -> Tuple[float, float, float, str]:
    """Async wrapper: runs blocking SOCKS5 speed test in executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _xray_speed_test_blocking, socks_port, size, timeout,
    )


def _extract_vless_ws_params(config_json: dict) -> Optional[dict]:
    """Extract VLESS-over-WS params from xray config JSON.

    Returns dict with ip, port, uuid, sni, host, path, security -- or None
    if this config is not a VLESS+WS combination.
    """
    outbounds = config_json.get("outbounds", [])
    if not outbounds:
        return None
    out = outbounds[0]
    if out.get("protocol") != "vless":
        return None
    stream = out.get("streamSettings", {})
    if stream.get("network") not in ("ws", "websocket"):
        return None
    vnext = out.get("settings", {}).get("vnext", [{}])
    if not vnext:
        return None
    vnext0 = vnext[0]
    users = vnext0.get("users", [{}])
    if not users:
        return None
    ws = stream.get("wsSettings", {})
    tls = stream.get("tlsSettings", {})
    security = stream.get("security", "none")
    return {
        "ip": vnext0.get("address", ""),
        "port": int(vnext0.get("port", 443)),
        "uuid": users[0].get("id", ""),
        "sni": tls.get("serverName", ""),
        "host": ws.get("headers", {}).get("Host", "") or ws.get("host", ""),
        "path": ws.get("path", "/"),
        "security": security,
    }


async def _vless_ws_read_tunnel(
    reader: asyncio.StreamReader, wsp: _WsFrameParser,
    vless_hdr_done: bool, timeout: float = 5.0,
) -> Tuple[bytes, bool, bool, str]:
    """Read next non-empty data chunk from VLESS tunnel.

    Strips WS framing and VLESS response header automatically.
    Loops internally until real data arrives or the connection closes.

    Returns (data, vless_hdr_done, closed, reason).
    - data: decapsulated tunnel bytes (non-empty unless closed)
    - vless_hdr_done: updated flag
    - closed: True if connection ended
    - reason: error description when closed (empty string otherwise)
    """
    while True:
        frame = wsp.next_frame()
        if frame is not None:
            op, payload = frame
            if op == 8:
                cc = int.from_bytes(payload[:2], 'big') \
                    if len(payload) >= 2 else 0
                return b"", vless_hdr_done, True, f"ws-close:{cc}"
            if op not in (0, 2):
                continue
            # Strip VLESS v0 response header from first data frame
            if not vless_hdr_done:
                if len(payload) >= 2 and payload[0] == 0x00:
                    addon_len = payload[1]
                    payload = payload[2 + addon_len:]
                    vless_hdr_done = True
                elif payload:
                    return (b"", vless_hdr_done, True,
                            f"vless-bad:{payload[:6].hex()}")
                else:
                    continue  # empty frame, keep reading
            # Skip empty payloads (e.g. VLESS header was in its own frame)
            if not payload:
                continue
            return payload, vless_hdr_done, False, ""

        # Need more data from network
        try:
            chunk = await asyncio.wait_for(
                reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError:
            return b"", vless_hdr_done, True, "tunnel-timeout"
        except (OSError, ssl.SSLError) as e:
            return b"", vless_hdr_done, True, f"tunnel:{str(e)[:30]}"
        if not chunk:
            return b"", vless_hdr_done, True, "tunnel-eof"
        wsp.feed(chunk)


async def _vless_ws_speed_test(
    ip: str, port: int, sni: str, host: str, ws_path: str,
    uuid_str: str, size: int, timeout: float,
    security: str = "tls",
) -> Tuple[float, float, float, str]:
    """Python-native VLESS-over-WS speed test -- no xray binary needed.

    Two modes based on download size:
    - Quick probe (<=200KB): HTTP to cp.cloudflare.com:80 through tunnel.
      No inner TLS. Proves tunnel works and measures latency.
    - Speed test (>200KB): HTTPS to speed.cloudflare.com:443 with
      inner TLS via ssl.MemoryBIO. Full throughput measurement.

    Returns (connect_ms, ttfb_ms, speed_mbps, error).
    """
    writer = None
    try:
        t0 = time.monotonic()

        # -- 1. Outer connection (TLS or plain) --
        if security == "tls":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx,
                                        server_hostname=sni),
                timeout=6.0)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=6.0)

        # -- 2. WebSocket upgrade --
        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        ws_req = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        writer.write(ws_req)
        await writer.drain()

        # Read HTTP 101 response
        hdr_buf = b""
        hdr_end = time.monotonic() + 6.0
        while b"\r\n\r\n" not in hdr_buf:
            if time.monotonic() > hdr_end:
                return -1, -1, 0, "ws-hdr-timeout"
            chunk = await asyncio.wait_for(reader.read(4096), timeout=4.0)
            if not chunk:
                return -1, -1, 0, "ws-eof"
            hdr_buf += chunk
            if len(hdr_buf) > 16384:
                return -1, -1, 0, "ws-hdr-overflow"

        sep = hdr_buf.index(b"\r\n\r\n") + 4
        hdr_txt = hdr_buf[:sep].decode("latin-1", errors="replace")
        m = re.search(r'HTTP/\S+\s+(\d{3})', hdr_txt)
        ws_status = m.group(1) if m else ""
        if ws_status != "101":
            return -1, -1, 0, f"ws-{ws_status or 'no-resp'}"

        extra = hdr_buf[sep:]
        connect_ms = (time.monotonic() - t0) * 1000
        uuid_bytes = uuid.UUID(uuid_str).bytes

        # -- HTTP probe to cp.cloudflare.com:80 (no inner TLS) --
        # Always use cp.cloudflare.com -- speed.cloudflare.com is commonly
        # blocked by VLESS server routing rules.
        dest = b"cp.cloudflare.com"
        http_req = (
            b"GET /cdn-cgi/trace HTTP/1.1\r\n"
            b"Host: cp.cloudflare.com\r\n"
            b"Connection: close\r\n\r\n"
        )
        vless_payload = (
            b'\x00' + uuid_bytes + b'\x00'
            + b'\x01' + (80).to_bytes(2, 'big')
            + b'\x02' + bytes([len(dest)]) + dest
            + http_req
        )
        writer.write(_ws_frame_encode(vless_payload))
        await writer.drain()

        # Read VLESS response + HTTP data directly from WS frames
        wsp = _WsFrameParser(extra)
        vless_hdr_done = False
        http_hdr_done = False
        http_buf = b""
        body_total = 0
        ttfb_ms = -1.0
        dl_deadline = time.monotonic() + timeout + 3.0

        while time.monotonic() < dl_deadline:
            tun_data, vless_hdr_done, closed, _reason = \
                await _vless_ws_read_tunnel(
                    reader, wsp, vless_hdr_done, timeout=6.0)
            if closed:
                if not http_hdr_done:
                    return connect_ms, -1, 0, _reason or "probe-closed"
                break
            if not tun_data:
                continue

            if not http_hdr_done:
                http_buf += tun_data
                if b"\r\n\r\n" in http_buf:
                    h_sep = http_buf.index(b"\r\n\r\n") + 4
                    h_line = http_buf[:h_sep].decode(
                        "latin-1", errors="replace")
                    h_parts = h_line.split("\r\n")[0].split(None, 2)
                    h_code = h_parts[1] if len(h_parts) >= 2 else ""
                    if h_code not in ("200", "204"):
                        return connect_ms, -1, 0, f"probe-http:{h_code}"
                    ttfb_ms = ((time.monotonic() - t0) * 1000
                               - connect_ms)
                    body_total = len(http_buf) - h_sep
                    http_hdr_done = True
            else:
                body_total += len(tun_data)
                # /cdn-cgi/trace is small (~300B) -- done once we have it
                if body_total > 50:
                    break

        if not http_hdr_done:
            return connect_ms, -1, 0, "probe-no-response"

        dl_t = (time.monotonic() - t0) - (connect_ms / 1000)
        mbps = (body_total / 1_000_000) / dl_t if dl_t > 0.001 else 0.01
        # Ensure non-zero speed so config is marked alive
        return connect_ms, ttfb_ms, max(mbps, 0.001), ""

    except asyncio.TimeoutError:
        return -1, -1, 0, "timeout"
    except asyncio.CancelledError:
        return -1, -1, 0, "cancelled"
    except (OSError, ssl.SSLError) as e:
        return -1, -1, 0, str(e)[:60]
    except Exception as e:
        return -1, -1, 0, f"{type(e).__name__}:{str(e)[:40]}"
    finally:
        if writer:
            try:
                writer.close()
            except OSError:
                pass


def generate_xray_variations(
    uri: str,
    snis: Optional[List[str]],
    frag_preset: str,
    base_port: int,
    clean_ips: Optional[List[str]] = None,
) -> List[XrayVariation]:
    """Generate IP x SNI x fragment combinations from a single URI.

    When clean_ips is provided, each IP is tested with each SNI/fragment combo.
    The original config IP is always tested first.
    """
    parsed = None
    if uri.strip().startswith("vless://"):
        parsed = parse_vless_full(uri)
    elif uri.strip().startswith("vmess://"):
        parsed = parse_vmess_full(uri)
    if not parsed:
        return []

    if not snis:
        snis = [_infer_orig_sni(parsed) or parsed.get("address", "")]

    fragments = XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS["all"])
    orig_addr = parsed["address"]

    # Always prepend the original SNI/host so the base config is tested first
    orig_sni = _infer_orig_sni(parsed)
    # Ensure host is set so SNI rotation doesn't change the WS Host header
    if not parsed.get("host") and orig_sni:
        parsed["host"] = orig_sni
    if orig_sni and parsed.get("security") not in ("none", "", "reality"):
        snis = [s for s in snis if s != orig_sni]
        snis.insert(0, orig_sni)

    # REALITY: SNI is cryptographically bound to public key, don't rotate
    if parsed.get("security") == "reality":
        snis = [parsed.get("sni") or (snis[0] if snis else "")]

    # No TLS / REALITY: SNI is meaningless or crypto-bound -- don't rotate
    # Also nothing to fragment (tlshello fragmentation is meaningless or breaks REALITY)
    # XTLS-Vision manages its own packet flow -- fragments break it
    if parsed.get("security") in ("none", "", "reality"):
        if parsed.get("security") != "reality":
            snis = [_infer_orig_sni(parsed) or parsed.get("address", "")]
        fragments = [None]
    elif parsed.get("flow", "").startswith("xtls-rprx-vision"):
        fragments = [None]

    # Build list of IPs to test: original first, then clean IPs
    ips_to_test = [orig_addr]
    if clean_ips:
        for ip in clean_ips:
            if ip != orig_addr and ip not in ips_to_test:
                ips_to_test.append(ip)

    # When testing multiple IPs, limit SNIs/frags to keep total manageable
    if len(ips_to_test) > 1:
        # For multi-IP: top 8 SNIs x 2 frags x N IPs
        snis = snis[:8]
        if len(fragments) > 2:
            fragments = [fragments[0], fragments[-1]]  # none + heaviest

    # Guard: cap variations so base_port + idx stays in valid port range
    max_variations = max(1, 65535 - base_port)
    total_combos = len(ips_to_test) * len(snis) * len(fragments)
    if total_combos > max_variations:
        per_ip = max(1, max_variations // len(ips_to_test))
        snis = snis[:max(1, per_ip // max(1, len(fragments)))]

    variations: List[XrayVariation] = []
    idx = 0
    for ip in ips_to_test:
        for sni in snis:
            for fi, frag in enumerate(fragments):
                if base_port + idx > 65535:
                    break
                frag_label = "none" if frag is None else f"{frag.get('length', '?')}"
                ip_short = ip if ip == orig_addr else ip
                tag = f"{ip_short}|{sni}|{frag_label}"
                config_json = build_xray_config(
                    parsed, sni, frag, base_port + idx,
                    address_override=ip,
                )
                # Build result URI with the tested IP as address
                _p = copy.copy(parsed)
                _p["address"] = ip
                result_uri = _build_uri(_p, sni, tag)
                variations.append(XrayVariation(
                    tag=tag,
                    sni=sni,
                    fragment=frag,
                    config_json=config_json,
                    source_uri=uri,
                    result_uri=result_uri,
                ))
                idx += 1

    return variations


def generate_pipeline_variations(
    parsed: dict,
    source_uri: str,
    working_ips: List[str],
    sni_pool: List[str],
    frag_preset: str,
    transport_variants: List[str],
    base_port: int,
    max_total: int = 200,
    max_snis_per_ip: int = 10,
    ip_ports: Optional[dict] = None,
) -> List[XrayVariation]:
    """Generate xray variations for proven working IPs with budget control.

    Budget math distributes max_total across IPs x ports x transports x SNIs x frags.
    ip_ports: optional {ip: [port1, port2, ...]} for multi-port variations.
    Reuses build_xray_config(), switch_transport(), and URI builders.
    """
    if not working_ips or not parsed:
        return []

    _sec = parsed.get("security") or "none"
    _flow = parsed.get("flow") or ""
    _no_tls = _sec in ("none", "")
    _is_reality = _sec == "reality"
    _is_vision = _flow.startswith("xtls-rprx-vision")
    _orig_port = int(parsed.get("port", 443))

    # Ensure host is set before SNI rotation -- if empty, rotating SNIs
    # would change the WS/HTTP Host header (build_xray_config falls back
    # to sni when host is empty).  Set it to the original SNI so the
    # Host stays constant regardless of which SNI is being tested.
    orig_sni = _infer_orig_sni(parsed)
    if not parsed.get("host") and orig_sni:
        parsed = dict(parsed)  # don't mutate caller's dict
        parsed["host"] = orig_sni

    # Build SNI list -- use helper that handles CDN fronting correctly
    # CF enforces zone matching: SNI must be in the same CF zone as the
    # Host header.  The host domain is therefore ALWAYS a valid SNI and
    # should appear first.  orig_sni (address domain) may be a *different*
    # zone (domain-fronting configs), so it goes second.
    if _is_reality:
        effective_snis = [parsed.get("sni") or orig_sni or ""]
    elif _no_tls:
        effective_snis = [orig_sni or parsed.get("address", "")]
    else:
        effective_snis = []
        # Host domain first -- guaranteed same-zone as what CF routes by
        _host = parsed.get("host", "")
        if _host:
            try:
                ipaddress.ip_address(_host)
            except (ValueError, TypeError):
                # host is a domain (not IP) -> include it
                effective_snis.append(_host)
        # Original SNI second (may be different zone -- works for base config)
        if orig_sni and orig_sni not in effective_snis:
            effective_snis.append(orig_sni)
        for s in sni_pool:
            if s not in effective_snis:
                effective_snis.append(s)

    # Build fragment list
    if _no_tls or _is_reality or _is_vision:
        fragments = [None]
    else:
        fragments = XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS["all"])

    # Build transport list: original + variants
    transport_configs = [("orig", parsed)]
    if not _is_reality and not _no_tls:
        for tv in transport_variants:
            orig_type = parsed.get("type") or parsed.get("net") or "tcp"
            if tv != orig_type:
                switched = switch_transport(parsed, tv)
                if switched:
                    transport_configs.append((tv, switched))

    # xhttp mode variations: test different modes for xhttp/splithttp configs
    _orig_net = parsed.get("type") or parsed.get("net") or "tcp"
    _xhttp_modes: List[str] = []
    if _orig_net in ("xhttp", "splithttp"):
        _orig_mode = parsed.get("mode", "auto") or "auto"
        for _m in ["auto", "packet-up", "stream-up", "stream-down"]:
            if _m != _orig_mode:
                _xhttp_modes.append(_m)

    # Budget: distribute max_total across IPs x ports x SNIs x frags x transports
    # With empty sni_pool, effective_snis has just host + orig_sni (1-2 entries).
    # Budget goes mostly to IPs x fragments.
    n_ips = len(working_ips)
    n_transports = len(transport_configs)
    n_frags = len(fragments)
    # Count total port variants per IP
    _avg_ports = 1
    if ip_ports:
        _total_ports = sum(len(ip_ports.get(ip, [_orig_port])) for ip in working_ips)
        _avg_ports = max(1, _total_ports // n_ips)
    per_ip = max(1, max_total // n_ips)
    per_port = max(1, per_ip // _avg_ports)
    # SNIs get the full per-port budget -- fragments divide what's left per SNI
    snis_budget = max(1, min(max_snis_per_ip, per_port,
                             len(effective_snis)))
    n_frags_eff = max(1, per_port // max(1, snis_budget))
    fragments = fragments[:n_frags_eff]
    # Cap transports to fit remaining budget
    _t_budget = max(1, per_port // max(1, snis_budget * n_frags_eff))
    transport_configs = transport_configs[:_t_budget]
    effective_snis = effective_snis[:snis_budget]

    _dbg(f"[gen_vars] n_ips={n_ips} max_total={max_total} per_ip={per_ip} "
         f"per_port={per_port} snis_budget={snis_budget} n_frags={n_frags_eff} "
         f"transports={len(transport_configs)} effective_snis={len(effective_snis)} "
         f"expected={n_ips * snis_budget * n_frags_eff * len(transport_configs)}")

    variations: List[XrayVariation] = []
    idx = 0

    def _add_variation(ip: str, srv_port: int, t_name: str, t_parsed: dict,
                       sni: str, frag, mode_label: str = "") -> bool:
        """Add one variation. Returns False if budget exhausted."""
        nonlocal idx
        if base_port + idx > 65535 or len(variations) >= max_total:
            return False
        t_type = t_parsed.get("type") or t_parsed.get("net") or "tcp"
        frag_label = "none" if frag is None else f"{frag.get('length', '?')}"
        t_label = t_type if t_name != "orig" else ""
        port_label = f":{srv_port}" if srv_port != 443 else ""
        tag = f"{ip}{port_label}|{sni}|{frag_label}"
        if t_label:
            tag += f"|{t_label}"
        if mode_label:
            tag += f"|{mode_label}"

        _p = copy.copy(t_parsed)
        _p["address"] = ip
        _p["port"] = srv_port

        config_json = build_xray_config(
            _p, sni, frag, base_port + idx,
            address_override=ip,
        )
        result_uri = _build_uri(_p, sni, tag)

        variations.append(XrayVariation(
            tag=tag, sni=sni, fragment=frag,
            config_json=config_json,
            source_uri=source_uri,
            result_uri=result_uri,
        ))
        idx += 1
        return True

    for ip in working_ips:
        ports = ip_ports.get(ip, [_orig_port]) if ip_ports else [_orig_port]
        for srv_port in ports:
            for t_name, t_parsed in transport_configs:
                for sni in effective_snis:
                    for frag in fragments:
                        if not _add_variation(ip, srv_port, t_name, t_parsed,
                                              sni, frag):
                            break
                        # xhttp mode variations: test other modes on first frag only
                        if _xhttp_modes and frag is None:
                            t_type = t_parsed.get("type") or t_parsed.get("net") or "tcp"
                            if t_type in ("xhttp", "splithttp"):
                                for _m in _xhttp_modes:
                                    _mp = copy.copy(t_parsed)
                                    _mp["mode"] = _m
                                    if not _add_variation(ip, srv_port, t_name, _mp,
                                                          sni, frag, _m):
                                        break
                    if len(variations) >= max_total:
                        break
                if len(variations) >= max_total:
                    break
            if len(variations) >= max_total:
                break
        if len(variations) >= max_total:
            break

    return variations


def expand_custom_ips(raw_input: str) -> List[str]:
    """Expand user input (IPs, CIDRs, or file path) into a list of individual IPs.

    Accepts:
      - Single IPs: "1.2.3.4"
      - CIDR notation: "104.16.0.0/24"
      - Comma-separated mix: "1.2.3.4, 10.0.0.0/30"
      - File path (one IP/CIDR per line)
    Returns deduplicated list of IPs (max 6666 to avoid memory issues).
    """
    MAX_IPS = 6666
    entries: List[str] = []

    # Check if input is a file path
    raw = raw_input.strip()
    if os.path.isfile(raw):
        try:
            with open(raw, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(line)
        except OSError:
            pass
    else:
        # Comma or newline separated
        for part in raw.replace("\n", ",").split(","):
            part = part.strip()
            if part:
                entries.append(part)

    seen: set = set()
    result: List[str] = []
    for entry in entries:
        try:
            # Try as single IP first
            ip = ipaddress.IPv4Address(entry)
            if str(ip) not in seen:
                seen.add(str(ip))
                result.append(str(ip))
        except ValueError:
            try:
                # Try as CIDR
                net = ipaddress.IPv4Network(entry, strict=False)
                for host in net.hosts():
                    if len(result) >= MAX_IPS:
                        break
                    s = str(host)
                    if s not in seen:
                        seen.add(s)
                        result.append(s)
            except ValueError:
                continue
        if len(result) >= MAX_IPS:
            break
    return result


def _xray_calc_scores(xst: XrayTestState):
    """Calculate scores for xray variations."""
    for v in xst.variations:
        if not v.alive:
            v.score = 0
            continue
        cms = v.connect_ms if v.connect_ms >= 0 else 1000
        tms = v.ttfb_ms if v.ttfb_ms >= 0 else 1000
        lat = max(0.0, 100.0 - cms / 10.0)
        ttfb = max(0.0, 100.0 - tms / 5.0)
        if v.native_tested or v.speed_mbps < 0.01:
            # Native VLESS test: no real speed data, score on latency only
            v.score = round(lat * 0.55 + ttfb * 0.45, 1)
        else:
            spd = min(100.0, v.speed_mbps * 20.0)
            v.score = round(lat * 0.35 + spd * 0.50 + ttfb * 0.15, 1)


async def _test_single_variation(
    var: XrayVariation, xray_bin: str, size: int, timeout: float,
) -> bool:
    """Test one XrayVariation via Python-native VLESS or xray SOCKS5.

    For VLESS+WS configs without fragments, uses a direct Python tunnel
    (TLS->WS->VLESS->HTTP) which avoids xray binary issues.
    Falls back to xray SOCKS5 proxy for all other protocols.

    Mutates var in place (alive, connect_ms, ttfb_ms, speed_mbps, error).
    Returns True if alive (mbps > 0).
    """
    # -- Try Python-native VLESS test for ALL VLESS+WS configs --
    # Even for fragment variations: if the SNI/IP doesn't work without
    # fragments (e.g. CF returns 403), it won't work with fragments either
    # (fragments only affect DPI, not CF routing). This avoids falling
    # through to the xray binary which has SSL issues.
    params = _extract_vless_ws_params(var.config_json)
    if params and params["uuid"]:
        connect_ms, ttfb_ms, mbps, err = await _vless_ws_speed_test(
            ip=params["ip"], port=params["port"],
            sni=params["sni"] or params["host"],
            host=params["host"] or params["sni"],
            ws_path=params["path"],
            uuid_str=params["uuid"],
            size=size, timeout=timeout,
            security=params["security"],
        )
        var.connect_ms = connect_ms
        if mbps > 0:
            var.alive = True
            var.native_tested = True
            var.ttfb_ms = ttfb_ms
            var.speed_mbps = mbps
            return True
        else:
            # For fragment variations: native test proves connectivity.
            # If it fails, no point trying xray binary (same CF routing).
            var.error = err or "no-data"
            return False

    # -- Fallback: xray SOCKS5 proxy test --
    loop = asyncio.get_running_loop()
    os.makedirs(XRAY_TMP_DIR, exist_ok=True)

    ports = _find_free_ports(XRAY_BASE_PORT, 1)
    if not ports:
        var.error = "no-free-port"
        return False
    port = ports[0]

    test_cfg = copy.deepcopy(var.config_json)
    test_cfg["inbounds"][0]["port"] = port

    config_path = os.path.join(XRAY_TMP_DIR, f"xray_{port}.json")
    try:
        _fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            json.dump(test_cfg, f)
    except OSError as e:
        var.error = f"write-cfg:{str(e)[:30]}"
        try:
            os.remove(config_path)
        except OSError:
            pass
        return False

    xp = XrayProcess(xray_bin, config_path, port)
    try:
        if not await loop.run_in_executor(None, xp.start):
            var.error = xp.last_error[:40] if xp.last_error else "xray-start-fail"
            return False

        connect_ms, ttfb_ms, mbps, err = await xray_speed_test(
            port, size, timeout,
        )
        var.connect_ms = connect_ms
        if mbps > 0:
            var.alive = True
            var.ttfb_ms = ttfb_ms
            var.speed_mbps = mbps
            return True
        else:
            _py_err = err or "no-data"
            # Stop xray FIRST so it flushes all output to .err file
            xp.stop()
            xp._read_stderr_file()
            if xp.last_error:
                var.error = xp.last_error[:60]
            else:
                var.error = _py_err
            return False
    finally:
        xp.stop()  # safe to call twice
        xp.cleanup()


async def xray_pipeline_test(xst: XrayTestState, pcfg: PipelineConfig):
    """Progressive 3-stage pipeline for xray proxy testing.

    Stage 1: IP Scan       -- TLS probe CF_TEST_IPS + original IP (~10s)
    Stage 2: Base Test     -- Real xray test with original config on live IPs (~30-60s)
    Stage 3: Expansion     -- SNI + fragment + transport variations on working IPs (~2-3 min)
    """
    xst.pipeline_mode = True
    xst.start_time = time.monotonic()
    os.makedirs(XRAY_TMP_DIR, exist_ok=True)
    # Clean stale temp configs
    for stale in globmod.glob(os.path.join(XRAY_TMP_DIR, "xray_*.json")):
        try:
            os.remove(stale)
        except OSError:
            pass

    orig_addr = pcfg.parsed.get("address", "")
    orig_sni = _infer_orig_sni(pcfg.parsed) or SPEED_HOST
    orig_port = int(pcfg.parsed.get("port", 443))
    _sec = pcfg.parsed.get("security") or "none"
    _is_reality = _sec == "reality"
    _no_tls = _sec in ("none", "")
    _is_cf = _is_cf_address(orig_addr)
    if not _is_cf and not _is_reality and not _no_tls:
        _is_cf = _resolve_is_cf(orig_addr)

    # Auto-detect: find alternative SNI to try if primary fails
    # With new _infer_orig_sni, orig_sni is the address domain for CDN
    # fronting configs; the host domain becomes the fallback (and vice versa).
    _alt_sni = ""
    if not _is_reality and not _no_tls:
        _host = pcfg.parsed.get("host", "")
        _av = pcfg.parsed.get("address", "")
        _addr_is_domain = False
        try:
            ipaddress.ip_address(_av)
        except (ValueError, TypeError):
            _addr_is_domain = bool(_av)
        # Pick an alternative that differs from orig_sni
        if _host and _host != orig_sni:
            _alt_sni = _host
        elif _addr_is_domain and _av != orig_sni:
            _alt_sni = _av

    # -- Pre-flight: verify server and auto-detect SNI mode --
    if not _is_reality and not _no_tls and orig_addr:
        _pf_addr = orig_addr
        try:
            ipaddress.ip_address(orig_addr)
        except (ValueError, TypeError):
            if _CF_PREFLIGHT_IPS:
                _pf_addr = _CF_PREFLIGHT_IPS[0]

        xst.phase_label = f"Pre-flight: checking {orig_sni}:{orig_port}..."
        pf_lat, pf_is_cf, pf_err = await _tls_probe(
            _pf_addr, orig_sni, timeout=5.0, validate=True, port=orig_port)
        xst.preflight_is_cf = pf_is_cf if pf_lat > 0 else None

        # Only switch SNI if the TLS connection itself completely failed.
        if _alt_sni and pf_lat <= 0:
            xst.phase_label = f"Pre-flight: trying {_alt_sni}..."
            pf2_lat, pf2_is_cf, pf2_err = await _tls_probe(
                _pf_addr, _alt_sni, timeout=5.0, validate=True,
                port=orig_port)
            if pf2_lat > 0 and pf2_is_cf and not pf2_err.startswith(
                    "cf-origin-"):
                # Alternative SNI works -- switch
                orig_sni = _alt_sni
                _alt_sni = ""
                xst.preflight_is_cf = True
                pf_lat, pf_is_cf, pf_err = pf2_lat, pf2_is_cf, pf2_err

        # Set warnings based on final pre-flight result
        if pf_lat <= 0:
            xst.preflight_warning = (
                f"Server {orig_sni}:{orig_port} unreachable")
        elif not pf_is_cf:
            xst.preflight_warning = (
                f"TLS OK but HTTP validation inconclusive for {orig_sni} "
                f"(origin may only accept WebSocket)")
        elif pf_err.startswith("cf-origin-"):
            _pf_code = pf_err.split('-')[-1]
            if _pf_code == "403":
                _pf_hint = "domain may not be on Cloudflare"
            elif _pf_code in ("521", "522", "523"):
                _pf_hint = "origin server is down or unreachable"
            elif _pf_code in ("502", "520", "530"):
                _pf_hint = "origin DNS or routing error"
            else:
                _pf_hint = "server may be down or misconfigured"
            xst.preflight_warning = (
                f"CF edge OK but HTTP {_pf_code} -- {_pf_hint}")

        # -- VLESS tunnel probe: test WS upgrade + VLESS handshake --
        _ws_net = pcfg.parsed.get("type") or pcfg.parsed.get("net") or "tcp"
        _ws_host = pcfg.parsed.get("host") or orig_sni
        _ws_path = pcfg.parsed.get("path") or "/"
        _uuid_str = pcfg.parsed.get("uuid", "")
        if pf_lat > 0 and _ws_net in ("ws", "websocket") and _uuid_str:
            xst.phase_label = f"Pre-flight: testing VLESS tunnel..."
            _vless_diag = ""
            try:
                _ws_ip = _pf_addr
                _ws_ctx = ssl.create_default_context()
                _ws_ctx.check_hostname = False
                _ws_ctx.verify_mode = ssl.CERT_NONE
                _ws_r, _ws_w = await asyncio.wait_for(
                    asyncio.open_connection(
                        _ws_ip, orig_port, ssl=_ws_ctx,
                        server_hostname=orig_sni),
                    timeout=5.0)
                # Step 1: WebSocket upgrade
                _ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
                _ws_req = (
                    f"GET {_ws_path} HTTP/1.1\r\n"
                    f"Host: {_ws_host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {_ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                _ws_w.write(_ws_req.encode())
                await _ws_w.drain()

                # Read HTTP response -- must find \r\n\r\n boundary
                _hdr_buf = b""
                _hdr_deadline = time.monotonic() + 5.0
                while b"\r\n\r\n" not in _hdr_buf:
                    if time.monotonic() > _hdr_deadline:
                        break
                    _chunk = await asyncio.wait_for(
                        _ws_r.read(4096), timeout=3.0)
                    if not _chunk:
                        break
                    _hdr_buf += _chunk
                    if len(_hdr_buf) > 8192:
                        break

                _ws_txt = _hdr_buf.decode("latin-1", errors="replace")
                _ws_status = ""
                _ws_m = re.search(r'HTTP/\S+\s+(\d{3})', _ws_txt)
                if _ws_m:
                    _ws_status = _ws_m.group(1)

                # Extract any WS data after the HTTP headers
                _ws_extra = b""
                if b"\r\n\r\n" in _hdr_buf:
                    _ws_extra = _hdr_buf[_hdr_buf.index(b"\r\n\r\n") + 4:]

                if _ws_status != "101":
                    _ws_first_line = _ws_txt.split("\r\n", 1)[0]
                    _vless_diag = f"WS {_ws_status or 'no-resp'}: {_ws_first_line[:40]}"
                else:
                    # Step 2: Build VLESS header + HTTP request payload
                    _uuid_bytes = uuid.UUID(_uuid_str).bytes
                    _dest = b"cp.cloudflare.com"
                    _http_req = (
                        b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                        b"Host: cp.cloudflare.com\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    _vless_payload = (
                        b'\x00'                      # version
                        + _uuid_bytes                 # UUID (16 bytes)
                        + b'\x00'                     # addon length
                        + b'\x01'                     # command: TCP
                        + (80).to_bytes(2, 'big')     # port 80 (HTTP)
                        + b'\x02'                     # addr type: domain
                        + bytes([len(_dest)])          # domain length
                        + _dest                        # domain
                        + _http_req                    # first data chunk
                    )
                    # Wrap in WS binary frame (client must mask)
                    _mask = secrets.token_bytes(4)
                    _masked = bytes(
                        b ^ _mask[i % 4] for i, b in enumerate(_vless_payload))
                    _frame_len = len(_vless_payload)
                    if _frame_len <= 125:
                        _ws_frame = (bytes([0x82, 0x80 | _frame_len])
                                     + _mask + _masked)
                    else:
                        _ws_frame = (bytes([0x82, 0xFE])
                                     + _frame_len.to_bytes(2, 'big')
                                     + _mask + _masked)
                    _ws_w.write(_ws_frame)
                    await _ws_w.drain()

                    # Step 3: Read VLESS response + HTTP data (over WS)
                    try:
                        _vr = _ws_extra  # include any data from HTTP read
                        _vr += await asyncio.wait_for(
                            _ws_r.read(2048), timeout=8.0)
                        if len(_vr) >= 4:
                            # Parse WS frame
                            _op = _vr[0] & 0x0F
                            _plen = _vr[1] & 0x7F
                            _pstart = 2
                            if _plen == 126:
                                _plen = int.from_bytes(_vr[2:4], 'big')
                                _pstart = 4
                            elif _plen == 127:
                                _pstart = 10
                            _payload = _vr[_pstart:_pstart + _plen]

                            if _op == 8:
                                # WS close frame
                                _close_code = int.from_bytes(
                                    _payload[:2], 'big') if len(_payload) >= 2 else 0
                                _close_reason = _payload[2:].decode(
                                    'utf-8', errors='replace') if len(_payload) > 2 else ""
                                _vless_diag = (
                                    f"VLESS rejected: WS close {_close_code}"
                                    f"{' ' + _close_reason[:30] if _close_reason else ''}"
                                    f" (UUID may be wrong/expired)")
                            elif len(_payload) >= 2 and _payload[0] == 0x00:
                                # VLESS v0 response header (2+ bytes)
                                _addon_len = _payload[1]
                                _data_after = _payload[2 + _addon_len:]
                                # Check if HTTP response follows
                                if b"HTTP" in _data_after[:20]:
                                    _vless_diag = "VLESS tunnel OK -- proxy works!"
                                else:
                                    _vless_diag = (
                                        f"VLESS tunnel OK (v0) "
                                        f"data={_data_after[:16].hex()}")
                            else:
                                _vless_diag = (
                                    f"VLESS unexpected: op={_op} len={_plen} "
                                    f"hex={_payload[:12].hex() if _payload else 'empty'}")
                        elif len(_vr) > 0:
                            _vless_diag = (
                                f"VLESS short: {len(_vr)}B "
                                f"{_vr[:20].hex()}")
                        else:
                            _vless_diag = "VLESS: empty response"
                    except asyncio.TimeoutError:
                        _vless_diag = "VLESS: timeout (origin can't reach destination?)"

                _ws_w.close()
                try:
                    await _ws_w.wait_closed()
                except OSError:
                    pass
            except asyncio.TimeoutError:
                _vless_diag = "TLS/WS timeout"
            except OSError as _ws_e:
                _vless_diag = f"connect: {str(_ws_e)[:40]}"

            if _vless_diag:
                xst.preflight_warning = (
                    (xst.preflight_warning + " | " if xst.preflight_warning else "")
                    + _vless_diag)

    # -- Stage 1: IP Scan --
    xst.pipeline_stage = 0
    xst.pipeline_stages[0]["status"] = "active"
    xst.phase = "ip_scan"

    if _is_reality:
        # REALITY: only probe the original server IP on its port/SNI
        xst.phase_label = f"Probing {orig_addr}:{orig_port}..."
        probe_ips = [orig_addr] if orig_addr else []
        probe_sni = orig_sni
        probe_ports = [orig_port]
    else:
        # Cloudflare-fronted: probe CF IPs on configured ports
        probe_ips = list(pcfg.custom_ips) if pcfg.custom_ips else list(CF_TEST_IPS)
        if orig_addr and orig_addr not in probe_ips:
            probe_ips.insert(0, orig_addr)
        probe_sni = SPEED_HOST
        probe_ports = pcfg.probe_ports if pcfg.probe_ports else [orig_port]
        n_ports = len(probe_ports)
        port_label = f" x {n_ports} ports ({','.join(str(p) for p in probe_ports)})" if n_ports > 1 else f" on port {probe_ports[0]}"
        if pcfg.custom_ips:
            _cf_range_count = sum(1 for ip in probe_ips if _is_cf_address(ip))
            _non_cf = len(probe_ips) - _cf_range_count
            if _non_cf > len(probe_ips) * 0.5:
                xst.preflight_warning = (
                    (xst.preflight_warning + " | " if xst.preflight_warning else "")
                    + f"{_non_cf}/{len(probe_ips)} custom IPs outside known CF ranges")
            xst.phase_label = (
                f"Scanning {len(probe_ips)} IPs "
                f"({_cf_range_count} in CF ranges){port_label}...")
        else:
            xst.phase_label = f"Scanning {len(probe_ips)} IPs{port_label}..."

    # Build (ip, port) probe pairs
    probe_pairs: List[Tuple[str, int]] = []
    for ip in probe_ips:
        for port in probe_ports:
            probe_pairs.append((ip, port))

    # Scale concurrency: 50 for default CF_TEST_IPS, up to 200 for large custom sets
    _sem_count = min(200, max(50, len(probe_pairs) // 20))
    sem = asyncio.Semaphore(_sem_count)
    xst.total = len(probe_pairs)
    xst.done_count = 0

    async def _probe_one(ip: str, port: int) -> Optional[Tuple[str, int, float]]:
        async with sem:
            if xst.interrupted:
                return None
            try:
                lat, is_cf, err = await _tls_probe(ip, probe_sni, timeout=4.0,
                                                    validate=True, port=port)
                xst.done_count += 1
                if lat > 0 and is_cf:
                    if err.startswith("cf-origin-"):
                        xst.cf_origin_errors += 1
                    return (ip, port, lat)
            except (OSError, asyncio.TimeoutError):
                xst.done_count += 1
            return None

    results = await asyncio.gather(*[_probe_one(ip, port) for ip, port in probe_pairs])
    # Deduplicate IPs -- keep best latency per IP; track all working ports
    _ip_best: dict = {}  # ip -> best latency
    xst.live_ip_ports = {}
    for r in results:
        if r is not None:
            ip, port, lat = r
            if ip not in _ip_best or lat < _ip_best[ip]:
                _ip_best[ip] = lat
            if ip not in xst.live_ip_ports:
                xst.live_ip_ports[ip] = []
            if port not in xst.live_ip_ports[ip]:
                xst.live_ip_ports[ip].append(port)
    xst.live_ips = sorted([(ip, lat) for ip, lat in _ip_best.items()], key=lambda x: x[1])

    xst.pipeline_stages[0]["status"] = "done"
    _cf_count = len(xst.live_ips)
    _origin_warn = f" ({xst.cf_origin_errors} with origin errors)" if xst.cf_origin_errors else ""
    _port_info = f" on port {probe_ports[0]}" if len(probe_ports) == 1 else f" on ports {','.join(str(p) for p in probe_ports)}"
    xst.phase_label = f"IP Scan: {_cf_count} CF confirmed{_port_info}{_origin_warn}"

    if not xst.live_ips or xst.interrupted:
        xst.pipeline_stages[0]["status"] = "interrupted"
        xst.finished = True
        if _is_cf:
            if xst.preflight_warning:
                xst.phase_label = "No Cloudflare IPs found -- server may not be behind CF CDN"
            else:
                xst.phase_label = "No Cloudflare IPs found -- check your network or IP list"
        else:
            xst.phase_label = f"Server {orig_addr}:{orig_port} unreachable -- check address/port"
        _xray_calc_scores(xst)
        return

    # -- Stage 2: Base Connectivity --
    xst.pipeline_stage = 1
    xst.pipeline_stages[1]["status"] = "active"
    xst.phase = "base_test"

    # For config-less mode: test each base URI on original IP first
    if pcfg.configless and pcfg.base_uris:
        xst.phase_label = f"Testing {len(pcfg.base_uris)} base configs..."
        xst.total = len(pcfg.base_uris)
        xst.done_count = 0

        working_uri = None
        working_parsed = None
        for uri, parsed in pcfg.base_uris:
            if xst.interrupted:
                break
            _sni = _infer_orig_sni(parsed) or SPEED_HOST
            cfg_json = build_xray_config(parsed, _sni, None, XRAY_BASE_PORT,
                                         address_override=orig_addr)
            var = XrayVariation(
                tag=f"{orig_addr}|{_sni}|none",
                sni=_sni, fragment=None,
                config_json=cfg_json,
                source_uri=uri, result_uri=uri,
            )
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            if alive:
                working_uri = uri
                working_parsed = parsed
                xst.working_ips.append(orig_addr)
                xst.variations.append(var)
                xst.alive_count += 1
                break
            else:
                xst.dead_count += 1

        if not working_uri:
            xst.pipeline_stages[1]["status"] = "done"
            xst.finished = True
            xst.phase_label = "No base config could connect -- server may not support ws/xhttp"
            _xray_calc_scores(xst)
            return

        # Use the working config for remaining stages
        pcfg.uri = working_uri
        pcfg.parsed = working_parsed
        orig_sni = _infer_orig_sni(working_parsed)

    # Test live IPs with the base config
    test_ips = [ip for ip, _ in xst.live_ips[:pcfg.max_stage2_ips]]
    # Ensure original IP is always tested
    if orig_addr and orig_addr not in test_ips:
        test_ips.insert(0, orig_addr)

    xst.total = len(test_ips)
    xst.done_count = 0
    xst.phase_label = f"Base test: 0/{len(test_ips)} IPs..."

    # Build all base variations upfront
    _base_vars: List[Tuple[str, XrayVariation]] = []
    for ip in test_ips:
        _test_port = (xst.live_ip_ports.get(ip, []) or [orig_port])[0]
        _p = copy.copy(pcfg.parsed)
        _p["address"] = ip
        _p["port"] = _test_port
        cfg_json = build_xray_config(_p, orig_sni, None,
                                     XRAY_BASE_PORT + len(_base_vars),
                                     address_override=ip)
        r_uri = _build_uri(_p, orig_sni, f"{ip}|{orig_sni}|none")
        var = XrayVariation(
            tag=f"{ip}|{orig_sni}|none",
            sni=orig_sni, fragment=None,
            config_json=cfg_json,
            source_uri=pcfg.uri, result_uri=r_uri,
        )
        _base_vars.append((ip, var))

    # Run Stage 2 in parallel batches
    _base_sem = asyncio.Semaphore(10)

    async def _test_base(ip: str, var: XrayVariation) -> None:
        async with _base_sem:
            if xst.interrupted:
                return
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            xst.variations.append(var)
            if alive:
                if ip not in xst.working_ips:
                    xst.working_ips.append(ip)
                xst.alive_count += 1
            else:
                xst.dead_count += 1
            xst.phase_label = (
                f"Base test: {xst.done_count}/{len(test_ips)} "
                f"({len(xst.working_ips)} working)")

    for _ci in range(0, len(_base_vars), 20):
        if xst.interrupted:
            break
        batch = _base_vars[_ci:_ci + 20]
        await asyncio.gather(*[_test_base(ip, var) for ip, var in batch])

    # Fallback: if no IPs work, try alternative SNIs on original IP
    # Skip for REALITY (SNI is crypto-bound) and no-TLS (SNI meaningless)
    if not xst.working_ips and not xst.interrupted and not _is_reality and not _no_tls:
        _fb_base = [_alt_sni] if _alt_sni else []
        _fb_common = [SPEED_HOST, "dash.cloudflare.com", "chatgpt.com"]
        fallback_snis = _fb_base + [s for s in _fb_common if s not in _fb_base]
        fallback_snis = [s for s in fallback_snis if s and s != orig_sni]
        xst.phase_label = "Trying fallback SNIs..."
        for fb_sni in fallback_snis:
            if xst.interrupted:
                break
            cfg_json = build_xray_config(pcfg.parsed, fb_sni, None, XRAY_BASE_PORT,
                                         address_override=orig_addr)
            _fb_p = copy.copy(pcfg.parsed)
            _fb_p["address"] = orig_addr
            fb_result_uri = _build_uri(_fb_p, fb_sni, f"{orig_addr}|{fb_sni}|none")
            var = XrayVariation(
                tag=f"{orig_addr}|{fb_sni}|none",
                sni=fb_sni, fragment=None,
                config_json=cfg_json,
                source_uri=pcfg.uri, result_uri=fb_result_uri,
            )
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            if alive:
                orig_sni = fb_sni  # Update SNI for Stage 3
                xst.working_ips.append(orig_addr)
                xst.variations.append(var)
                xst.alive_count += 1
                break

    xst.pipeline_stages[1]["status"] = "interrupted" if xst.interrupted else "done"

    # If base config failed but we have live CF IPs, don't give up --
    # proceed to expansion with different SNIs/fragments/transports.
    _base_failed = not xst.working_ips
    _fallback_ips: List[str] = []
    if _base_failed and not xst.interrupted and _is_cf and xst.live_ips:
        _fallback_ips = [ip for ip, _ in xst.live_ips[:min(20, pcfg.max_stage2_ips)]]
        xst.phase_label = (
            f"Base config failed -- expanding with fragments "
            f"on {len(_fallback_ips)} IPs...")
    elif not xst.working_ips or xst.interrupted:
        xst.finished = True
        if not _is_cf:
            xst.phase_label = (
                f"Connection failed -- server {orig_addr}:{orig_port} "
                f"not responding to xray")
        elif xst.cf_origin_errors > 0:
            xst.phase_label = (
                "CF edge IPs found but origin is unreachable -- "
                "check server config (UUID, path, protocol)")
        else:
            xst.phase_label = (
                "No working IP found -- config may be invalid or "
                "server not properly behind Cloudflare")
        _xray_calc_scores(xst)
        return

    # -- Stage 3: Expansion --
    xst.pipeline_stage = 2
    xst.pipeline_stages[2]["status"] = "active"
    xst.phase = "expansion"

    # When base config failed, use live CF IPs for expansion instead
    _expansion_ips = xst.working_ips if xst.working_ips else (
        _fallback_ips if _base_failed else [])

    # Ensure the proven working SNI is first in the pool for Stage 3
    if orig_sni:
        if orig_sni in pcfg.sni_pool:
            pcfg.sni_pool.remove(orig_sni)
        pcfg.sni_pool.insert(0, orig_sni)

    _dbg(f"[expansion] IPs={len(_expansion_ips)} sni_pool={len(pcfg.sni_pool)} "
         f"frag={pcfg.frag_preset} transports={pcfg.transport_variants} "
         f"max_exp={pcfg.max_expansion} max_snis={pcfg.max_snis_per_ip} "
         f"sni_sample={pcfg.sni_pool[:5]}")

    expansion_vars = generate_pipeline_variations(
        pcfg.parsed, pcfg.uri, _expansion_ips, pcfg.sni_pool,
        pcfg.frag_preset, pcfg.transport_variants,
        XRAY_BASE_PORT, pcfg.max_expansion, pcfg.max_snis_per_ip,
        ip_ports=xst.live_ip_ports if xst.live_ip_ports else None,
    )

    _dbg(f"[expansion] generated={len(expansion_vars)} "
         f"unique_snis={len(set(v.sni for v in expansion_vars))}")

    # Remove duplicates (variations already tested in Stage 2)
    tested_tags = {v.tag for v in xst.variations}
    expansion_vars = [v for v in expansion_vars if v.tag not in tested_tags]
    _dbg(f"[expansion] after dedup={len(expansion_vars)}")

    _exp_frag_count = len(set(str(v.fragment) for v in expansion_vars))
    xst.total = len(expansion_vars)
    xst.done_count = 0
    xst.phase_label = (f"Expansion: 0/{len(expansion_vars)} "
                       f"({len(_expansion_ips)} IPs, {_exp_frag_count} frags)...")

    # Run expansion tests in parallel batches for speed
    _exp_sem = asyncio.Semaphore(20)

    async def _test_exp(var: XrayVariation) -> None:
        async with _exp_sem:
            if xst.interrupted:
                return
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            if alive:
                xst.alive_count += 1
            else:
                xst.dead_count += 1
            xst.phase_label = (
                f"Expansion: {xst.done_count}/{len(expansion_vars)} "
                f"({xst.alive_count} alive)")

    # Process in chunks to allow interrupt checks and append results in order
    _chunk = 60
    for _ci in range(0, len(expansion_vars), _chunk):
        if xst.interrupted:
            break
        batch = expansion_vars[_ci:_ci + _chunk]
        await asyncio.gather(*[_test_exp(v) for v in batch])
        xst.variations.extend(batch)

    xst.pipeline_stages[2]["status"] = "interrupted" if xst.interrupted else "done"
    xst.quick_passed = xst.alive_count

    xst.finished = True
    _xray_calc_scores(xst)
