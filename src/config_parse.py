import base64
import http.client
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

from src.constants import SPEED_HOST
from src.models import ConfigEntry, RoundCfg


def parse_vless(uri: str) -> Optional[ConfigEntry]:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    rest = uri[8:]
    name = ""
    if "#" in rest:
        rest, name = rest.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    if "?" in rest:
        rest = rest.split("?", 1)[0]
    if "@" not in rest:
        return None
    _, addr = rest.split("@", 1)
    if addr.startswith("["):
        if "]" not in addr:
            return None
        address = addr[1 : addr.index("]")]
    else:
        address = addr.rsplit(":", 1)[0]
    return ConfigEntry(address=address, name=name, original_uri=uri.strip())


def parse_vmess(uri: str) -> Optional[ConfigEntry]:
    uri = uri.strip()
    if not uri.startswith("vmess://"):
        return None
    b64 = uri[8:]
    if "#" in b64:
        b64 = b64.split("#", 1)[0]
    b64 += "=" * (-len(b64) % 4)
    try:
        try:
            raw = base64.b64decode(b64).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            raw = base64.urlsafe_b64decode(b64).decode("utf-8", errors="replace")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    address = str(obj.get("add", ""))
    if not address:
        return None
    name = str(obj.get("ps", ""))
    return ConfigEntry(address=address, name=name, original_uri=uri.strip())


def parse_config(uri: str) -> Optional[ConfigEntry]:
    return parse_vless(uri) or parse_vmess(uri)


def _infer_orig_sni(parsed: dict) -> str:
    if parsed.get("sni"):
        return parsed["sni"]
    addr = parsed.get("address", "")
    try:
        ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        if addr:
            return addr
    return parsed.get("host") or addr


def parse_vless_full(uri: str) -> Optional[dict]:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    rest = uri[8:]
    name = ""
    if "#" in rest:
        rest, name = rest.split("#", 1)
        name = urllib.parse.unquote(name)
    params_str = ""
    if "?" in rest:
        rest, params_str = rest.split("?", 1)
    if "@" not in rest:
        return None
    uuid_part, addr_part = rest.split("@", 1)
    if not uuid_part or len(uuid_part) < 8:
        return None
    if addr_part.startswith("["):
        if "]" not in addr_part:
            return None
        bracket_end = addr_part.index("]")
        address = addr_part[1:bracket_end]
        port_str = addr_part[bracket_end + 2:] if len(addr_part) > bracket_end + 1 and addr_part[bracket_end + 1] == ":" else "443"
    else:
        parts = addr_part.rsplit(":", 1)
        address = parts[0]
        port_str = parts[1] if len(parts) > 1 and parts[1].isdigit() else "443"
    if not address:
        return None
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            port = 443
    except ValueError:
        port = 443
    params = dict(urllib.parse.parse_qsl(params_str, keep_blank_values=True))
    security = params.get("security") or "none"
    return {
        "protocol": "vless",
        "uuid": uuid_part,
        "address": address,
        "port": port,
        "name": name,
        "type": params.get("type") or "tcp",
        "security": security,
        "sni": params.get("sni") or "",
        "host": params.get("host") or "",
        "path": params.get("path") or "/",
        "fp": params.get("fp") or "",
        "flow": params.get("flow") or "",
        "alpn": params.get("alpn") or "",
        "encryption": params.get("encryption") or "none",
        "serviceName": params.get("serviceName", ""),
        "headerType": params.get("headerType", ""),
        "pbk": params.get("pbk", ""),
        "sid": params.get("sid", ""),
        "spx": params.get("spx", ""),
        "mode": params.get("mode") or "auto",
    }


def parse_vmess_full(uri: str) -> Optional[dict]:
    uri = uri.strip()
    if not uri.startswith("vmess://"):
        return None
    b64 = uri[8:]
    if "#" in b64:
        b64 = b64.split("#", 1)[0]
    b64 += "=" * (-len(b64) % 4)
    try:
        try:
            raw = base64.b64decode(b64).decode("utf-8", errors="replace")
        except ValueError:
            raw = base64.urlsafe_b64decode(b64).decode("utf-8", errors="replace")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
    except (ValueError, TypeError):
        return None
    address = str(obj.get("add", ""))
    if not address:
        return None
    try:
        port = int(obj.get("port", 443))
        if not (1 <= port <= 65535):
            port = 443
    except (ValueError, TypeError):
        port = 443
    try:
        aid = int(obj.get("aid", 0))
    except (ValueError, TypeError):
        aid = 0
    uuid_val = str(obj.get("id", ""))
    if not uuid_val or len(uuid_val) < 8:
        return None
    tls_val = str(obj.get("tls") or "")
    return {
        "protocol": "vmess",
        "uuid": uuid_val,
        "address": address,
        "port": port,
        "name": str(obj.get("ps") or ""),
        "type": str(obj.get("net") or "tcp"),
        "security": "tls" if tls_val.lower() == "tls" else "none",
        "sni": str(obj.get("sni") or ""),
        "host": str(obj.get("host") or ""),
        "path": str(obj.get("path") or "/"),
        "fp": str(obj.get("fp") or ""),
        "aid": aid,
        "scy": str(obj.get("scy") or "auto"),
        "alpn": str(obj.get("alpn") or ""),
        "headerType": str(obj.get("type") or ""),
        "mode": str(obj.get("mode") or "auto"),
    }


def load_input(path: str) -> List[ConfigEntry]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"  Error reading {path}: {e}")
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "data" in data:
            data = data["data"]
        out: List[ConfigEntry] = []
        for i, e in enumerate(data):
            d = e.get("domain", "")
            if d:
                out.append(
                    ConfigEntry(address=d, name=f"d-{i+1}", ip=e.get("ipv4", ""))
                )
        if out:
            return out
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    out = []
    for ln in raw.splitlines():
        c = parse_config(ln)
        if c:
            out.append(c)
    return out


def fetch_sub(url: str) -> List[ConfigEntry]:
    from src.utils import _dbg
    if not url.lower().startswith(("http://", "https://")):
        print(f"  Error: --sub only accepts http:// or https:// URLs")
        return []
    _dbg(f"Fetching subscription: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
    except (OSError, http.client.HTTPException, urllib.error.URLError) as e:
        _dbg(f"Subscription fetch failed: {e}")
        print(f"  Error fetching subscription: {e}")
        return []
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
        if "://" in decoded:
            raw = decoded
    except (ValueError, TypeError):
        pass
    out = []
    for ln in raw.splitlines():
        c = parse_config(ln.strip())
        if c:
            out.append(c)
    _dbg(f"Subscription loaded: {len(out)} configs")
    return out


def generate_from_template(template: str, addresses: List[str]) -> List[ConfigEntry]:
    out = []
    parsed = parse_config(template)
    if not parsed:
        return out
    for i, addr in enumerate(addresses):
        addr = addr.strip()
        if not addr:
            continue
        addr_ip = addr
        addr_port = None
        if ":" in addr and not addr.startswith("["):
            parts = addr.rsplit(":", 1)
            if parts[1].isdigit():
                addr_ip, addr_port = parts[0], parts[1]
        uri = re.sub(
            r"(@)(\[[^\]]+\]|[^:]+)(:|$)",
            lambda m: m.group(1) + addr_ip + m.group(3),
            template,
            count=1,
        )
        if addr_port:
            if re.search(r"@[^:/?#]+:\d+", uri):
                uri = re.sub(r"(@[^:/?#]+:)\d+", lambda m: m.group(1) + addr_port, uri, count=1)
            else:
                uri = re.sub(r"(@[^/?#]+)([?/#])", lambda m: m.group(1) + ":" + addr_port + m.group(2), uri, count=1)
        uri = re.sub(r"#.*$", f"#cfg-{i+1}-{addr_ip[:20]}", uri)
        c = parse_config(uri)
        if c:
            out.append(c)
    return out


def load_addresses(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"  Error reading {path}: {e}")
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(d) for d in data if d]
        if isinstance(data, dict):
            for key in ("addresses", "domains", "ips", "data"):
                if key in data and isinstance(data[key], list):
                    return [str(d) for d in data[key] if d]
    except (json.JSONDecodeError, TypeError):
        pass
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def parse_size(s: str) -> int:
    s = s.strip().upper()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(MB|KB|GB|B)?$", s)
    if not m:
        try:
            return max(1, int(s))
        except ValueError:
            return 1_000_000
    n = float(m.group(1))
    u = m.group(2) or "B"
    mul = {"B": 1, "KB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000}
    return max(1, int(n * mul.get(u, 1)))


def parse_rounds_str(s: str) -> List[RoundCfg]:
    out = []
    for p in s.split(","):
        p = p.strip()
        if ":" in p:
            sz, top = p.split(":", 1)
            try:
                out.append(RoundCfg(parse_size(sz), int(top)))
            except ValueError:
                pass
    return out
