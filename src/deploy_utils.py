import copy
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from typing import List, Optional, Tuple

from src.constants import (
    A,
    ANSI,
    RESULTS_DIR,
    XRAY_BIN_DIR,
    XRAY_HOME,
    DEBUG_LOG,
    SPEED_HOST,
    DEPLOY_XRAY_BIN,
    DEPLOY_XRAY_CONFIG,
    DEPLOY_XRAY_CONFIG_DIR,
    DEPLOY_XRAY_SERVICE,
    DEPLOY_XRAY_SHARE,
    DEPLOY_XRAY_BACKUP_DIR,
    DEPLOY_SYSTEMD_UNIT,
)
from src.config_parse import (
    parse_vless_full,
    parse_vmess_full,
    load_input,
)
from src.models import (
    DeployState,
)
from src.utils import (
    _dbg,
    _read_key_blocking,
    _w,
    _fl,
    _wait_any_key,
    term_size,
    _char_width,
    _vl,
    _results_path,
)
from src.xray_utils import (
    build_vless_uri,
    xray_find_binary,
    xray_install,
    _build_uri,
)
from src.tui import _tui_prompt_text


def deploy_check_prerequisites() -> Tuple[bool, str]:
    """Check that we're on Linux as root with systemd."""
    if sys.platform != "linux":
        return False, f"Server deploy is Linux-only (detected: {sys.platform})"
    try:
        if os.geteuid() != 0:
            return False, "Must run as root (try: sudo python3 scanner.py --deploy)"
    except AttributeError:
        return False, "Cannot detect root status"
    if not shutil.which("systemctl"):
        return False, "systemd not found (systemctl not in PATH)"
    return True, ""


def deploy_detect_server_ip() -> str:
    """Detect server's public IP by querying external services."""
    for url in (
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read(1024).decode().strip()
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return ""


def deploy_check_port(port: int) -> bool:
    """Check if a TCP port is free."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def deploy_generate_uuid() -> str:
    """Generate a random UUID v4."""
    return str(uuid.uuid4())


def deploy_generate_reality_keys(xray_bin: str) -> Tuple[str, str]:
    """Generate x25519 key pair using xray binary. Returns (private, public).

    Handles both output formats:
    - Old: "Private key: xxx\nPublic key: yyy"
    - New: "PrivateKey: xxx\nPassword: yyy"  (Password = public key)
    """
    try:
        kw = {}
        if sys.platform == "win32":
            kw["creationflags"] = 0x08000000
        result = subprocess.run(
            [xray_bin, "x25519"],
            capture_output=True,
            text=True,
            timeout=10,
            **kw,
        )
        if result.returncode != 0:
            return "", ""
        private_key = ""
        public_key = ""
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("private key:") or low.startswith("privatekey:"):
                private_key = line.split(":", 1)[1].strip()
            elif low.startswith("public key:") or low.startswith("publickey:"):
                public_key = line.split(":", 1)[1].strip()
            elif low.startswith("password:"):
                # New xray format: "Password" is the public key
                public_key = line.split(":", 1)[1].strip()
        return private_key, public_key
    except (OSError, subprocess.SubprocessError, ValueError):
        return "", ""


def deploy_generate_short_id() -> str:
    """Generate a random short ID (8 hex chars) for REALITY."""
    return os.urandom(4).hex()


def _build_single_inbound(parsed: dict, ds: "DeployState", index: int) -> dict:
    """Build a single server inbound from a parsed client config dict."""
    protocol = parsed.get("protocol", "vless")
    if protocol not in ("vless", "vmess"):
        raise ValueError(f"Unsupported protocol: {protocol}")
    try:
        raw_port = ds.listen_port if index == 0 else int(parsed.get("port", 443))
    except (ValueError, TypeError):
        raw_port = 443
    port = raw_port if 1 <= raw_port <= 65535 else 443

    inbound: dict = {
        "tag": f"inbound-{index}",
        "port": port,
        "listen": "::",
        "protocol": protocol,
        "settings": {},
        "streamSettings": {},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }

    # -- Settings (clients) --
    uuid_val = parsed.get("uuid", "")
    if not uuid_val:
        uuid_val = deploy_generate_uuid()
    if protocol == "vmess":
        try:
            alter_id = int(parsed.get("aid", 0))
        except (ValueError, TypeError):
            alter_id = 0
        inbound["settings"] = {
            "clients": [
                {
                    "id": uuid_val,
                    "alterId": alter_id,
                }
            ],
        }
    else:  # vless
        client: dict = {"id": uuid_val}
        flow = parsed.get("flow", "")
        if flow:
            client["flow"] = flow
        inbound["settings"] = {
            "clients": [client],
            "decryption": "none",
        }

    # -- Stream Settings --
    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "none")
    stream: dict = {"network": net, "security": sec}

    # Security layer
    if sec == "reality":
        sni_val = parsed.get("sni", "") or "www.google.com"
        stream["realitySettings"] = {
            "show": False,
            "dest": f"{sni_val}:443",
            "xver": 0,
            "serverNames": [sni_val],
            "privateKey": ds.reality_private_key,
            "shortIds": [ds.reality_short_id or ""],
        }
    elif sec == "tls":
        tls_settings: dict = {
            "certificates": [
                {
                    "certificateFile": ds.tls_cert_path
                    or "/usr/local/etc/xray/cert.pem",
                    "keyFile": ds.tls_key_path or "/usr/local/etc/xray/key.pem",
                }
            ],
        }
        alpn = parsed.get("alpn", "")
        if alpn:
            tls_settings["alpn"] = alpn.split(",")
        stream["tlsSettings"] = tls_settings

    # Transport layer
    if net == "ws":
        ws_cfg: dict = {"path": parsed.get("path", "/")}
        stream["wsSettings"] = ws_cfg
    elif net == "grpc":
        sn = parsed.get("serviceName") or parsed.get("path", "")
        if sn == "/":
            sn = ""
        stream["grpcSettings"] = {"serviceName": sn or "grpc"}
    elif net in ("h2", "http"):
        host_val = parsed.get("host") or parsed.get("sni", "")
        stream["httpSettings"] = {
            "host": [host_val] if host_val else [],
            "path": parsed.get("path", "/"),
        }
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xhttp_cfg: dict = {"path": parsed.get("path", "/xhttp")}
        mode = parsed.get("mode", "")
        if mode and mode != "auto":
            xhttp_cfg["mode"] = mode
        stream["xhttpSettings"] = xhttp_cfg
    elif net == "tcp":
        htype = parsed.get("headerType", "")
        if htype == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "response": {
                        "version": "1.1",
                        "status": "200",
                        "reason": "OK",
                    },
                },
            }

    inbound["streamSettings"] = stream
    return inbound


def build_server_config(ds: "DeployState") -> dict:
    """Build Xray server JSON config from DeployState."""
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            ],
        },
    }

    for i, parsed in enumerate(ds.parsed_configs):
        inbound = _build_single_inbound(parsed, ds, i)
        config["inbounds"].append(inbound)

    ds.server_config = config
    return config


def build_client_uri_for_server(
    parsed: dict, ds: "DeployState", tag: str, index: int = 0
) -> str:
    """Build a client URI pointing to the deployed server."""
    p = copy.copy(parsed)
    p["address"] = ds.server_ip
    try:
        p["port"] = int(ds.listen_port if index == 0 else parsed.get("port", 443))
    except (ValueError, TypeError):
        p["port"] = 443
    if p.get("security") == "reality" and ds.reality_public_key:
        p["pbk"] = ds.reality_public_key
    if p.get("security") == "reality" and ds.reality_short_id:
        p["sid"] = ds.reality_short_id

    sni = p.get("sni") or p.get("host") or ""
    return _build_uri(p, sni, tag)


def deploy_fresh_config(
    protocol: str,
    transport: str,
    security: str,
    port: int,
    uuid_val: str,
    sni: str,
    ds: "DeployState",
) -> dict:
    """Generate a fresh parsed-config dict for from-scratch deployment."""
    parsed = {
        "protocol": protocol,
        "uuid": uuid_val,
        "address": ds.server_ip,
        "port": port,
        "name": f"cfedge-{protocol}-{transport}",
        "type": transport,
        "security": security,
        "sni": sni,
        "host": sni,
        "path": (
            "/ws"
            if transport == "ws"
            else (
                "/xhttp"
                if transport in ("xhttp", "splithttp")
                else ("/" if transport in ("h2", "http") else "")
            )
        ),
        "fp": "chrome",
        "flow": (
            "xtls-rprx-vision"
            if (protocol == "vless" and security == "reality" and transport == "tcp")
            else ""
        ),
        "alpn": "h2,http/1.1" if security == "tls" else "",
        "encryption": "none",
        "serviceName": "grpc" if transport == "grpc" else "",
        "headerType": "",
        "mode": "auto" if transport in ("xhttp", "splithttp") else "",
        "pbk": ds.reality_public_key if security == "reality" else "",
        "sid": ds.reality_short_id if security == "reality" else "",
        "spx": "",
    }
    if protocol == "vmess":
        parsed["aid"] = 0
        parsed["scy"] = "auto"
    return parsed


def generate_configless_base(
    server: str,
    port: int,
    uuid_val: str,
    protocol: str = "vless",
) -> List[Tuple[str, dict]]:
    """Generate base (uri, parsed) configs for config-less pipeline mode.

    Creates ws/tls and xhttp/tls variants (plus vmess/ws/tls if vmess protocol).
    Returns list of (uri_string, parsed_dict) tuples.
    """
    results: List[Tuple[str, dict]] = []
    default_sni = SPEED_HOST

    transports = ["ws", "xhttp"]
    for transport in transports:
        path = "/ws" if transport == "ws" else "/xhttp"
        parsed = {
            "protocol": protocol,
            "uuid": uuid_val,
            "address": server,
            "port": port,
            "name": f"cfedge-{protocol}-{transport}",
            "type": transport,
            "security": "tls",
            "sni": default_sni,
            "host": default_sni,
            "path": path,
            "fp": "chrome",
            "flow": "",
            "alpn": "h2,http/1.1",
            "encryption": "none",
            "serviceName": "",
            "headerType": "",
            "pbk": "",
            "sid": "",
            "spx": "",
            "mode": "auto" if transport == "xhttp" else "",
        }
        if protocol == "vmess":
            parsed["aid"] = 0
            parsed["scy"] = "auto"
        uri = _build_uri(parsed, default_sni, parsed["name"])
        results.append((uri, parsed))

    # If VMess, also add a VLESS ws/tls variant for broader testing
    if protocol == "vmess":
        vless_parsed = {
            "protocol": "vless",
            "uuid": uuid_val,
            "address": server,
            "port": port,
            "name": "cfedge-vless-ws",
            "type": "ws",
            "security": "tls",
            "sni": default_sni,
            "host": default_sni,
            "path": "/ws",
            "fp": "chrome",
            "flow": "",
            "alpn": "h2,http/1.1",
            "encryption": "none",
            "serviceName": "",
            "headerType": "",
            "pbk": "",
            "sid": "",
            "spx": "",
            "mode": "",
        }
        vless_uri = build_vless_uri(vless_parsed, default_sni, "cfedge-vless-ws")
        results.append((vless_uri, vless_parsed))

    return results


# ─── Xray Server Deploy — Pipeline Functions ─────────────────────────────


def deploy_install_xray_system() -> Tuple[bool, str]:
    """Install xray to /usr/local/bin/ with geo files. Returns (ok, message)."""
    if os.path.isfile(DEPLOY_XRAY_BIN):
        try:
            result = subprocess.run(
                [DEPLOY_XRAY_BIN, "version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ver = (
                    result.stdout.strip().splitlines()[0]
                    if result.stdout.strip()
                    else "unknown"
                )
                return True, f"Xray already installed: {ver}"
        except (OSError, subprocess.SubprocessError):
            pass

    local_bin = xray_find_binary()
    if not local_bin:
        local_bin = xray_install()
    if not local_bin:
        return False, "Failed to download Xray binary"

    try:
        os.makedirs(os.path.dirname(DEPLOY_XRAY_BIN), exist_ok=True)
        shutil.copy2(local_bin, DEPLOY_XRAY_BIN)
        os.chmod(DEPLOY_XRAY_BIN, 0o755)
    except OSError as e:
        return False, f"Failed to install to {DEPLOY_XRAY_BIN}: {e}"

    try:
        os.makedirs(DEPLOY_XRAY_SHARE, exist_ok=True)
        for gf in ("geoip.dat", "geosite.dat"):
            src = os.path.join(XRAY_BIN_DIR, gf)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(DEPLOY_XRAY_SHARE, gf))
    except OSError:
        pass  # geo files are optional

    return True, f"Installed to {DEPLOY_XRAY_BIN}"


def deploy_write_config(ds: "DeployState") -> Tuple[bool, str]:
    """Write server config JSON with backup of existing."""
    try:
        os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
        if os.path.isfile(DEPLOY_XRAY_CONFIG):
            os.makedirs(DEPLOY_XRAY_BACKUP_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            backup = os.path.join(DEPLOY_XRAY_BACKUP_DIR, f"config_{ts}.json")
            shutil.copy2(DEPLOY_XRAY_CONFIG, backup)

        config_str = json.dumps(ds.server_config, indent=2, ensure_ascii=False)
        tmp_path = DEPLOY_XRAY_CONFIG + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(config_str + "\n")
            os.replace(tmp_path, DEPLOY_XRAY_CONFIG)
        except BaseException:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        return True, DEPLOY_XRAY_CONFIG
    except OSError as e:
        return False, f"Failed to write config: {e}"


def deploy_validate_config() -> Tuple[bool, str]:
    """Run xray to validate the config file."""
    try:
        result = subprocess.run(
            [DEPLOY_XRAY_BIN, "run", "-test", "-c", DEPLOY_XRAY_CONFIG],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, "Config validated OK"
        err_msg = (result.stderr or result.stdout).strip()[:200]
        return False, f"Config validation failed: {err_msg}"
    except FileNotFoundError:
        return False, "Xray binary not found — cannot validate config"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Validation error: {e}"


def deploy_setup_certbot(domain: str) -> Tuple[bool, str, str]:
    """Try to obtain TLS cert via certbot. Returns (ok, cert_path, key_path)."""
    if not domain:
        return False, "", ""
    # Validate domain: must look like a hostname (no flags, no special chars)
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$", domain):
        return False, "", ""
    # Certbot standalone needs port 80
    if not deploy_check_port(80):
        return False, "", ""
    certbot = shutil.which("certbot")
    if not certbot:
        for cmd in (
            ["apt-get", "install", "-y", "certbot"],
            ["yum", "install", "-y", "certbot"],
            ["dnf", "install", "-y", "certbot"],
        ):
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=120)
                if result.returncode == 0:
                    certbot = shutil.which("certbot")
                    break
            except (OSError, subprocess.SubprocessError):
                continue

    if not certbot:
        return False, "", ""

    try:
        result = subprocess.run(
            [
                certbot,
                "certonly",
                "--standalone",
                "--agree-tos",
                "--register-unsafely-without-email",
                "-d",
                domain,
                "--non-interactive",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            key = f"/etc/letsencrypt/live/{domain}/privkey.pem"
            if os.path.isfile(cert) and os.path.isfile(key):
                # Copy certs to xray config dir for reliable access
                try:
                    os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
                    dst_cert = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "cert.pem")
                    dst_key = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "key.pem")
                    shutil.copy2(cert, dst_cert)
                    shutil.copy2(key, dst_key)
                    os.chmod(dst_cert, 0o644)
                    os.chmod(dst_key, 0o600)
                    return True, dst_cert, dst_key
                except OSError:
                    return True, cert, key
        return False, "", ""
    except (OSError, subprocess.SubprocessError):
        return False, "", ""


def deploy_systemd_service() -> Tuple[bool, str]:
    """Write systemd unit, enable and start xray service."""
    try:
        with open(DEPLOY_XRAY_SERVICE, "w", encoding="utf-8") as f:
            f.write(DEPLOY_SYSTEMD_UNIT)
    except OSError as e:
        return False, f"Failed to write service file: {e}"

    for cmd, label in [
        (["systemctl", "daemon-reload"], "daemon-reload"),
        (["systemctl", "enable", "xray"], "enable"),
        (["systemctl", "restart", "xray"], "start"),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return False, f"systemctl {label} failed: {result.stderr.strip()[:100]}"
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"systemctl {label} error: {e}"

    time.sleep(1)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip() == "active":
            return True, "Xray service running"
        return False, f"Service status: {result.stdout.strip()}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Status check failed: {e}"


def deploy_run_pipeline(ds: "DeployState", print_fn) -> bool:
    """Run the full deploy pipeline. Returns True on success."""

    # Direct Mode: write config.json + systemd
    steps = [
        ("Installing Xray binary", deploy_install_xray_system),
        ("Writing server config", lambda: deploy_write_config(ds)),
        ("Validating config", deploy_validate_config),
        ("Setting up systemd service", deploy_systemd_service),
    ]

    for label, step_fn in steps:
        print_fn(f"  [{label}]...")
        ok, msg = step_fn()
        if ok:
            print_fn(f"    OK: {msg}")
            ds.steps_done.append(label)
        else:
            print_fn(f"    FAILED: {msg}")
            ds.error = f"{label}: {msg}"
            return False

    # Generate client URIs
    ds.client_uris = []
    try:
        for i, parsed in enumerate(ds.parsed_configs):
            tag = f"cfedge-{parsed.get('protocol', 'vless')}-{i + 1}"
            uri = build_client_uri_for_server(parsed, ds, tag, index=i)
            ds.client_uris.append(uri)
    except (KeyError, ValueError, TypeError) as e:
        print_fn(f"    FAILED to generate client URIs: {e}")
        ds.error = f"URI generation: {e}"
        return False

    return True


def deploy_save_results(ds: "DeployState") -> str:
    """Save client URIs and deployment info to results/deploy_<ts>.txt."""
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = _results_path(f"deploy_{ts}.txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# Xray Server Deploy - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Server IP: {ds.server_ip}\n")
            f.write(f"# Port: {ds.listen_port}\n")
            f.write(f"# Config: {DEPLOY_XRAY_CONFIG}\n\n")
            f.write("# Client URIs (paste into v2rayNG / Nekobox / Hiddify):\n\n")
            for uri in ds.client_uris:
                f.write(uri + "\n")
            f.write(f"\n# Server config JSON:\n")
            f.write(json.dumps(ds.server_config, indent=2) + "\n")
        return path
    except OSError as e:
        _dbg(f"deploy_save_results failed: {e}")
        return ""


# ─── Xray Server Deploy — Server Config Management ───────────────────────────


def _read_server_config() -> Optional[dict]:
    """Read and parse the xray server config."""
    try:
        with open(DEPLOY_XRAY_CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return None


def _write_server_config(config: dict) -> bool:
    """Write xray server config atomically with backup. Returns True on success."""
    os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
    backup_dir = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    # Validate JSON serialisable before touching disk
    try:
        data = json.dumps(config, indent=2)
    except (TypeError, ValueError):
        return False
    # Backup existing config
    if os.path.isfile(DEPLOY_XRAY_CONFIG):
        ts = time.strftime("%Y%m%d_%H%M%S")
        try:
            shutil.copy2(
                DEPLOY_XRAY_CONFIG, os.path.join(backup_dir, f"config_{ts}.json")
            )
        except OSError:
            pass
    # Atomic write: write to tmp then rename
    tmp_path = DEPLOY_XRAY_CONFIG + ".tmp"
    try:
        _fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp_path, DEPLOY_XRAY_CONFIG)
        return True
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


def _restart_xray_service() -> Tuple[bool, str]:
    """Restart xray via systemctl. Returns (success, message)."""
    if sys.platform in ("win32", "darwin"):
        return False, "systemctl not available on this platform"
    try:
        result = subprocess.run(
            ["systemctl", "restart", "xray"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return False, f"restart failed: {result.stderr.strip()[:100]}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"restart error: {e}"
    time.sleep(1)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip() == "active":
            return True, "Xray service running"
        return False, f"Service status: {result.stdout.strip()}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Status check: {e}"


def _parse_inbound_summary(inbound: dict) -> dict:
    """Extract readable summary from a server inbound config."""
    stream = inbound.get("streamSettings") or {}
    if isinstance(stream, str):
        try:
            stream = json.loads(stream)
        except (ValueError, TypeError):
            stream = {}
    if not isinstance(stream, dict):
        stream = {}
    clients = []
    settings = inbound.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except (ValueError, TypeError):
            settings = {}
    if not isinstance(settings, dict):
        settings = {}
    if isinstance(settings.get("clients"), list):
        clients = settings["clients"]
    return {
        "tag": inbound.get("remark") or inbound.get("tag", "?"),
        "id": inbound.get("id"),
        "protocol": inbound.get("protocol", "?"),
        "port": inbound.get("port", "?"),
        "transport": stream.get("network", "tcp"),
        "security": stream.get("security", "none"),
        "users": len(clients),
    }


def _cm_build_client_uri(inbound: dict, uuid_val: str, server_ip: str) -> Optional[str]:
    """Build a client URI from an existing inbound config + UUID. Returns None on failure."""
    try:
        stream = inbound.get("streamSettings") or {}
        if isinstance(stream, str):
            stream = json.loads(stream)
        if not isinstance(stream, dict):
            stream = {}
        protocol = inbound.get("protocol", "vless")
        port = int(inbound.get("port", 443))
        transport = stream.get("network", "tcp")
        security = stream.get("security", "none")
        parsed: dict = {
            "protocol": protocol,
            "address": server_ip,
            "port": port,
            "uuid": uuid_val,
            "type": transport,
            "security": security,
            "fp": "chrome",
        }
        # Transport paths
        if transport == "ws":
            ws = stream.get("wsSettings") or {}
            parsed["path"] = ws.get("path", "/ws")
            parsed["host"] = ws.get("headers", {}).get("Host", "")
        elif transport in ("xhttp", "splithttp"):
            parsed["type"] = "xhttp"
            xh = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
            parsed["path"] = xh.get("path", "/xhttp")
        elif transport == "grpc":
            gs = stream.get("grpcSettings") or {}
            parsed["serviceName"] = gs.get("serviceName", "grpc")
        elif transport in ("h2", "http"):
            hs = stream.get("httpSettings") or {}
            parsed["path"] = hs.get("path", "/h2")
        # Security: REALITY
        sni = ""
        if security == "reality":
            rs = stream.get("realitySettings") or {}
            snames = rs.get("serverNames") or []
            sni = snames[0] if snames else ""
            parsed["sni"] = sni
            sid_list = rs.get("shortIds") or []
            parsed["sid"] = sid_list[0] if sid_list else ""
            # Derive public key from private key
            priv = rs.get("privateKey", "")
            if priv:
                _xbin = xray_find_binary(None)
                if _xbin:
                    try:
                        kw = {}
                        if sys.platform == "win32":
                            kw["creationflags"] = 0x08000000
                        r = subprocess.run(
                            [_xbin, "x25519", "-i", priv],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            **kw,
                        )
                        for line in r.stdout.strip().splitlines():
                            if line.strip().lower().startswith("public key:"):
                                parsed["pbk"] = line.split(":", 1)[1].strip()
                                break
                    except (OSError, subprocess.SubprocessError):
                        pass
            if protocol == "vless" and transport == "tcp":
                parsed["flow"] = "xtls-rprx-vision"
        elif security == "tls":
            tls_s = stream.get("tlsSettings") or {}
            sni = tls_s.get("serverName", "")
            parsed["sni"] = sni
        tag = f"cfedge-{protocol}-{port}"
        return _build_uri(parsed, sni, tag)
    except (KeyError, ValueError, TypeError, IndexError):
        return None


# ─── Xray Server Deploy — TUI Functions ──────────────────────────────────────


def _tui_deploy_detect_ip(ds: "DeployState"):
    """Auto-detect server IP and prompt for override."""
    _w(f"\n {A.DIM}Detecting server IP...{A.RST}")
    _fl()
    ds.server_ip = deploy_detect_server_ip()
    if ds.server_ip:
        _w(f" {A.GRN}{ds.server_ip}{A.RST}\n")
    else:
        _w(f" {A.YEL}could not detect{A.RST}\n")
    _w(f" {A.BOLD}Server IP [{ds.server_ip or 'enter manually'}]:{A.RST} ")
    _fl()
    try:
        ip_input = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return False
    if ip_input:
        try:
            ipaddress.ip_address(ip_input)
            ds.server_ip = ip_input
        except ValueError:
            _w(f" {A.RED}Invalid IP address.{A.RST}\n")
            _fl()
            time.sleep(1)
            return False
    if not ds.server_ip:
        _w(f" {A.RED}No server IP.{A.RST}\n")
        _fl()
        time.sleep(1)
        return False
    return True


def _tui_deploy_handle_security(parsed: dict, ds: "DeployState") -> bool:
    """Handle REALITY key gen or TLS cert setup for an existing config."""
    sec = parsed.get("security", "none")
    if sec == "reality":
        _w(f"\n {A.DIM}Generating REALITY keys...{A.RST}")
        _fl()
        xray_bin = xray_find_binary() or ""
        if not xray_bin:
            xray_bin = xray_install() or ""
        if not xray_bin:
            _w(f" {A.RED}Need Xray to generate keys.{A.RST}\n")
            _fl()
            time.sleep(2)
            return False
        priv, pub = deploy_generate_reality_keys(xray_bin)
        if not priv or not pub:
            _w(f" {A.RED}Key generation failed.{A.RST}\n")
            _fl()
            time.sleep(2)
            return False
        ds.reality_private_key = priv
        ds.reality_public_key = pub
        ds.reality_short_id = deploy_generate_short_id()
        parsed["pbk"] = pub
        parsed["sid"] = ds.reality_short_id
        _w(f" {A.GRN}OK{A.RST}\n")
    elif sec == "tls":
        _w(f"\n {A.BOLD}TLS Certificate:{A.RST}\n")
        _w(f"  {A.CYN}1{A.RST}. Auto-obtain via certbot\n")
        _w(f"  {A.CYN}2{A.RST}. Enter cert/key paths\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            cc = input().strip() or "1"
        except (EOFError, KeyboardInterrupt, OSError):
            return False
        ds.tls_domain = parsed.get("sni", "") or parsed.get("host", "")
        if cc == "1" and not ds.tls_domain:
            _w(
                f" {A.YEL}No domain found in config. Enter cert paths manually.{A.RST}\n"
            )
            cc = "2"
        if cc == "1" and ds.tls_domain:
            _w(f" {A.DIM}Running certbot for {ds.tls_domain}...{A.RST}\n")
            _fl()
            ok, cert, key = deploy_setup_certbot(ds.tls_domain)
            if ok:
                ds.tls_cert_path = cert
                ds.tls_key_path = key
                _w(f" {A.GRN}Certificate obtained!{A.RST}\n")
            else:
                _w(f" {A.RED}Certbot failed. Enter paths manually.{A.RST}\n")
                cc = "2"
        if cc == "2":
            _w(f" {A.CYN}Certificate file path:{A.RST} ")
            _fl()
            try:
                ds.tls_cert_path = input().strip()
            except (EOFError, KeyboardInterrupt, OSError):
                return False
            _w(f" {A.CYN}Private key file path:{A.RST} ")
            _fl()
            try:
                ds.tls_key_path = input().strip()
            except (EOFError, KeyboardInterrupt, OSError):
                return False
            if not os.path.isfile(ds.tls_cert_path) or not os.path.isfile(
                ds.tls_key_path
            ):
                _w(f" {A.RED}Cert/key files not found.{A.RST}\n")
                _fl()
                time.sleep(1)
                return False
    return True


def _tui_deploy_fresh_wizard(ds: "DeployState") -> Optional["DeployState"]:
    """Wizard for generating a fresh Xray server config (supports multiple configs)."""
    if not _tui_deploy_detect_ip(ds):
        return None

    ds.parsed_configs = []
    config_num = 0
    _reality_done = False
    _tls_done = False
    _saved_reality_sni = ""
    _saved_tls_sni = ""

    while True:
        if config_num > 0:
            _w(f"\n {A.BOLD}{A.CYN}── Config #{config_num + 1} ──{A.RST}\n")

        # Protocol
        _w(f"\n {A.BOLD}Protocol:{A.RST}\n")
        _w(f"  {A.CYN}1{A.RST}. VLESS {A.GRN}(recommended){A.RST}\n")
        _w(f"  {A.CYN}2{A.RST}. VMess\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            proto = input().strip() or "1"
        except (EOFError, KeyboardInterrupt, OSError):
            break
        protocol = "vmess" if proto == "2" else "vless"

        # Security
        _w(f"\n {A.BOLD}Security:{A.RST}\n")
        _w(
            f"  {A.CYN}1{A.RST}. REALITY (no certs needed) {A.GRN}(recommended){A.RST}\n"
        )
        _w(f"  {A.CYN}2{A.RST}. TLS (needs domain + certificate)\n")
        _w(f"  {A.CYN}3{A.RST}. None (no encryption)\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            sec_choice = input().strip() or "1"
        except (EOFError, KeyboardInterrupt, OSError):
            break
        security = {"1": "reality", "2": "tls", "3": "none"}.get(sec_choice, "reality")

        if security == "reality" and protocol == "vmess":
            _w(f" {A.YEL}REALITY requires VLESS. Switching to VLESS.{A.RST}\n")
            protocol = "vless"

        # Transport
        _w(f"\n {A.BOLD}Transport:{A.RST}\n")
        if security == "reality":
            _w(
                f"  {A.CYN}1{A.RST}. TCP (+ XTLS Vision) {A.GRN}(recommended for REALITY){A.RST}\n"
            )
            _w(f"  {A.CYN}2{A.RST}. gRPC\n")
            _w(f"  {A.CYN}3{A.RST}. H2\n")
        else:
            _w(f"  {A.CYN}1{A.RST}. TCP\n")
            _w(f"  {A.CYN}2{A.RST}. WebSocket {A.GRN}(CDN-compatible){A.RST}\n")
            _w(f"  {A.CYN}3{A.RST}. gRPC {A.GRN}(CDN-compatible){A.RST}\n")
            _w(f"  {A.CYN}4{A.RST}. H2\n")
            _w(f"  {A.CYN}5{A.RST}. XHTTP {A.GRN}(CDN-compatible){A.RST}\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            trans_choice = input().strip() or "1"
        except (EOFError, KeyboardInterrupt, OSError):
            break
        if security == "reality":
            transport = {"1": "tcp", "2": "grpc", "3": "h2"}.get(trans_choice, "tcp")
        else:
            transport = {
                "1": "tcp",
                "2": "ws",
                "3": "grpc",
                "4": "h2",
                "5": "xhttp",
            }.get(trans_choice, "tcp")

        # Port
        if config_num == 0:
            _w(f"\n {A.BOLD}Port [443]:{A.RST} ")
            _fl()
            try:
                port_input = input().strip() or "443"
            except (EOFError, KeyboardInterrupt, OSError):
                break
            try:
                port = int(port_input)
                if not (1 <= port <= 65535):
                    port = 443
            except ValueError:
                port = 443
            ds.listen_port = port

            # Check if port is free
            if not deploy_check_port(port):
                _w(
                    f" {A.YEL}Warning: port {port} is already in use by another process{A.RST}\n"
                )
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt, OSError):
                    break
                if _pc not in ("y", "yes"):
                    break
        else:
            port = ds.listen_port + config_num
            _w(f"\n {A.DIM}Port: {port}{A.RST}\n")

        # SNI / domain
        sni = ""
        if security == "reality":
            if _saved_reality_sni and config_num > 0:
                sni = _saved_reality_sni
                _w(f"\n {A.DIM}REALITY dest: {sni} (reusing){A.RST}\n")
            else:
                _w(f"\n {A.BOLD}REALITY dest domain [www.google.com]:{A.RST} ")
                _fl()
                try:
                    sni = input().strip() or "www.google.com"
                except (EOFError, KeyboardInterrupt, OSError):
                    break
                _saved_reality_sni = sni
        elif security == "tls":
            if _saved_tls_sni and config_num > 0:
                sni = _saved_tls_sni
                _w(f"\n {A.DIM}TLS domain: {sni} (reusing){A.RST}\n")
            else:
                _w(f"\n {A.BOLD}Domain for TLS certificate:{A.RST} ")
                _fl()
                try:
                    sni = input().strip()
                except (EOFError, KeyboardInterrupt, OSError):
                    break
                if not sni:
                    _w(f" {A.RED}Domain required for TLS.{A.RST}\n")
                    _fl()
                    time.sleep(1)
                    break
                _saved_tls_sni = sni
                ds.tls_domain = sni

        # Generate UUID
        uuid_val = deploy_generate_uuid()
        _w(f"\n {A.DIM}Generated UUID: {uuid_val}{A.RST}\n")

        # Generate REALITY keys (once)
        if security == "reality" and not _reality_done:
            _w(f" {A.DIM}Generating REALITY keys...{A.RST}")
            _fl()
            xray_bin = xray_find_binary() or ""
            if not xray_bin:
                _w(f" {A.YEL}installing Xray first...{A.RST}")
                _fl()
                xray_bin = xray_install() or ""
            if not xray_bin:
                _w(f" {A.RED}Failed to install Xray.{A.RST}\n")
                _fl()
                time.sleep(2)
                break
            priv, pub = deploy_generate_reality_keys(xray_bin)
            if not priv or not pub:
                _w(f" {A.RED}Key generation failed.{A.RST}\n")
                _fl()
                time.sleep(2)
                break
            ds.reality_private_key = priv
            ds.reality_public_key = pub
            ds.reality_short_id = deploy_generate_short_id()
            _w(f" {A.GRN}OK{A.RST}\n")
            _reality_done = True
        elif security == "reality":
            _w(f" {A.DIM}Reusing REALITY keys{A.RST}\n")

        # Handle TLS certs (once)
        if security == "tls" and not _tls_done:
            _tmp_parsed = {"security": "tls", "sni": sni, "host": sni}
            if not _tui_deploy_handle_security(_tmp_parsed, ds):
                break
            _tls_done = True
        elif security == "tls":
            _w(f" {A.DIM}Reusing TLS certificate{A.RST}\n")

        # Build this config
        parsed = deploy_fresh_config(
            protocol, transport, security, port, uuid_val, sni, ds
        )
        parsed["port"] = port
        ds.parsed_configs.append(parsed)
        config_num += 1

        _w(
            f"\n {A.GRN}Config #{config_num} added: {protocol}/{transport}/{security} on port {port}{A.RST}\n"
        )
        _w(f"\n {A.CYN}Add another config? [y/N]:{A.RST} ")
        _fl()
        try:
            again = input().strip().lower()
        except (EOFError, KeyboardInterrupt, OSError):
            break
        if again not in ("y", "yes"):
            break

    if not ds.parsed_configs:
        return None
    build_server_config(ds)
    return ds


def _tui_deploy_from_uri(ds: "DeployState") -> Optional["DeployState"]:
    """Deploy from an existing VLESS/VMess URI."""
    _w(f"\n {A.BOLD}Paste VLESS/VMess URI:{A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None

    parsed = parse_vless_full(uri) or parse_vmess_full(uri)
    if not parsed:
        _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    ds.source_uris = [uri]
    ds.parsed_configs = [parsed]

    if not _tui_deploy_detect_ip(ds):
        return None

    try:
        ds.listen_port = int(parsed.get("port", 443))
    except (ValueError, TypeError):
        ds.listen_port = 443
    if not (1 <= ds.listen_port <= 65535):
        ds.listen_port = 443
    _w(f" {A.BOLD}Port [{ds.listen_port}]:{A.RST} ")
    _fl()
    try:
        port_in = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    if port_in:
        try:
            pv = int(port_in)
            if 1 <= pv <= 65535:
                ds.listen_port = pv
        except ValueError:
            pass

    # Reject VMess + REALITY (not supported by Xray)
    if parsed.get("protocol") == "vmess" and parsed.get("security") == "reality":
        _w(f" {A.RED}VMess + REALITY is not supported. Use VLESS instead.{A.RST}\n")
        _fl()
        time.sleep(2)
        return None

    if not _tui_deploy_handle_security(parsed, ds):
        return None

    parsed["address"] = ds.server_ip
    build_server_config(ds)
    return ds


def _tui_deploy_from_file(ds: "DeployState") -> Optional["DeployState"]:
    """Deploy from a file of URIs."""
    _w(f" {A.CYN}File path:{A.RST} ")
    _fl()
    try:
        path = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    if not os.path.isfile(path):
        _w(f" {A.RED}File not found.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    configs = load_input(path)
    if not configs:
        _w(f" {A.RED}No valid configs found.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    for c in configs:
        if c.original_uri:
            parsed = parse_vless_full(c.original_uri) or parse_vmess_full(
                c.original_uri
            )
            if parsed:
                ds.source_uris.append(c.original_uri)
                ds.parsed_configs.append(parsed)

    if not ds.parsed_configs:
        _w(f" {A.RED}No parseable VLESS/VMess URIs in file.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    _w(f" {A.GRN}Found {len(ds.parsed_configs)} config(s){A.RST}\n")

    if not _tui_deploy_detect_ip(ds):
        return None

    try:
        ds.listen_port = int(ds.parsed_configs[0].get("port", 443))
    except (ValueError, TypeError):
        ds.listen_port = 443
    if not (1 <= ds.listen_port <= 65535):
        ds.listen_port = 443
    _w(f" {A.BOLD}Port [{ds.listen_port}]:{A.RST} ")
    _fl()
    try:
        port_in = input().strip()
    except (EOFError, KeyboardInterrupt, OSError):
        return None
    if port_in:
        try:
            pv = int(port_in)
            if 1 <= pv <= 65535:
                ds.listen_port = pv
        except ValueError:
            pass

    # Filter out VMess + REALITY (not supported) -- keep source_uris in sync
    paired = [
        (u, p)
        for u, p in zip(ds.source_uris, ds.parsed_configs)
        if not (p.get("protocol") == "vmess" and p.get("security") == "reality")
    ]
    skipped = len(ds.parsed_configs) - len(paired)
    if skipped:
        _w(
            f" {A.YEL}Skipped {skipped} VMess+REALITY config(s) (not supported){A.RST}\n"
        )
    if not paired:
        _w(f" {A.RED}No valid configs after filtering.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None
    ds.source_uris = [u for u, _ in paired]
    ds.parsed_configs = [p for _, p in paired]

    # Warn about mixed security types
    sec_types = set(p.get("security", "none") for p in ds.parsed_configs)
    if len(sec_types) > 1:
        _w(
            f" {A.YEL}Warning: mixed security types ({', '.join(sec_types)}). "
            f"Keys/certs configured for first config only.{A.RST}\n"
        )
        _fl()

    if not _tui_deploy_handle_security(ds.parsed_configs[0], ds):
        return None

    for p in ds.parsed_configs:
        p["address"] = ds.server_ip

    build_server_config(ds)
    return ds


def tui_deploy_input() -> Optional["DeployState"]:
    """Interactive wizard for server deployment.
    Returns a configured DeployState or None.
    """
    _w(A.SHOW)
    _w(f"\n {A.BOLD}{A.CYN}Deploy Xray Server{A.RST}\n")
    _w(
        f" {A.YEL}For:{A.RST} You have a Linux VPS and want to install xray on it (no tunnel).\n"
    )
    _w(
        f" {A.DIM}Installs xray, generates config, starts the service. Run this ON your server.{A.RST}\n\n"
    )

    ok, err = deploy_check_prerequisites()
    if not ok:
        _w(f" {A.RED}ERROR: {err}{A.RST}\n")
        _fl()
        time.sleep(3)
        return None

    ds = DeployState()

    ds.fresh_mode = True
    return _tui_deploy_fresh_wizard(ds)


async def _tui_run_deploy(args, preloaded_uri: str = ""):
    """Run the deploy flow inside TUI."""
    if preloaded_uri:
        ds = DeployState()
        parsed = parse_vless_full(preloaded_uri) or parse_vmess_full(preloaded_uri)
        if parsed:
            ds.source_uris = [preloaded_uri]
            ds.parsed_configs = [parsed]
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Deploy Xray Server{A.RST}\n")
            _w(f" {A.DIM}Deploying best config from xray test.{A.RST}\n")
            ok, err = deploy_check_prerequisites()
            if not ok:
                _w(f" {A.RED}ERROR: {err}{A.RST}\n")
                _fl()
                time.sleep(3)
                return
            if not _tui_deploy_detect_ip(ds):
                return
            try:
                ds.listen_port = int(parsed.get("port", 443))
            except (ValueError, TypeError):
                ds.listen_port = 443
            if not (1 <= ds.listen_port <= 65535):
                ds.listen_port = 443
            if not deploy_check_port(ds.listen_port):
                _w(f" {A.YEL}Warning: port {ds.listen_port} is already in use{A.RST}\n")
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt, OSError):
                    return
                if _pc not in ("y", "yes"):
                    return
            if (
                parsed.get("protocol") == "vmess"
                and parsed.get("security") == "reality"
            ):
                _w(f" {A.RED}VMess + REALITY is not supported.{A.RST}\n")
                _fl()
                time.sleep(2)
                return
            if not _tui_deploy_handle_security(parsed, ds):
                return
            parsed["address"] = ds.server_ip
            build_server_config(ds)
        else:
            _w(f" {A.RED}Failed to parse config URI.{A.RST}\n")
            _fl()
            time.sleep(2)
            return
    else:
        ds = tui_deploy_input()
    if ds is None:
        return

    _w(A.SHOW)
    _w(f"\n {A.BOLD}{A.CYN}Deploying Xray Server{A.RST}\n")
    _w(f" {A.DIM}{'=' * 50}{A.RST}\n\n")

    def tui_print(msg):
        _w(f"{msg}\n")
        _fl()

    success = deploy_run_pipeline(ds, tui_print)

    if success:
        _w(f"\n {A.GRN}{'=' * 50}{A.RST}\n")
        _w(f" {A.BOLD}{A.GRN}Deploy successful!{A.RST}\n")
        _w(f" {A.GRN}{'=' * 50}{A.RST}\n\n")
        _w(f" {A.BOLD}Server:{A.RST} {ds.server_ip}:{ds.listen_port}\n")
        _w(f" {A.BOLD}Config:{A.RST} {DEPLOY_XRAY_CONFIG}\n")
        _w(f" {A.BOLD}Status:{A.RST} systemctl status xray\n\n")

        _w(
            f" {A.BOLD}{A.CYN}Client URIs (paste into v2rayNG / Nekobox / Hiddify):{A.RST}\n\n"
        )
        for uri in ds.client_uris:
            _w(f" {A.GRN}{uri}{A.RST}\n\n")

        save_path = deploy_save_results(ds)
        if save_path:
            _w(f" {A.DIM}Saved to: {save_path}{A.RST}\n")
        else:
            _w(f" {A.RED}Could not save deploy results.{A.RST}\n")
    else:
        _w(f"\n {A.RED}Deploy failed: {ds.error}{A.RST}\n")
        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    # Post-deploy interactive menu
    while True:
        _w(f"\n {A.CYN}[V]{A.RST} View configs/URIs  ")
        _w(f"{A.CYN}[M]{A.RST} Connection Manager  ")
        _w(f"{A.CYN}[Q]{A.RST} Back to menu\n")
        _w(f" Choice: ")
        _fl()
        post_key = _read_key_blocking()
        if isinstance(post_key, str):
            post_key = post_key.lower()
        if post_key in ("q", "esc", "ctrl-c", "b"):
            break
        elif post_key == "v":
            _w(f"\n {A.BOLD}{A.CYN}Client URIs:{A.RST}\n\n")
            for uri in ds.client_uris:
                _w(f" {A.GRN}{uri}{A.RST}\n\n")
            if save_path:
                _w(f" {A.DIM}Saved to: {save_path}{A.RST}\n")
            _fl()
        elif post_key == "m":
            await _tui_connection_manager(args)
            break


# ─── Uninstall ─────────────────────────────────────────────────────────────────


def _uninstall_all() -> Tuple[bool, str]:
    """Remove everything Cloudflare Edge Scanner installed on this system."""
    _out: list = []
    _had_errors = False

    def _log(msg: str):
        _out.append(msg)
        print(f"  {msg}")

    def _log_err(msg: str):
        nonlocal _had_errors
        _had_errors = True
        _out.append(msg)
        print(f"  ERROR: {msg}")

    if sys.platform in ("win32", "darwin"):
        if os.path.isdir(XRAY_HOME):
            shutil.rmtree(XRAY_HOME, ignore_errors=True)
            if os.path.isdir(XRAY_HOME):
                _log_err(f"Could not fully remove {XRAY_HOME}")
            else:
                _log(f"Removed {XRAY_HOME}")
        else:
            _log("Nothing to remove (no local Cloudflare Edge Scanner directory)")
        return not _had_errors, "; ".join(_out)

    # --- 1. Stop xray service ---
    for action in ["stop", "disable"]:
        try:
            subprocess.run(
                ["systemctl", action, "xray"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    _log("Stopped and disabled xray service")

    # --- 2. Remove xray server files ---
    _removed = []
    for path in [DEPLOY_XRAY_SERVICE, DEPLOY_XRAY_BIN]:
        if os.path.isfile(path):
            try:
                os.remove(path)
                _removed.append(path)
            except OSError:
                _log_err(f"Could not remove {path}")
    for dpath in [DEPLOY_XRAY_CONFIG_DIR, DEPLOY_XRAY_SHARE]:
        if os.path.isdir(dpath):
            shutil.rmtree(dpath, ignore_errors=True)
            if os.path.isdir(dpath):
                _log_err(f"Could not fully remove {dpath}")
            else:
                _removed.append(dpath)
    if _removed:
        _log(f"Removed xray server: {', '.join(os.path.basename(p) for p in _removed)}")
    elif not _had_errors:
        _log("No xray server files found")

    # --- 3. Reload systemd ---
    try:
        subprocess.run(
            ["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        pass

    # --- 4. Remove local client dir (~/.cfedge/) ---
    if os.path.isdir(XRAY_HOME):
        shutil.rmtree(XRAY_HOME, ignore_errors=True)
        if os.path.isdir(XRAY_HOME):
            _log_err(f"Could not fully remove {XRAY_HOME}")
        else:
            _log(f"Removed {XRAY_HOME}")
    else:
        _log(f"No local directory at {XRAY_HOME}")

    return not _had_errors, "; ".join(_out)


# ─── Connection Manager (Direct JSON mode) ───────────────────────────────────


async def _tui_connection_manager(args):
    """TUI for managing xray server configs and connections."""
    if sys.platform in ("win32", "darwin"):
        _w(A.SHOW)
        _w(f"\n {A.RED}Connection Manager requires Linux (systemctl).{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    _cm_server_ip = ""  # Cached; detected on first need

    while True:
        # Direct JSON mode only
        config = _read_server_config()
        if config is not None:
            ib_val = config.get("inbounds")
            if not isinstance(ib_val, list):
                ib_val = []
                config["inbounds"] = ib_val
            inbounds = ib_val
        else:
            inbounds = []
        inbound_indices = [i for i, ib in enumerate(inbounds) if isinstance(ib, dict)]

        summaries = [_parse_inbound_summary(inbounds[i]) for i in inbound_indices]

        # Service status
        xray_running = False
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "xray"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            xray_running = r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            pass

        _w(A.CLR + A.HOME + A.SHOW)
        W, _ = term_size()
        W = max(60, W - 2)
        out = []
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        _cmhdr = f" {A.BOLD}{A.CYN}Connection Manager{A.RST}"
        out.append(
            f"{A.CYN}|{A.RST}{_cmhdr}{' ' * max(0, W - _vl(_cmhdr))}{A.CYN}|{A.RST}"
        )
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        # Service status
        def bx(txt):
            vlen = _vl(txt)
            if vlen > W:
                vis = 0
                i = 0
                while i < len(txt) and vis < W - 1:
                    if txt[i] == "\033" and i + 1 < len(txt) and txt[i + 1] == "[":
                        j = i + 2
                        while j < len(txt) and txt[j] != "m":
                            j += 1
                        i = j + 1
                    else:
                        vis += _char_width(txt[i])
                        i += 1
                txt = txt[:i] + A.RST + "..."
                vlen = _vl(txt)
            pad = " " * max(0, W - vlen)
            out.append(f"{A.CYN}|{A.RST}{txt}{pad}{A.CYN}|{A.RST}")

        xray_dot = (
            f"{A.GRN}*{A.RST} running" if xray_running else f"{A.RED}*{A.RST} stopped"
        )
        bx(f"  Xray Service: {xray_dot}  {A.DIM}(system){A.RST}")

        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")

        # Inbounds
        _has_inbounds = bool(summaries)
        if not config:
            bx(f"  {A.DIM}No xray server config found.{A.RST}")
            bx(f"  {A.DIM}Use [D] Deploy to set up xray first.{A.RST}")
        elif not summaries:
            bx(f"  {A.DIM}No inbounds configured.{A.RST}")
        else:
            bx(f"  {A.BOLD}Server Inbounds ({len(summaries)}){A.RST}")
            bx(f"  {A.DIM}{'-' * (W - 4)}{A.RST}")
            hdr = f"  {'#':>2}  {'Protocol':<10} {'Port':>6} {'Transport':<12} {'Security':<10} {'Users':>5}"
            bx(f"{A.BOLD}{hdr}{A.RST}")
            for i, s in enumerate(summaries[:20]):
                line = f"  {i+1:>2}  {s['protocol']:<10} {s['port']:>6} {s['transport']:<12} {s['security']:<10} {s['users']:>5}"
                bx(line)

        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")

        # Footer
        parts = []
        if _has_inbounds:
            parts.append(f"{A.CYN}[V]{A.RST} View")
            parts.append(f"{A.CYN}[S]{A.RST} Show URIs")
            parts.append(f"{A.CYN}[U]{A.RST} Add user")
            parts.append(f"{A.CYN}[X]{A.RST} Remove")
        parts.append(f"{A.CYN}[A]{A.RST} Add inbound")
        parts.append(f"{A.CYN}[R]{A.RST} Restart xray")
        parts.append(f"{A.CYN}[L]{A.RST} Logs")
        parts.append(f"{A.CYN}[D]{A.RST} Uninstall")
        parts.append(f"{A.CYN}[B]{A.RST} Back")
        bx(f"  {'  '.join(parts)}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()

        key = _read_key_blocking()
        if isinstance(key, str):
            key = key.lower()
        if key in ("b", "esc", "q", "ctrl-c"):
            return

        if key == "r":
            _w(f"\n {A.DIM}Restarting xray...{A.RST}\n")
            _fl()
            ok, msg = _restart_xray_service()
            if ok:
                _w(f" {A.GRN}{msg}{A.RST}\n")
            else:
                _w(f" {A.RED}{msg}{A.RST}\n")
            _fl()
            time.sleep(1.5)
            continue

        if key == "l":
            _w(A.CLR + A.HOME)
            _w(f"\n {A.BOLD}{A.CYN}xray Logs (last 30 lines){A.RST}\n")
            _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
            _fl()
            try:
                result = subprocess.run(
                    ["journalctl", "-u", "xray", "-n", "30", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                _w(
                    result.stdout[:3000]
                    if result.stdout
                    else f" {A.DIM}(no logs){A.RST}\n"
                )
            except (OSError, subprocess.SubprocessError) as e:
                _w(f" {A.RED}Failed to read logs: {e}{A.RST}\n")
            _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            continue

        if key == "d":
            _w(A.SHOW)
            _w(f"\n {A.RED}{A.BOLD}Uninstall Xray completely?{A.RST}\n")
            _w(
                f" {A.DIM}This will stop xray, remove the binary, config, and systemd service.{A.RST}\n"
            )
            _w(f"\n {A.RED}Type 'uninstall' to confirm:{A.RST} ")
            _fl()
            try:
                confirm = input().strip().lower()
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            if confirm == "uninstall":
                _w(f"\n {A.DIM}Uninstalling...{A.RST}\n")
                _fl()
                ok, msg = _uninstall_all()
                if ok:
                    _w(f"\n {A.GRN}{msg}{A.RST}\n")
                else:
                    _w(f"\n {A.RED}{msg}{A.RST}\n")
                _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
                _fl()
                _read_key_blocking()
                return
            else:
                _w(f" {A.DIM}Cancelled.{A.RST}\n")
                _fl()
                time.sleep(1)
            continue

        if key == "v" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(f"View which inbound? [1-{len(summaries)}]:")
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        ib_data = inbounds[inbound_indices[sel]]
                        _w(A.CLR + A.HOME)
                        _w(f"\n {A.BOLD}{A.CYN}Inbound #{sel+1}{A.RST}\n")
                        _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
                        pretty = json.dumps(ib_data, indent=2, ensure_ascii=False)
                        _w(f"{pretty[:3000]}\n")
                        _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
                        _fl()
                        _read_key_blocking()
                except (ValueError, IndexError):
                    pass
            continue

        if key == "s" and summaries:
            _w(A.CLR + A.HOME)
            _w(f"\n {A.BOLD}{A.CYN}All Client URIs{A.RST}\n")
            _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
            if not _cm_server_ip:
                _cm_server_ip = deploy_detect_server_ip() or "<server-ip>"
            for i, s in enumerate(summaries):
                real_idx = inbound_indices[i]
                ib_data = inbounds[real_idx]
                settings = ib_data.get("settings") or {}
                clients = settings.get("clients") or []
                _w(
                    f" {A.BOLD}Inbound #{i+1}{A.RST} ({s['protocol']}:{s['port']} {s['transport']}/{s['security']})\n"
                )
                for cl in clients:
                    _cl_uuid = cl.get("id", "")
                    if _cl_uuid:
                        _cl_uri = _cm_build_client_uri(ib_data, _cl_uuid, _cm_server_ip)
                        if _cl_uri:
                            _w(f"   {A.GRN}{_cl_uri}{A.RST}\n")
                _w("\n")
            _w(f" {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            continue

        if key == "u" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(
                f"Add user to which inbound? [1-{len(summaries)}]:"
            )
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        new_uuid = deploy_generate_uuid()
                        _user_add_ok = False
                        real_idx = inbound_indices[sel]
                        ib = inbounds[real_idx]
                        settings = ib.get("settings")
                        if not isinstance(settings, dict):
                            settings = {}
                            ib["settings"] = settings
                        clients = settings.get("clients")
                        if not isinstance(clients, list):
                            clients = []
                            settings["clients"] = clients
                        proto = ib.get("protocol", "vless")
                        new_client = {"id": new_uuid}
                        if proto == "vmess":
                            new_client["alterId"] = 0
                        clients.append(new_client)
                        if _write_server_config(config):
                            ok, msg = _restart_xray_service()
                            _w(f"\n {A.GRN}User added: {new_uuid}{A.RST}\n")
                            if not ok:
                                _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                            _user_add_ok = True
                        else:
                            clients.pop()
                            _w(
                                f"\n {A.RED}Failed to write config (run as root?){A.RST}\n"
                            )
                        if _user_add_ok:
                            if not _cm_server_ip:
                                _cm_server_ip = (
                                    deploy_detect_server_ip() or "<server-ip>"
                                )
                            _u_uri = _cm_build_client_uri(ib, new_uuid, _cm_server_ip)
                            if _u_uri:
                                _w(f"\n {A.BOLD}{A.CYN}Client URI:{A.RST}\n")
                                _w(f" {A.GRN}{_u_uri}{A.RST}\n")
                        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
                        _fl()
                        _wait_any_key()
                except (ValueError, IndexError):
                    pass
            continue

        if key == "x" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(f"Remove which inbound? [1-{len(summaries)}]:")
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        s = summaries[sel]
                        _w(
                            f" {A.YEL}Remove {s['protocol']}:{s['port']}? [y/N]:{A.RST} "
                        )
                        _fl()
                        try:
                            confirm = input().strip().lower()
                        except (EOFError, KeyboardInterrupt, OSError):
                            confirm = ""
                        if confirm in ("y", "yes"):
                            real_idx = inbound_indices[sel]
                            removed = inbounds[real_idx]
                            inbounds.pop(real_idx)
                            if _write_server_config(config):
                                ok, msg = _restart_xray_service()
                                _w(f" {A.GRN}Inbound removed.{A.RST}\n")
                                if not ok:
                                    _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                            else:
                                # Restore in-memory state on write failure
                                inbounds.insert(real_idx, removed)
                                _w(
                                    f" {A.RED}Failed to write config (run as root?){A.RST}\n"
                                )
                            _fl()
                            time.sleep(1.5)
                except (ValueError, IndexError):
                    pass
            continue

        if key == "a":
            # Add inbound wizard
            _w(A.CLR + A.HOME + A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Add New Inbound{A.RST}\n")
            _w(f" {A.DIM}{'-' * 40}{A.RST}\n\n")
            _w(f"  {A.CYN}1{A.RST}. VLESS\n")
            _w(f"  {A.CYN}2{A.RST}. VMess\n")
            _w(f"\n Protocol [1]: ")
            _fl()
            try:
                proto_ch = input().strip() or "1"
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            protocol = "vmess" if proto_ch == "2" else "vless"

            _w(f" Port [443]: ")
            _fl()
            try:
                port_str = input().strip() or "443"
                new_port = int(port_str)
                if not (1 <= new_port <= 65535):
                    _w(f" {A.YEL}Invalid port, using 443{A.RST}\n")
                    new_port = 443
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            except ValueError:
                _w(f" {A.YEL}Invalid port, using 443{A.RST}\n")
                new_port = 443
            # Check for port conflicts -- our own inbounds
            used_ports = {
                int(ib.get("port", 0))
                for ib in inbounds
                if isinstance(ib, dict) and ib.get("port")
            }
            if new_port in used_ports:
                _w(
                    f" {A.YEL}Warning: port {new_port} already used by another inbound{A.RST}\n"
                )
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt, OSError):
                    continue
                if _pc not in ("y", "yes"):
                    continue
            elif not deploy_check_port(new_port):
                _w(
                    f" {A.YEL}Warning: port {new_port} is already in use by another process{A.RST}\n"
                )
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt, OSError):
                    continue
                if _pc not in ("y", "yes"):
                    continue

            _w(f"\n  {A.CYN}1{A.RST}. TCP\n")
            _w(f"  {A.CYN}2{A.RST}. WebSocket (ws)\n")
            _w(f"  {A.CYN}3{A.RST}. XHTTP (xhttp)\n")
            _w(f"  {A.CYN}4{A.RST}. gRPC\n")
            _w(f"  {A.CYN}5{A.RST}. HTTP/2 (h2)\n")
            _w(f"\n Transport [1]: ")
            _fl()
            try:
                tr_ch = input().strip() or "1"
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            tr_map = {"1": "tcp", "2": "ws", "3": "xhttp", "4": "grpc", "5": "h2"}
            transport = tr_map.get(tr_ch, "tcp")

            _w(f"\n  {A.CYN}1{A.RST}. REALITY\n")
            _w(f"  {A.CYN}2{A.RST}. TLS\n")
            _w(f"  {A.CYN}3{A.RST}. None\n")
            _w(f"\n Security [3]: ")
            _fl()
            try:
                sec_ch = input().strip() or "3"
            except (EOFError, KeyboardInterrupt, OSError):
                continue
            sec_map = {"1": "reality", "2": "tls", "3": "none"}
            security = sec_map.get(sec_ch, "none")

            # REALITY needs x25519 keys
            _reality_priv = _reality_pub = _reality_sid = _rsni = ""
            _tls_cert = _tls_key = ""
            if security == "reality":
                _xbin = xray_find_binary(None)
                if not _xbin:
                    _w(
                        f" {A.RED}REALITY requires xray binary for key generation.{A.RST}\n"
                    )
                    _w(
                        f" {A.DIM}Falling back to no security. Use Deploy for REALITY.{A.RST}\n"
                    )
                    _fl()
                    time.sleep(1.5)
                    security = "none"
                else:
                    _reality_priv, _reality_pub = deploy_generate_reality_keys(_xbin)
                    if not _reality_priv:
                        _w(
                            f" {A.RED}Key generation failed. Falling back to none.{A.RST}\n"
                        )
                        _fl()
                        time.sleep(1.5)
                        security = "none"
                    else:
                        _reality_sid = deploy_generate_short_id()
                        _w(f" {A.DIM}SNI for REALITY [www.google.com]:{A.RST} ")
                        _fl()
                        try:
                            _rsni = input().strip() or "www.google.com"
                        except (EOFError, KeyboardInterrupt, OSError):
                            _rsni = "www.google.com"
            elif security == "tls":
                _w(f" {A.DIM}TLS cert path [/usr/local/etc/xray/cert.pem]:{A.RST} ")
                _fl()
                try:
                    _tls_cert = input().strip() or "/usr/local/etc/xray/cert.pem"
                except (EOFError, KeyboardInterrupt, OSError):
                    _tls_cert = "/usr/local/etc/xray/cert.pem"
                _w(f" {A.DIM}TLS key path  [/usr/local/etc/xray/key.pem]:{A.RST} ")
                _fl()
                try:
                    _tls_key = input().strip() or "/usr/local/etc/xray/key.pem"
                except (EOFError, KeyboardInterrupt, OSError):
                    _tls_key = "/usr/local/etc/xray/key.pem"

            new_uuid = deploy_generate_uuid()
            _w(f"\n {A.DIM}Generated UUID: {new_uuid}{A.RST}\n")

            # Build inbound manually (use uuid4 suffix for unique tag)
            _tag_id = deploy_generate_uuid()[:8]
            new_inbound: dict = {
                "tag": f"inbound-{_tag_id}",
                "port": new_port,
                "listen": "::",
                "protocol": protocol,
                "settings": {},
                "streamSettings": {"network": transport, "security": security},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            }

            # Client
            client_entry: dict = {"id": new_uuid}
            if protocol == "vmess":
                client_entry["alterId"] = 0
                new_inbound["settings"] = {"clients": [client_entry]}
            else:
                new_inbound["settings"] = {
                    "clients": [client_entry],
                    "decryption": "none",
                }

            # Transport settings
            stream = new_inbound["streamSettings"]
            if transport == "ws":
                stream["wsSettings"] = {"path": "/ws"}
            elif transport in ("xhttp", "splithttp"):
                stream["network"] = "xhttp"
                stream["xhttpSettings"] = {"path": "/xhttp"}
            elif transport == "grpc":
                stream["grpcSettings"] = {"serviceName": "grpc"}
            elif transport in ("h2", "http"):
                stream["httpSettings"] = {"host": [], "path": "/h2"}

            # Security settings
            if security == "reality" and _reality_priv:
                stream["realitySettings"] = {
                    "show": False,
                    "dest": f"{_rsni}:443",
                    "xver": 0,
                    "serverNames": [_rsni],
                    "privateKey": _reality_priv,
                    "shortIds": [_reality_sid],
                }
                # VLESS+REALITY+TCP needs flow
                if protocol == "vless" and transport == "tcp":
                    client_entry["flow"] = "xtls-rprx-vision"
                _w(f" {A.DIM}Public key: {_reality_pub}{A.RST}\n")
                _w(f" {A.DIM}Short ID:   {_reality_sid}{A.RST}\n")
            elif security == "tls":
                stream["tlsSettings"] = {
                    "certificates": [
                        {
                            "certificateFile": _tls_cert,
                            "keyFile": _tls_key,
                        }
                    ],
                }

            if config is None:
                config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [],
                    "outbounds": [
                        {"tag": "direct", "protocol": "freedom"},
                        {"tag": "block", "protocol": "blackhole"},
                    ],
                    "routing": {
                        "domainStrategy": "AsIs",
                        "rules": [
                            {
                                "type": "field",
                                "ip": ["geoip:private"],
                                "outboundTag": "block",
                            }
                        ],
                    },
                }
                inbounds = config["inbounds"]

            _add_ok = False
            inbounds.append(new_inbound)
            if _write_server_config(config):
                ok, msg = _restart_xray_service()
                _w(
                    f"\n {A.GRN}Inbound added: {protocol}:{new_port} ({transport}/{security}){A.RST}\n"
                )
                if not ok:
                    _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                _add_ok = True
            else:
                inbounds.pop()
                _w(f"\n {A.RED}Failed to write config (run as root?){A.RST}\n")

            # Generate and display client URI after successful add
            if _add_ok:
                if not _cm_server_ip:
                    _cm_server_ip = deploy_detect_server_ip() or "<server-ip>"
                _uri_sni = _rsni or ""
                _uri_parsed = {
                    "protocol": protocol,
                    "address": _cm_server_ip,
                    "port": new_port,
                    "uuid": new_uuid,
                    "type": transport,
                    "security": security,
                    "fp": "chrome",
                }
                if transport == "ws":
                    _uri_parsed["path"] = "/ws"
                    _uri_parsed["host"] = _uri_sni
                elif transport in ("xhttp", "splithttp"):
                    _uri_parsed["type"] = "xhttp"
                    _uri_parsed["path"] = "/xhttp"
                elif transport == "grpc":
                    _uri_parsed["serviceName"] = "grpc"
                elif transport in ("h2", "http"):
                    _uri_parsed["path"] = "/h2"
                if security == "reality" and _reality_pub:
                    _uri_parsed["pbk"] = _reality_pub
                    _uri_parsed["sid"] = _reality_sid
                    _uri_parsed["sni"] = _rsni
                    if protocol == "vless" and transport == "tcp":
                        _uri_parsed["flow"] = "xtls-rprx-vision"
                elif security == "tls":
                    _uri_parsed["sni"] = _uri_sni
                _uri_tag = f"cfedge-{protocol}-{new_port}"
                try:
                    _client_uri = _build_uri(_uri_parsed, _uri_sni, _uri_tag)
                    _w(f"\n {A.BOLD}{A.CYN}Client URI:{A.RST}\n")
                    _w(f" {A.GRN}{_client_uri}{A.RST}\n")
                except (KeyError, ValueError, TypeError) as _uri_err:
                    _w(f" {A.DIM}(Could not generate client URI: {_uri_err}){A.RST}\n")

            _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
            _fl()
            _wait_any_key()
            continue


# ─── End Xray Server Deploy ──────────────────────────────────────────────
