import os
import random
import socket
import ipaddress
from typing import List

VERSION = "1.1"
SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down"
DEBUG_LOG = os.path.join("results", "debug.log")
LOG_MAX_BYTES = 5 * 1024 * 1024

LATENCY_WORKERS = 50
SPEED_WORKERS = 10
LATENCY_TIMEOUT = 5.0
SPEED_TIMEOUT = 30.0

CDN_FALLBACK = ("cloudflaremirrors.com", "/archlinux/iso/latest/archlinux-x86_64.iso")

CF_SUBNETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13",
]

CF_HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

CLEAN_MODES = {
    "quick":  {"label": "Quick",  "sample": 1, "workers": 500,  "validate": False,
               "ports": [443], "desc": "1 random IP per /24 (~4K IPs, ~30s)"},
    "normal": {"label": "Normal", "sample": 3, "workers": 500,  "validate": True,
               "ports": [443], "desc": "3 IPs per /24 + CF verify (~12K IPs, ~2 min)"},
    "full":   {"label": "Full",   "sample": 0, "workers": 1000, "validate": True,
               "ports": [443], "desc": "All IPs + CF verify (~1.5M IPs, 20+ min)"},
    "mega":   {"label": "Mega",   "sample": 0, "workers": 1500, "validate": True,
               "ports": [443, 8443], "desc": "All IPs × 2 ports (~3M probes, 30-60 min)"},
}

XRAY_HOME = os.path.join(os.path.expanduser("~"), ".cfedge")
XRAY_BIN_DIR = os.path.join(XRAY_HOME, "bin")
XRAY_TMP_DIR = os.path.join(XRAY_HOME, "tmp")
XRAY_BASE_PORT = 10900
XRAY_CONNECT_TIMEOUT = 8.0
XRAY_QUICK_TIMEOUT = 10.0
XRAY_QUICK_SIZE = 100_000
XRAY_SPEED_TIMEOUT = 20.0
XRAY_SPEED_SIZE = 5_000_000
XRAY_PROFILES_DIR = os.path.join(XRAY_HOME, "profiles")
RESULTS_DIR = "results"

_CF_PREFLIGHT_IPS = ["104.16.128.1", "198.41.192.1", "172.67.128.1"]


def _generate_random_cf_ips(count: int = 100) -> List[str]:
    blocks = []
    for sub in CF_SUBNETS:
        try:
            net = ipaddress.IPv4Network(sub.strip(), strict=False)
            if net.prefixlen <= 24:
                blocks.extend(net.subnets(new_prefix=24))
            else:
                blocks.append(net)
        except (ValueError, TypeError):
            continue
    random.shuffle(blocks)
    ips: List[str] = []
    for blk in blocks[:count]:
        hosts = list(blk.hosts())
        ips.append(str(random.choice(hosts)))
    return ips


CF_TEST_IPS = _generate_random_cf_ips(6666)
_CF_NETS = [ipaddress.IPv4Network(s, strict=False) for s in CF_SUBNETS]


def _is_cf_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _CF_NETS)
    except (ValueError, TypeError):
        return False


def _resolve_is_cf(addr: str) -> bool:
    if _is_cf_address(addr):
        return True
    try:
        infos = socket.getaddrinfo(addr, None, socket.AF_INET, socket.SOCK_STREAM)
        for _, _, _, _, (ip_str, _) in infos:
            if _is_cf_address(ip_str):
                return True
    except (socket.gaierror, OSError):
        pass
    return False


XRAY_FRAG_PRESETS = {
    "none": [None],
    "light": [
        {"packets": "tlshello", "length": "100-200", "interval": "10-20"},
    ],
    "medium": [
        {"packets": "tlshello", "length": "50-100", "interval": "10-20"},
        {"packets": "tlshello", "length": "100-200", "interval": "20-40"},
    ],
    "heavy": [
        {"packets": "tlshello", "length": "10-50", "interval": "5-10"},
        {"packets": "tlshello", "length": "50-100", "interval": "10-30"},
        {"packets": "tlshello", "length": "100-300", "interval": "20-50"},
    ],
    "all": [
        None,
        {"packets": "tlshello", "length": "100-200", "interval": "10-20"},
        {"packets": "tlshello", "length": "50-100", "interval": "10-30"},
        {"packets": "tlshello", "length": "10-50", "interval": "5-10"},
    ],
}

XRAY_CONFIG_TEMPLATE = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "tag": "socks", "port": XRAY_BASE_PORT, "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }],
    "outbounds": [{
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "", "port": 443, "users": []}]},
        "streamSettings": {},
    }],
}

DEPLOY_XRAY_BIN = "/usr/local/bin/xray"
DEPLOY_XRAY_CONFIG = "/usr/local/etc/xray/config.json"
DEPLOY_XRAY_CONFIG_DIR = "/usr/local/etc/xray"
DEPLOY_XRAY_SHARE = "/usr/local/share/xray"
DEPLOY_XRAY_SERVICE = "/etc/systemd/system/xray.service"
DEPLOY_XRAY_BACKUP_DIR = "/usr/local/etc/xray/backups"

DEPLOY_SYSTEMD_UNIT = """\
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
"""

PRESETS = {
    "quick": {
        "label": "Quick",
        "desc": "Latency sort -> 1MB top 100 -> 5MB top 20",
        "dynamic": True,
        "latency_cut": 50,
        "round_sizes": [1_000_000, 5_000_000],
        "round_pcts": [100, 20],
        "round_min": [50, 10],
        "round_max": [100, 20],
        "data": "~200 MB",
        "time": "~2-3 min",
    },
    "normal": {
        "label": "Normal",
        "desc": "Latency sort -> 1MB top 200 -> 5MB top 50 -> 20MB top 20",
        "dynamic": True,
        "latency_cut": 40,
        "round_sizes": [1_000_000, 5_000_000, 20_000_000],
        "round_pcts": [100, 25, 10],
        "round_min": [50, 20, 10],
        "round_max": [200, 50, 20],
        "data": "~850 MB",
        "time": "~5-10 min",
    },
    "thorough": {
        "label": "Thorough",
        "desc": "Deep funnel: 5MB / 25MB / 50MB",
        "dynamic": True,
        "latency_cut": 15,
        "round_sizes": [5_000_000, 25_000_000, 50_000_000],
        "round_pcts": [100, 25, 10],
        "round_min": [0, 30, 15],
        "round_max": [0, 150, 50],
        "data": "~5-10 GB",
        "time": "~20-45 min",
    },
}


class ANSI:
    RST = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITAL = "\033[3m"
    ULINE = "\033[4m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    WHT = "\033[97m"
    BGBL = "\033[44m"
    BGDG = "\033[100m"
    HOME = "\033[H"
    CLR = "\033[H\033[J"
    EL = "\033[2K"
    HIDE = "\033[?25l"
    SHOW = "\033[?25h"


# Backward compat alias
A = ANSI
