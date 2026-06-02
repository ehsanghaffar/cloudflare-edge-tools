from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def calc_scores(st: "State"):
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


def sorted_alive(st: "State", key: str = "score") -> List["Result"]:
    alive = [r for r in st.res.values() if r.alive]
    if key == "score":
        alive.sort(key=lambda r: r.score, reverse=True)
    elif key == "latency":
        alive.sort(key=lambda r: r.tls_ms)
    elif key == "speed":
        alive.sort(key=lambda r: r.best_mbps, reverse=True)
    return alive


def sorted_all(st: "State", key: str = "score") -> List["Result"]:
    alive = sorted_alive(st, key)
    dead = [r for r in st.res.values() if not r.alive]
    dead.sort(key=lambda r: r.ip)
    return alive + dead


@dataclass
class ConfigEntry:
    address: str
    name: str = ""
    original_uri: str = ""
    ip: str = ""


@dataclass
class RoundCfg:
    size: int
    keep: int

    @property
    def label(self) -> str:
        if self.size >= 1_000_000:
            return f"{self.size // 1_000_000}MB"
        return f"{self.size // 1000}KB"


@dataclass
class Result:
    ip: str
    domains: List[str] = field(default_factory=list)
    uris: List[str] = field(default_factory=list)
    tcp_ms: float = -1
    tls_ms: float = -1
    ttfb_ms: float = -1
    speeds: List[float] = field(default_factory=list)
    best_mbps: float = -1
    colo: str = ""
    score: float = 0
    error: str = ""
    alive: bool = False


class State:
    def __init__(self):
        self.input_file = ""
        self.configs: List[ConfigEntry] = []
        self.ip_map: Dict[str, List[ConfigEntry]] = defaultdict(list)
        self.ips: List[str] = []
        self.res: Dict[str, Result] = {}
        self.rounds: List[RoundCfg] = []
        self.mode = "normal"

        self.phase = "init"
        self.phase_label = ""
        self.cur_round = 0
        self.total = 0
        self.done_count = 0
        self.alive_n = 0
        self.dead_n = 0
        self.best_speed = 0.0
        self.start_time = 0.0
        self.notify = ""
        self.notify_until = 0.0

        self.top = 50
        self.finished = False
        self.interrupted = False
        self.saved = False
        self.latency_cut_n = 0


@dataclass
class XrayVariation:
    tag: str
    sni: str
    fragment: Optional[dict]
    config_json: dict
    source_uri: str
    alive: bool = False
    connect_ms: float = -1
    ttfb_ms: float = -1
    speed_mbps: float = -1
    error: str = ""
    score: float = 0
    result_uri: str = ""
    native_tested: bool = False


class XrayTestState:
    def __init__(self):
        self.variations: List[XrayVariation] = []
        self.phase = "init"
        self.phase_label = ""
        self.total = 0
        self.done_count = 0
        self.alive_count = 0
        self.dead_count = 0
        self.best_speed = 0.0
        self.start_time = 0.0
        self.finished = False
        self.interrupted = False
        self.source_uri = ""
        self.xray_bin = ""
        self.export_error = ""
        self.quick_passed = 0
        self.pipeline_mode = False
        self.pipeline_stage = 0
        self.pipeline_stages = [
            {"name": "ip_scan",    "label": "IP Scan",           "status": "pending"},
            {"name": "base_test",  "label": "Base Connectivity",  "status": "pending"},
            {"name": "expansion",  "label": "Expansion",          "status": "pending"},
        ]
        self.live_ips: List[Tuple[str, float]] = []
        self.live_ip_ports: dict = {}
        self.working_ips: List[str] = []
        self.preflight_is_cf: Optional[bool] = None
        self.preflight_warning: str = ""
        self.cf_origin_errors: int = 0


@dataclass
class PipelineConfig:
    uri: str
    parsed: dict
    sni_pool: List[str] = field(default_factory=list)
    frag_preset: str = "all"
    transport_variants: List[str] = field(default_factory=list)
    max_stage2_ips: int = 120
    max_expansion: int = 1000
    max_snis_per_ip: int = 20
    configless: bool = False
    base_uris: List[Tuple[str, dict]] = field(default_factory=list)
    custom_ips: List[str] = field(default_factory=list)
    probe_ports: List[int] = field(default_factory=lambda: [443])


class DeployState:
    def __init__(self):
        self.source_uris: List[str] = []
        self.parsed_configs: List[dict] = []
        self.fresh_mode = False

        self.server_config: dict = {}
        self.client_uris: List[str] = []

        self.server_ip = ""
        self.listen_port = 443

        self.reality_private_key = ""
        self.reality_public_key = ""
        self.reality_short_id = ""
        self.tls_cert_path = ""
        self.tls_key_path = ""
        self.tls_domain = ""

        self.phase = "init"
        self.steps_done: List[str] = []
        self.error = ""


@dataclass
class CleanScanState:
    total: int = 0
    done: int = 0
    found: int = 0
    interrupted: bool = False
    results: List[Tuple[str, float]] = field(default_factory=list)
    all_results: List[Tuple[str, float]] = field(default_factory=list)
    start_time: float = 0.0
