"""GeoIP lookup: host → ISO-код страны, с детектом CDN-фронтов.

Драйверы (по порядку):
    * cache  — data/geoip_cache.json (вечный: IP-страна не меняется)
    * mmdb   — оффлайн, если maxminddb и .mmdb файл рядом
    * http   — ip-api.com/batch (100 IP / запрос, 15 запросов/мин)

CDN-детект (geoip.detect_cdn=true, дефолт):
    IP попадает в зашитые CIDR Cloudflare/Fastly → "__CDN__".
    HTTP-lookup: ASN или ISP из списка известных CDN → "__CDN__".
    В обоих случаях страна НЕ ставится, pipeline откатывается
    на remark (в ключах часто указана настоящая страна origin'а).

Особенности:
    mmdb не содержит ASN (только country), поэтому оффлайн-детект
    ограничен зашитым списком CF/Fastly. Для Akamai/AWS/Google
    CDN-детект работает только при http_fallback=true.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address, ip_network
from pathlib import Path

log = logging.getLogger(__name__)

BATCH_SIZE = 100
HTTP_URL = "http://ip-api.com/batch?fields=countryCode,query,status,as,isp"
HTTP_DELAY = 4.2  # 15 req/min у ip-api free

CDN_MARKER = "__CDN__"


# ──────────────────────────────────────────────────────────────────────
#  CIDR Cloudflare IPv4 — https://www.cloudflare.com/ips-v4
# ──────────────────────────────────────────────────────────────────────
_CLOUDFLARE_V4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# ──────────────────────────────────────────────────────────────────────
#  CIDR Fastly IPv4 — https://api.fastly.com/public-ip-list
# ──────────────────────────────────────────────────────────────────────
_FASTLY_V4 = [
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "146.75.0.0/16",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
]

_ALL_CDN_CIDRS = _CLOUDFLARE_V4 + _FASTLY_V4

# ──────────────────────────────────────────────────────────────────────
#  ASN известных CDN — для детекта по ip-api `as`
# ──────────────────────────────────────────────────────────────────────
_CDN_ASN = {
    13335,   # Cloudflare
    54113,   # Fastly
    20940,   # Akamai
    16625,   # Akamai
    32787,   # Akamai (Prolexic)
    21342,   # Akamai
    16509,   # Amazon AWS
    14618,   # Amazon AWS
    38895,   # Amazon AWS
    15169,   # Google
    396982,  # Google Cloud
    19527,   # Google
    139070,  # Google Cloud
    8075,    # Microsoft
}

# ──────────────────────────────────────────────────────────────────────
#  ISP-подстроки для детекта CDN (нижний регистр)
# ──────────────────────────────────────────────────────────────────────
_CDN_ISP_KEYWORDS = (
    "cloudflare",
    "fastly",
    "akamai",
    "amazon",
    "amazonaws",
    "google llc",
    "google cloud",
    "microsoft azure",
    "limelight",
    "stackpath",
)


def _compile_cidrs(cidrs: list[str]) -> list:
    out = []
    for c in cidrs:
        try:
            out.append(ip_network(c))
        except Exception:
            pass
    return out


class GeoIPResolver:
    def __init__(self, cfg, base_dir: Path):
        self.cfg = cfg
        self.base_dir = Path(base_dir)
        self.cache_file = self.base_dir / "geoip_cache.json"
        self.db_path = (
            Path(cfg.db_path) if getattr(cfg, "db_path", "")
            else self.base_dir / "dbip-country-lite.mmdb"
        )
        self._cache: dict[str, str] = self._load_cache()
        self._cache_dirty = False
        self._reader = self._open_mmdb()
        self._session = None

        self._detect_cdn = bool(getattr(cfg, "detect_cdn", True))
        self._cdn_networks = _compile_cidrs(_ALL_CDN_CIDRS) \
            if self._detect_cdn else []
        log.info(
            "geoip: init (cache=%d, mmdb=%s, http_fallback=%s, detect_cdn=%s, "
            "cdn_cidrs=%d)",
            len(self._cache),
            "yes" if self._reader else "no",
            getattr(cfg, "http_fallback", True),
            self._detect_cdn,
            len(self._cdn_networks),
        )

    # ── cache ────────────────────────────────────────────────────────
    def _load_cache(self) -> dict[str, str]:
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception as e:
            log.warning("geoip: cache read failed: %s", e)
            return {}

    def save_cache(self):
        if not self._cache_dirty:
            return
        try:
            tmp = self.cache_file.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(self._cache, ensure_ascii=False, indent=0),
                encoding="utf-8",
            )
            os.replace(tmp, self.cache_file)
            self._cache_dirty = False
        except Exception as e:
            log.warning("geoip: cache write failed: %s", e)

    def cache_size(self) -> int:
        return len(self._cache)

    # ── mmdb ─────────────────────────────────────────────────────────
    def _open_mmdb(self):
        if not self.db_path.exists():
            return None
        try:
            import maxminddb
        except ImportError:
            log.debug("geoip: maxminddb не установлен, mmdb пропущен")
            return None
        try:
            reader = maxminddb.open_database(str(self.db_path))
            log.info("geoip: mmdb loaded %s", self.db_path)
            return reader
        except Exception as e:
            log.warning("geoip: mmdb open failed: %s", e)
            return None

    def _mmdb_lookup(self, ip: str) -> str:
        if self._reader is None:
            return ""
        try:
            rec = self._reader.get(ip)
        except Exception:
            return ""
        if not rec or not isinstance(rec, dict):
            return ""
        c = rec.get("country")
        if isinstance(c, dict):
            cc = c.get("iso_code") or c.get("iso-code") or ""
            if cc:
                return cc.upper()
        cc = rec.get("country_code") or rec.get("countryCode") or ""
        return cc.upper() if cc else ""

    # ── CDN-детект ───────────────────────────────────────────────────
    def _is_cdn_by_cidr(self, ip: str) -> bool:
        if not self._cdn_networks:
            return False
        try:
            addr = ip_address(ip)
        except Exception:
            return False
        for net in self._cdn_networks:
            if addr.version == net.version and addr in net:
                return True
        return False

    @staticmethod
    def _is_cdn_by_row(row: dict) -> bool:
        asn_field = row.get("as") or ""
        isp = (row.get("isp") or "").lower()
        m = re.match(r"AS(\d+)", asn_field)
        if m:
            try:
                if int(m.group(1)) in _CDN_ASN:
                    return True
            except ValueError:
                pass
        for kw in _CDN_ISP_KEYWORDS:
            if kw in isp:
                return True
        return False

    # ── HTTP (ip-api.com) ────────────────────────────────────────────
    def _http_session(self):
        if self._session is not None:
            return self._session
        try:
            import requests
        except ImportError:
            log.warning("geoip: requests не установлен")
            return None
        s = requests.Session()
        s.trust_env = False
        s.headers["User-Agent"] = "Mozilla/5.0 (straysifter-geoip/1.0)"
        proxy = getattr(self.cfg, "proxy", None)
        if proxy:
            s.proxies.update({"http": proxy, "https": proxy})
        self._session = s
        return s

    def _http_batch(self, ips: list[str]) -> dict[str, str]:
        """Возвращает {ip: cc}, где cc — ISO или CDN_MARKER."""
        s = self._http_session()
        if s is None:
            return {}
        out: dict[str, str] = {}
        total = (len(ips) + BATCH_SIZE - 1) // BATCH_SIZE
        for i in range(0, len(ips), BATCH_SIZE):
            batch = ips[i:i + BATCH_SIZE]
            n = i // BATCH_SIZE + 1
            log.info("geoip: http batch %d/%d (%d ips)", n, total, len(batch))
            try:
                r = s.post(
                    HTTP_URL,
                    json=[{"query": ip} for ip in batch],
                    timeout=10,
                )
                r.raise_for_status()
                rows = r.json()
                for row in rows:
                    if row.get("status") != "success":
                        continue
                    ip = row.get("query", "")
                    if not ip:
                        continue
                    if self._detect_cdn and self._is_cdn_by_row(row):
                        out[ip] = CDN_MARKER
                        continue
                    cc = (row.get("countryCode") or "").upper()
                    if cc:
                        out[ip] = cc
            except Exception as e:
                log.warning("geoip: http batch %d failed: %s", n, e)
            if i + BATCH_SIZE < len(ips):
                time.sleep(HTTP_DELAY)
        return out

    # ── host → ip ────────────────────────────────────────────────────
    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET, s)
            return True
        except OSError:
            return False

    @staticmethod
    def _resolve_host(host: str) -> str:
        if not host:
            return ""
        if GeoIPResolver._is_ip(host):
            return host
        try:
            return socket.gethostbyname(host)
        except Exception:
            return ""

    # ── публичный API ────────────────────────────────────────────────
    def resolve_countries(self, hosts: list[str]) -> dict[str, str]:
        """host → cc.

        cc = ISO-код или CDN_MARKER ("__CDN__").
        Если не узнали — host отсутствует в словаре.
        """
        unique_hosts = sorted({h for h in hosts if h})
        if not unique_hosts:
            return {}

        # 1) DNS
        host_to_ip: dict[str, str] = {}
        workers = min(64, len(unique_hosts))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fmap = {ex.submit(self._resolve_host, h): h for h in unique_hosts}
            for fut in as_completed(fmap):
                h = fmap[fut]
                ip = fut.result()
                if ip:
                    host_to_ip[h] = ip

        # 2) для каждого IP: cdn(cidr) → cache → mmdb → отложить на http
        result: dict[str, str] = {}          # host -> cc
        need_http: list[str] = []            # ips для http
        for h, ip in host_to_ip.items():
            if self._detect_cdn and self._is_cdn_by_cidr(ip):
                result[h] = CDN_MARKER
                if self._cache.get(ip) != CDN_MARKER:
                    self._cache[ip] = CDN_MARKER
                    self._cache_dirty = True
                continue

            cc = self._cache.get(ip, "")
            if not cc:
                cc = self._mmdb_lookup(ip)
                if cc:
                    self._cache[ip] = cc
                    self._cache_dirty = True
            if cc:
                result[h] = cc
            elif getattr(self.cfg, "http_fallback", True):
                need_http.append(ip)

        # 3) http для незнакомых
        if need_http and getattr(self.cfg, "http_fallback", True):
            uniq_ips = sorted(set(need_http))
            log.info("geoip: http lookup for %d uncached IPs", len(uniq_ips))
            fetched = self._http_batch(uniq_ips)
            for ip, cc in fetched.items():
                self._cache[ip] = cc
                self._cache_dirty = True
            for h, ip in host_to_ip.items():
                if h not in result and ip in fetched:
                    result[h] = fetched[ip]

        self.save_cache()

        n_cdn = sum(1 for v in result.values() if v == CDN_MARKER)
        n_cc = len(result) - n_cdn
        log.info("geoip: resolved %d/%d hosts (cc=%d, cdn=%d)",
                 len(result), len(unique_hosts), n_cc, n_cdn)
        return result