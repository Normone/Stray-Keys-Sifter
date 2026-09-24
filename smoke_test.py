"""Smoke-тест straysifter.

Без --net: оффлайн (импорты, парсеры, конфиг, storage, CLI-парсер).
С --net: плюс TCP-чек 1.1.1.1:443 и GeoIP lookup.
"""
from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path


PASS, FAIL = "PASS", "FAIL"
_results: list[tuple[str, str, str]] = []


def check(name):
    def deco(fn):
        def wrapper():
            try:
                fn()
                _results.append((name, PASS, ""))
                print(f"[{PASS}] {name}")
            except Exception as e:
                _results.append((name, FAIL, str(e)))
                print(f"[{FAIL}] {name}: {e}")
                traceback.print_exc()
        return wrapper
    return deco


# ── импорты ──────────────────────────────────────────────────────────

@check("imports: core")
def t1():
    from straysifter.core import (
        Config, load_config, FetcherConfig, ChecksConfig,
        ScheduleConfig, StorageConfig, SourceFetcher,
    )


@check("imports: pipeline + storage")
def t2():
    from straysifter.core.pipeline import run_cycle, apply_geoip
    from straysifter.core.storage import (
        Storage, WorkingRecord, SourceStats, STATUS_LABEL,
        compute_status, _sanitize_uri_for_client,
    )


@check("imports: cli + service")
def t3():
    from straysifter.frontends.cli import build_parser, main
    from straysifter.service.runner import Runner
    from straysifter.service import daemon_windows, daemon_posix


@check("imports: geoip + country + checks + singbox")
def t4():
    from straysifter.core.geoip import GeoIPResolver
    from straysifter.core.country import parse_country, country_flag
    from straysifter.core.checks import run_check, _try_ips_parallel
    from straysifter.core.singbox import (
        run_singbox_check, build_outbound, find_binary,
        _extract_outbound_index, _normalize_flow, _is_valid_pbk,
        _is_valid_sid, _is_valid_uuid, _normalize_fp,
        _normalize_ss_method, _normalize_vmess_security,
    )


# ── конфиг ───────────────────────────────────────────────────────────

@check("config: defaults совпадают с заявленными")
def t5():
    from straysifter.core import ChecksConfig
    c = ChecksConfig()
    assert c.tcp_workers == 120
    assert c.tcp_timeout == 3.0
    assert c.tcp_timeout_step == 3.0
    assert c.tcp_timeout_max == 9.0
    assert c.tcp_attempts == 3
    assert c.tcp_retry_jitter == 0.4
    assert c.tcp_sequential_max_ips == 3
    assert c.tcp_sequential_after == 2
    assert c.tcp_endpoint_budget == 30.0
    assert c.exclude_countries == []
    assert c.singbox_path == ""
    assert c.singbox_timeout == 8.0


@check("config: pyproject version == __init__.__version__")
def t6():
    import re
    root = Path(__file__).parent
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    pyproj_v = m.group(1) if m else None
    from straysifter import __version__ as pkg_v
    assert pyproj_v == pkg_v, f"pyproject={pyproj_v} vs __init__={pkg_v}"


@check("config: env override SIFTER_MODE")
def t7():
    os.environ["SIFTER_MODE"] = "tcp+tls"
    try:
        from straysifter.core import load_config
        cfg = load_config(Path("__nonexistent_config__.json"))
        assert cfg.checks.mode == "tcp+tls", cfg.checks.mode
    finally:
        os.environ.pop("SIFTER_MODE", None)


# ── парсеры ──────────────────────────────────────────────────────────

@check("parsers: vless reality")
def t10():
    from straysifter.core.parsers import parse_any
    p = parse_any(
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
        "?type=tcp&security=reality&pbk=abcdef&sni=example.com#Test"
    )
    assert p and p.scheme == "vless"
    assert p.host == "1.2.3.4" and p.port == 443
    assert p.security == "reality"
    assert p.name == "Test"


@check("parsers: vmess base64")
def t11():
    import base64, json
    from straysifter.core.parsers import parse_any
    payload = {"v":"2","ps":"x","add":"1.2.3.4","port":"443","id":"aaa",
               "aid":"0","scy":"auto","net":"ws","type":"none","host":"",
               "path":"/","tls":"tls","sni":"","alpn":"","fp":""}
    b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    p = parse_any("vmess://" + b64)
    assert p and p.scheme == "vmess"
    assert p.host == "1.2.3.4" and p.port == 443


@check("parsers: trojan")
def t12():
    from straysifter.core.parsers import parse_any
    p = parse_any("trojan://pass@1.2.3.4:443?sni=x.com#N")
    assert p and p.scheme == "trojan" and p.password == "pass"


@check("parsers: ss base64")
def t13():
    import base64
    from straysifter.core.parsers import parse_any
    creds = base64.urlsafe_b64encode(b"aes-256-gcm:pass").decode().rstrip("=")
    p = parse_any(f"ss://{creds}@1.2.3.4:8388#N")
    assert p and p.scheme == "ss" and p.method == "aes-256-gcm"


@check("parsers: socks5")
def t14():
    from straysifter.core.parsers import parse_any
    p = parse_any("socks5://user:pass@1.2.3.4:1080")
    assert p and p.scheme == "socks"


@check("parsers: http")
def t15():
    from straysifter.core.parsers import parse_any
    p = parse_any("http://1.2.3.4:8080")
    assert p and p.scheme == "http" and p.port == 8080


@check("parsers: mtproto (tg://)")
def t16():
    from straysifter.core.parsers import parse_any
    p = parse_any("tg://proxy?server=1.2.3.4&port=443&secret=abcdef")
    assert p and p.scheme == "mtproto"
    assert p.host == "1.2.3.4" and p.port == 443


@check("parsers: hysteria2 + hy2 alias")
def t17():
    from straysifter.core.parsers import parse_any
    p1 = parse_any("hysteria2://pass@1.2.3.4:443?sni=x.com#N")
    p2 = parse_any("hy2://pass@1.2.3.4:443?sni=x.com#N")
    assert p1 and p1.scheme == "hysteria2"
    assert p2 and p2.scheme == "hysteria2"


@check("parsers: dedup_key")
def t18():
    from straysifter.core.parsers import parse_any
    p = parse_any("vless://uuid@1.2.3.4:443?type=tcp#N")
    assert p.dedup_key == "vless://uuid@1.2.3.4:443"


@check("parsers: analyze_text dedup")
def t19():
    from straysifter.core.parsers import analyze_text
    txt = (
        "vless://uuid1@1.2.3.4:443?type=tcp#A\n"
        "vless://uuid1@1.2.3.4:443?type=tcp#B\n"
        "trojan://p@5.6.7.8:443#C\n"
    )
    st, _ = analyze_text(txt)
    assert st.raw_uris == 3 and st.unique == 2


@check("parsers: base64 subscription")
def t20():
    import base64
    from straysifter.core.parsers import analyze_text
    plain = "vless://uuid@1.2.3.4:443?type=tcp#A\n"
    txt = base64.b64encode(plain.encode()).decode()
    st, _ = analyze_text(txt)
    assert st.unique == 1


@check("parsers: CSV с заголовком")
def t21():
    from straysifter.core.parsers import analyze_text
    txt = "ip,port,type\n1.2.3.4,8080,http\n5.6.7.8,1080,socks5\n"
    st, _ = analyze_text(txt)
    assert st.unique >= 2, st.unique


@check("parsers: Clash YAML")
def t22():
    from straysifter.core.parsers import analyze_text
    txt = (
        "proxies:\n"
        "  - name: A\n"
        "    type: ss\n"
        "    server: 1.2.3.4\n"
        "    port: 8388\n"
        "    cipher: aes-256-gcm\n"
        "    password: pass\n"
    )
    st, _ = analyze_text(txt)
    assert st.unique == 1, st.unique


# ── country ──────────────────────────────────────────────────────────

@check("country: flag RU")
def t30():
    from straysifter.core.country import country_flag
    assert country_flag("RU") == "🇷🇺"


@check("country: parse from remark")
def t31():
    from straysifter.core.country import parse_country
    from straysifter.core.parsers import parse_any
    p = parse_any("vless://uuid@1.2.3.4:443?type=tcp#DE-Frankfurt")
    assert parse_country(p) == "DE"


# ── storage ──────────────────────────────────────────────────────────

@check("storage: export + sanitize (?ed=N и type=raw)")
def t40():
    import tempfile
    from straysifter.core.checks import CheckResult
    from straysifter.core.parsers import parse_any
    from straysifter.core.storage import Storage
    from straysifter.core.country import parse_country, country_flag

    with tempfile.TemporaryDirectory() as td:
        st = Storage(td)
        p = parse_any(
            "vless://uuid@1.2.3.4:443?type=ws&path=/x?ed=2048&headerType=raw#RU"
        )
        assert p is not None
        r = CheckResult(info=p, ping=42)
        out = st.export_checked([r], parse_country, country_flag)
        text = out.read_text(encoding="utf-8")
        assert "ed=2048" not in text, text
        assert "type=raw" not in text, text


@check("storage: working.json round-trip")
def t41():
    import tempfile
    from straysifter.core.checks import CheckResult
    from straysifter.core.parsers import parse_any
    from straysifter.core.storage import Storage

    with tempfile.TemporaryDirectory() as td:
        st = Storage(td)
        p = parse_any("vless://uuid@1.2.3.4:443?type=tcp#N")
        st.replace_working([CheckResult(info=p, ping=42)])
        db = st.load_working()
        assert len(db) == 1 and db[0].host == "1.2.3.4"


@check("storage: hysteria2_candidates export")
def t42():
    import tempfile
    from straysifter.core.parsers import parse_any
    from straysifter.core.storage import Storage
    from straysifter.core.country import parse_country, country_flag

    with tempfile.TemporaryDirectory() as td:
        st = Storage(td)
        p = parse_any("hysteria2://pass@1.2.3.4:443#DE-Test")
        out = st.export_hysteria_candidates([p], parse_country, country_flag)
        assert out is not None and out.exists()
        text = out.read_text(encoding="utf-8")
        assert "unverified" in text


# ── singbox ──────────────────────────────────────────────────────────

@check("singbox: _normalize_flow")
def t60():
    from straysifter.core.singbox import _normalize_flow
    assert _normalize_flow("") == ""
    assert _normalize_flow("xtls-rprx-vision") == "xtls-rprx-vision"
    assert _normalize_flow("xtls-rprx-vision-udp443") == "xtls-rprx-vision"
    assert _normalize_flow("xtls-rprx-direct") == ""
    assert _normalize_flow("garbage") == ""


@check("singbox: _is_valid_pbk")
def t61():
    from straysifter.core.singbox import _is_valid_pbk
    assert not _is_valid_pbk("")
    assert not _is_valid_pbk("short")
    assert not _is_valid_pbk("!" * 44)
    # валидный base64url ~44 символа
    import base64
    ok = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
    assert _is_valid_pbk(ok)


@check("singbox: _is_valid_sid")
def t62():
    from straysifter.core.singbox import _is_valid_sid
    assert _is_valid_sid("")
    assert _is_valid_sid("abcd1234")
    assert not _is_valid_sid("hello world")
    assert not _is_valid_sid("z" * 8)
    assert not _is_valid_sid("a" * 20)


@check("singbox: _is_valid_uuid")
def t63():
    from straysifter.core.singbox import _is_valid_uuid
    assert _is_valid_uuid("11111111-2222-3333-4444-555555555555")
    assert _is_valid_uuid("11111111222233334444555555555555")
    assert not _is_valid_uuid("")
    assert not _is_valid_uuid("not-a-uuid")


@check("singbox: _normalize_fp")
def t64():
    from straysifter.core.singbox import _normalize_fp
    assert _normalize_fp("") == "chrome"
    assert _normalize_fp("firefox") == "firefox"
    assert _normalize_fp("hellochrome_120") == "chrome"
    assert _normalize_fp("randomized") == "randomized"


@check("singbox: _normalize_ss_method")
def t65():
    from straysifter.core.singbox import _normalize_ss_method
    assert _normalize_ss_method("aes-256-gcm") == "aes-256-gcm"
    assert _normalize_ss_method("chacha20-poly1305") == "chacha20-ietf-poly1305"
    assert _normalize_ss_method("xchacha20-poly1305") == "xchacha20-ietf-poly1305"
    assert _normalize_ss_method("garbage") is None
    assert _normalize_ss_method("") is None


@check("singbox: _normalize_vmess_security")
def t66():
    from straysifter.core.singbox import _normalize_vmess_security
    assert _normalize_vmess_security("auto") == "auto"
    assert _normalize_vmess_security("aes-128-gcm") == "aes-128-gcm"
    assert _normalize_vmess_security("garbage") == "auto"


@check("singbox: _extract_outbound_index")
def t67():
    from straysifter.core.singbox import _extract_outbound_index
    err = ("FATAL[0000] create service: initialize outbound[776]: "
           "unsupported flow")
    assert _extract_outbound_index(err) == 776
    assert _extract_outbound_index("nothing here") is None


@check("singbox: build_outbound vless reality валидный")
def t68():
    from straysifter.core.parsers import parse_any
    from straysifter.core.singbox import build_outbound
    import base64
    pbk = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    p = parse_any(
        f"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
        f"?type=tcp&security=reality&pbk={pbk}&sid=abcd1234&sni=x.com#N"
    )
    ob = build_outbound(p, "p0")
    assert ob is not None
    assert ob["type"] == "vless"
    assert ob["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert ob["tls"]["reality"]["public_key"] == pbk
    assert ob["tls"]["reality"]["short_id"] == "abcd1234"


@check("singbox: build_outbound vless xhttp → None")
def t69():
    from straysifter.core.parsers import parse_any
    from straysifter.core.singbox import build_outbound
    p = parse_any(
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
        "?type=xhttp&security=tls&sni=x.com#N"
    )
    assert p is not None
    assert build_outbound(p, "p0") is None


@check("singbox: build_outbound битый pbk → None")
def t70():
    from straysifter.core.parsers import parse_any
    from straysifter.core.singbox import build_outbound
    p = parse_any(
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
        "?type=tcp&security=reality&pbk=bad&sid=zz&sni=x.com#N"
    )
    assert p is not None
    assert build_outbound(p, "p0") is None


@check("singbox: build_outbound ss chacha alias")
def t71():
    from straysifter.core.parsers import parse_any
    from straysifter.core.singbox import build_outbound
    import base64
    creds = base64.urlsafe_b64encode(
        b"chacha20-poly1305:pass").decode().rstrip("=")
    p = parse_any(f"ss://{creds}@1.2.3.4:8388#N")
    ob = build_outbound(p, "p0")
    assert ob is not None
    assert ob["method"] == "chacha20-ietf-poly1305"


# ── CLI ──────────────────────────────────────────────────────────────

@check("cli: build_parser + все subcommands")
def t50():
    from straysifter.frontends.cli import build_parser
    p = build_parser()
    for cmd in ("sources", "sources-stats", "export", "geoip-update",
                "geoip-clear", "status", "history", "clean"):
        p.parse_args([cmd])
    p.parse_args(["collect"])
    p.parse_args(["collect", "--no-geoip", "--exclude-country", "RU,CN"])
    p.parse_args(["collect", "--mode", "singbox"])
    p.parse_args(["collect", "--mode", "tcp+tls"])
    p.parse_args(["inspect", "pattern"])
    p.parse_args(["export-source", "pattern"])
    p.parse_args(["export-source", "pattern", "--mode", "singbox"])


@check("service: __main__ build_parser")
def t51():
    from straysifter.service.__main__ import build_parser
    p = build_parser()
    for cmd in ("install", "uninstall", "start", "stop", "restart",
                "status", "debug"):
        p.parse_args([cmd])


# ── сеть ─────────────────────────────────────────────────────────────

def _net():
    @check("net: TCP 1.1.1.1:443")
    def n1():
        import asyncio
        from straysifter.core.checks import _try_ips_parallel
        r, _ = asyncio.run(_try_ips_parallel(["1.1.1.1"], 443, 5.0))
        assert r is not None, "1.1.1.1:443 не ответил"

    @check("net: GeoIP cache read (offline, детерминированный)")
    def n2():
        import json, tempfile
        from pathlib import Path
        from straysifter.core.geoip import GeoIPResolver
        from straysifter.core.config import GeoIPConfig
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "geoip_cache.json").write_text(
                json.dumps({"1.1.1.1": "US"}), encoding="utf-8")
            r = GeoIPResolver(GeoIPConfig(), p)
            m = r.resolve_countries(["1.1.1.1"])
            assert m.get("1.1.1.1") == "US", m

    @check("net: GeoIP HTTP fallback (>=3 IPs)")
    def n3():
        import tempfile
        from pathlib import Path
        from straysifter.core.geoip import GeoIPResolver
        from straysifter.core.config import GeoIPConfig
        with tempfile.TemporaryDirectory() as td:
            r = GeoIPResolver(GeoIPConfig(), Path(td))
            m = r.resolve_countries(["1.1.1.1", "8.8.8.8", "77.88.8.8"])
            assert len(m) >= 1, f"got nothing: {m}"
            print("      → ", m)

    @check("net: sing-box binary present")
    def n4():
        from straysifter.core.singbox import find_binary
        b = find_binary()
        assert b is not None, ("sing-box.exe не найден в bin/sing-box/. "
                               "Скачай и положи, или пропусти этот тест")
        print(f"      → {b}")

    n1(); n2(); n3()
    try:
        n4()
    except AssertionError as e:
        print(f"[SKIP] net: sing-box binary present: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", action="store_true")
    args = ap.parse_args()

    os.chdir(Path(__file__).parent)

    for t in (t1, t2, t3, t4, t5, t6, t7,
              t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20,
              t21, t22, t30, t31, t40, t41, t42,
              t60, t61, t62, t63, t64, t65, t66, t67, t68, t69, t70, t71,
              t50, t51):
        t()

    if args.net:
        _net()

    fails = [r for r in _results if r[1] == FAIL]
    print()
    print(f"Итого: {len(_results) - len(fails)}/{len(_results)} pass")
    if fails:
        print("Провалились:")
        for n, _, e in fails:
            print(f"  - {n}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())