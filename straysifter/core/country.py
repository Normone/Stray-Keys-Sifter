"""Определение страны по VLESS-ключу.

Приоритеты:
    0. GeoIP (info.params["__cc"]) — если посчитан pipeline'ом.
    1. Явный ISO-код в ремарке: [RU], RU-, _DE_, (NL).
    2. Синонимы в ремарке и хосте.
    3. Код страны в домене (de.example.com).
    4. XX — неизвестно.
"""
from __future__ import annotations

import re

from .parsers import VlessInfo

_FALSE_POSITIVE_CODES = frozenset({
    "IS", "AS", "BY", "AM", "AN", "TO", "IT", "US", "NO", "IN",
})


def country_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "\U0001F3F4"
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + \
           chr(0x1F1E6 + ord(code[1]) - ord("A"))


COUNTRY_MAP: dict[str, str] = {
    "RU": country_flag("RU"), "PL": country_flag("PL"),
    "FI": country_flag("FI"), "NL": country_flag("NL"),
    "DE": country_flag("DE"), "FR": country_flag("FR"),
    "GB": country_flag("GB"), "US": country_flag("US"),
    "TR": country_flag("TR"), "IR": country_flag("IR"),
    "UA": country_flag("UA"), "AT": country_flag("AT"),
    "CH": country_flag("CH"), "SE": country_flag("SE"),
    "NO": country_flag("NO"), "BE": country_flag("BE"),
    "ES": country_flag("ES"), "IT": country_flag("IT"),
    "CZ": country_flag("CZ"), "SK": country_flag("SK"),
    "HU": country_flag("HU"), "RO": country_flag("RO"),
    "BG": country_flag("BG"), "GR": country_flag("GR"),
    "PT": country_flag("PT"), "DK": country_flag("DK"),
    "LT": country_flag("LT"), "LV": country_flag("LV"),
    "EE": country_flag("EE"), "HR": country_flag("HR"),
    "RS": country_flag("RS"), "BA": country_flag("BA"),
    "MD": country_flag("MD"), "BY": country_flag("BY"),
    "KZ": country_flag("KZ"), "UZ": country_flag("UZ"),
    "AE": country_flag("AE"), "SG": country_flag("SG"),
    "JP": country_flag("JP"), "KR": country_flag("KR"),
    "CN": country_flag("CN"), "HK": country_flag("HK"),
    "TW": country_flag("TW"), "IN": country_flag("IN"),
    "BR": country_flag("BR"), "CA": country_flag("CA"),
    "AU": country_flag("AU"), "NZ": country_flag("NZ"),
    "MX": country_flag("MX"), "AR": country_flag("AR"),
    "ZA": country_flag("ZA"), "IL": country_flag("IL"),
    "SA": country_flag("SA"), "TH": country_flag("TH"),
    "VN": country_flag("VN"), "MY": country_flag("MY"),
    "ID": country_flag("ID"), "PH": country_flag("PH"),
}

COUNTRY_KEYWORDS_EN: dict[str, list[str]] = {
    "RU": ["RUSSIA", "MOSCOW", "SPBU", "SAINT PETER"],
    "PL": ["POLAND", "WARSAW"],
    "FI": ["FINLAND", "HELSINKI"],
    "NL": ["NETHERLANDS", "NEDERLAND", "AMSTERDAM"],
    "DE": ["GERMANY", "BERLIN", "FRANKFURT"],
    "FR": ["FRANCE", "PARIS"],
    "GB": ["UK", "UNITED KINGDOM", "BRITAIN", "LONDON"],
    "US": ["USA", "AMERICA", "UNITED STATES", "NEW YORK", "CHICAGO",
           "LOS ANGELES"],
    "TR": ["TURKEY", "ISTANBUL", "ANKARA"],
    "IR": ["IRAN", "TEHRAN"],
    "UA": ["UKRAINE", "KYIV", "KIEV"],
    "CH": ["SWITZERLAND", "ZURICH"],
    "SE": ["SWEDEN", "STOCKHOLM"],
    "NO": ["NORWAY", "OSLO"],
    "AT": ["AUSTRIA", "VIENNA"],
    "BE": ["BELGIUM", "BRUSSELS"],
    "ES": ["SPAIN", "MADRID"],
    "IT": ["ITALY", "ROME", "MILAN"],
    "CZ": ["CZECH", "PRAGUE"],
    "HU": ["HUNGARY", "BUDAPEST"],
    "RO": ["ROMANIA", "BUCHAREST"],
    "BG": ["BULGARIA", "SOFIA"],
    "KZ": ["KAZAKHSTAN", "ALMATY"],
    "BY": ["BELARUS", "MINSK"],
    "AE": ["UAE", "EMIRATES", "DUBAI", "ABU DHABI"],
    "SG": ["SINGAPORE"],
    "JP": ["JAPAN", "TOKYO", "OSAKA"],
    "KR": ["KOREA", "SEOUL"],
    "CN": ["CHINA", "BEIJING", "SHANGHAI"],
    "HK": ["HONG KONG", "HONGKONG"],
    "TW": ["TAIWAN"],
    "IN": ["INDIA", "MUMBAI", "DELHI"],
    "BR": ["BRAZIL", "SAO PAULO"],
    "CA": ["CANADA", "TORONTO", "VANCOUVER"],
    "AU": ["AUSTRALIA", "SYDNEY", "MELBOURNE"],
    "ID": ["INDONESIA", "JAKARTA"],
    "TH": ["THAILAND", "BANGKOK"],
    "VN": ["VIETNAM", "HANOI"],
    "MY": ["MALAYSIA", "KUALA LUMPUR"],
}

COUNTRY_KEYWORDS_RU: dict[str, list[str]] = {
    "RU": ["\u0420\u041e\u0421\u0421\u0418\u042f", "\u0420\u0423\u0421",
           "\u041c\u041e\u0421\u041a\u0412\u0410",
           "\u041f\u0418\u0422\u0415\u0420"],
    "PL": ["\u041f\u041e\u041b\u042c\u0428\u0410",
           "\u0412\u0410\u0420\u0428\u0410\u0412\u0410"],
    "FI": ["\u0424\u0418\u041d\u041b\u042f\u041d\u0414\u0418\u042f"],
    "NL": ["\u0413\u041e\u041b\u041b\u0410\u041d\u0414\u0418\u042f"],
    "DE": ["\u0413\u0415\u0420\u041c\u0410\u041d\u0418\u042f",
           "\u0411\u0415\u0420\u041b\u0418\u041d"],
    "FR": ["\u0424\u0420\u0410\u041d\u0426\u0418\u042f",
           "\u041f\u0410\u0420\u0418\u0416"],
    "GB": ["\u041b\u041e\u041d\u0414\u041e\u041d"],
    "TR": ["\u0422\u0423\u0420\u0426\u0418\u042f",
           "\u0421\u0422\u0410\u041c\u0411\u0423\u041b"],
    "IR": ["\u0418\u0420\u0410\u041d",
           "\u0422\u0415\u0413\u0415\u0420\u0410\u041d"],
    "UA": ["\u0423\u041a\u0420\u0410\u0418\u041d\u0410"],
    "CH": ["\u0428\u0412\u0415\u0419\u0426\u0410\u0420\u0418\u042f"],
    "SE": ["\u0428\u0412\u0415\u0426\u0418\u042f"],
    "NO": ["\u041d\u041e\u0420\u0412\u0415\u0413\u0418\u042f"],
    "AT": ["\u0410\u0412\u0421\u0422\u0420\u0418\u042f",
           "\u0412\u0415\u041d\u0410"],
    "BE": ["\u0411\u0415\u041b\u042c\u0413\u0418\u042f"],
    "ES": ["\u0418\u0421\u041f\u0410\u041d\u0418\u042f"],
    "IT": ["\u0418\u0422\u0410\u041b\u0418\u042f",
           "\u0420\u0418\u041c"],
    "CZ": ["\u0427\u0415\u0425\u0418\u042f",
           "\u041f\u0420\u0410\u0413\u0410"],
    "KZ": ["\u041a\u0410\u0417\u0410\u0425\u0421\u0422\u0410\u041d",
           "\u0410\u041b\u041c\u0410"],
    "BY": ["\u0411\u0415\u041b\u0410\u0420\u0423\u0421\u042c",
           "\u041c\u0418\u041d\u0421\u041a"],
    "AE": ["\u042d\u041c\u0418\u0420\u0410\u0422\u042b",
           "\u0414\u0423\u0411\u0410\u0419"],
    "SG": ["\u0421\u0418\u041d\u0413\u0410\u041f\u0423\u0420"],
    "JP": ["\u042f\u041f\u041e\u041d\u0418\u042f",
           "\u0422\u041e\u041a\u0418\u041e"],
    "KR": ["\u041a\u041e\u0420\u0415\u042f",
           "\u0421\u0415\u0423\u041b"],
    "CN": ["\u041a\u0418\u0422\u0410\u0419",
           "\u041f\u0415\u041a\u0418\u041d"],
    "HK": ["\u0413\u041e\u041d\u041a\u041e\u041d\u0413"],
    "TW": ["\u0422\u0410\u0419\u0412\u0410\u041d\u042c"],
    "IN": ["\u0418\u041d\u0414\u0418\u042f"],
    "BR": ["\u0411\u0420\u0410\u0417\u0418\u041b\u0418\u042f"],
    "CA": ["\u041a\u0410\u041d\u0410\u0414\u0410"],
    "AU": ["\u0410\u0412\u0421\u0422\u0420\u0410\u041b\u0418\u042f"],
    "ID": ["\u0418\u041d\u0414\u041e\u041d\u0415\u0417\u0418\u042f"],
    "TH": ["\u0422\u0410\u0419\u041b\u0410\u041d\u0414",
           "\u0411\u0410\u041d\u0413\u041a\u041e\u041a"],
    "VN": ["\u0412\u042c\u0415\u0422\u041d\u0410\u041c"],
    "MY": ["\u041c\u0410\u041b\u0410\u0419\u0417\u0418\u042f"],
}

COUNTRY_KEYWORDS: dict[str, list[str]] = {
    code: COUNTRY_KEYWORDS_EN.get(code, []) + COUNTRY_KEYWORDS_RU.get(code, [])
    for code in set(COUNTRY_KEYWORDS_EN) | set(COUNTRY_KEYWORDS_RU)
}

_ISO_IN_REMARK = re.compile(r"(?<![A-Za-z])([A-Z]{2})(?![A-Za-z])")


def parse_country(info: VlessInfo) -> str:
    """ISO-код страны для ключа или "XX".

    Приоритет 0: GeoIP-хинт (info.params["__cc"]), если pipeline его установил.
    """
    # GeoIP hint — приоритетнее всего
    hint = ""
    if info.params:
        hint = (info.params.get("__cc") or "").upper()
    if len(hint) == 2 and hint in COUNTRY_MAP:
        return hint

    remark = (info.name or "").upper()
    host = (info.host or "").upper()
    combined = f"{remark} {host}"

    for m in _ISO_IN_REMARK.finditer(remark):
        code = m.group(1)
        if code in COUNTRY_MAP:
            return code

    for code, words in COUNTRY_KEYWORDS.items():
        for w in words:
            if w and w in combined:
                return code

    for part in re.split(r"[.\-_]", host):
        if (len(part) == 2
                and part in COUNTRY_MAP
                and part not in _FALSE_POSITIVE_CODES):
            return part

    return "XX"