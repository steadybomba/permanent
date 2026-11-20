import threading
import os
import time
import random
import re
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

_lock = threading.Lock()
_proxies: List[str] = []
_index = 0

# Global helpers (will be initialized below)
_proxy_health_checker = None
_proxy_metrics = None


def load_proxies_from_env_or_file(env_key: str = 'PROXY_LIST', file_path: Optional[str] = None) -> List[str]:
    """Load proxies from `PROXY_LIST` env var or from a proxy.txt file.
    Normalizes proxies to include scheme (defaults to http:// when missing).
    Returns the list of proxies stored in the manager.
    """
    global _proxies, _index
    proxies: List[str] = []

    # First try environment
    env_val = os.environ.get(env_key, '') or ''
    if env_val:
        parts = [p.strip() for p in env_val.split(',') if p.strip()]
        proxies.extend(parts)

    # Fallback to file if no env proxies
    if not proxies and file_path:
        p = Path(file_path)
        if p.exists():
            with p.open('r', encoding='utf-8') as fh:
                for line in fh:
                    ln = line.strip()
                    if not ln or ln.startswith('#'):
                        continue
                    proxies.append(ln)

    # Normalize and validate
    normalized = []
    for ln in proxies:
        ln = ln.strip()
        if not ln:
            continue
        # Ensure scheme
        if not re.match(r'^[a-zA-Z]+://', ln):
            ln = 'http://' + ln
        if validate_proxy(ln):
            normalized.append(ln)

    if not normalized and proxies:
        # warn if proxies were provided but none valid
        print(f"Warning: 0 valid proxies loaded from input (skipping invalid entries)")

    with _lock:
        _proxies = normalized
        _index = 0

    return list(_proxies)


# -------------------- PROXY VALIDATION --------------------
def validate_proxy(proxy_url: str) -> bool:
    """Validate proxy URL format."""
    if not proxy_url:
        return False
    try:
        parsed = urlparse(proxy_url)
        if not parsed.scheme:
            parsed = urlparse('http://' + proxy_url)

        valid_schemes = ['http', 'https', 'socks5', 'socks4', 'socks']
        if parsed.scheme not in valid_schemes:
            return False

        if not parsed.hostname:
            return False

        if parsed.port and not (1 <= parsed.port <= 65535):
            return False

        return True
    except Exception:
        return False


def clean_proxy_url(proxy_url: str) -> str:
    proxy_url = proxy_url.strip()
    if not proxy_url.startswith(('http://', 'https://', 'socks')):
        proxy_url = 'http://' + proxy_url
    return proxy_url


def get_proxy_count() -> int:
    with _lock:
        return len(_proxies)


def get_current_proxy() -> Optional[str]:
    """Return the next proxy that would be returned without advancing rotation."""
    with _lock:
        if not _proxies:
            return None
        return _proxies[_index % len(_proxies)]


def get_proxy_index() -> int:
    """Return the current rotation index for the next proxy."""
    with _lock:
        return _index


def get_all_proxies() -> List[str]:
    with _lock:
        return list(_proxies)


# -------------------- PROXY HEALTH CHECKER --------------------
class ProxyHealthChecker:
    """Check proxy health and performance with aggressive multi-URL testing."""

    def __init__(self):
        self._healthy_proxies = set()
        self._unhealthy_proxies = set()
        self._proxy_metrics: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        # Aggressive test parameters: multiple URLs to increase success rate
        self._test_urls = [
            'https://httpbin.org/ip',
            'http://httpbin.org/ip',
            'https://api.ipify.org',
            'http://api.ipify.org',
            'https://ipinfo.io/json',
            'http://checkip.amazonaws.com',
        ]
        self._timeouts = [10, 15, 20]  # Extended timeouts in seconds
        self._retries = int(os.environ.get('PROXY_TEST_RETRIES', '2'))  # Retries per proxy
        self._timeout = float(os.environ.get('PROXY_TEST_TIMEOUT', '10'))  # Primary timeout

    def check_proxy(self, proxy_url: str) -> Tuple[bool, float, Optional[str]]:
        """Check if a proxy is working using aggressive multi-URL, multi-timeout, multi-retry strategy."""
        for attempt in range(self._retries):
            for timeout in self._timeouts:
                for test_url in self._test_urls:
                    try:
                        start = time.time()
                        response = requests.get(
                            test_url,
                            proxies={'http': proxy_url, 'https': proxy_url},
                            timeout=timeout,
                            headers={'User-Agent': 'Mozilla/5.0'},
                            allow_redirects=True
                        )
                        duration = time.time() - start

                        if response.status_code in [200, 301, 302]:
                            with self._lock:
                                self._healthy_proxies.add(proxy_url)
                                self._unhealthy_proxies.discard(proxy_url)
                                if proxy_url not in self._proxy_metrics:
                                    self._proxy_metrics[proxy_url] = {}
                                self._proxy_metrics[proxy_url]['last_check'] = time.time()
                                self._proxy_metrics[proxy_url]['response_time'] = duration
                                self._proxy_metrics[proxy_url]['success_count'] = self._proxy_metrics[proxy_url].get('success_count', 0) + 1
                                self._proxy_metrics[proxy_url]['fail_count'] = 0
                                self._proxy_metrics[proxy_url]['success_url'] = test_url
                                self._proxy_metrics[proxy_url]['success_timeout'] = timeout
                            return True, duration, response.text.strip()[:20]
                    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
                        continue
                    except Exception:
                        continue

        # All attempts failed
        with self._lock:
            self._unhealthy_proxies.add(proxy_url)
            self._healthy_proxies.discard(proxy_url)
            if proxy_url not in self._proxy_metrics:
                self._proxy_metrics[proxy_url] = {}
            self._proxy_metrics[proxy_url]['fail_count'] = self._proxy_metrics[proxy_url].get('fail_count', 0) + 1
            self._proxy_metrics[proxy_url]['last_failure'] = time.time()
        return False, 0, None

    def check_all_proxies(self, proxies: List[str], max_workers: int = 50) -> Dict[str, bool]:
        """Check all proxies concurrently with aggressive testing."""
        results: Dict[str, bool] = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.check_proxy, p): p for p in proxies}
            for future in as_completed(futures):
                p = futures[future]
                try:
                    success, duration, ip = future.result()
                    results[p] = success
                except Exception:
                    results[p] = False
        return results

    def get_healthy_proxies(self) -> List[str]:
        with self._lock:
            return list(self._healthy_proxies)

    def is_proxy_healthy(self, proxy_url: str) -> bool:
        with self._lock:
            return proxy_url in self._healthy_proxies

    def get_proxy_metrics(self) -> Dict[str, Dict]:
        with self._lock:
            return dict(self._proxy_metrics)


# -------------------- PROXY METRICS --------------------
class ProxyMetrics:
    """Track proxy usage metrics."""

    def __init__(self):
        self._metrics: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def record_use(self, proxy: str, success: bool, duration: float):
        """Record proxy usage."""
        with self._lock:
            if proxy not in self._metrics:
                self._metrics[proxy] = {
                    'uses': 0,
                    'success': 0,
                    'failure': 0,
                    'total_time': 0.0,
                    'avg_time': 0.0,
                    'last_use': None,
                    'success_rate': 0.0
                }

            m = self._metrics[proxy]
            m['uses'] += 1
            m['total_time'] += duration
            if success:
                m['success'] += 1
            else:
                m['failure'] += 1

            m['avg_time'] = m['total_time'] / m['uses'] if m['uses'] > 0 else 0
            m['success_rate'] = m['success'] / m['uses'] if m['uses'] > 0 else 0
            m['last_use'] = time.time()

    def get_best_proxy(self) -> Optional[str]:
        with self._lock:
            if not self._metrics:
                return None
            best_proxy = None
            best_score = -1
            for proxy, m in self._metrics.items():
                # speed_score normalized
                speed_score = 1 / (m['avg_time'] + 0.1)
                score = (m['success_rate'] * 0.7) + (min(speed_score, 1) * 0.3)
                if score > best_score:
                    best_score = score
                    best_proxy = proxy
            return best_proxy

    def get_stats(self) -> Dict:
        with self._lock:
            total_uses = sum(m['uses'] for m in self._metrics.values())
            total_success = sum(m['success'] for m in self._metrics.values())
            return {
                'total_proxies': len(self._metrics),
                'total_uses': total_uses,
                'total_success': total_success,
                'overall_success_rate': (total_success / max(1, total_uses)),
                'best_proxy': self.get_best_proxy(),
                'metrics': dict(self._metrics)
            }


# Initialize global instances
_proxy_health_checker = ProxyHealthChecker()
_proxy_metrics = ProxyMetrics()


# -------------------- SCORING / SELECTION --------------------
def score_proxy(proxy_url: str) -> float:
    """Score a proxy based on health, speed, and success rate."""
    score = 50.0
    try:
        if _proxy_health_checker.is_proxy_healthy(proxy_url):
            score += 30

        metrics = _proxy_metrics.get_stats().get('metrics', {})
        if proxy_url in metrics:
            m = metrics[proxy_url]
            if m.get('avg_time', 9999) < 1:
                score += 20
            elif m.get('avg_time', 9999) < 2:
                score += 10
            elif m.get('avg_time', 9999) < 3:
                score += 5
            score += m.get('success_rate', 0) * 20

        if proxy_url.startswith('socks'):
            score += 10
        elif proxy_url.startswith('https'):
            score += 5
    except Exception:
        pass
    return min(score, 100.0)


def get_next_proxy(force_rotation: bool = True) -> Optional[str]:
    """Return the following proxy in round-robin order and advance the pointer."""
    global _index
    with _lock:
        if not _proxies:
            return None

        if len(_proxies) == 1:
            return _proxies[0]

        next_index = (_index + 1) % len(_proxies)
        proxy = _proxies[next_index]
        _index = next_index
        return proxy


def get_next_proxy_weighted() -> Optional[str]:
    """Select a proxy using weighted random selection based on scores."""
    proxies = get_all_proxies()
    if not proxies:
        return None
    scored = [(p, score_proxy(p)) for p in proxies]
    total = sum(s for _, s in scored)
    if total <= 0:
        return get_next_proxy()
    r = random.uniform(0, total)
    cum = 0.0
    for p, s in scored:
        cum += s
        if r <= cum:
            return p
    return proxies[0]


def categorize_proxy(proxy_url: str) -> str:
    """Categorize a proxy by protocol and simple country code detection."""
    cats = []
    if proxy_url.startswith('socks5'):
        cats.append('socks5')
    elif proxy_url.startswith('socks4'):
        cats.append('socks4')
    elif proxy_url.startswith('https'):
        cats.append('https')
    elif proxy_url.startswith('http'):
        cats.append('http')

    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname or ''
        patterns = {'US': ['us', 'usa'], 'UK': ['uk', 'gb'], 'DE': ['de', 'germany'], 'FR': ['fr', 'france']}
        for code, pats in patterns.items():
            if any(p in host.lower() for p in pats):
                cats.append(code)
                break
    except Exception:
        pass

    return '-'.join(cats)


def get_proxies_by_category(category: str) -> List[str]:
    return [p for p in get_all_proxies() if categorize_proxy(p) == category]


def get_proxy_health_status() -> Dict[str, bool]:
    return {p: _proxy_health_checker.is_proxy_healthy(p) for p in get_all_proxies()}
