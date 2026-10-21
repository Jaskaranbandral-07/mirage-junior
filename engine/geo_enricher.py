import requests
import json
import os
import time
import ipaddress
from config.settings import GEO_API_URL, GEO_CACHE_DURATION

class GeoEnricher:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(GeoEnricher, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        self._initialized = True
        self.cache_file = "database/geo_cache.json"
        self.cache = self._load_cache()
        self.last_req = 0
        self.api_url = GEO_API_URL
        self.cache_duration = GEO_CACHE_DURATION

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, "w") as f:
                json.dump(self.cache, f)
        except Exception:
            pass

    @classmethod
    def lookup(cls, ip_address):
        """Looks up IP geolocation info, with caching and private IP handling."""
        instance = cls._instance if cls._instance is not None else cls()
        return instance._lookup(ip_address)

    def _lookup(self, ip_address):
        if not ip_address or ip_address in ('localhost', '127.0.0.1', '::1'):
            return {
                "country": "Local",
                "city": "Local",
                "isp": "Local Network",
                "lat": 0,
                "lon": 0,
                "as": "Local"
            }

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "country": "Local",
                    "city": "Local",
                    "isp": "Local Network",
                    "lat": 0,
                    "lon": 0,
                    "as": "Local"
                }
        except ValueError:
            pass

        now = time.time()
        if ip_address in self.cache:
            entry = self.cache[ip_address]
            cached_at = entry.get('_cached_at', 0) if isinstance(entry, dict) else 0
            if now - cached_at < self.cache_duration:
                return {k: v for k, v in entry.items() if k != '_cached_at'}

        # Rate limit: max 45 req/min (1.33 sec per req)
        if now - self.last_req < 1.35:
            time.sleep(1.35 - (now - self.last_req))

        try:
            url = self.api_url.format(ip=ip_address) if "{ip}" in self.api_url else f"{self.api_url}/{ip_address}"
            resp = requests.get(url, timeout=5)
            self.last_req = time.time()
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "as": data.get("as"),
                        "_cached_at": time.time()
                    }
                    self.cache[ip_address] = info
                    self._save_cache()
                    return {k: v for k, v in info.items() if k != '_cached_at'}
        except Exception:
            pass
        return None

    def enrich_ip(self, ip_address):
        """Fetches IP info from ip-api.com with rate limiting and caching."""
        return self.lookup(ip_address)
