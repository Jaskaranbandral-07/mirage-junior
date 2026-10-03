import requests
import json
import os
import time

class GeoEnricher:
    def __init__(self):
        self.cache_file = "database/geo_cache.json"
        self.cache = self._load_cache()
        self.last_req = 0

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r") as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        with open(self.cache_file, "w") as f:
            json.dump(self.cache, f)

    def enrich_ip(self, ip_address):
        """Fetches IP info from ip-api.com with rate limiting and caching."""
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        # Rate limit: max 45 req/min (1.33 sec per req)
        now = time.time()
        if now - self.last_req < 1.35:
            time.sleep(1.35 - (now - self.last_req))
            
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip_address}")
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
                        "as": data.get("as")
                    }
                    self.cache[ip_address] = info
                    self._save_cache()
                    return info
        except Exception as e:
            pass
        return None
