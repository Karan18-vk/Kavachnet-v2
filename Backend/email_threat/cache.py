"""Simple file-based cache for API results to avoid rate-limit exhaustion."""
import json, time, hashlib, logging
from pathlib import Path

logger = logging.getLogger(__name__)

class APICache:
    def __init__(self, cache_dir: str = ".cache", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl

    def _key_path(self, key: str) -> Path:
        hashed = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed}.json"

    def get(self, key: str):
        path = self._key_path(key)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if time.time() - data["ts"] < self.ttl:
                    return data["value"]
                path.unlink()
            except Exception:
                pass
        return None

    def set(self, key: str, value):
        path = self._key_path(key)
        try:
            path.write_text(json.dumps({"ts": time.time(), "value": value}))
        except Exception as e:
            logger.debug(f"Cache write error: {e}")
