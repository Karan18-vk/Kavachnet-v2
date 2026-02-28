# Backend/utils/state.py

import redis
import time
import threading
from config import Config
from utils.logger import app_logger

class StateStore:
    def __init__(self):
        self.use_redis = False
        self.memory_store = {}
        self.lock = threading.Lock()
        
        try:
            self.redis_client = redis.from_url(Config.REDIS_URL, decode_responses=True, socket_timeout=1)
            self.redis_client.ping()
            self.use_redis = True
            app_logger.info("Connected to Redis successfully for production state.")
        except Exception as e:
            app_logger.warning(f"Redis unavailable ({str(e)}). Falling back to Local Memory Store. (Security Note: Not persistent across worker restarts)")

    def setex(self, key, seconds, value):
        if self.use_redis:
            try:
                self.redis_client.setex(key, seconds, value)
                return
            except:
                pass
        
        with self.lock:
            self.memory_store[key] = {
                "val": value,
                "exp": time.time() + seconds
            }

    def get(self, key):
        if self.use_redis:
            try:
                return self.redis_client.get(key)
            except:
                pass
        
        with self.lock:
            record = self.memory_store.get(key)
            if not record:
                return None
            if time.time() > record["exp"]:
                del self.memory_store[key]
                return None
            return record["val"]

    def delete(self, key):
        if self.use_redis:
            try:
                self.redis_client.delete(key)
                return
            except:
                pass
                
        with self.lock:
            if key in self.memory_store:
                del self.memory_store[key]

state_store = StateStore()
