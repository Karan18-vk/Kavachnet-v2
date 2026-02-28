import json
import logging
import datetime
from logging import StreamHandler

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Inject custom kwargs passed via 'extra'
        if hasattr(record, "metrics"):
            log_data.update(record.metrics)
            
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def setup_json_logger(name="kavach_json_logger", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers if called multiple times
    if not logger.handlers:
        handler = StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        
    logger.propagate = False
    return logger

json_metrics_logger = setup_json_logger("kavach_observability")
