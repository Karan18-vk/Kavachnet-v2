# Backend/utils/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(name, log_file, level=logging.INFO):
    """Function to setup as many loggers as you want"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    
    handler = RotatingFileHandler(f'logs/{log_file}', maxBytes=10000000, backupCount=5)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

# Create specific loggers
security_logger = setup_logger('security', 'security.log')
app_logger = setup_logger('app', 'app.log')
audit_logger = setup_logger('audit', 'audit.log')
