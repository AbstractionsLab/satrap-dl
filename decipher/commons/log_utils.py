"""
Centralized logging configuration for DECIPHER.

Configures logging based on settings from config/decipher.yml.
Supports console and file output with different log levels.
"""

import logging
from datetime import datetime

from decipher.settings import (
    ENABLE_FILE_LOGGING,
    LOG_LEVEL,
    LOGS_DIR,
)


# Log format configuration
DEFAULT_LOGGING_FORMAT = (
    "[%(levelname)s] %(asctime)s - %(name)s: %(message)s"
)
CONSOLE_LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
SHORT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def assign_log_level() -> int:
    """
    Determine log level from settings.
    Supported levels: DEBUG, INFO, WARNING, ERROR (case-insensitive)

    Returns:
        Python logging level constant.
    """
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    try:
        log_level = level_map.get(LOG_LEVEL.upper(), logging.INFO)
    except Exception as e:
        print(f"[Warning] Invalid log level '{LOG_LEVEL}' in settings. Defaulting to INFO. Error: {e}")
        log_level = logging.INFO
    return log_level


def setup_logging(log_level: int | None = None, enable_file_logging: bool | None = None):
    """
    Configure centralized logging for the entire DECIPHER package.
    
    Sets up both console and file handlers with appropriate formatters.
    File logs are organized by date in /logs/decipher/<YYYY-MM-DD>/.
    
    Args:
        log_level: Override log level (uses config file if not provided).
        enable_file_logging: Enable file output (uses config if not provided, default: False).
    """
    if log_level is None:
        log_level = assign_log_level()

    if enable_file_logging is None:
        enable_file_logging = ENABLE_FILE_LOGGING
    
    # Configure root logger for decipher package
    decipher_logger = logging.getLogger("decipher")
    decipher_logger.setLevel(log_level)
    
    # Clear any existing handlers to avoid duplicates
    decipher_logger.handlers.clear()
    
    # Console handler - always enabled
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    # console_formatter = logging.Formatter(CONSOLE_LOGGING_FORMAT, datefmt=SHORT_DATE_FORMAT)
    console_formatter = logging.Formatter(DEFAULT_LOGGING_FORMAT, datefmt=SHORT_DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    decipher_logger.addHandler(console_handler)
    
    # File handler - optional
    if enable_file_logging:
        log_dir = LOGS_DIR / datetime.now().strftime("%Y-%m-%d")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"decipher_{datetime.now().strftime('%H%M%S')}.log"
        
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(DEFAULT_LOGGING_FORMAT, datefmt=SHORT_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        decipher_logger.addHandler(file_handler)
        
        decipher_logger.info(f"File logging enabled: {log_file}")
    
    # Prevent propagation to root logger to avoid duplicate logs
    decipher_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a DECIPHER module.
    
    All loggers are children of the 'decipher' logger and inherit its configuration.
    
    Args:
        name: Module name (typically __name__).
        
    Returns:
        Configured logger instance.
    """
    # Ensure name is under decipher namespace
    if not name.startswith("decipher."):
        name = f"decipher.{name}"
    
    return logging.getLogger(name)


# Initialize logging when module is imported, subsequent imports reuse the loaded module
setup_logging()
