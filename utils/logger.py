import logging

def get_logger(name: str = "app_logger"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def log_activity(level: str, message: str):
    """
    Log general activity with a severity level.
    Example:
        log_activity("error", "Feed loading failed")
        log_activity("info", "Threat classification started")
    """
    logger = get_logger("activity")
    logger.info(f"[{level.upper()}] {message}")


def log_api_call(api_name: str, status: str, details: str = ""):
    """
    Log API-specific events
    """
    logger = get_logger("api")
    logger.info(f"{api_name} | Status: {status} | Details: {details}")
