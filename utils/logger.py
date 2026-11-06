import os
import logging
from logging.handlers import RotatingFileHandler

class SQLiteHandler(logging.Handler):
    """Custom logging handler to write structured log records into SQLite."""
    def __init__(self, db_manager):
        super().__init__()
        self.db_manager = db_manager

    def emit(self, record):
        # Avoid recursion loops: do not log messages from sqlite itself or db_manager back into sqlite
        if record.name == 'db_manager' or 'sqlite' in record.name.lower():
            return
        try:
            log_msg = self.format(record)
            self.db_manager.add_detection_log(
                log_level=record.levelname,
                component=record.name,
                message=log_msg
            )
        except Exception:
            # If the database is busy or unavailable, fall back to standard error handling
            self.handleError(record)

def setup_logger(name, db_manager=None, log_file=None, level=logging.INFO):
    """Set up a logger with File and (optionally) SQLite handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers if logger is already configured
    if logger.hasHandlers():
        return logger

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] - %(message)s'
    )

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # File Handler
    if log_file is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(base_dir, "logs", "ids.log")
        
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    try:
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create RotatingFileHandler for {log_file}: {e}")

    # SQLite Handler (if DB manager is provided)
    if db_manager is not None:
        db_handler = SQLiteHandler(db_manager)
        # Only log INFO and above in DB to avoid bloating it with DEBUG logs
        db_handler.setLevel(logging.INFO)
        db_handler.setFormatter(logging.Formatter('%(message)s'))  # simple format since db has fields
        logger.addHandler(db_handler)

    return logger
