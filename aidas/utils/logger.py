"""
Advanced logging system for AIDAS protocol
Provides structured logging with multiple handlers and formatters
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any
import json


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color coding for different log levels"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        # Add color to the log level
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        
        # Add timestamp and module info
        record.timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        record.module_line = f"{record.filename}:{record.lineno}"
        
        return super().format(record)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
            
        return json.dumps(log_entry)


class AIDALogger:
    """Enhanced logger for AIDAS protocol with multiple output streams"""
    
    def __init__(self, name: str, log_level: str = "INFO", 
                 log_dir: str = "logs", enable_file_logging: bool = True):
        self.name = name
        self.log_level = getattr(logging, log_level.upper())
        self.log_dir = log_dir
        self.enable_file_logging = enable_file_logging
        
        # Create logs directory
        if self.enable_file_logging:
            os.makedirs(self.log_dir, exist_ok=True)
        
        # Initialize logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_console_handler()
        if self.enable_file_logging:
            self._setup_file_handlers()
    
    def _setup_console_handler(self):
        """Setup colorized console output"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        
        console_format = '[%(timestamp)s] %(levelname)s [%(name)s:%(module_line)s] %(message)s'
        console_formatter = ColoredFormatter(console_format)
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(console_handler)
    
    def _setup_file_handlers(self):
        """Setup file handlers for different log levels"""
        
        # General log file (all levels)
        general_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.name}.log"),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        general_handler.setLevel(logging.DEBUG)
        
        general_format = '[%(asctime)s] %(levelname)s [%(name)s:%(filename)s:%(lineno)d] %(message)s'
        general_formatter = logging.Formatter(general_format)
        general_handler.setFormatter(general_formatter)
        
        self.logger.addHandler(general_handler)
        
        # Error log file (errors and critical only)
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.name}_errors.log"),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(general_formatter)
        
        self.logger.addHandler(error_handler)
        
        # Structured JSON log for analysis
        json_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f"{self.name}_structured.jsonl"),
            maxBytes=20*1024*1024,  # 20MB
            backupCount=5
        )
        json_handler.setLevel(logging.INFO)
        json_formatter = StructuredFormatter()
        json_handler.setFormatter(json_formatter)
        
        self.logger.addHandler(json_handler)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log debug message"""
        self.logger.debug(message, extra={'extra': extra} if extra else {})
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log info message"""
        self.logger.info(message, extra={'extra': extra} if extra else {})
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        self.logger.warning(message, extra={'extra': extra} if extra else {})
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log error message"""
        self.logger.error(message, extra={'extra': extra} if extra else {})
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log critical message"""
        self.logger.critical(message, extra={'extra': extra} if extra else {})
    
    def log_authentication_attempt(self, operator_id: str, vehicle_id: str, 
                                 station_id: str, success: bool, latency_ms: float):
        """Log authentication attempt with structured data"""
        extra = {
            'event_type': 'authentication_attempt',
            'operator_id': operator_id,
            'vehicle_id': vehicle_id,
            'station_id': station_id,
            'success': success,
            'latency_ms': latency_ms
        }
        
        if success:
            self.info(f"Authentication successful: {operator_id} -> {vehicle_id} via {station_id} ({latency_ms:.2f}ms)", extra)
        else:
            self.warning(f"Authentication failed: {operator_id} -> {vehicle_id} via {station_id}", extra)
    
    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log security events with detailed information"""
        extra = {
            'event_type': 'security_event',
            'security_event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        message = f"Security event: {event_type} (severity: {severity})"
        
        if severity.upper() in ['HIGH', 'CRITICAL']:
            self.error(message, extra)
        else:
            self.warning(message, extra)
    
    def log_performance_metrics(self, component: str, metrics: Dict[str, Any]):
        """Log performance metrics"""
        extra = {
            'event_type': 'performance_metrics',
            'component': component,
            'metrics': metrics
        }
        
        self.info(f"Performance metrics for {component}", extra)


# Global logger instances
_loggers: Dict[str, AIDALogger] = {}


def get_logger(name: str, log_level: str = "INFO", 
               log_dir: str = "logs", enable_file_logging: bool = True) -> AIDALogger:
    """Get or create a logger instance"""
    
    if name not in _loggers:
        _loggers[name] = AIDALogger(name, log_level, log_dir, enable_file_logging)
    
    return _loggers[name]


# Default logger for the package
logger = get_logger("aidas")