"""
Configuration management system for AIDAS protocol
Handles loading and validation of configuration settings
"""

import os
import yaml
import json
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    encryption_key_length: int = 32
    hash_algorithm: str = "sha256"
    aes_mode: str = "CBC"
    puf_noise_level: float = 0.03
    puf_verification_threshold: float = 0.9
    session_timeout_seconds: int = 3600
    max_authentication_attempts: int = 3
    enable_fuzzy_matching: bool = True


@dataclass
class AIConfig:
    """AI/ML configuration settings"""
    dqn_state_dim: int = 10
    dqn_action_dim: int = 4
    dqn_memory_size: int = 10000
    learning_rate: float = 0.001
    epsilon_start: float = 1.0
    epsilon_min: float = 0.01
    epsilon_decay: float = 0.995
    gamma: float = 0.97
    batch_size: int = 32
    target_update_frequency: int = 100
    training_episodes: int = 1000


@dataclass
class ChaoticMapConfig:
    """Chaotic map configuration"""
    control_parameter: float = 3.99
    initial_condition_range: tuple = field(default_factory=lambda: (0.1, 0.9))
    key_generation_iterations: int = 1000
    randomness_threshold: float = 0.45


@dataclass
class NetworkConfig:
    """Network configuration settings"""
    esp_host: str = "localhost"
    esp_port: int = 8080
    api_version: str = "v1"
    timeout_seconds: int = 30
    max_retries: int = 3
    enable_tls: bool = True
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


@dataclass
class DatabaseConfig:
    """Database configuration"""
    db_type: str = "sqlite"
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "aidas"
    db_user: str = "aidas_user"
    db_password: str = ""
    db_path: str = "aidas.db"
    enable_migrations: bool = True
    connection_pool_size: int = 10


@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_level: str = "INFO"
    log_dir: str = "logs"
    enable_file_logging: bool = True
    enable_console_logging: bool = True
    enable_structured_logging: bool = True
    max_log_file_size: str = "10MB"
    log_retention_days: int = 30


@dataclass
class PerformanceConfig:
    """Performance tuning configuration"""
    enable_caching: bool = True
    cache_size: int = 1000
    cache_ttl_seconds: int = 300
    enable_metrics: bool = True
    metrics_collection_interval: int = 60
    enable_profiling: bool = False


@dataclass
class GUIConfig:
    """GUI configuration settings"""
    theme: str = "light"
    window_width: int = 1200
    window_height: int = 800
    enable_animations: bool = True
    refresh_rate: int = 1000
    chart_update_interval: int = 5000


class Config:
    """Main configuration class that handles all AIDAS settings"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        
        # Initialize configuration sections
        self.security = SecurityConfig()
        self.ai = AIConfig()
        self.chaotic_map = ChaoticMapConfig()
        self.network = NetworkConfig()
        self.database = DatabaseConfig()
        self.logging = LoggingConfig()
        self.performance = PerformanceConfig()
        self.gui = GUIConfig()
        
        # Load configuration if file exists
        if self.config_path and os.path.exists(self.config_path):
            self.load_config()
        
        # Override with environment variables
        self._load_from_environment()
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in standard locations"""
        possible_paths = [
            os.path.join(os.getcwd(), "config.yaml"),
            os.path.join(os.getcwd(), "config.yml"),
            os.path.join(os.getcwd(), "config", "config.yaml"),
            os.path.join(os.getcwd(), "config", "config.yml"),
            os.path.expanduser("~/.aidas/config.yaml"),
            "/etc/aidas/config.yaml"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def load_config(self, config_path: Optional[str] = None):
        """Load configuration from file"""
        if config_path:
            self.config_path = config_path
        
        if not self.config_path or not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                if self.config_path.endswith('.json'):
                    config_data = json.load(f)
                else:
                    config_data = yaml.safe_load(f)
            
            self._update_from_dict(config_data)
            
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}")
    
    def _update_from_dict(self, config_data: Dict[str, Any]):
        """Update configuration from dictionary"""
        
        # Update security settings
        if 'security' in config_data:
            self._update_dataclass(self.security, config_data['security'])
        
        # Update AI settings
        if 'ai' in config_data:
            self._update_dataclass(self.ai, config_data['ai'])
        
        # Update chaotic map settings
        if 'chaotic_map' in config_data:
            self._update_dataclass(self.chaotic_map, config_data['chaotic_map'])
        
        # Update network settings
        if 'network' in config_data:
            self._update_dataclass(self.network, config_data['network'])
        
        # Update database settings
        if 'database' in config_data:
            self._update_dataclass(self.database, config_data['database'])
        
        # Update logging settings
        if 'logging' in config_data:
            self._update_dataclass(self.logging, config_data['logging'])
        
        # Update performance settings
        if 'performance' in config_data:
            self._update_dataclass(self.performance, config_data['performance'])
        
        # Update GUI settings
        if 'gui' in config_data:
            self._update_dataclass(self.gui, config_data['gui'])
    
    def _update_dataclass(self, dataclass_instance, update_dict: Dict[str, Any]):
        """Update dataclass instance with values from dictionary"""
        for key, value in update_dict.items():
            if hasattr(dataclass_instance, key):
                setattr(dataclass_instance, key, value)
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'AIDAS_LOG_LEVEL': ('logging', 'log_level'),
            'AIDAS_DB_TYPE': ('database', 'db_type'),
            'AIDAS_DB_HOST': ('database', 'db_host'),
            'AIDAS_DB_PORT': ('database', 'db_port'),
            'AIDAS_DB_NAME': ('database', 'db_name'),
            'AIDAS_DB_USER': ('database', 'db_user'),
            'AIDAS_DB_PASSWORD': ('database', 'db_password'),
            'AIDAS_ESP_HOST': ('network', 'esp_host'),
            'AIDAS_ESP_PORT': ('network', 'esp_port'),
            'AIDAS_ENABLE_TLS': ('network', 'enable_tls'),
            'AIDAS_GUI_THEME': ('gui', 'theme'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            if env_var in os.environ:
                section_obj = getattr(self, section)
                value = os.environ[env_var]
                
                # Type conversion
                current_value = getattr(section_obj, key)
                if isinstance(current_value, bool):
                    value = value.lower() in ('true', '1', 'yes', 'on')
                elif isinstance(current_value, int):
                    value = int(value)
                elif isinstance(current_value, float):
                    value = float(value)
                
                setattr(section_obj, key, value)
    
    def save_config(self, config_path: Optional[str] = None):
        """Save current configuration to file"""
        if config_path:
            self.config_path = config_path
        
        if not self.config_path:
            raise ValueError("No configuration path specified")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        # Convert to dictionary
        config_dict = {
            'security': self._dataclass_to_dict(self.security),
            'ai': self._dataclass_to_dict(self.ai),
            'chaotic_map': self._dataclass_to_dict(self.chaotic_map),
            'network': self._dataclass_to_dict(self.network),
            'database': self._dataclass_to_dict(self.database),
            'logging': self._dataclass_to_dict(self.logging),
            'performance': self._dataclass_to_dict(self.performance),
            'gui': self._dataclass_to_dict(self.gui)
        }
        
        # Save to file
        with open(self.config_path, 'w') as f:
            if self.config_path.endswith('.json'):
                json.dump(config_dict, f, indent=2)
            else:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def _dataclass_to_dict(self, dataclass_instance) -> Dict[str, Any]:
        """Convert dataclass to dictionary"""
        return {
            field.name: getattr(dataclass_instance, field.name)
            for field in dataclass_instance.__dataclass_fields__.values()
        }
    
    def validate(self) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Validate security settings
        if self.security.encryption_key_length not in [16, 24, 32]:
            errors.append("Invalid encryption key length. Must be 16, 24, or 32 bytes.")
        
        if not 0 < self.security.puf_noise_level < 1:
            errors.append("PUF noise level must be between 0 and 1.")
        
        if not 0 < self.security.puf_verification_threshold <= 1:
            errors.append("PUF verification threshold must be between 0 and 1.")
        
        # Validate AI settings
        if self.ai.learning_rate <= 0:
            errors.append("Learning rate must be positive.")
        
        if not 0 <= self.ai.epsilon_min <= self.ai.epsilon_start <= 1:
            errors.append("Epsilon values must be between 0 and 1, with epsilon_min <= epsilon_start.")
        
        # Validate chaotic map settings
        if not 3.57 <= self.chaotic_map.control_parameter <= 4.0:
            errors.append("Chaotic map control parameter should be between 3.57 and 4.0 for chaotic behavior.")
        
        # Validate network settings
        if not 1 <= self.network.esp_port <= 65535:
            errors.append("ESP port must be between 1 and 65535.")
        
        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(errors))
        
        return True
    
    def get_database_url(self) -> str:
        """Get database connection URL"""
        if self.database.db_type.lower() == 'sqlite':
            return f"sqlite:///{self.database.db_path}"
        elif self.database.db_type.lower() == 'postgresql':
            return f"postgresql://{self.database.db_user}:{self.database.db_password}@{self.database.db_host}:{self.database.db_port}/{self.database.db_name}"
        else:
            raise ValueError(f"Unsupported database type: {self.database.db_type}")
    
    def __repr__(self) -> str:
        return f"Config(path={self.config_path})"


# Global configuration instance
config = Config()