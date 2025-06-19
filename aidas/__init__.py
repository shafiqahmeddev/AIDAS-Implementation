"""
AIDAS: AI-Enhanced Intrusion Detection and Authentication for Autonomous Vehicles
Main package initialization file
"""

from .core.entities import Operator, AutonomousVehicle, ChargingStation, ElectricServiceProvider
from .core.crypto import CryptographicEngine
from .core.puf import PUFSimulator
from .core.chaotic_map import ChaoticMap
from .ai.dqn_detector import DQNIntrusionDetector
from .protocol.authentication import AIDASimulator
from .utils.logger import get_logger
from .utils.config import Config

__version__ = "1.0.0"
__author__ = "AIDAS Development Team"

__all__ = [
    "Operator",
    "AutonomousVehicle", 
    "ChargingStation",
    "ElectricServiceProvider",
    "CryptographicEngine",
    "PUFSimulator",
    "ChaoticMap",
    "DQNIntrusionDetector",
    "AIDASimulator",
    "get_logger",
    "Config"
]