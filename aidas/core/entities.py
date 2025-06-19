"""
AIDAS Protocol Entity Classes
Defines all participating entities in the authentication protocol
"""

import time
import secrets
from typing import Dict, Optional, Any, List
from cryptography.hazmat.primitives import serialization
from .puf import PUFSimulator
from .chaotic_map import ChaoticMap
from .crypto import CryptographicEngine
from ..ai.dqn_detector import DQNIntrusionDetector
from ..utils.logger import get_logger
from ..utils.config import config
import numpy as np

logger = get_logger(__name__)


class Entity:
    """
    Base class for all protocol entities
    
    Provides common functionality for authentication participants
    including cryptographic operations and session management.
    """
    
    def __init__(self, entity_id: str, entity_type: str):
        """
        Initialize base entity
        
        Args:
            entity_id: Unique identifier for the entity
            entity_type: Type of entity (Operator, AV, CS, ESP)
        """
        if not entity_id or not entity_type:
            raise ValueError("Entity ID and type cannot be empty")
        
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.crypto = CryptographicEngine()
        self.sessions = {}
        self.created_at = time.time()
        self.last_activity = time.time()
        
        # Generate entity-specific keypair
        self.private_key, self.public_key = self.crypto.generate_ecc_keypair()
        
        logger.info(f"Entity created", {
            'entity_id': entity_id,
            'entity_type': entity_type,
            'created_at': self.created_at
        })
    
    def generate_random(self, length: int = 16) -> bytes:
        """Generate cryptographically secure random bytes"""
        return self.crypto.generate_random_bytes(length)
    
    def timestamp(self) -> int:
        """Get current timestamp in milliseconds"""
        return int(time.time() * 1000)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def cleanup_expired_sessions(self, max_age_seconds: int = None):
        """Clean up expired sessions"""
        max_age_seconds = max_age_seconds or config.security.session_timeout_seconds
        current_time = time.time()
        
        expired_sessions = []
        for session_id, session_data in self.sessions.items():
            if current_time - session_data.get('established_at', 0) > max_age_seconds:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            logger.debug(f"Session expired", {
                'entity_id': self.entity_id,
                'session_id': session_id
            })
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Get session information"""
        return self.sessions.get(session_id)
    
    def __repr__(self) -> str:
        return f"{self.entity_type}(id='{self.entity_id}', sessions={len(self.sessions)})"


class Operator(Entity):
    """
    Remote Operator entity
    
    Represents a human operator who needs to authenticate
    to access and control autonomous vehicles.
    """
    
    def __init__(self, operator_id: str, password: str, biometric_data: bytes):
        """
        Initialize operator entity
        
        Args:
            operator_id: Unique operator identifier
            password: Authentication password
            biometric_data: Biometric template data
        """
        super().__init__(operator_id, "Operator")
        
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        if not biometric_data or len(biometric_data) < 16:
            raise ValueError("Biometric data must be at least 16 bytes")
        
        self.password = password
        self.biometric_data = biometric_data
        self.smart_card = None
        self.failed_attempts = 0
        self.locked_until = None
        
        # Generate biometric hash for privacy
        self.biometric_hash = self.crypto.sha256_hash(biometric_data)
        
        logger.info(f"Operator initialized", {
            'operator_id': operator_id,
            'biometric_hash_length': len(self.biometric_hash)
        })
    
    def register_with_esp(self, esp: 'ElectricServiceProvider', token: str) -> bool:
        """
        Register operator with Electric Service Provider
        
        Args:
            esp: ESP instance
            token: Registration token
            
        Returns:
            True if registration successful
        """
        logger.info(f"Operator {self.entity_id} registering with ESP")
        
        registration_data = {
            "operator_id": self.entity_id,
            "token": token,
            "bio_hash": self.biometric_hash.hex(),
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            ).hex()
        }
        
        self.smart_card = esp.register_operator(registration_data, self.password)
        
        if self.smart_card:
            logger.info(f"Operator {self.entity_id} registered successfully")
            return True
        else:
            logger.error(f"Operator {self.entity_id} registration failed")
            return False
    
    def is_locked(self) -> bool:
        """Check if operator account is locked"""
        if self.locked_until is None:
            return False
        return time.time() < self.locked_until
    
    def lock_account(self, duration_seconds: int = 300):
        """Lock operator account for specified duration"""
        self.locked_until = time.time() + duration_seconds
        logger.warning(f"Operator {self.entity_id} account locked for {duration_seconds} seconds")
    
    def unlock_account(self):
        """Unlock operator account"""
        self.locked_until = None
        self.failed_attempts = 0
        logger.info(f"Operator {self.entity_id} account unlocked")
    
    def verify_credentials(self, password: str, biometric_data: bytes) -> bool:
        """
        Verify operator credentials
        
        Args:
            password: Provided password
            biometric_data: Provided biometric data
            
        Returns:
            True if credentials are valid
        """
        if self.is_locked():
            logger.warning(f"Authentication attempt on locked account: {self.entity_id}")
            return False
        
        # Verify password
        password_valid = self.crypto.secure_compare(
            password.encode(), 
            self.password.encode()
        )
        
        # Verify biometric data (fuzzy matching)
        bio_hash = self.crypto.sha256_hash(biometric_data)
        biometric_valid = self.crypto.secure_compare(bio_hash, self.biometric_hash)
        
        if password_valid and biometric_valid:
            self.failed_attempts = 0
            self.update_activity()
            logger.info(f"Operator {self.entity_id} credentials verified")
            return True
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= config.security.max_authentication_attempts:
                self.lock_account()
            
            logger.warning(f"Invalid credentials for operator {self.entity_id}", {
                'failed_attempts': self.failed_attempts,
                'password_valid': password_valid,
                'biometric_valid': biometric_valid
            })
            return False
    
    def login_and_authenticate(self, esp: 'ElectricServiceProvider', av_id: str) -> bool:
        """
        Perform login and authentication protocol
        
        Args:
            esp: Electric Service Provider
            av_id: Target autonomous vehicle ID
            
        Returns:
            True if authentication successful
        """
        if not self.smart_card:
            raise ValueError("Operator not registered - no smart card")
        
        if self.is_locked():
            logger.warning(f"Authentication attempt on locked account: {self.entity_id}")
            return False
        
        logger.info(f"Operator {self.entity_id} initiating authentication for AV {av_id}")
        
        try:
            # Step 1: Smart Card Verification
            temp_id = self.crypto.sha256_hash(
                f"{self.entity_id}_{self.password}_{self.biometric_hash.hex()}".encode()
            )
            
            # Generate authentication message MS1
            r_o = self.generate_random()
            j1 = self.crypto.sha256_hash(f"{self.entity_id}_{temp_id.hex()}_{r_o.hex()}".encode())
            b1 = self.crypto.sha256_hash(f"{temp_id.hex()}_{j1.hex()}_{self.timestamp()}".encode())
            
            ms1 = {
                "operator_id_masked": temp_id.hex(),
                "j1": j1.hex(),
                "b1": b1.hex(),
                "av_id": av_id,
                "timestamp": self.timestamp(),
                "public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                ).hex()
            }
            
            # Send to ESP and receive session key
            session_key = esp.authenticate_operator(ms1, self)
            
            if session_key:
                self.sessions[av_id] = {
                    "session_key": session_key,
                    "established_at": time.time(),
                    "last_used": time.time(),
                    "message_count": 0
                }
                
                self.update_activity()
                logger.info(f"Authentication successful. Session established with AV {av_id}")
                return True
            else:
                self.failed_attempts += 1
                if self.failed_attempts >= config.security.max_authentication_attempts:
                    self.lock_account()
                return False
                
        except Exception as e:
            logger.error(f"Authentication error for operator {self.entity_id}: {e}")
            return False
    
    def send_encrypted_command(self, av_id: str, command: Dict[str, Any]) -> Optional[bytes]:
        """
        Send encrypted command to autonomous vehicle
        
        Args:
            av_id: Target vehicle ID
            command: Command to send
            
        Returns:
            Encrypted command bytes
        """
        if av_id not in self.sessions:
            logger.error(f"No active session with AV {av_id}")
            return None
        
        session = self.sessions[av_id]
        session_key = session["session_key"]
        
        # Serialize command
        import json
        command_json = json.dumps(command).encode()
        
        # Encrypt command
        ciphertext, iv = self.crypto.aes_encrypt(session_key, command_json)
        
        # Update session statistics
        session["last_used"] = time.time()
        session["message_count"] += 1
        
        logger.debug(f"Command encrypted for AV {av_id}", {
            'command_size': len(command_json),
            'ciphertext_size': len(ciphertext)
        })
        
        return ciphertext + iv  # Combine for transmission


class AutonomousVehicle(Entity):
    """
    Autonomous Vehicle entity with PUF capability
    
    Represents an autonomous vehicle that participates in the
    authentication protocol using hardware-level security.
    """
    
    def __init__(self, vehicle_id: str):
        """
        Initialize autonomous vehicle
        
        Args:
            vehicle_id: Unique vehicle identifier
        """
        super().__init__(vehicle_id, "AV")
        
        # Initialize PUF for hardware-level security
        self.puf = PUFSimulator(vehicle_id)
        
        # Initialize chaotic map for key generation
        self.chaotic_map = ChaoticMap()
        
        # Vehicle-specific data
        self.registration_data = None
        self.vehicle_status = "offline"
        self.location = {"lat": 0.0, "lon": 0.0}
        self.battery_level = 100.0
        self.charging_session = None
        
        logger.info(f"Autonomous vehicle initialized", {
            'vehicle_id': vehicle_id,
            'puf_device': vehicle_id,
            'status': self.vehicle_status
        })
    
    def register_with_esp(self, esp: 'ElectricServiceProvider', token: str) -> bool:
        """
        Register vehicle with ESP
        
        Args:
            esp: Electric Service Provider
            token: Registration token
            
        Returns:
            True if registration successful
        """
        logger.info(f"Vehicle {self.entity_id} registering with ESP")
        
        registration_result = esp.register_vehicle(self.entity_id, token)
        
        if registration_result["status"] == "registered":
            self.registration_data = registration_result
            
            # Generate PUF response for enrollment
            alpha_av = bytes.fromhex(registration_result["alpha_av"])
            beta_av = self.puf.generate_response(alpha_av)
            
            # Store enrollment data
            self.registration_data["beta_av"] = beta_av.hex()
            
            self.vehicle_status = "registered"
            self.update_activity()
            
            logger.info(f"Vehicle {self.entity_id} registered and PUF enrolled")
            return True
        else:
            logger.error(f"Vehicle {self.entity_id} registration failed")
            return False
    
    def update_status(self, status: str, location: Optional[Dict] = None, 
                     battery_level: Optional[float] = None):
        """
        Update vehicle status
        
        Args:
            status: Vehicle status (online, offline, charging, etc.)
            location: GPS coordinates
            battery_level: Battery percentage
        """
        self.vehicle_status = status
        
        if location:
            self.location.update(location)
        
        if battery_level is not None:
            self.battery_level = max(0.0, min(100.0, battery_level))
        
        self.update_activity()
        
        logger.debug(f"Vehicle status updated", {
            'vehicle_id': self.entity_id,
            'status': status,
            'location': self.location,
            'battery_level': self.battery_level
        })
    
    def process_authentication_request(self, ms3: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process authentication request from charging station
        
        Args:
            ms3: Authentication message from charging station
            
        Returns:
            Authentication response message MS4
        """
        if not self.registration_data:
            raise ValueError("Vehicle not registered")
        
        if self.vehicle_status == "offline":
            raise ValueError("Vehicle is offline")
        
        logger.info(f"Vehicle {self.entity_id} processing authentication request")
        
        # Extract and verify authentication data
        operator_data = ms3.get("operator_data", {})
        station_id = ms3.get("station_id")
        r_cs = ms3.get("r_cs")
        
        # Generate session key using chaotic map
        session_key = self.chaotic_map.generate_key(32)
        
        # Generate PUF response for additional security
        challenge = bytes.fromhex(r_cs) if r_cs else self.generate_random()
        puf_response = self.puf.generate_response(challenge)
        
        # Generate response message MS4
        r_av = self.generate_random()
        b3 = self.crypto.sha256_hash(
            f"{self.entity_id}_{session_key.hex()}_{r_av.hex()}_{self.timestamp()}".encode()
        )
        
        ms4 = {
            "r_av": r_av.hex(),
            "b3": b3.hex(),
            "vehicle_id": self.entity_id,
            "puf_response": puf_response.hex(),
            "timestamp": self.timestamp(),
            "vehicle_status": self.vehicle_status,
            "battery_level": self.battery_level,
            "location": self.location
        }
        
        # Store session information
        session_id = f"{station_id}_{operator_data.get('operator_id', 'unknown')}"
        self.sessions[session_id] = {
            "session_key": session_key,
            "established_at": time.time(),
            "station_id": station_id,
            "operator_id": operator_data.get("operator_id"),
            "puf_challenge": challenge.hex(),
            "puf_response": puf_response.hex()
        }
        
        self.update_activity()
        logger.info(f"Vehicle {self.entity_id} authentication response generated")
        
        return ms4
    
    def start_charging_session(self, station_id: str, operator_id: str) -> Optional[str]:
        """
        Start charging session with validated station and operator
        
        Args:
            station_id: Charging station ID
            operator_id: Operator ID
            
        Returns:
            Charging session ID if successful
        """
        session_key = f"{station_id}_{operator_id}"
        
        if session_key not in self.sessions:
            logger.error(f"No valid authentication session for charging")
            return None
        
        charging_session_id = f"CHG_{self.entity_id}_{int(time.time())}"
        
        self.charging_session = {
            "session_id": charging_session_id,
            "station_id": station_id,
            "operator_id": operator_id,
            "start_time": time.time(),
            "start_battery": self.battery_level,
            "status": "charging"
        }
        
        self.update_status("charging")
        
        logger.info(f"Charging session started", {
            'vehicle_id': self.entity_id,
            'session_id': charging_session_id,
            'station_id': station_id,
            'operator_id': operator_id
        })
        
        return charging_session_id
    
    def stop_charging_session(self) -> Optional[Dict[str, Any]]:
        """
        Stop current charging session
        
        Returns:
            Charging session summary
        """
        if not self.charging_session:
            logger.warning(f"No active charging session to stop")
            return None
        
        session_summary = {
            **self.charging_session,
            "end_time": time.time(),
            "end_battery": self.battery_level,
            "energy_consumed": max(0, self.battery_level - self.charging_session["start_battery"]),
            "duration_minutes": (time.time() - self.charging_session["start_time"]) / 60
        }
        
        self.charging_session = None
        self.update_status("online")
        
        logger.info(f"Charging session completed", session_summary)
        
        return session_summary
    
    def get_diagnostic_data(self) -> Dict[str, Any]:
        """Get vehicle diagnostic information"""
        return {
            "vehicle_id": self.entity_id,
            "status": self.vehicle_status,
            "location": self.location,
            "battery_level": self.battery_level,
            "active_sessions": len(self.sessions),
            "charging_session": self.charging_session,
            "last_activity": self.last_activity,
            "puf_status": "operational",
            "chaotic_map_state": self.chaotic_map.x
        }


class ChargingStation(Entity):
    """
    Charging Station entity - Authentication intermediary
    
    Acts as an intermediary in the authentication protocol,
    facilitating secure communication between operators and vehicles.
    """
    
    def __init__(self, station_id: str):
        """
        Initialize charging station
        
        Args:
            station_id: Unique station identifier
        """
        super().__init__(station_id, "CS")
        
        self.registration_data = None
        self.station_status = "offline"
        self.location = {"lat": 0.0, "lon": 0.0, "address": ""}
        self.charging_ports = []
        self.active_sessions = {}
        self.energy_capacity = 150.0  # kW
        self.current_load = 0.0
        
        logger.info(f"Charging station initialized", {
            'station_id': station_id,
            'status': self.station_status
        })
    
    def register_with_esp(self, esp: 'ElectricServiceProvider', token: str) -> bool:
        """
        Register charging station with ESP
        
        Args:
            esp: Electric Service Provider
            token: Registration token
            
        Returns:
            True if registration successful
        """
        logger.info(f"Charging Station {self.entity_id} registering with ESP")
        
        registration_result = esp.register_charging_station(self.entity_id, token)
        
        if registration_result["status"] == "registered":
            self.registration_data = registration_result
            self.station_status = "online"
            self.update_activity()
            
            logger.info(f"Charging Station {self.entity_id} registered successfully")
            return True
        else:
            logger.error(f"Charging Station {self.entity_id} registration failed")
            return False
    
    def initialize_charging_ports(self, port_count: int = 4):
        """
        Initialize charging ports
        
        Args:
            port_count: Number of charging ports
        """
        self.charging_ports = []
        
        for i in range(port_count):
            port = {
                "port_id": f"{self.entity_id}_P{i+1:02d}",
                "status": "available",
                "vehicle_id": None,
                "session_id": None,
                "power_rating": 50.0,  # kW
                "current_power": 0.0
            }
            self.charging_ports.append(port)
        
        logger.info(f"Initialized {port_count} charging ports for station {self.entity_id}")
    
    def get_available_port(self) -> Optional[Dict[str, Any]]:
        """Get next available charging port"""
        for port in self.charging_ports:
            if port["status"] == "available":
                return port
        return None
    
    def relay_authentication(self, ms2: Dict[str, Any], vehicle: AutonomousVehicle) -> Dict[str, Any]:
        """
        Relay authentication messages between ESP and AV
        
        Args:
            ms2: Message from ESP
            vehicle: Target autonomous vehicle
            
        Returns:
            Message MS5 for ESP
        """
        if not self.registration_data:
            raise ValueError("Charging station not registered")
        
        if self.station_status != "online":
            raise ValueError("Charging station is offline")
        
        logger.info(f"Station {self.entity_id} relaying authentication for vehicle {vehicle.entity_id}")
        
        # Generate charging station parameters
        r_cs = self.generate_random()
        
        # Create message MS3 for vehicle
        ms3 = {
            "operator_data": ms2,
            "r_cs": r_cs.hex(),
            "station_id": self.entity_id,
            "timestamp": self.timestamp(),
            "station_location": self.location,
            "available_ports": len([p for p in self.charging_ports if p["status"] == "available"])
        }
        
        # Get response from vehicle
        ms4 = vehicle.process_authentication_request(ms3)
        
        # Create message MS5 for ESP
        station_verification = self.crypto.sha256_hash(
            f"{self.entity_id}_{r_cs.hex()}_{ms4['timestamp']}".encode()
        )
        
        ms5 = {
            "vehicle_response": ms4,
            "station_verification": station_verification.hex(),
            "station_id": self.entity_id,
            "timestamp": self.timestamp(),
            "relay_latency": self.timestamp() - ms3["timestamp"]
        }
        
        self.update_activity()
        logger.info(f"Station {self.entity_id} authentication relay completed")
        
        return ms5
    
    def allocate_charging_port(self, vehicle_id: str, operator_id: str) -> Optional[str]:
        """
        Allocate charging port for authenticated vehicle
        
        Args:
            vehicle_id: Vehicle ID
            operator_id: Operator ID
            
        Returns:
            Port ID if allocation successful
        """
        available_port = self.get_available_port()
        
        if not available_port:
            logger.warning(f"No available ports at station {self.entity_id}")
            return None
        
        # Allocate port
        available_port["status"] = "occupied"
        available_port["vehicle_id"] = vehicle_id
        available_port["session_id"] = f"SESSION_{vehicle_id}_{int(time.time())}"
        
        # Create charging session
        self.active_sessions[available_port["session_id"]] = {
            "port_id": available_port["port_id"],
            "vehicle_id": vehicle_id,
            "operator_id": operator_id,
            "start_time": time.time(),
            "status": "active"
        }
        
        logger.info(f"Port allocated", {
            'station_id': self.entity_id,
            'port_id': available_port["port_id"],
            'vehicle_id': vehicle_id,
            'operator_id': operator_id
        })
        
        return available_port["port_id"]
    
    def release_charging_port(self, port_id: str) -> bool:
        """
        Release charging port
        
        Args:
            port_id: Port to release
            
        Returns:
            True if release successful
        """
        for port in self.charging_ports:
            if port["port_id"] == port_id:
                # Clean up session
                if port["session_id"] and port["session_id"] in self.active_sessions:
                    del self.active_sessions[port["session_id"]]
                
                # Reset port
                port["status"] = "available"
                port["vehicle_id"] = None
                port["session_id"] = None
                port["current_power"] = 0.0
                
                logger.info(f"Port released", {
                    'station_id': self.entity_id,
                    'port_id': port_id
                })
                
                return True
        
        logger.warning(f"Port not found: {port_id}")
        return False
    
    def get_station_status(self) -> Dict[str, Any]:
        """Get comprehensive station status"""
        total_ports = len(self.charging_ports)
        available_ports = len([p for p in self.charging_ports if p["status"] == "available"])
        occupied_ports = total_ports - available_ports
        
        return {
            "station_id": self.entity_id,
            "status": self.station_status,
            "location": self.location,
            "total_ports": total_ports,
            "available_ports": available_ports,
            "occupied_ports": occupied_ports,
            "active_sessions": len(self.active_sessions),
            "current_load": self.current_load,
            "energy_capacity": self.energy_capacity,
            "utilization": (occupied_ports / total_ports * 100) if total_ports > 0 else 0,
            "last_activity": self.last_activity
        }


class ElectricServiceProvider(Entity):
    """
    Electric Service Provider - Central authentication authority
    
    Acts as the trusted third party that manages registration
    and authentication for all entities in the AIDAS ecosystem.
    """
    
    def __init__(self, esp_id: str):
        """
        Initialize Electric Service Provider
        
        Args:
            esp_id: Unique ESP identifier
        """
        super().__init__(esp_id, "ESP")
        
        # Master secret key for the ESP
        self.secret_key = self.generate_random(32)
        
        # Entity registries
        self.registered_operators = {}
        self.registered_vehicles = {}
        self.registered_stations = {}
        
        # AI-based intrusion detection
        self.intrusion_detector = DQNIntrusionDetector()
        
        # Authentication statistics
        self.auth_stats = {
            "total_attempts": 0,
            "successful_auths": 0,
            "blocked_attempts": 0,
            "average_latency": 0.0,
            "security_incidents": 0
        }
        
        logger.info(f"Electric Service Provider initialized", {
            'esp_id': esp_id,
            'secret_key_length': len(self.secret_key)
        })
    
    def register_operator(self, registration_data: Dict[str, str], password: str) -> Optional[Dict[str, str]]:
        """
        Register a new operator
        
        Args:
            registration_data: Operator registration information
            password: Operator password
            
        Returns:
            Smart card credentials if successful
        """
        operator_id = registration_data["operator_id"]
        
        if operator_id in self.registered_operators:
            logger.warning(f"Operator {operator_id} already registered")
            return None
        
        # Generate smart card credentials
        r_o = self.generate_random()
        temp_id = self.crypto.sha256_hash(f"{operator_id}_{r_o.hex()}".encode())
        
        d_o = self.crypto.sha256_hash(f"{operator_id}_{self.secret_key.hex()}_{temp_id.hex()}".encode())
        e_o = self.crypto.sha256_hash(f"smart_card_{self.secret_key.hex()}".encode())
        
        smart_card = {
            "r_o": r_o.hex(),
            "d_o": d_o.hex(),
            "e_o": e_o.hex(),
            "temp_id": temp_id.hex(),
            "issued_at": time.time()
        }
        
        # Store operator registration
        self.registered_operators[operator_id] = {
            "temp_id": temp_id.hex(),
            "smart_card_id": f"SC_{operator_id}",
            "bio_hash": registration_data["bio_hash"],
            "public_key": registration_data.get("public_key"),
            "registered_at": time.time(),
            "last_auth": None,
            "auth_count": 0,
            "failed_attempts": 0
        }
        
        logger.info(f"Operator {operator_id} registered successfully")
        return smart_card
    
    def register_vehicle(self, vehicle_id: str, token: str) -> Dict[str, str]:
        """
        Register an autonomous vehicle
        
        Args:
            vehicle_id: Vehicle identifier
            token: Registration token
            
        Returns:
            Registration result
        """
        if vehicle_id in self.registered_vehicles:
            logger.info(f"Vehicle {vehicle_id} already registered")
            return {"status": "already_registered"}
        
        # Generate PUF challenge and vehicle credentials
        alpha_av = self.generate_random()
        r_av = self.generate_random()
        k_av = self.crypto.sha256_hash(f"{vehicle_id}_{self.secret_key.hex()}_{r_av.hex()}".encode())
        
        self.registered_vehicles[vehicle_id] = {
            "alpha_av": alpha_av.hex(),
            "k_av": k_av.hex(),
            "r_av": r_av.hex(),
            "registered_at": time.time(),
            "last_auth": None,
            "auth_count": 0,
            "status": "active"
        }
        
        logger.info(f"Vehicle {vehicle_id} registered successfully")
        return {
            "status": "registered",
            "alpha_av": alpha_av.hex(),
            "k_av": k_av.hex()
        }
    
    def register_charging_station(self, station_id: str, token: str) -> Dict[str, str]:
        """
        Register a charging station
        
        Args:
            station_id: Station identifier
            token: Registration token
            
        Returns:
            Registration result
        """
        if station_id in self.registered_stations:
            logger.info(f"Charging station {station_id} already registered")
            return {"status": "already_registered"}
        
        alpha_cs = self.generate_random()
        r_cs = self.generate_random()
        k_cs = self.crypto.sha256_hash(f"{station_id}_{self.secret_key.hex()}_{r_cs.hex()}".encode())
        
        self.registered_stations[station_id] = {
            "alpha_cs": alpha_cs.hex(),
            "k_cs": k_cs.hex(),
            "r_cs": r_cs.hex(),
            "registered_at": time.time(),
            "last_auth": None,
            "auth_count": 0,
            "status": "active"
        }
        
        logger.info(f"Charging Station {station_id} registered successfully")
        return {
            "status": "registered",
            "alpha_cs": alpha_cs.hex(),
            "k_cs": k_cs.hex()
        }
    
    def authenticate_operator(self, ms1: Dict[str, Any], operator: Operator) -> Optional[bytes]:
        """
        Authenticate operator and establish session
        
        Args:
            ms1: Authentication message from operator
            operator: Operator instance
            
        Returns:
            Session key if authentication successful
        """
        operator_id = operator.entity_id
        start_time = time.time()
        
        self.auth_stats["total_attempts"] += 1
        
        if operator_id not in self.registered_operators:
            logger.warning(f"Operator {operator_id} not registered")
            self.auth_stats["blocked_attempts"] += 1
            return None
        
        # AI-based intrusion detection
        network_features = self._extract_network_features(ms1, operator)
        detection_result = self.intrusion_detector.detect_intrusion(network_features)
        
        if detection_result["action"] == 3:  # Blocked
            logger.warning(f"Authentication blocked for operator {operator_id} due to security concerns", {
                'detection_result': detection_result
            })
            self.auth_stats["blocked_attempts"] += 1
            self.auth_stats["security_incidents"] += 1
            return None
        
        # Verify authentication message
        if not self._verify_authentication_message(ms1, operator_id):
            logger.warning(f"Invalid authentication message from {operator_id}")
            self.registered_operators[operator_id]["failed_attempts"] += 1
            return None
        
        # Generate session key
        r_esp = self.generate_random()
        session_key = self.crypto.sha256_hash(
            f"{operator_id}_{self.entity_id}_{r_esp.hex()}_{ms1['timestamp']}".encode()
        )
        
        # Update statistics
        auth_latency = (time.time() - start_time) * 1000
        self.auth_stats["successful_auths"] += 1
        self.auth_stats["average_latency"] = (
            (self.auth_stats["average_latency"] * (self.auth_stats["successful_auths"] - 1) + auth_latency) /
            self.auth_stats["successful_auths"]
        )
        
        # Update operator record
        operator_record = self.registered_operators[operator_id]
        operator_record["last_auth"] = time.time()
        operator_record["auth_count"] += 1
        operator_record["failed_attempts"] = 0
        
        self.update_activity()
        
        logger.info(f"Session key generated for operator {operator_id}", {
            'latency_ms': auth_latency,
            'security_posture': detection_result["posture"]["level"]
        })
        
        return session_key
    
    def _extract_network_features(self, ms1: Dict[str, Any], operator: Operator) -> np.ndarray:
        """
        Extract network features for AI-based intrusion detection
        
        Args:
            ms1: Authentication message
            operator: Operator instance
            
        Returns:
            Feature vector for DQN
        """
        current_time = time.time()
        
        # Extract features from message and operator history
        features = [
            len(ms1.get("j1", "")) / 64.0,  # Normalized message length
            min((current_time - ms1.get("timestamp", 0)/1000) / 60.0, 1.0),  # Time delay (clamped)
            1.0 if operator.entity_id in self.registered_operators else 0.0,  # Registration status
            min(operator.failed_attempts / 10.0, 1.0),  # Failure rate (normalized)
            min(len(operator.sessions) / 5.0, 1.0),  # Active sessions (normalized)
            np.random.random(),  # Simulated network metrics
            np.random.random(),  # Packet loss rate
            np.random.random(),  # Authentication frequency
            np.random.random(),  # Attack indicators
            np.random.random()   # System load
        ]
        
        return np.array(features, dtype=np.float32)
    
    def _verify_authentication_message(self, ms1: Dict[str, Any], operator_id: str) -> bool:
        """
        Verify authentication message integrity
        
        Args:
            ms1: Authentication message
            operator_id: Operator ID
            
        Returns:
            True if message is valid
        """
        # Basic message structure validation
        required_fields = ["operator_id_masked", "j1", "b1", "av_id", "timestamp"]
        
        for field in required_fields:
            if field not in ms1:
                logger.warning(f"Missing field in authentication message: {field}")
                return False
        
        # Timestamp validation (within 5 minutes)
        message_time = ms1.get("timestamp", 0) / 1000
        current_time = time.time()
        
        if abs(current_time - message_time) > 300:  # 5 minutes
            logger.warning(f"Authentication message timestamp too old", {
                'message_time': message_time,
                'current_time': current_time,
                'difference': current_time - message_time
            })
            return False
        
        # Additional cryptographic verification would go here
        # For now, we'll assume the message is structurally valid
        
        return True
    
    def revoke_entity(self, entity_id: str, entity_type: str) -> bool:
        """
        Revoke entity registration
        
        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            
        Returns:
            True if revocation successful
        """
        registry_map = {
            "Operator": self.registered_operators,
            "AV": self.registered_vehicles,
            "CS": self.registered_stations
        }
        
        registry = registry_map.get(entity_type)
        
        if not registry or entity_id not in registry:
            logger.warning(f"Entity not found for revocation: {entity_type}:{entity_id}")
            return False
        
        # Mark as revoked instead of deleting for audit trail
        registry[entity_id]["status"] = "revoked"
        registry[entity_id]["revoked_at"] = time.time()
        
        logger.info(f"Entity revoked", {
            'entity_id': entity_id,
            'entity_type': entity_type,
            'revoked_at': time.time()
        })
        
        return True
    
    def get_entity_status(self, entity_id: str, entity_type: str) -> Optional[Dict[str, Any]]:
        """
        Get entity registration status
        
        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            
        Returns:
            Entity status information
        """
        registry_map = {
            "Operator": self.registered_operators,
            "AV": self.registered_vehicles,
            "CS": self.registered_stations
        }
        
        registry = registry_map.get(entity_type)
        
        if not registry or entity_id not in registry:
            return None
        
        return registry[entity_id].copy()
    
    def get_authentication_statistics(self) -> Dict[str, Any]:
        """Get comprehensive authentication statistics"""
        success_rate = (
            (self.auth_stats["successful_auths"] / self.auth_stats["total_attempts"] * 100)
            if self.auth_stats["total_attempts"] > 0 else 0
        )
        
        detection_stats = self.intrusion_detector.get_statistics()
        
        return {
            "authentication": self.auth_stats.copy(),
            "success_rate_percent": success_rate,
            "registered_entities": {
                "operators": len(self.registered_operators),
                "vehicles": len(self.registered_vehicles),
                "stations": len(self.registered_stations)
            },
            "intrusion_detection": detection_stats,
            "esp_uptime": time.time() - self.created_at
        }
    
    def backup_registrations(self, filepath: str):
        """
        Backup entity registrations to file
        
        Args:
            filepath: Backup file path
        """
        import json
        
        backup_data = {
            "esp_id": self.entity_id,
            "backup_timestamp": time.time(),
            "operators": self.registered_operators,
            "vehicles": self.registered_vehicles,
            "stations": self.registered_stations,
            "auth_stats": self.auth_stats
        }
        
        with open(filepath, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        logger.info(f"Registrations backed up to {filepath}")
    
    def restore_registrations(self, filepath: str) -> bool:
        """
        Restore entity registrations from backup
        
        Args:
            filepath: Backup file path
            
        Returns:
            True if restore successful
        """
        import json
        import os
        
        if not os.path.exists(filepath):
            logger.error(f"Backup file not found: {filepath}")
            return False
        
        try:
            with open(filepath, 'r') as f:
                backup_data = json.load(f)
            
            self.registered_operators = backup_data.get("operators", {})
            self.registered_vehicles = backup_data.get("vehicles", {})
            self.registered_stations = backup_data.get("stations", {})
            self.auth_stats = backup_data.get("auth_stats", self.auth_stats)
            
            logger.info(f"Registrations restored from {filepath}", {
                'operators': len(self.registered_operators),
                'vehicles': len(self.registered_vehicles),
                'stations': len(self.registered_stations)
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore registrations: {e}")
            return False
    
    def __repr__(self) -> str:
        return (f"ElectricServiceProvider(id='{self.entity_id}', "
                f"operators={len(self.registered_operators)}, "
                f"vehicles={len(self.registered_vehicles)}, "
                f"stations={len(self.registered_stations)})")