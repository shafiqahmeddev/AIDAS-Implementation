#!/usr/bin/env python3
"""
Example test file for AIDAS protocol components
This demonstrates the testing structure for the project
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from aidas_protocol import (
    PUFSimulator, ChaoticMap, CryptographicEngine,
    Entity, Operator, AutonomousVehicle, ChargingStation,
    ElectricServiceProvider, AIDASimulator
)
import secrets


class TestPUFSimulator:
    """Test Physical Unclonable Function simulator"""
    
    def test_puf_creation(self):
        """Test PUF simulator creation"""
        puf = PUFSimulator("test_device")
        assert puf.device_id == "test_device"
        assert puf.noise_level == 0.03
    
    def test_response_generation(self):
        """Test PUF response generation"""
        puf = PUFSimulator("test_device")
        challenge = secrets.token_bytes(16)
        response = puf.generate_response(challenge)
        
        assert isinstance(response, bytes)
        assert len(response) == 16
    
    def test_response_uniqueness(self):
        """Test that different devices generate different responses"""
        puf1 = PUFSimulator("device1")
        puf2 = PUFSimulator("device2")
        challenge = secrets.token_bytes(16)
        
        response1 = puf1.generate_response(challenge)
        response2 = puf2.generate_response(challenge)
        
        assert response1 != response2
    
    def test_response_verification(self):
        """Test PUF response verification with fuzzy matching"""
        puf = PUFSimulator("test_device")
        challenge = secrets.token_bytes(16)
        response = puf.generate_response(challenge)
        
        # Same response should verify
        assert puf.verify_response(challenge, response, threshold=0.9)
        
        # Completely different response should fail
        wrong_response = secrets.token_bytes(16)
        assert not puf.verify_response(challenge, wrong_response, threshold=0.9)


class TestChaoticMap:
    """Test Chaotic Map cryptography"""
    
    def test_chaotic_map_creation(self):
        """Test chaotic map initialization"""
        cm = ChaoticMap(r=3.99, x0=0.5)
        assert cm.r == 3.99
        assert cm.x == 0.5
    
    def test_chaotic_map_iteration(self):
        """Test chaotic map iteration"""
        cm = ChaoticMap(r=3.99, x0=0.5)
        initial_value = cm.x
        
        # Iterate once
        new_value = cm.iterate()
        assert new_value != initial_value
        assert 0 <= new_value <= 1
    
    def test_key_generation(self):
        """Test cryptographic key generation"""
        cm = ChaoticMap()
        key16 = cm.generate_key(16)
        key32 = cm.generate_key(32)
        
        assert len(key16) == 16
        assert len(key32) == 32
        assert key16 != key32[:16]  # Keys should be different
    
    def test_sensitivity_to_initial_conditions(self):
        """Test butterfly effect in chaotic maps"""
        cm1 = ChaoticMap(r=3.99, x0=0.5)
        cm2 = ChaoticMap(r=3.99, x0=0.50001)  # Slightly different
        
        # After several iterations, values should diverge
        for _ in range(10):
            cm1.iterate()
            cm2.iterate()
        
        assert abs(cm1.x - cm2.x) > 0.1  # Significant divergence


class TestCryptographicEngine:
    """Test cryptographic operations"""
    
    def test_sha256_hash(self):
        """Test SHA-256 hashing"""
        crypto = CryptographicEngine()
        data = b"test data"
        hash_result = crypto.sha256_hash(data)
        
        assert len(hash_result) == 32  # SHA-256 produces 32 bytes
        # Hash should be deterministic
        assert hash_result == crypto.sha256_hash(data)
    
    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption"""
        crypto = CryptographicEngine()
        key = secrets.token_bytes(32)
        plaintext = b"This is a secret message for AIDAS testing"
        
        # Encrypt
        ciphertext, iv = crypto.aes_encrypt(key, plaintext)
        assert ciphertext != plaintext
        assert len(iv) == 16
        
        # Decrypt
        decrypted = crypto.aes_decrypt(key, ciphertext, iv)
        assert decrypted == plaintext
    
    def test_hmac_hash(self):
        """Test HMAC-SHA256"""
        crypto = CryptographicEngine()
        key = secrets.token_bytes(32)
        data = b"test data"
        
        hmac_result = crypto.hmac_hash(key, data)
        assert len(hmac_result) == 32
        
        # HMAC should be deterministic for same key and data
        assert hmac_result == crypto.hmac_hash(key, data)
        
        # Different key should produce different HMAC
        different_key = secrets.token_bytes(32)
        assert hmac_result != crypto.hmac_hash(different_key, data)


class TestEntities:
    """Test entity creation and management"""
    
    def test_operator_creation(self):
        """Test operator entity creation"""
        bio_data = secrets.token_bytes(32)
        operator = Operator("OP001", "secure_password", bio_data)
        
        assert operator.entity_id == "OP001"
        assert operator.entity_type == "Operator"
        assert operator.password == "secure_password"
        assert operator.biometric_data == bio_data
    
    def test_vehicle_creation(self):
        """Test autonomous vehicle creation"""
        vehicle = AutonomousVehicle("AV001")
        
        assert vehicle.entity_id == "AV001"
        assert vehicle.entity_type == "AV"
        assert vehicle.puf is not None
        assert vehicle.chaotic_map is not None
    
    def test_charging_station_creation(self):
        """Test charging station creation"""
        station = ChargingStation("CS001")
        
        assert station.entity_id == "CS001"
        assert station.entity_type == "CS"
    
    def test_esp_creation(self):
        """Test ESP creation"""
        esp = ElectricServiceProvider("ESP001")
        
        assert esp.entity_id == "ESP001"
        assert esp.entity_type == "ESP"
        assert len(esp.secret_key) == 32


class TestProtocolIntegration:
    """Test complete protocol flows"""
    
    @pytest.fixture
    def simulator(self):
        """Create a simulator instance for testing"""
        return AIDASimulator()
    
    def test_entity_registration(self, simulator):
        """Test entity registration with ESP"""
        # Create and register operator
        bio_data = secrets.token_bytes(32)
        operator = simulator.create_operator("TEST_OP", "password123", bio_data)
        assert operator is not None
        assert "TEST_OP" in simulator.entities
        
        # Create and register vehicle
        vehicle = simulator.create_vehicle("TEST_AV")
        assert vehicle is not None
        assert "TEST_AV" in simulator.entities
        
        # Create and register charging station
        station = simulator.create_charging_station("TEST_CS")
        assert station is not None
        assert "TEST_CS" in simulator.entities
    
    def test_authentication_session(self, simulator):
        """Test complete authentication session"""
        # Create entities
        bio_data = secrets.token_bytes(32)
        operator = simulator.create_operator("AUTH_OP", "password", bio_data)
        vehicle = simulator.create_vehicle("AUTH_AV")
        station = simulator.create_charging_station("AUTH_CS")
        
        # Run authentication session
        try:
            simulator.simulate_authentication_session("AUTH_OP", "AUTH_AV", "AUTH_CS")
            
            # Check if session was established
            assert "AUTH_AV" in operator.sessions
            session_info = operator.sessions["AUTH_AV"]
            assert "session_key" in session_info
            assert len(session_info["session_key"]) == 32
            
        except Exception as e:
            pytest.fail(f"Authentication session failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
