"""
Physical Unclonable Function (PUF) Implementation
Simulates hardware-level security for device authentication
"""

import hashlib
import numpy as np
from typing import Optional
from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class PUFSimulator:
    """
    Simulates Physical Unclonable Function for hardware-level security
    
    PUFs exploit manufacturing variations to create unique device fingerprints
    that are practically unclonable and provide hardware-level authentication.
    """
    
    def __init__(self, device_id: str, noise_level: Optional[float] = None):
        """
        Initialize PUF simulator for a specific device
        
        Args:
            device_id: Unique identifier for the device
            noise_level: Noise level for PUF responses (0.0 to 1.0)
        """
        self.device_id = device_id
        self.noise_level = noise_level or config.security.puf_noise_level
        
        # Generate device-specific seed based on device ID
        self.seed = int(hashlib.sha256(device_id.encode()).hexdigest(), 16) % (2**32)
        
        logger.debug(f"PUF initialized for device {device_id}", {
            'device_id': device_id,
            'noise_level': self.noise_level,
            'seed': self.seed
        })
        
    def generate_response(self, challenge: bytes) -> bytes:
        """
        Generate PUF response for given challenge
        
        Simulates SRAM PUF behavior with controlled noise to model
        real-world manufacturing variations and environmental effects.
        
        Args:
            challenge: Input challenge bytes
            
        Returns:
            PUF response bytes (16 bytes)
        """
        if not challenge:
            raise ValueError("Challenge cannot be empty")
            
        # Convert challenge to integer
        challenge_int = int.from_bytes(challenge, 'big')
        combined = self.seed ^ challenge_int
        
        # Add controlled noise to simulate real PUF behavior
        np.random.seed(combined % (2**32))
        noise = np.random.random() < self.noise_level
        
        # Generate deterministic response with noise
        response_input = f"{combined}_{self.device_id}_{noise}"
        response = hashlib.sha256(response_input.encode()).digest()[:16]
        
        logger.debug(f"PUF response generated", {
            'device_id': self.device_id,
            'challenge_length': len(challenge),
            'response_length': len(response),
            'noise_applied': noise
        })
        
        return response
    
    def verify_response(self, challenge: bytes, response: bytes, 
                       threshold: Optional[float] = None) -> bool:
        """
        Verify PUF response with fuzzy matching
        
        Uses Hamming distance to account for noise in PUF responses,
        which is essential for practical PUF implementations.
        
        Args:
            challenge: Original challenge
            response: Response to verify
            threshold: Similarity threshold (0.0 to 1.0)
            
        Returns:
            True if response is valid, False otherwise
        """
        if not challenge or not response:
            return False
            
        threshold = threshold or config.security.puf_verification_threshold
        expected = self.generate_response(challenge)
        
        if len(expected) != len(response):
            logger.warning(f"Response length mismatch", {
                'device_id': self.device_id,
                'expected_length': len(expected),
                'actual_length': len(response)
            })
            return False
        
        # Calculate Hamming distance for fuzzy matching
        hamming_distance = sum(a != b for a, b in zip(expected, response))
        similarity = 1.0 - (hamming_distance / len(expected))
        
        is_valid = similarity >= threshold
        
        logger.debug(f"PUF verification result", {
            'device_id': self.device_id,
            'similarity': similarity,
            'threshold': threshold,
            'hamming_distance': hamming_distance,
            'valid': is_valid
        })
        
        return is_valid
    
    def get_uniqueness_metrics(self, other_puf: 'PUFSimulator', 
                              num_challenges: int = 1000) -> dict:
        """
        Calculate uniqueness metrics between two PUFs
        
        Args:
            other_puf: Another PUF to compare against
            num_challenges: Number of challenges to test
            
        Returns:
            Dictionary with uniqueness metrics
        """
        if self.device_id == other_puf.device_id:
            raise ValueError("Cannot compare PUF with itself")
        
        import secrets
        
        hamming_distances = []
        
        for _ in range(num_challenges):
            challenge = secrets.token_bytes(16)
            response1 = self.generate_response(challenge)
            response2 = other_puf.generate_response(challenge)
            
            hamming_distance = sum(a != b for a, b in zip(response1, response2))
            hamming_distances.append(hamming_distance)
        
        avg_hamming_distance = np.mean(hamming_distances)
        response_length_bits = len(response1) * 8
        uniqueness = avg_hamming_distance / response_length_bits
        
        metrics = {
            'average_hamming_distance': avg_hamming_distance,
            'uniqueness_percentage': uniqueness * 100,
            'ideal_uniqueness': 50.0,  # 50% for ideal PUF
            'uniqueness_quality': abs(50.0 - (uniqueness * 100)),
            'num_challenges_tested': num_challenges
        }
        
        logger.info(f"PUF uniqueness analysis completed", {
            'device1': self.device_id,
            'device2': other_puf.device_id,
            'metrics': metrics
        })
        
        return metrics
    
    def get_reliability_metrics(self, num_tests: int = 100) -> dict:
        """
        Calculate reliability metrics for this PUF
        
        Tests how consistently the PUF responds to the same challenge
        under different conditions (simulated by multiple generations).
        
        Args:
            num_tests: Number of reliability tests to perform
            
        Returns:
            Dictionary with reliability metrics
        """
        import secrets
        
        # Generate test challenges
        challenges = [secrets.token_bytes(16) for _ in range(10)]
        
        reliability_scores = []
        
        for challenge in challenges:
            # Generate reference response
            reference_response = self.generate_response(challenge)
            
            # Test multiple times
            matches = 0
            for _ in range(num_tests):
                test_response = self.generate_response(challenge)
                if self.verify_response(challenge, test_response):
                    matches += 1
            
            reliability = matches / num_tests
            reliability_scores.append(reliability)
        
        avg_reliability = np.mean(reliability_scores)
        
        metrics = {
            'average_reliability': avg_reliability,
            'reliability_percentage': avg_reliability * 100,
            'min_reliability': np.min(reliability_scores),
            'max_reliability': np.max(reliability_scores),
            'std_reliability': np.std(reliability_scores),
            'num_challenges_tested': len(challenges),
            'tests_per_challenge': num_tests
        }
        
        logger.info(f"PUF reliability analysis completed", {
            'device_id': self.device_id,
            'metrics': metrics
        })
        
        return metrics
    
    def export_challenge_response_pairs(self, num_pairs: int = 100) -> list:
        """
        Export challenge-response pairs for enrollment/testing
        
        Args:
            num_pairs: Number of CRP pairs to generate
            
        Returns:
            List of (challenge, response) tuples
        """
        import secrets
        
        crp_pairs = []
        
        for _ in range(num_pairs):
            challenge = secrets.token_bytes(16)
            response = self.generate_response(challenge)
            crp_pairs.append((challenge.hex(), response.hex()))
        
        logger.info(f"Exported {num_pairs} CRP pairs for device {self.device_id}")
        
        return crp_pairs
    
    def __repr__(self) -> str:
        return f"PUFSimulator(device_id='{self.device_id}', noise_level={self.noise_level})"