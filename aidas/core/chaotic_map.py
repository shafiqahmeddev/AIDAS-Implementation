"""
Chaotic Map Cryptography Implementation
Uses logistic chaotic map for secure key generation and cryptographic operations
"""

import secrets
import numpy as np
from typing import Optional, List
from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class ChaoticMap:
    """
    Implements Logistic Chaotic Map for cryptographic operations
    
    The logistic map exhibits chaotic behavior for certain parameter values,
    making it suitable for generating cryptographically secure sequences.
    
    Logistic Map: x(n+1) = r * x(n) * (1 - x(n))
    where r is the control parameter and x(n) is the current state.
    """
    
    def __init__(self, r: Optional[float] = None, x0: Optional[float] = None):
        """
        Initialize chaotic map with parameters
        
        Args:
            r: Control parameter (3.57 ≤ r ≤ 4.0 for chaotic behavior)
            x0: Initial condition (0 < x0 < 1)
        """
        self.r = r or config.chaotic_map.control_parameter
        
        # Validate control parameter
        if not 3.57 <= self.r <= 4.0:
            logger.warning(f"Control parameter r={self.r} may not exhibit chaotic behavior")
        
        # Initialize with random value if not provided
        if x0 is None:
            min_x, max_x = config.chaotic_map.initial_condition_range
            x0 = min_x + (max_x - min_x) * secrets.randbelow(1000) / 1000.0
        
        if not 0 < x0 < 1:
            raise ValueError("Initial condition x0 must be between 0 and 1")
        
        self.x = x0
        self.initial_x = x0
        self.iteration_count = 0
        
        logger.debug(f"Chaotic map initialized", {
            'control_parameter': self.r,
            'initial_condition': x0
        })
    
    def iterate(self, n: int = 1) -> float:
        """
        Iterate the chaotic map n times
        
        Args:
            n: Number of iterations
            
        Returns:
            Current state value after n iterations
        """
        if n <= 0:
            raise ValueError("Number of iterations must be positive")
        
        for _ in range(n):
            self.x = self.r * self.x * (1 - self.x)
            self.iteration_count += 1
        
        return self.x
    
    def reset(self, x0: Optional[float] = None):
        """
        Reset the chaotic map to initial or specified state
        
        Args:
            x0: New initial condition (optional)
        """
        if x0 is not None:
            if not 0 < x0 < 1:
                raise ValueError("Initial condition x0 must be between 0 and 1")
            self.initial_x = x0
            self.x = x0
        else:
            self.x = self.initial_x
        
        self.iteration_count = 0
        
        logger.debug("Chaotic map reset", {
            'initial_condition': self.x
        })
    
    def generate_sequence(self, length: int, skip_iterations: int = 100) -> List[float]:
        """
        Generate a sequence of chaotic values
        
        Args:
            length: Length of sequence to generate
            skip_iterations: Initial iterations to skip (removes transients)
            
        Returns:
            List of chaotic values
        """
        if length <= 0:
            raise ValueError("Sequence length must be positive")
        
        # Skip initial transient behavior
        if skip_iterations > 0:
            self.iterate(skip_iterations)
        
        sequence = []
        for _ in range(length):
            self.iterate()
            sequence.append(self.x)
        
        logger.debug(f"Generated chaotic sequence of length {length}")
        
        return sequence
    
    def generate_key(self, length: int) -> bytes:
        """
        Generate cryptographic key using chaotic sequence
        
        Uses the chaotic map to generate a sequence of values that are
        converted to bits based on a threshold, then packed into bytes.
        
        Args:
            length: Key length in bytes
            
        Returns:
            Cryptographic key as bytes
        """
        if length <= 0:
            raise ValueError("Key length must be positive")
        
        key_bits = []
        iterations_needed = length * 8
        
        # Skip initial transients
        self.iterate(config.chaotic_map.key_generation_iterations // 10)
        
        for _ in range(iterations_needed):
            self.iterate()
            # Convert chaotic value to bit (0 or 1)
            key_bits.append(1 if self.x > 0.5 else 0)
        
        # Convert bits to bytes
        key = bytearray()
        for i in range(0, len(key_bits), 8):
            byte_val = sum(bit << (7-j) for j, bit in enumerate(key_bits[i:i+8]))
            key.append(byte_val)
        
        logger.debug(f"Generated {length}-byte cryptographic key", {
            'key_length': length,
            'iterations_used': iterations_needed
        })
        
        return bytes(key)
    
    def generate_keystream(self, length: int) -> bytes:
        """
        Generate keystream for stream cipher operations
        
        Args:
            length: Keystream length in bytes
            
        Returns:
            Keystream bytes
        """
        return self.generate_key(length)
    
    def encrypt_xor(self, plaintext: bytes, key_length: Optional[int] = None) -> bytes:
        """
        Encrypt data using XOR with chaotic keystream
        
        Args:
            plaintext: Data to encrypt
            key_length: Key length (defaults to plaintext length)
            
        Returns:
            Encrypted data
        """
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        
        key_length = key_length or len(plaintext)
        keystream = self.generate_keystream(key_length)
        
        # XOR plaintext with keystream
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        
        logger.debug(f"XOR encryption completed", {
            'plaintext_length': len(plaintext),
            'keystream_length': key_length
        })
        
        return ciphertext
    
    def decrypt_xor(self, ciphertext: bytes, key_length: Optional[int] = None) -> bytes:
        """
        Decrypt data using XOR with chaotic keystream
        
        Note: For XOR encryption, decryption is the same as encryption
        
        Args:
            ciphertext: Data to decrypt
            key_length: Key length (defaults to ciphertext length)
            
        Returns:
            Decrypted data
        """
        return self.encrypt_xor(ciphertext, key_length)
    
    def analyze_randomness(self, sequence_length: int = 10000) -> dict:
        """
        Analyze randomness quality of the chaotic sequence
        
        Args:
            sequence_length: Length of sequence to analyze
            
        Returns:
            Dictionary with randomness metrics
        """
        # Generate test sequence
        sequence = self.generate_sequence(sequence_length)
        
        # Convert to binary
        binary_sequence = [1 if x > 0.5 else 0 for x in sequence]
        
        # Calculate metrics
        ones_count = sum(binary_sequence)
        zeros_count = len(binary_sequence) - ones_count
        balance_ratio = ones_count / len(binary_sequence)
        
        # Run test for consecutive patterns
        runs = []
        current_run = 1
        for i in range(1, len(binary_sequence)):
            if binary_sequence[i] == binary_sequence[i-1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        runs.append(current_run)
        
        # Calculate autocorrelation for different lags
        autocorrelations = []
        for lag in range(1, min(100, len(sequence))):
            correlation = np.corrcoef(sequence[:-lag], sequence[lag:])[0, 1]
            autocorrelations.append(abs(correlation))
        
        metrics = {
            'sequence_length': sequence_length,
            'ones_count': ones_count,
            'zeros_count': zeros_count,
            'balance_ratio': balance_ratio,
            'balance_quality': abs(0.5 - balance_ratio),  # Closer to 0 is better
            'average_run_length': np.mean(runs),
            'max_run_length': max(runs),
            'min_run_length': min(runs),
            'run_count': len(runs),
            'max_autocorrelation': max(autocorrelations) if autocorrelations else 0,
            'avg_autocorrelation': np.mean(autocorrelations) if autocorrelations else 0
        }
        
        logger.info(f"Randomness analysis completed", {
            'control_parameter': self.r,
            'metrics': metrics
        })
        
        return metrics
    
    def get_lyapunov_exponent(self, iterations: int = 10000) -> float:
        """
        Calculate Lyapunov exponent to measure chaotic behavior
        
        Positive Lyapunov exponent indicates chaotic behavior.
        
        Args:
            iterations: Number of iterations for calculation
            
        Returns:
            Lyapunov exponent
        """
        # Save current state
        saved_x = self.x
        saved_count = self.iteration_count
        
        # Reset to initial condition
        self.reset()
        
        lyapunov_sum = 0.0
        
        for _ in range(iterations):
            # Calculate derivative: d/dx[r*x*(1-x)] = r*(1-2*x)
            derivative = abs(self.r * (1 - 2 * self.x))
            if derivative > 0:
                lyapunov_sum += np.log(derivative)
            
            self.iterate()
        
        lyapunov_exponent = lyapunov_sum / iterations
        
        # Restore state
        self.x = saved_x
        self.iteration_count = saved_count
        
        logger.debug(f"Lyapunov exponent calculated", {
            'control_parameter': self.r,
            'lyapunov_exponent': lyapunov_exponent,
            'iterations': iterations,
            'is_chaotic': lyapunov_exponent > 0
        })
        
        return lyapunov_exponent
    
    def synchronize_with(self, other_map: 'ChaoticMap', iterations: int = 1000) -> bool:
        """
        Attempt to synchronize with another chaotic map
        
        Args:
            other_map: Another ChaoticMap instance
            iterations: Number of synchronization iterations
            
        Returns:
            True if synchronization achieved, False otherwise
        """
        if self.r != other_map.r:
            logger.warning("Different control parameters may prevent synchronization")
        
        # Simple synchronization: set both to same state
        sync_state = (self.x + other_map.x) / 2
        
        self.x = sync_state
        other_map.x = sync_state
        
        # Iterate both maps
        for _ in range(iterations):
            self.iterate()
            other_map.iterate()
        
        # Check if synchronized (within tolerance)
        tolerance = 1e-10
        is_synchronized = abs(self.x - other_map.x) < tolerance
        
        logger.debug(f"Synchronization attempt", {
            'synchronized': is_synchronized,
            'final_difference': abs(self.x - other_map.x),
            'iterations': iterations
        })
        
        return is_synchronized
    
    def __repr__(self) -> str:
        return f"ChaoticMap(r={self.r}, x={self.x:.6f}, iterations={self.iteration_count})"