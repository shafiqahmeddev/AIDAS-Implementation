"""
Cryptographic Engine Implementation
Handles all cryptographic operations for the AIDAS protocol
"""

import hashlib
import hmac
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class CryptographicEngine:
    """
    Handles all cryptographic operations for the AIDAS protocol
    
    Provides a unified interface for:
    - Symmetric encryption (AES)
    - Hash functions (SHA-256, HMAC)
    - Asymmetric cryptography (ECC)
    - Key derivation and management
    """
    
    def __init__(self):
        """Initialize the cryptographic engine"""
        self.backend = default_backend()
        self.key_length = config.security.encryption_key_length
        self.hash_algorithm = config.security.hash_algorithm
        
        logger.debug("Cryptographic engine initialized", {
            'key_length': self.key_length,
            'hash_algorithm': self.hash_algorithm,
            'backend': str(self.backend)
        })
    
    def generate_random_bytes(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        if length <= 0:
            raise ValueError("Length must be positive")
        
        return secrets.token_bytes(length)
    
    def sha256_hash(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-256 hash digest
        """
        if not isinstance(data, bytes):
            raise TypeError("Input data must be bytes")
        
        hash_digest = hashlib.sha256(data).digest()
        
        logger.debug("SHA-256 hash computed", {
            'input_length': len(data),
            'output_length': len(hash_digest)
        })
        
        return hash_digest
    
    def hmac_hash(self, key: bytes, data: bytes, algorithm: str = "sha256") -> bytes:
        """
        Compute HMAC hash
        
        Args:
            key: HMAC key
            data: Data to authenticate
            algorithm: Hash algorithm to use
            
        Returns:
            HMAC digest
        """
        if not isinstance(key, bytes) or not isinstance(data, bytes):
            raise TypeError("Key and data must be bytes")
        
        if algorithm.lower() == "sha256":
            hash_func = hashlib.sha256
        elif algorithm.lower() == "sha1":
            hash_func = hashlib.sha1
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hmac_digest = hmac.new(key, data, hash_func).digest()
        
        logger.debug("HMAC computed", {
            'key_length': len(key),
            'data_length': len(data),
            'algorithm': algorithm,
            'output_length': len(hmac_digest)
        })
        
        return hmac_digest
    
    def aes_encrypt(self, key: bytes, plaintext: bytes, 
                   mode: str = "CBC") -> Tuple[bytes, bytes]:
        """
        AES encryption with random IV
        
        Args:
            key: Encryption key (16, 24, or 32 bytes)
            plaintext: Data to encrypt
            mode: Encryption mode (CBC, GCM)
            
        Returns:
            Tuple of (ciphertext, iv)
        """
        if not isinstance(key, bytes) or not isinstance(plaintext, bytes):
            raise TypeError("Key and plaintext must be bytes")
        
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes")
        
        # Generate random IV
        iv = self.generate_random_bytes(16)
        
        if mode.upper() == "CBC":
            cipher = Cipher(
                algorithms.AES(key[:32]), 
                modes.CBC(iv), 
                backend=self.backend
            )
            
            # Pad plaintext to block size (PKCS7 padding)
            padding_length = 16 - (len(plaintext) % 16)
            padded_plaintext = plaintext + bytes([padding_length] * padding_length)
            
        elif mode.upper() == "GCM":
            cipher = Cipher(
                algorithms.AES(key[:32]), 
                modes.GCM(iv), 
                backend=self.backend
            )
            padded_plaintext = plaintext
            
        else:
            raise ValueError(f"Unsupported encryption mode: {mode}")
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        logger.debug("AES encryption completed", {
            'key_length': len(key),
            'plaintext_length': len(plaintext),
            'ciphertext_length': len(ciphertext),
            'mode': mode,
            'iv_length': len(iv)
        })
        
        return ciphertext, iv
    
    def aes_decrypt(self, key: bytes, ciphertext: bytes, iv: bytes, 
                   mode: str = "CBC") -> bytes:
        """
        AES decryption
        
        Args:
            key: Decryption key
            ciphertext: Encrypted data
            iv: Initialization vector
            mode: Decryption mode (CBC, GCM)
            
        Returns:
            Decrypted plaintext
        """
        if not all(isinstance(x, bytes) for x in [key, ciphertext, iv]):
            raise TypeError("Key, ciphertext, and IV must be bytes")
        
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes")
        
        if mode.upper() == "CBC":
            cipher = Cipher(
                algorithms.AES(key[:32]), 
                modes.CBC(iv), 
                backend=self.backend
            )
            
        elif mode.upper() == "GCM":
            cipher = Cipher(
                algorithms.AES(key[:32]), 
                modes.GCM(iv), 
                backend=self.backend
            )
            
        else:
            raise ValueError(f"Unsupported decryption mode: {mode}")
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        if mode.upper() == "CBC":
            # Remove PKCS7 padding
            padding_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-padding_length]
        else:
            plaintext = padded_plaintext
        
        logger.debug("AES decryption completed", {
            'key_length': len(key),
            'ciphertext_length': len(ciphertext),
            'plaintext_length': len(plaintext),
            'mode': mode
        })
        
        return plaintext
    
    def generate_ecc_keypair(self, curve: str = "secp256r1") -> Tuple[object, object]:
        """
        Generate ECC keypair for key exchange
        
        Args:
            curve: Elliptic curve to use
            
        Returns:
            Tuple of (private_key, public_key)
        """
        if curve.lower() == "secp256r1":
            curve_obj = ec.SECP256R1()
        elif curve.lower() == "secp384r1":
            curve_obj = ec.SECP384R1()
        elif curve.lower() == "secp521r1":
            curve_obj = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported curve: {curve}")
        
        private_key = ec.generate_private_key(curve_obj, self.backend)
        public_key = private_key.public_key()
        
        logger.debug("ECC keypair generated", {
            'curve': curve,
            'private_key_size': private_key.key_size,
            'public_key_size': public_key.key_size
        })
        
        return private_key, public_key
    
    def ecc_shared_secret(self, private_key: object, peer_public_key: object) -> bytes:
        """
        Generate shared secret using ECDH
        
        Args:
            private_key: Own private key
            peer_public_key: Peer's public key
            
        Returns:
            Shared secret bytes
        """
        try:
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            
            logger.debug("ECDH shared secret generated", {
                'shared_secret_length': len(shared_key)
            })
            
            return shared_key
            
        except Exception as e:
            logger.error(f"ECDH key exchange failed: {e}")
            raise
    
    def derive_key(self, shared_secret: bytes, salt: Optional[bytes] = None, 
                  info: Optional[bytes] = None, length: int = 32) -> bytes:
        """
        Derive key from shared secret using HKDF
        
        Args:
            shared_secret: Input key material
            salt: Optional salt value
            info: Optional context information
            length: Output key length
            
        Returns:
            Derived key
        """
        if not isinstance(shared_secret, bytes):
            raise TypeError("Shared secret must be bytes")
        
        if salt is None:
            salt = b""
        if info is None:
            info = b"AIDAS-Protocol-Key-Derivation"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=self.backend
        )
        
        derived_key = hkdf.derive(shared_secret)
        
        logger.debug("Key derivation completed", {
            'input_length': len(shared_secret),
            'output_length': len(derived_key),
            'salt_length': len(salt),
            'info_length': len(info)
        })
        
        return derived_key
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks
        
        Args:
            a: First bytes object
            b: Second bytes object
            
        Returns:
            True if equal, False otherwise
        """
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("Both inputs must be bytes")
        
        # Use secrets.compare_digest for constant-time comparison
        return secrets.compare_digest(a, b)
    
    def generate_nonce(self, length: int = 16) -> bytes:
        """
        Generate cryptographic nonce
        
        Args:
            length: Nonce length in bytes
            
        Returns:
            Random nonce
        """
        return self.generate_random_bytes(length)
    
    def kdf_pbkdf2(self, password: bytes, salt: bytes, iterations: int = 100000, 
                   length: int = 32) -> bytes:
        """
        Password-based key derivation using PBKDF2
        
        Args:
            password: Input password
            salt: Random salt
            iterations: Number of iterations
            length: Output key length
            
        Returns:
            Derived key
        """
        if not isinstance(password, bytes) or not isinstance(salt, bytes):
            raise TypeError("Password and salt must be bytes")
        
        if iterations < 1000:
            logger.warning(f"Low iteration count: {iterations}")
        
        derived_key = hashlib.pbkdf2_hmac(
            self.hash_algorithm, 
            password, 
            salt, 
            iterations, 
            length
        )
        
        logger.debug("PBKDF2 key derivation completed", {
            'password_length': len(password),
            'salt_length': len(salt),
            'iterations': iterations,
            'output_length': len(derived_key)
        })
        
        return derived_key
    
    def sign_data(self, private_key: object, data: bytes) -> bytes:
        """
        Sign data using ECC private key
        
        Args:
            private_key: ECC private key
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        try:
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            
            logger.debug("Data signed", {
                'data_length': len(data),
                'signature_length': len(signature)
            })
            
            return signature
            
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify_signature(self, public_key: object, signature: bytes, data: bytes) -> bool:
        """
        Verify signature using ECC public key
        
        Args:
            public_key: ECC public key
            signature: Signature to verify
            data: Original data
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not isinstance(signature, bytes) or not isinstance(data, bytes):
            raise TypeError("Signature and data must be bytes")
        
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            
            logger.debug("Signature verification successful", {
                'data_length': len(data),
                'signature_length': len(signature)
            })
            
            return True
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False
    
    def encrypt_hybrid(self, public_key: object, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Hybrid encryption: ECC + AES
        
        Args:
            public_key: Recipient's ECC public key
            plaintext: Data to encrypt
            
        Returns:
            Tuple of (encrypted_key, encrypted_data, iv)
        """
        # Generate ephemeral ECC keypair
        ephemeral_private, ephemeral_public = self.generate_ecc_keypair()
        
        # Generate shared secret
        shared_secret = self.ecc_shared_secret(ephemeral_private, public_key)
        
        # Derive AES key
        aes_key = self.derive_key(shared_secret, length=32)
        
        # Encrypt data with AES
        ciphertext, iv = self.aes_encrypt(aes_key, plaintext)
        
        # Serialize ephemeral public key
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        logger.debug("Hybrid encryption completed", {
            'plaintext_length': len(plaintext),
            'ciphertext_length': len(ciphertext),
            'ephemeral_key_length': len(ephemeral_public_bytes)
        })
        
        return ephemeral_public_bytes, ciphertext, iv
    
    def decrypt_hybrid(self, private_key: object, ephemeral_public_bytes: bytes, 
                      ciphertext: bytes, iv: bytes) -> bytes:
        """
        Hybrid decryption: ECC + AES
        
        Args:
            private_key: Recipient's ECC private key
            ephemeral_public_bytes: Sender's ephemeral public key
            ciphertext: Encrypted data
            iv: AES initialization vector
            
        Returns:
            Decrypted plaintext
        """
        # Deserialize ephemeral public key
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_bytes
        )
        
        # Generate shared secret
        shared_secret = self.ecc_shared_secret(private_key, ephemeral_public)
        
        # Derive AES key
        aes_key = self.derive_key(shared_secret, length=32)
        
        # Decrypt data
        plaintext = self.aes_decrypt(aes_key, ciphertext, iv)
        
        logger.debug("Hybrid decryption completed", {
            'ciphertext_length': len(ciphertext),
            'plaintext_length': len(plaintext)
        })
        
        return plaintext
    
    def __repr__(self) -> str:
        return f"CryptographicEngine(key_length={self.key_length}, hash_algorithm='{self.hash_algorithm}')"