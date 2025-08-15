#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CRYPTON API Server - REST API for Multi-Algorithm Encryption
FastAPI-based REST API for cloud deployment and mobile integration

Author: @sarpataturker
GitHub: https://github.com/sarpataturker/crypton
License: MIT License
Version: 5.2.0
"""

import os
import sys
import base64
import hashlib
import secrets
import string
import binascii
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

# FastAPI and Pydantic imports - IMPORT CONTROL REMOVED
from fastapi import FastAPI, HTTPException, Depends, status, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field, validator
import uvicorn
try:
    import jwt
except ImportError:
    from jose import jwt

# Cryptographic imports (same as main.py)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519, x25519, dsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import bcrypt
import argon2
import nacl.secret
import nacl.utils
from passlib.hash import sha512_crypt

# FastAPI app configuration
app = FastAPI(
    title="CRYPTON API",
    description="Ultimate Multi-Algorithm Encryption Suite REST API - 43+ Algorithms",
    version="5.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS middleware for web/mobile apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configuration
security = HTTPBearer(auto_error=False)
SECRET_KEY = os.environ.get("CRYPTON_SECRET_KEY", "crypton-secret-key-change-in-production")
ALGORITHM = "HS256"

# ===== PYDANTIC MODELS =====

class APIResponse(BaseModel):
    """Standard API response model"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: str
    details: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class AlgorithmInfo(BaseModel):
    """Algorithm information model"""
    name: str
    description: str
    category: str
    key_required: bool
    supports_encryption: bool
    supports_decryption: bool
    supports_hashing: bool

class EncryptRequest(BaseModel):
    """Encryption request model"""
    algorithm: str = Field(..., description="Algorithm to use for encryption")
    data: str = Field(..., description="Data to encrypt")
    key: Optional[str] = Field(None, description="Encryption key (required for most algorithms)")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional options")

class DecryptRequest(BaseModel):
    """Decryption request model"""
    algorithm: str = Field(..., description="Algorithm to use for decryption")
    encrypted_data: str = Field(..., description="Encrypted data to decrypt")
    key: str = Field(..., description="Decryption key")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional options")

class HashRequest(BaseModel):
    """Hash request model"""
    algorithm: str = Field(..., description="Hash algorithm to use")
    data: str = Field(..., description="Data to hash")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional options")

class KeyGenerationRequest(BaseModel):
    """Key generation request model"""
    algorithm: str = Field(..., description="Algorithm to generate key for")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Key generation options")

class PasswordHashRequest(BaseModel):
    """Password hash request model"""
    algorithm: str = Field(..., description="Password hashing algorithm")
    password: str = Field(..., description="Password to hash")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Hashing options")

class PasswordVerifyRequest(BaseModel):
    """Password verification request model"""
    algorithm: str = Field(..., description="Password hashing algorithm used")
    password: str = Field(..., description="Plain password to verify")
    hash_value: str = Field(..., description="Hash to verify against")

# ===== CRYPTON ENGINE =====

class CRYPTONEngine:
    """CRYPTON cryptographic engine for API"""
    
    def __init__(self):
        # All 43 algorithms (same as main.py)
        self.algorithms = {
            # Symmetric Encryption (12)
            "fernet": "Fernet (AES-128 CBC + HMAC SHA256)",
            "aes_256_gcm": "AES-256 GCM (Authenticated Encryption)",
            "aes_192_gcm": "AES-192 GCM (Authenticated Encryption)",
            "aes_128_gcm": "AES-128 GCM (Authenticated Encryption)",
            "aes_256_cbc": "AES-256 CBC (Traditional AES)",
            "aes_256_ctr": "AES-256 CTR (Counter Mode)",
            "aes_256_ofb": "AES-256 OFB (Output Feedback)",
            "chacha20_poly1305": "ChaCha20-Poly1305 (Modern AEAD)",
            "chacha20": "ChaCha20 (Stream Cipher)",
            "salsa20": "Salsa20 (Stream Cipher)",
            "xchacha20": "XChaCha20 (Extended Nonce)",
            "threedes": "3DES (Triple DES)",
            
            # Asymmetric Encryption (8)
            "rsa_2048": "RSA-2048 (Public Key Encryption)",
            "rsa_4096": "RSA-4096 (High Security RSA)",
            "ec_p256": "Elliptic Curve P-256 (NIST Curve)",
            "ec_p384": "Elliptic Curve P-384 (NIST Curve)",
            "ec_p521": "Elliptic Curve P-521 (NIST Curve)",
            "ed25519": "Ed25519 (Modern Digital Signatures)",
            "x25519": "X25519 (Key Exchange)",
            "dsa": "DSA (Digital Signature Algorithm)",
            
            # Password Hashing (7)
            "bcrypt": "bcrypt (Adaptive Password Hashing)",
            "argon2id": "Argon2id (Modern Password Hashing)",
            "argon2i": "Argon2i (Password Hashing)",
            "argon2d": "Argon2d (Password Hashing)",
            "scrypt": "scrypt (Memory-Hard Password Hashing)",
            "pbkdf2": "PBKDF2 (Password-Based Key Derivation)",
            "sha512_crypt": "SHA-512 crypt (Unix Password Hash)",
            
            # Hash Functions (8)
            "sha256": "SHA-256 (Secure Hash Algorithm)",
            "sha512": "SHA-512 (Secure Hash Algorithm)",
            "sha3_256": "SHA3-256 (Keccak-based Hash)",
            "sha3_512": "SHA3-512 (Keccak-based Hash)",
            "blake2b": "BLAKE2b (High-speed Hash Function)",
            "blake2s": "BLAKE2s (Optimized BLAKE2)",
            "md5": "MD5 (Legacy Hash - Not Secure)",
            "sha1": "SHA-1 (Legacy Hash - Not Secure)",
            
            # Encoding & Classical (8)
            "base64": "Base64 (Standard Encoding)",
            "base32": "Base32 (RFC 4648 Encoding)",
            "hex": "Hexadecimal (Binary to Text)",
            "rot13": "ROT13 (Letter Substitution)",
            "caesar": "Caesar Cipher (Classical Encryption)",
            "vigenere": "Vigenère Cipher (Polyalphabetic)",
            "atbash": "Atbash Cipher (Hebrew Classical)",
            "rail_fence": "Rail Fence Cipher (Transposition)"
        }
        
        self.categories = {
            "Symmetric Encryption": ["fernet", "aes_256_gcm", "aes_192_gcm", "aes_128_gcm", 
                                   "aes_256_cbc", "aes_256_ctr", "aes_256_ofb", 
                                   "chacha20_poly1305", "chacha20", "salsa20", "xchacha20", "threedes"],
            "Asymmetric Encryption": ["rsa_2048", "rsa_4096", "ec_p256", "ec_p384", "ec_p521", 
                                    "ed25519", "x25519", "dsa"],
            "Password Hashing": ["bcrypt", "argon2id", "argon2i", "argon2d", "scrypt", 
                               "pbkdf2", "sha512_crypt"],
            "Hash Functions": ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s", "md5", "sha1"],
            "Encoding & Classical": ["base64", "base32", "hex", "rot13", "caesar", "vigenere", "atbash", "rail_fence"]
        }
    
    def get_algorithm_info(self, algorithm: str) -> AlgorithmInfo:
        """Get detailed information about an algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Algorithm '{algorithm}' not supported")
        
        category = self._get_category(algorithm)
        
        # Determine capabilities
        key_required = algorithm not in ["sha256", "sha512", "sha3_256", "sha3_512", 
                                       "blake2b", "blake2s", "md5", "sha1", "base64", 
                                       "base32", "hex", "rot13", "atbash"]
        
        supports_encryption = algorithm not in ["sha256", "sha512", "sha3_256", "sha3_512", 
                                              "blake2b", "blake2s", "md5", "sha1"]
        
        supports_decryption = supports_encryption and algorithm not in ["bcrypt", "argon2id", 
                                                                      "argon2i", "argon2d", 
                                                                      "scrypt", "pbkdf2", "sha512_crypt"]
        
        supports_hashing = algorithm in ["sha256", "sha512", "sha3_256", "sha3_512", 
                                       "blake2b", "blake2s", "md5", "sha1", "bcrypt", 
                                       "argon2id", "argon2i", "argon2d", "scrypt", "pbkdf2", "sha512_crypt"]
        
        return AlgorithmInfo(
            name=algorithm,
            description=self.algorithms[algorithm],
            category=category,
            key_required=key_required,
            supports_encryption=supports_encryption,
            supports_decryption=supports_decryption,
            supports_hashing=supports_hashing
        )
    
    def _get_category(self, algorithm: str) -> str:
        """Get category for algorithm"""
        for category, algos in self.categories.items():
            if algorithm in algos:
                return category
        return "Unknown"
    
    def generate_key(self, algorithm: str, options: Dict = None) -> str:
        """Generate key for specified algorithm"""
        if options is None:
            options = {}
        
        if algorithm == "fernet":
            key = Fernet.generate_key()
            return key.decode()
        
        elif algorithm in ["aes_256_gcm", "aes_256_cbc", "aes_256_ctr", "aes_256_ofb", 
                          "chacha20_poly1305", "chacha20", "salsa20", "xchacha20"]:
            key = os.urandom(32)  # 256-bit
            return base64.b64encode(key).decode()
        
        elif algorithm == "aes_192_gcm":
            key = os.urandom(24)  # 192-bit
            return base64.b64encode(key).decode()
        
        elif algorithm == "aes_128_gcm":
            key = os.urandom(16)  # 128-bit
            return base64.b64encode(key).decode()
        
        elif algorithm == "threedes":
            key = os.urandom(24)  # 192-bit for 3DES
            return base64.b64encode(key).decode()
        
        elif algorithm == "caesar":
            shift = options.get("shift", secrets.randbelow(25) + 1)
            return str(shift)
        
        elif algorithm == "vigenere":
            length = options.get("length", secrets.randbelow(8) + 5)
            keyword = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))
            return keyword
        
        elif algorithm == "rail_fence":
            rails = options.get("rails", secrets.randbelow(5) + 3)
            return str(rails)
        
        elif algorithm in ["rsa_2048", "rsa_4096"]:
            key_size = 2048 if algorithm == "rsa_2048" else 4096
            private_key = rsa.generate_private_key(
                public_exponent=65537, 
                key_size=key_size, 
                backend=default_backend()
            )
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return base64.b64encode(private_pem).decode()
        
        else:
            return f"{algorithm}_ready"
    
    def encrypt(self, algorithm: str, data: str, key: str = None, options: Dict = None) -> str:
        """Encrypt data with specified algorithm"""
        if options is None:
            options = {}
        
        # Hash functions
        if algorithm in ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s", "md5", "sha1"]:
            return self._hash_data(algorithm, data)
        
        # Encoding
        elif algorithm in ["base64", "base32", "hex", "rot13", "atbash"]:
            return self._encode_data(algorithm, data)
        
        # Password hashing
        elif algorithm in ["bcrypt", "argon2id", "argon2i", "argon2d", "scrypt", "pbkdf2", "sha512_crypt"]:
            return self._hash_password(algorithm, data, options)
        
        # Encryption algorithms (require key)
        if not key:
            raise ValueError(f"Key required for {algorithm}")
        
        if algorithm == "fernet":
            f = Fernet(key.encode())
            return f.encrypt(data.encode()).decode()
        
        elif algorithm in ["aes_256_gcm", "aes_192_gcm", "aes_128_gcm"]:
            return self._aes_gcm_encrypt(data, base64.b64decode(key.encode()))
        
        elif algorithm == "aes_256_cbc":
            return self._aes_cbc_encrypt(data, base64.b64decode(key.encode()))
        
        elif algorithm == "caesar":
            return self._caesar_encrypt(data, int(key))
        
        elif algorithm == "vigenere":
            return self._vigenere_encrypt(data, key)
        
        elif algorithm == "rail_fence":
            return self._rail_fence_encrypt(data, int(key))
        
        else:
            raise ValueError(f"Encryption not implemented for {algorithm}")
    
    def decrypt(self, algorithm: str, encrypted_data: str, key: str, options: Dict = None) -> str:
        """Decrypt data with specified algorithm"""
        if options is None:
            options = {}
        
        if algorithm == "fernet":
            f = Fernet(key.encode())
            return f.decrypt(encrypted_data.encode()).decode()
        
        elif algorithm == "base64":
            return base64.b64decode(encrypted_data.encode()).decode()
        
        elif algorithm == "base32":
            return base64.b32decode(encrypted_data.encode()).decode()
        
        elif algorithm == "hex":
            return bytes.fromhex(encrypted_data).decode()
        
        elif algorithm == "rot13":
            return encrypted_data.encode().decode('rot13')
        
        elif algorithm == "caesar":
            return self._caesar_decrypt(encrypted_data, int(key))
        
        elif algorithm == "vigenere":
            return self._vigenere_decrypt(encrypted_data, key)
        
        elif algorithm == "atbash":
            return self._atbash_encrypt(encrypted_data)  # Atbash is symmetric
        
        else:
            raise ValueError(f"Decryption not implemented for {algorithm}")
    
    def verify_password(self, algorithm: str, password: str, hash_value: str) -> bool:
        """Verify password against hash"""
        if algorithm == "bcrypt":
            return bcrypt.checkpw(password.encode(), hash_value.encode())
        
        elif "argon2" in algorithm:
            try:
                ph = argon2.PasswordHasher()
                ph.verify(hash_value, password)
                return True
            except:
                return False
        
        else:
            raise ValueError(f"Password verification not implemented for {algorithm}")
    
    # Helper methods (implement as needed)
    def _hash_data(self, algorithm: str, data: str) -> str:
        """Hash data with specified algorithm"""
        if algorithm == "sha256":
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data.encode()).hexdigest()
        elif algorithm == "sha3_256":
            return hashlib.sha3_256(data.encode()).hexdigest()
        elif algorithm == "sha3_512":
            return hashlib.sha3_512(data.encode()).hexdigest()
        elif algorithm == "blake2b":
            return hashlib.blake2b(data.encode()).hexdigest()
        elif algorithm == "blake2s":
            return hashlib.blake2s(data.encode()).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(data.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data.encode()).hexdigest()
    
    def _encode_data(self, algorithm: str, data: str) -> str:
        """Encode data with specified algorithm"""
        if algorithm == "base64":
            return base64.b64encode(data.encode()).decode()
        elif algorithm == "base32":
            return base64.b32encode(data.encode()).decode()
        elif algorithm == "hex":
            return data.encode().hex()
        elif algorithm == "rot13":
            return data.encode().decode('rot13')
        elif algorithm == "atbash":
            return self._atbash_encrypt(data)
    
    def _hash_password(self, algorithm: str, password: str, options: Dict) -> str:
        """Hash password with specified algorithm"""
        if algorithm == "bcrypt":
            rounds = options.get("rounds", 12)
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds)).decode()
        
        elif algorithm == "argon2id":
            ph = argon2.PasswordHasher(variant=argon2.Type.ID)
            return ph.hash(password)
        
        elif algorithm == "argon2i":
            ph = argon2.PasswordHasher(variant=argon2.Type.I)
            return ph.hash(password)
        
        elif algorithm == "argon2d":
            ph = argon2.PasswordHasher(variant=argon2.Type.D)
            return ph.hash(password)
        
        elif algorithm == "sha512_crypt":
            return sha512_crypt.hash(password)
    
    def _aes_gcm_encrypt(self, text: str, key: bytes) -> str:
        """AES-GCM encryption"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
    
    def _aes_cbc_encrypt(self, text: str, key: bytes) -> str:
        """AES-CBC encryption"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_length = 16 - (len(text.encode()) % 16)
        padded_text = text.encode() + bytes([padding_length] * padding_length)
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def _caesar_encrypt(self, text: str, shift: int) -> str:
        """Caesar cipher encryption"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def _caesar_decrypt(self, text: str, shift: int) -> str:
        """Caesar cipher decryption"""
        return self._caesar_encrypt(text, -shift)
    
    def _vigenere_encrypt(self, text: str, key: str) -> str:
        """Vigenère cipher encryption"""
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = key[key_index % len(key)]
                shift = ord(key_char.upper()) - 65
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def _vigenere_decrypt(self, text: str, key: str) -> str:
        """Vigenère cipher decryption"""
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = key[key_index % len(key)]
                shift = ord(key_char.upper()) - 65
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def _atbash_encrypt(self, text: str) -> str:
        """Atbash cipher (symmetric)"""
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr(90 - (ord(char) - 65))
                else:
                    result += chr(122 - (ord(char) - 97))
            else:
                result += char
        return result
    
    def _rail_fence_encrypt(self, text: str, rails: int) -> str:
        """Rail fence cipher encryption"""
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        
        return ''.join([''.join(rail) for rail in fence])

# Initialize engine
engine = CRYPTONEngine()

# ===== API ROUTES =====

@app.get("/", response_model=APIResponse)
async def root():
    """API root endpoint with welcome message"""
    return APIResponse(
        success=True,
        message="Welcome to CRYPTON API v5.2.0 - Ultimate Multi-Algorithm Encryption Suite",
        data={
            "version": "5.2.0",
            "total_algorithms": len(engine.algorithms),
            "categories": len(engine.categories),
            "endpoints": {
                "docs": "/docs",
                "redoc": "/redoc",
                "algorithms": "/algorithms",
                "encrypt": "/encrypt",
                "decrypt": "/decrypt",
                "hash": "/hash",
                "generate_key": "/generate-key"
            },
            "github": "https://github.com/sarpataturker/crypton",
            "author": "@sarpataturker"
        }
    )

@app.get("/health", response_model=APIResponse)
async def health_check():
    """Health check endpoint"""
    return APIResponse(
        success=True,
        message="CRYPTON API is healthy and operational",
        data={
            "status": "healthy",
            "version": "5.2.0",
            "algorithms_loaded": len(engine.algorithms),
            "uptime": "unknown"  # Could implement actual uptime tracking
        }
    )

@app.get("/algorithms", response_model=APIResponse)
async def get_all_algorithms():
    """Get all available algorithms with detailed information"""
    algorithms_info = []
    
    for name in engine.algorithms:
        try:
            info = engine.get_algorithm_info(name)
            algorithms_info.append(info.dict())
        except Exception as e:
            continue  # Skip problematic algorithms
    
    return APIResponse(
        success=True,
        message=f"Retrieved {len(algorithms_info)} algorithms across {len(engine.categories)} categories",
        data={
            "algorithms": algorithms_info,
            "categories": engine.categories,
            "total_count": len(algorithms_info),
            "category_count": len(engine.categories)
        }
    )

@app.get("/algorithms/{algorithm_name}", response_model=APIResponse)
async def get_algorithm_info(algorithm_name: str):
    """Get detailed information about a specific algorithm"""
    try:
        info = engine.get_algorithm_info(algorithm_name)
        return APIResponse(
            success=True,
            message=f"Algorithm information for {algorithm_name}",
            data=info.dict()
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.get("/categories", response_model=APIResponse)
async def get_categories():
    """Get all algorithm categories"""
    return APIResponse(
        success=True,
        message="Retrieved all algorithm categories",
        data={
            "categories": engine.categories,
            "category_count": len(engine.categories),
            "total_algorithms": sum(len(algos) for algos in engine.categories.values())
        }
    )

@app.post("/generate-key", response_model=APIResponse)
async def generate_key(request: KeyGenerationRequest):
    """Generate encryption key for specified algorithm"""
    try:
        key = engine.generate_key(request.algorithm, request.options)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Key generated successfully for {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "key": key,
                "algorithm_info": algorithm_info.dict(),
                "options_used": request.options,
                "generated_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")

@app.post("/encrypt", response_model=APIResponse)
async def encrypt_data(request: EncryptRequest):
    """Encrypt data using specified algorithm"""
    try:
        result = engine.encrypt(request.algorithm, request.data, request.key, request.options)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Data encrypted successfully using {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "original_data": request.data,
                "encrypted_data": result,
                "original_length": len(request.data),
                "encrypted_length": len(result),
                "algorithm_info": algorithm_info.dict(),
                "encrypted_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

@app.post("/decrypt", response_model=APIResponse)
async def decrypt_data(request: DecryptRequest):
    """Decrypt data using specified algorithm"""
    try:
        result = engine.decrypt(request.algorithm, request.encrypted_data, request.key, request.options)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Data decrypted successfully using {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "encrypted_data": request.encrypted_data,
                "decrypted_data": result,
                "decrypted_length": len(result),
                "algorithm_info": algorithm_info.dict(),
                "decrypted_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@app.post("/hash", response_model=APIResponse)
async def hash_data(request: HashRequest):
    """Hash data using specified algorithm"""
    try:
        result = engine.encrypt(request.algorithm, request.data, None, request.options)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Data hashed successfully using {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "original_data": request.data,
                "hash": result,
                "hash_length": len(result),
                "algorithm_info": algorithm_info.dict(),
                "hashed_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hashing failed: {str(e)}")

@app.post("/hash-password", response_model=APIResponse)
async def hash_password(request: PasswordHashRequest):
    """Hash password using specified algorithm"""
    try:
        result = engine.encrypt(request.algorithm, request.password, None, request.options)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Password hashed successfully using {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "hash": result,
                "algorithm_info": algorithm_info.dict(),
                "options_used": request.options,
                "hashed_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password hashing failed: {str(e)}")

@app.post("/verify-password", response_model=APIResponse)
async def verify_password(request: PasswordVerifyRequest):
    """Verify password against hash"""
    try:
        result = engine.verify_password(request.algorithm, request.password, request.hash_value)
        algorithm_info = engine.get_algorithm_info(request.algorithm)
        
        return APIResponse(
            success=True,
            message=f"Password verification completed using {request.algorithm}",
            data={
                "algorithm": request.algorithm,
                "verified": result,
                "status": "MATCH" if result else "NO_MATCH",
                "algorithm_info": algorithm_info.dict(),
                "verified_at": datetime.now().isoformat()
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password verification failed: {str(e)}")

# ===== ERROR HANDLERS =====

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            details=f"HTTP {exc.status_code}"
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            details=str(exc)
        ).dict()
    )

# ===== STARTUP/SHUTDOWN EVENTS =====

@app.on_event("startup")
async def startup_event():
    """Application startup"""
    print("🚀 CRYPTON API v5.2.0 starting up...")
    print(f"📊 Loaded {len(engine.algorithms)} algorithms")
    print(f"📚 Available categories: {len(engine.categories)}")
    print(f"🌐 API Documentation: http://localhost:8000/docs")
    print(f"📖 ReDoc: http://localhost:8000/redoc")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown"""
    print("🛑 CRYPTON API shutting down...")

# ===== MAIN ENTRY POINT =====

if __name__ == "__main__":
    # Configuration for different environments
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    reload = os.environ.get("ENVIRONMENT", "development") == "development"
    
    print(f"🔧 Starting CRYPTON API Server...")
    print(f"🌐 Host: {host}:{port}")
    print(f"📊 Algorithms: {len(engine.algorithms)}")
    print(f"🔄 Reload: {reload}")
    
    uvicorn.run(
        "api_server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )