# 🔐 CRYPTON - Ultimate Multi-Algorithm Encryption Suite

[![GitHub](https://img.shields.io/badge/GitHub-sarpataturker%2Fcrypton-blue?logo=github)](https://github.com/sarpataturker/crypton)
![Version](https://img.shields.io/badge/version-5.1.1-brightgreen)
![Python](https://img.shields.io/badge/python-3.6+-blue)
![Algorithms](https://img.shields.io/badge/algorithms-43+-orange)
![Categories](https://img.shields.io/badge/categories-5-purple)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

> **Created by [@sarpataturker](https://github.com/sarpataturker)** 🚀

**CRYPTON** is the ultimate multi-algorithm encryption suite supporting **43+ cryptographic algorithms** across 5 major categories. From military-grade symmetric encryption to classical ciphers, CRYPTON provides the most comprehensive cryptographic toolkit available.

```
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║
╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
```

## 🛡️ Complete Algorithm Arsenal (43+ Algorithms)

### 📊 **Complete Algorithm Count Verification**

CRYPTON truly supports **43 cryptographic algorithms** across 5 categories:

#### 🔒 **Symmetric Encryption: 12 Algorithms**
1. Fernet (AES-128 CBC + HMAC SHA256)
2. AES-256 GCM, 3. AES-192 GCM, 4. AES-128 GCM
5. AES-256 CBC, 6. AES-256 CTR, 7. AES-256 OFB
8. ChaCha20-Poly1305, 9. ChaCha20, 10. Salsa20, 11. XChaCha20
12. 3DES (Triple DES)

#### 🔑 **Asymmetric Encryption: 8 Algorithms**
13. RSA-2048, 14. RSA-4096
15. Elliptic Curve P-256, 16. EC P-384, 17. EC P-521
18. Ed25519, 19. X25519, 20. DSA

#### 🛡️ **Password Hashing: 7 Algorithms**
21. bcrypt, 22. Argon2id, 23. Argon2i, 24. Argon2d
25. scrypt, 26. PBKDF2, 27. SHA-512 crypt

#### 📊 **Hash Functions: 8 Algorithms**
28. SHA-256, 29. SHA-512, 30. SHA3-256, 31. SHA3-512
32. BLAKE2b, 33. BLAKE2s, 34. MD5, 35. SHA-1

#### 🎭 **Encoding & Classical: 8 Algorithms**
36. Base64, 37. Base32, 38. Hexadecimal
39. ROT13, 40. Caesar Cipher, 41. Vigenère Cipher
42. Atbash Cipher, 43. Rail Fence Cipher

**TOTAL: 43 ALGORITHMS** ✅

## ✨ Features

### 🎛️ **Multi-Algorithm Support**
- **7+ Encryption Algorithms**: Choose the right algorithm for your needs
- **Dynamic Algorithm Switching**: Change algorithms on-the-fly
- **Algorithm-Specific Key Generation**: Optimized keys for each algorithm
- **Universal .env Integration**: Store keys for any algorithm

### 🛡️ **Enterprise Security**
- **Military-Grade Encryption**: Industry-standard cryptographic implementations
- **Authenticated Encryption**: AEAD ciphers for maximum security
- **Key Validation**: Built-in integrity verification for all algorithms
- **Secure Key Storage**: Environment variable integration with security headers

### 🎨 **Professional Interface**
- **Algorithm Selection Menu**: Easy switching between encryption methods
- **Colorized Output**: Beautiful, readable command-line interface
- **Real-time Status**: Live algorithm and key status indicators
- **Cross-Platform**: Windows, macOS, and Linux compatible

### 🚀 **Smart Automation**
- **Auto-Dependency Installation**: Automatically installs required packages
- **Smart .env Management**: Creates and manages environment files
- **Error Recovery**: Comprehensive error handling and user guidance
- **One-Command Setup**: Ready to use immediately after clone

## 🔧 Installation

### Quick Start (Recommended)
```bash
# Clone the repository
git clone https://github.com/sarpataturker/crypton.git
cd crypton

# Run CRYPTON (auto-installs dependencies)
python main.py
```

### Manual Installation
```bash
# Install dependencies manually
pip install -r requirements.txt

# Run CRYPTON
python main.py
```

## 📋 Requirements

- **Python 3.6+**
- **cryptography** - For encryption operations (Fernet, AES, ChaCha20, RSA)
- **bcrypt** - For password hashing
- **colorama** - For colored terminal output

*Note: Dependencies are automatically installed on first run*

## 🚀 Usage

### 1. **Quick Start**
```bash
# Clone and run (auto-installs everything)
git clone https://github.com/yourusername/crypton.git
cd crypton
python main.py
```

### 2. **Algorithm Selection**
```bash
# 1. Select your preferred encryption algorithm
# 2. Generate appropriate key for the algorithm  
# 3. Start encrypting/decrypting!
```

### 3. **Example Workflows**

#### 🔒 **Fernet Encryption (Default)**
```bash
python main.py
# 1. Keep default Fernet algorithm
# 2. Generate new encryption key
# 3. Encrypt: "My secret data"
# 4. Get: gAAAAABh... (encrypted result)
```

#### 🛡️ **AES-256 GCM (High Security)**
```bash
python main.py
# 1. Select Algorithm → AES_GCM
# 2. Generate AES-256 key
# 3. Encrypt with authenticated encryption
```

#### 🔑 **RSA Asymmetric Encryption**
```bash
python main.py
# 1. Select Algorithm → RSA
# 2. Generate RSA-2048 key pair
# 3. Encrypt with public key
# 4. Decrypt with private key
```

#### 🔐 **Password Hashing with bcrypt**
```bash
python main.py
# 1. Select Algorithm → bcrypt
# 2. Hash passwords securely
# 3. Verify password authenticity
```

## 🎯 Algorithm Comparison

| Algorithm | Type | Key Size | Security Level | Use Case |
|-----------|------|----------|----------------|----------|
| **Fernet** | Symmetric | 32 bytes | High | General purpose, API tokens |
| **AES-256 GCM** | Symmetric | 32 bytes | Very High | High-security data, AEAD |
| **ChaCha20** | Symmetric | 32 bytes | Very High | Modern applications, mobile |
| **RSA-2048** | Asymmetric | 2048 bits | High | Key exchange, digital signatures |
| **bcrypt** | Hashing | N/A | High | Password storage |
| **Base64** | Encoding | N/A | None | Data transport, encoding |
| **Custom AES** | Symmetric | 32 bytes | High | Legacy compatibility |

## 🔧 Advanced Usage

### 🔄 **Algorithm Switching**
```bash
# Switch algorithms mid-session
# Keys are automatically cleared when changing algorithms
# Generate new appropriate keys for each algorithm
```

### 💾 **Key Management**
```bash
# Save different algorithm keys to .env
# Load algorithm-specific keys
# Validate keys for current algorithm
```

### 🛡️ **Security Best Practices**
```bash
# Use AES-256 GCM for maximum security
# Use RSA for key exchange
# Use bcrypt for password storage
# Use Fernet for general encryption
```

## 🔒 Security Best Practices

### 🛡️ **Key Management**
- **Never share your encryption keys**
- **Store .env files securely and privately**
- **Use different keys for different projects**
- **Regular key rotation for sensitive applications**

### 📁 **File Security**
- **.env files are automatically excluded from Git**
- **Never commit encryption keys to version control**
- **Keep backups of important keys in secure locations**
- **Use file permissions to restrict .env access**

## 🎯 Use Cases

### 💼 **Professional Applications**
- **API Security**: Encrypt API keys with Fernet
- **Database Encryption**: Secure sensitive data with AES-256 GCM  
- **Password Management**: Hash passwords with bcrypt
- **Configuration Files**: Protect config data with any algorithm
- **Inter-Service Communication**: RSA for key exchange

### 🏢 **Enterprise Scenarios**
- **Multi-tenant Applications**: Different algorithms per tenant
- **Compliance Requirements**: Choose algorithm based on regulations
- **Legacy System Integration**: Custom AES for compatibility
- **Modern Applications**: ChaCha20 for performance
- **Development Environments**: Base64 for data transport

### 🔒 **Security Levels**
- **Maximum Security**: AES-256 GCM or ChaCha20-Poly1305
- **General Purpose**: Fernet (recommended default)
- **Password Storage**: bcrypt (one-way hashing)
- **Key Exchange**: RSA asymmetric encryption
- **Data Transport**: Base64 encoding

## 🏗️ Project Structure

```
crypton/
├── main.py              # Multi-algorithm application
├── requirements.txt     # Enhanced dependencies  
├── .env                 # Algorithm-specific keys (auto-generated)
├── .gitignore          # Security-focused ignore rules
└── README.md           # This comprehensive documentation
```

## 🤝 Contributing

We welcome contributions! CRYPTON is designed to be extensible for additional algorithms.

### 🚀 **Adding New Algorithms**
1. Fork the repository: `https://github.com/sarpataturker/crypton`
2. Add algorithm to `self.algorithms` dictionary in main.py
3. Implement key generation in `generate_key()`
4. Add encryption logic in `encrypt_text()`
5. Add decryption logic in `decrypt_text()`
6. Update algorithm selection menu
7. Submit a Pull Request

### 🛠️ **Development Setup**
```bash
git clone https://github.com/sarpataturker/crypton.git
cd crypton
# Uncomment development dependencies in requirements.txt
pip install -r requirements.txt
python main.py  # Auto-installs all dependencies
```

### 📝 **Code Style**
- Follow existing code patterns
- Add comments for new algorithms
- Test your implementations
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/sarpataturker/crypton/blob/main/LICENSE) file for details.

## 👨‍💻 Author

**@sarpataturker**
- GitHub: [@sarpataturker](https://github.com/sarpataturker)
- Project: [CRYPTON](https://github.com/sarpataturker/crypton)

## 🆘 Support

If you encounter any issues or have questions:

1. **Check the documentation** in this README
2. **Validate your encryption key** using option 4
3. **Ensure .env file exists** and contains ENCRYPTION_KEY
4. **Verify Python version** is 3.6 or higher
5. **Create an issue** on [GitHub Issues](https://github.com/sarpataturker/crypton/issues)

## ⭐ Show Your Support

If CRYPTON helped you, please give it a star on GitHub! ⭐

```bash
# Star the repository
https://github.com/sarpataturker/crypton
```

## 🔮 Roadmap

### 🎯 **Version 4.1 (Next Release)**
- [ ] **Argon2 Password Hashing** - Modern password hashing
- [ ] **PBKDF2 Key Derivation** - Password-based key generation
- [ ] **Elliptic Curve Cryptography** - Modern public key crypto
- [ ] **File Encryption** - Direct file encryption support

### 🚀 **Version 4.2 (Future)**
- [ ] **Batch Operations** - Process multiple texts at once
- [ ] **Key Derivation Functions** - Advanced key management
- [ ] **Digital Signatures** - RSA/ECDSA signing support
- [ ] **Configuration Profiles** - Save algorithm preferences

### 🌟 **Version 5.0 (Long-term)**
- [ ] **GUI Interface** - Desktop application
- [ ] **REST API** - Web service interface
- [ ] **Mobile Apps** - iOS and Android support
- [ ] **Hardware Security Module** - HSM integration

## ⚡ Performance Benchmarks

| Algorithm | Encryption Speed | Decryption Speed | Key Generation |
|-----------|-----------------|------------------|----------------|
| **Fernet** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **AES-256 GCM** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **ChaCha20** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **RSA-2048** | ⭐⭐ | ⭐⭐ | ⭐⭐ |
| **bcrypt** | ⭐⭐ | ⭐⭐⭐⭐⭐ | N/A |

## 🏆 Why Choose CRYPTON?

✅ **Multi-Algorithm Support** - 7+ algorithms in one tool  
✅ **Enterprise Security** - Industry-standard implementations  
✅ **Easy Algorithm Switching** - Change algorithms on-the-fly  
✅ **Auto-Setup** - Zero-configuration required  
✅ **Cross-Platform** - Works everywhere Python runs  
✅ **Professional UI** - Beautiful command-line interface  
✅ **Extensible** - Easy to add new algorithms  
✅ **Well-Documented** - Comprehensive guides and examples  
✅ **Actively Maintained** - Regular updates and improvements  
✅ **Security-Focused** - Best practices built-in  

---

## 🙏 Acknowledgments

- Built with ❤️ for the cryptographic community
- Inspired by the need for comprehensive encryption tools
- Dedicated to advancing cybersecurity education

## 🔗 Links

- **GitHub Repository**: [github.com/sarpataturker/crypton](https://github.com/sarpataturker/crypton)
- **Author**: [@sarpataturker](https://github.com/sarpataturker)
- **Issues & Support**: [GitHub Issues](https://github.com/sarpataturker/crypton/issues)
- **Releases**: [GitHub Releases](https://github.com/sarpataturker/crypton/releases)

---

<div align="center">

**🔐 CRYPTON v5.1.1 - Ultimate Encryption Powerhouse 🔐**

*Created by [@sarpataturker](https://github.com/sarpataturker)*

[![Star on GitHub](https://img.shields.io/github/stars/sarpataturker/crypton?style=social)](https://github.com/sarpataturker/crypton)

*Remember: With great encryption power comes great responsibility. Keep your keys safe!* 

</div>