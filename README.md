# 🔐 CRYPTON - Ultimate Multi-Algorithm Encryption Suite

[![GitHub](https://img.shields.io/badge/GitHub-sarpataturker%2Fcrypton-blue?logo=github)](https://github.com/sarpataturker/crypton)
![Version](https://img.shields.io/badge/version-5.2.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Algorithms](https://img.shields.io/badge/algorithms-43+-orange)
![Categories](https://img.shields.io/badge/categories-5-purple)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![API](https://img.shields.io/badge/API-FastAPI-00c7b7)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ed)

> **Created by [@sarpataturker](https://github.com/sarpataturker)** 🚀

**CRYPTON Enhanced v5.2.0** is the ultimate multi-algorithm encryption suite supporting **43+ cryptographic algorithms** across 5 major categories. From military-grade symmetric encryption to classical ciphers, CRYPTON provides the most comprehensive cryptographic toolkit with **Docker integration** and **REST API** support.

```
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║
╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
```


## 🆕 What's New in v5.2.0

### 🐳 **Docker Integration**
- **Full Docker Support**: Containerized deployment ready
- **Docker Compose**: Multi-service orchestration
- **Production Ready**: Optimized for cloud deployment
- **Container Management**: Built-in Docker controls in main app

### 🌐 **REST API Server**
- **FastAPI Backend**: Modern, fast, and auto-documented API
- **43+ Algorithm Endpoints**: All algorithms accessible via HTTP
- **OpenAPI Documentation**: Interactive API docs at `/docs`
- **JSON Responses**: Structured API responses
- **CORS Support**: Web application integration ready

### 🎨 **Enhanced Terminal UI**
- **Responsive Design**: Adapts to terminal size
- **Smart Navigation**: Instant choice for ≤10 options, Enter for more
- **Paginated Menus**: Handle large algorithm lists efficiently
- **Professional Status Dashboard**: Real-time system information
- **Docker Status Integration**: Live container monitoring

### ⚡ **Performance Improvements**
- **Optimized Imports**: Faster startup times
- **Smart Dependency Management**: Auto-installation improvements
- **Memory Efficiency**: Reduced resource usage
- **Error Handling**: Comprehensive error recovery

## 🛡️ Complete Algorithm Arsenal (43+ Algorithms)

### 📊 **Complete Algorithm Count Verification**

CRYPTON truly supports **43 cryptographic algorithms** across 5 categories:

#### 🔒 **Symmetric Encryption: 12 Algorithms**
1. **Fernet** (AES-128 CBC + HMAC SHA256)
2. **AES-256 GCM** 
3. **AES-192 GCM** 
4. **AES-128 GCM**
5. **AES-256 CBC** 
6. **AES-256 CTR** 
7. **AES-256 OFB**
8. **ChaCha20-Poly1305** 
9. **ChaCha20** 
10. **Salsa20** 
11. **XChaCha20**
12. **3DES** (Triple DES)

#### 🔓 **Asymmetric Encryption: 8 Algorithms**
13. **RSA-2048** 
14. **RSA-4096**
15. **Elliptic Curve P-256** 
16. **EC P-384** 
17. **EC P-521**
18. **Ed25519** 
19. **X25519** 
20. **DSA**

#### 🛡️ **Password Hashing: 7 Algorithms**
21. **bcrypt** 
22. **Argon2id** 
23. **Argon2i** 
24. **Argon2d**
25. **scrypt** 
26. **PBKDF2** 
27. **SHA-512 crypt**

#### 📊 **Hash Functions: 8 Algorithms**
28. **SHA-256** 
29. **SHA-512** 
30. **SHA3-256** 
31. **SHA3-512**
32. **BLAKE2b** 
33. **BLAKE2s** 
34. **MD5** 
35. **SHA-1**

#### 🎭 **Encoding & Classical: 8 Algorithms**
36. **Base64** 
37. **Base32** 
38. **Hexadecimal**
39. **ROT13** 
40. **Caesar Cipher** 
41. **Vigenère Cipher**
42. **Atbash Cipher** 
43. **Rail Fence Cipher**

**TOTAL: 43 ALGORITHMS** ✅

## ✨ Features

### 🎛️ **Multi-Platform Support**
- **Terminal Application**: Rich interactive CLI interface
- **REST API Server**: HTTP/JSON API for integration
- **Docker Container**: Containerized deployment
- **Web Integration**: CORS-enabled for web applications

### 🛡️ **Enterprise Security**
- **Military-Grade Encryption**: Industry-standard cryptographic implementations
- **Authenticated Encryption**: AEAD ciphers for maximum security
- **Key Validation**: Built-in integrity verification for all algorithms
- **Secure Key Storage**: Environment variable integration with security headers

### 🎨 **Professional Interface**
- **Responsive Terminal UI**: Adapts to any terminal size
- **Smart Menu System**: Instant navigation for better UX
- **Algorithm Categorization**: Organized by encryption type
- **Real-time Status**: Live algorithm and key status indicators
- **Cross-Platform**: Windows, macOS, and Linux compatible

### 🚀 **Smart Automation**
- **Auto-Dependency Installation**: Automatically installs required packages
- **Smart .env Management**: Creates and manages environment files
- **Error Recovery**: Comprehensive error handling and user guidance
- **One-Command Setup**: Ready to use immediately after clone

## 🔧 Installation & Setup

### 🚀 Quick Start (Terminal App)
```bash
# Clone the repository
git clone https://github.com/sarpataturker/crypton.git
cd crypton

# Run CRYPTON (auto-installs dependencies)
python main.py
```

### 🐳 Docker Deployment
```bash
# Build and run with Docker
docker build -t crypton:latest .
docker run -d --name crypton-api -p 8000:8000 crypton:latest

# Or use the built-in Docker manager
python main.py
# Select: 9. 🐳 Docker API Management
```

### 🌐 API Server Only
```bash
# Install dependencies
pip install -r api_requirements.txt

# Start API server
python -m uvicorn api_server:app --host 0.0.0.0 --port 8000

# Access API documentation
# http://localhost:8000/docs
```

### 📦 Manual Installation
```bash
# Install dependencies manually
pip install -r requirements.txt
pip install -r api_requirements.txt

# Run CRYPTON
python main.py
```

## 📋 Requirements

### Terminal Application
- **Python 3.8+** (recommended 3.11+)
- **cryptography** - Core encryption operations
- **bcrypt** - Password hashing
- **argon2-cffi** - Modern password hashing
- **pynacl** - NaCl cryptographic library
- **passlib** - Password hashing utilities
- **colorama** - Terminal colors

### API Server
- **fastapi** - Modern web framework
- **uvicorn** - ASGI server
- **pydantic** - Data validation
- **python-jose** - JWT handling
- **python-multipart** - Form data support

*Note: Dependencies are automatically installed on first run*

## 🚀 Usage

### 1. **Terminal Application**
```bash
# Start the interactive terminal interface
python main.py

# Features:
# - Smart algorithm selection
# - Responsive menus
# - Docker management
# - Key generation and validation
# - File encryption/decryption
```

### 2. **REST API Server**
```bash
# Start API server
python -m uvicorn api_server:app --host 0.0.0.0 --port 8000

# Available endpoints:
# GET  /                     - API information
# GET  /health              - Health check
# GET  /algorithms          - List all algorithms
# POST /generate-key        - Generate encryption key
# POST /encrypt             - Encrypt data
# POST /decrypt             - Decrypt data
# POST /hash                - Hash data
# GET  /docs                - Interactive API documentation
```

### 3. **Docker Container**
```bash
# Using main.py Docker manager
python main.py
# Select: 9. 🐳 Docker API Management

# Manual Docker commands
docker build -t crypton:latest .
docker run -d --name crypton-api -p 8000:8000 crypton:latest

# Test the API
curl http://localhost:8000/health
curl http://localhost:8000/algorithms
```

## 🌐 REST API Examples

### 🔑 Generate Key
```bash
curl -X POST "http://localhost:8000/generate-key" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "fernet"}'
```

### 🔒 Encrypt Data
```bash
curl -X POST "http://localhost:8000/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "fernet",
    "data": "Hello, World!",
    "key": "your-generated-key-here"
  }'
```

### 🔓 Decrypt Data
```bash
curl -X POST "http://localhost:8000/decrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "fernet", 
    "encrypted_data": "encrypted-data-here",
    "key": "your-key-here"
  }'
```

### 📊 Hash Data
```bash
curl -X POST "http://localhost:8000/hash" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "sha256",
    "data": "data to hash"
  }'
```

## 🎯 Algorithm Comparison

| Algorithm | Type | Key Size | Security Level | Use Case | API Support |
|-----------|------|----------|----------------|----------|-------------|
| **Fernet** | Symmetric | 32 bytes | High | General purpose, API tokens | ✅ |
| **AES-256 GCM** | Symmetric | 32 bytes | Very High | High-security data, AEAD | ✅ |
| **ChaCha20** | Symmetric | 32 bytes | Very High | Modern applications, mobile | ✅ |
| **RSA-2048** | Asymmetric | 2048 bits | High | Key exchange, digital signatures | ✅ |
| **bcrypt** | Hashing | N/A | High | Password storage | ✅ |
| **Argon2id** | Hashing | N/A | Very High | Modern password hashing | ✅ |
| **Base64** | Encoding | N/A | None | Data transport, encoding | ✅ |

## 🐳 Docker Deployment

### 🏗️ Building the Image
```bash
# Standard build
docker build -t crypton:latest .

# Multi-stage production build
docker build -t crypton:production --target production .

# With build arguments
docker build --build-arg PYTHON_VERSION=3.11 -t crypton:custom .
```

### 🚀 Running Containers
```bash
# Basic run
docker run -d --name crypton-api -p 8000:8000 crypton:latest

# With environment variables
docker run -d \
  --name crypton-api \
  -p 8000:8000 \
  -e CRYPTON_SECRET_KEY="your-secret-key" \
  -e ENVIRONMENT="production" \
  crypton:latest

# With volume mounts
docker run -d \
  --name crypton-api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  crypton:latest
```

### 🔄 Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  crypton-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - CRYPTON_SECRET_KEY=your-secret-key
      - ENVIRONMENT=production
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 🔧 Advanced Usage

### 🔄 **Algorithm Switching**
```bash
# Terminal: Switch algorithms mid-session
# API: Use different algorithms per request
# Docker: Full algorithm support in container
```

### 💾 **Key Management**
```bash
# Terminal: Save/load algorithm-specific keys to .env
# API: Generate keys via REST endpoints
# Docker: Environment variable key injection
```

### 🛡️ **Security Best Practices**
```bash
# Production: Use environment variables for keys
# Development: Use .env files (never commit)
# API: Implement authentication for production
# Docker: Use secrets management in orchestration
```

## 📁 Project Structure

```
crypton/
├── main.py                 # Enhanced terminal application
├── api_server.py          # FastAPI REST API server
├── requirements.txt       # Terminal app dependencies
├── api_requirements.txt   # API server dependencies
├── Dockerfile            # Docker container configuration
├── docker-compose.yml    # Multi-service orchestration
├── .env                  # Environment variables (auto-generated)
├── .gitignore           # Git ignore rules
├── logs/                # Application logs (Docker)
├── data/                # Data directory (Docker)
└── README.md            # This documentation
```

## 🌍 Production Deployment

### ☁️ **Cloud Platforms**

#### **AWS ECS/Fargate**
```bash
# Build and push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -t crypton:latest .
docker tag crypton:latest <account>.dkr.ecr.us-east-1.amazonaws.com/crypton:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/crypton:latest
```

#### **Google Cloud Run**
```bash
# Deploy to Cloud Run
gcloud builds submit --tag gcr.io/PROJECT_ID/crypton
gcloud run deploy --image gcr.io/PROJECT_ID/crypton --platform managed
```

#### **Azure Container Instances**
```bash
# Deploy to Azure
az container create --resource-group myResourceGroup --name crypton-api --image crypton:latest --ports 8000
```

### 🌐 **Custom Domain Setup**
```nginx
# nginx.conf example for sarpataturker.me
server {
    listen 80;
    server_name api.sarpataturker.me;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 Performance Benchmarks

| Algorithm | Encryption Speed | Decryption Speed | Key Generation | Memory Usage |
|-----------|-----------------|------------------|----------------|--------------|
| **Fernet** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Low |
| **AES-256 GCM** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Low |
| **ChaCha20** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Low |
| **RSA-2048** | ⭐⭐ | ⭐⭐ | ⭐⭐ | Medium |
| **Argon2id** | ⭐⭐ | ⭐⭐⭐⭐⭐ | N/A | High |

## 🔒 Security Best Practices

### 🛡️ **Key Management**
- **Environment Variables**: Use secure environment variable injection
- **Secrets Management**: Integrate with cloud secrets managers
- **Key Rotation**: Implement regular key rotation policies
- **Access Control**: Restrict API access with authentication

### 🔐 **Production Security**
- **HTTPS Only**: Always use TLS in production
- **Rate Limiting**: Implement API rate limiting
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Log all cryptographic operations

### 🐳 **Container Security**
- **Non-root User**: Containers run as non-privileged user
- **Minimal Base Image**: Slim Python images for reduced attack surface
- **Security Scanning**: Regular vulnerability scans
- **Resource Limits**: CPU and memory constraints

## 🤝 Contributing

We welcome contributions! CRYPTON is designed to be extensible for additional algorithms.

### 🚀 **Adding New Algorithms**
1. Fork the repository: `https://github.com/sarpataturker/crypton`
2. Add algorithm to both `main.py` and `api_server.py`
3. Implement key generation, encryption, and decryption
4. Add comprehensive tests
5. Update documentation
6. Submit a Pull Request

### 🧪 **Development Setup**
```bash
git clone https://github.com/sarpataturker/crypton.git
cd crypton
pip install -r requirements.txt
pip install -r api_requirements.txt
python main.py  # Test terminal app
python -m uvicorn api_server:app --reload  # Test API
```

### 📝 **API Development**
```bash
# Start development server with auto-reload
python -m uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload

# Access interactive API docs
# http://localhost:8000/docs

# Test all endpoints
curl http://localhost:8000/algorithms
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**@sarpataturker**
- GitHub: [@sarpataturker](https://github.com/sarpataturker)
- Project: [CRYPTON](https://github.com/sarpataturker/crypton)
- Website: [sarpataturker.me](https://sarpataturker.me) (coming soon!)

## 🆘 Support & Documentation

### 📚 **Getting Help**
1. **Check the documentation** in this README
2. **API Documentation**: Visit `/docs` endpoint for interactive API docs
3. **Validate your setup** using built-in validation tools
4. **Check Docker status** using the Docker management interface
5. **Create an issue** on [GitHub Issues](https://github.com/sarpataturker/crypton/issues)

### 🔗 **Useful Links**
- **API Documentation**: `http://localhost:8000/docs` (when server is running)
- **Health Check**: `http://localhost:8000/health`
- **Algorithm List**: `http://localhost:8000/algorithms`
- **GitHub Repository**: [github.com/sarpataturker/crypton](https://github.com/sarpataturker/crypton)

## ⭐ Show Your Support

If CRYPTON helped you, please give it a star on GitHub! ⭐

```bash
# Star the repository
https://github.com/sarpataturker/crypton
```

## 🔮 Roadmap

### 🎯 **Version 5.3 (Next Release)**
- [ ] **Mobile SDKs** - iOS and Android libraries
- [ ] **GraphQL API** - Alternative to REST API
- [ ] **Web Dashboard** - Browser-based management interface
- [ ] **Kubernetes Helm Charts** - Easy K8s deployment

### 🚀 **Version 6.0 (Future)**
- [ ] **Hardware Security Module (HSM)** - Enterprise HSM integration
- [ ] **Blockchain Integration** - Crypto wallet support
- [ ] **Machine Learning** - AI-powered security recommendations
- [ ] **Zero-Knowledge Proofs** - Advanced cryptographic protocols

### 🌟 **Long-term Vision**
- [ ] **Cryptographic Standards Compliance** - FIPS 140-2, Common Criteria
- [ ] **Quantum-Resistant Algorithms** - Post-quantum cryptography
- [ ] **Global CDN** - Worldwide API availability
- [ ] **Enterprise Support** - Commercial licensing and support

## 🏆 Why Choose CRYPTON v5.2.0?

✅ **43+ Algorithms** - Largest algorithm selection available  
✅ **Multiple Interfaces** - Terminal, API, Docker, Web-ready  
✅ **Production Ready** - Docker, monitoring, health checks  
✅ **Enterprise Security** - Industry-standard implementations  
✅ **Auto-Documentation** - OpenAPI/Swagger docs included  
✅ **Cross-Platform** - Works everywhere Python and Docker run  
✅ **Professional UI** - Beautiful terminal and web interfaces  
✅ **Extensible** - Easy to add new algorithms and features  
✅ **Well-Documented** - Comprehensive guides and examples  
✅ **Actively Maintained** - Regular updates and improvements  
✅ **Modern Stack** - FastAPI, Docker, responsive design  
✅ **Security-Focused** - Best practices built-in  

---

## 🙏 Acknowledgments

- Built with ❤️ for the cryptographic and developer community
- Inspired by the need for comprehensive, production-ready encryption tools
- Dedicated to advancing cybersecurity education and accessibility
- Special thanks to the open-source cryptographic libraries that make this possible

## 📊 Repository Stats

![GitHub stars](https://img.shields.io/github/stars/sarpataturker/crypton?style=social)
![GitHub forks](https://img.shields.io/github/forks/sarpataturker/crypton?style=social)
![GitHub issues](https://img.shields.io/github/issues/sarpataturker/crypton)
![GitHub pull requests](https://img.shields.io/github/issues-pr/sarpataturker/crypton)

---

<div align="center">

**🔐 CRYPTON v5.2.0 - Ultimate Encryption Powerhouse 🔐**

*Created by [@sarpataturker](https://github.com/sarpataturker)*

[![Star on GitHub](https://img.shields.io/github/stars/sarpataturker/crypton?style=social)](https://github.com/sarpataturker/crypton)
[![Deploy to Railway](https://railway.app/button.svg)](https://railway.app/template/...)

*Remember: With great encryption power comes great responsibility. Keep your keys safe!* 

**🌐 Coming Soon: [sarpataturker.me](https://sarpataturker.me) 🌐**

</div>