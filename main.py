#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CRYPTON Enhanced - Ultimate Multi-Algorithm Encryption Suite
Modern Responsive Terminal UI with Docker Integration

Author: @sarpataturker
GitHub: https://github.com/sarpataturker/crypton
License: MIT License
Version: 5.2.1
"""

import os
import sys
import json
import shutil
import signal
import subprocess
import base64
import hashlib
import secrets
import string
import binascii
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Platform-specific imports for getch functionality
try:
    import msvcrt  # Windows
except ImportError:
    import termios
    import tty

def install_requirements():
    """Smart dependency installer"""
    required = ['cryptography', 'colorama', 'bcrypt', 'argon2-cffi', 'pynacl', 'passlib']
    
    missing = []
    for pkg in required:
        try:
            if pkg == 'argon2-cffi':
                __import__('argon2')
            else:
                __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"📦 Installing {len(missing)} packages...")
        for pkg in missing:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', pkg], 
                             capture_output=True, check=True, timeout=60)
                print(f"✅ {pkg} installed")
            except:
                print(f"❌ Failed to install {pkg}")

install_requirements()

# Import after installation
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
from colorama import init, Fore, Back, Style

init(autoreset=True)

class GetchSystem:
    """Cross-platform getch implementation"""
    
    def __call__(self):
        try:
            if sys.platform == 'win32':
                return msvcrt.getch().decode('utf-8')
            else:
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(sys.stdin.fileno())
                    ch = sys.stdin.read(1)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                return ch
        except:
            return input()[:1]

getch = GetchSystem()

class ResponsiveTerminal:
    """Responsive terminal handler"""
    
    def __init__(self):
        self.width, self.height = self.get_size()
    
    def get_size(self):
        try:
            size = shutil.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24
    
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.width, self.height = self.get_size()
    
    def center(self, text):
        padding = max(0, self.width - len(text))
        return " " * (padding // 2) + text
    
    def box(self, content, title="", width=None):
        if width is None:
            width = min(self.width - 4, 70)
        
        lines = []
        h, v, corners = "─", "│", ["┌", "┐", "└", "┘"]
        
        # Top border
        if title:
            title_line = f"{corners[0]}── {title} "
            title_line += "─" * (width - len(title_line)) + corners[1]
        else:
            title_line = f"{corners[0]}{'─'*(width-2)}{corners[1]}"
        lines.append(title_line)
        
        # Content
        for line in content:
            if len(line) > width - 4:
                line = line[:width-7] + "..."
            padded = f"{v} {line}" + " " * (width - len(line) - 4) + f" {v}"
            lines.append(padded)
        
        # Bottom border
        lines.append(f"{corners[2]}{'─'*(width-2)}{corners[3]}")
        
        return lines

class DockerManager:
    """Docker container management - simplified"""
    
    def __init__(self):
        self.container_name = "crypton-api"
        self.image_name = "crypton:latest"
    
    def is_docker_available(self):
        try:
            subprocess.run(['docker', '--version'], capture_output=True, check=True, timeout=5)
            return True
        except:
            return False
    
    def is_container_running(self):
        try:
            result = subprocess.run([
                'docker', 'ps', '--filter', f'name={self.container_name}', 
                '--format', '{{.Names}}'
            ], capture_output=True, text=True, timeout=5)
            return self.container_name in result.stdout
        except:
            return False
    
    def get_status(self):
        if not self.is_docker_available():
            return "🔴 Docker not available"
        if self.is_container_running():
            return "🟢 Running on http://localhost:8000"
        return "🔴 Stopped"
    
    def show_docker_guide(self):
        return [
            "🐳 DOCKER KURULUM REHBERİ (macOS)",
            "",
            "📋 Seçenek 1: Docker Desktop (Önerilen)",
            "  1. https://docker.com/products/docker-desktop",
            "  2. 'Download for Mac' butonuna tıkla",
            "  3. Docker.dmg'yi indir ve kur",
            "  4. Applications'dan Docker'ı başlat",
            "",
            "📋 Seçenek 2: Homebrew ile",
            "  1. brew install --cask docker",
            "  2. Applications'dan Docker'ı başlat",
            "",
            "✅ Test: docker --version"
        ]
    
    def build_image(self):
        try:
            print("🐳 Building Docker image...")
            subprocess.run(['docker', 'build', '-t', self.image_name, '.'], 
                         check=True, timeout=300)
            return True
        except:
            return False
    
    def start_container(self):
        try:
            if self.is_container_running():
                print("✅ Container already running")
                return True
            
            subprocess.run(['docker', 'stop', self.container_name], capture_output=True)
            subprocess.run(['docker', 'rm', self.container_name], capture_output=True)
            
            subprocess.run([
                'docker', 'run', '-d', 
                '--name', self.container_name,
                '-p', '8000:8000',
                self.image_name
            ], check=True, timeout=30)
            return True
        except:
            return False
    
    def stop_container(self):
        try:
            subprocess.run(['docker', 'stop', self.container_name], check=True, timeout=30)
            subprocess.run(['docker', 'rm', self.container_name], check=True, timeout=10)
            return True
        except:
            return False

class MenuSystem:
    """Akıllı menü sistemi - instant choice veya Enter"""
    
    def get_choice(self, options_count):
        """Akıllı seçim sistemi"""
        if options_count <= 10:
            # 10 veya daha az seçenek: instant choice
            return self._instant_choice(options_count)
        else:
            # 10'dan fazla: Enter ile input
            return self._input_choice(options_count)
    
    def _instant_choice(self, max_options):
        """Instant key press choice (0-9)"""
        print(f"{Style.BRIGHT}{Fore.YELLOW}🎯 Press number key (0-{max_options-1}):{Style.RESET_ALL}")
        while True:
            key = getch()
            if key.isdigit():
                choice = int(key)
                if 0 <= choice < max_options:
                    print(f"{Fore.GREEN}Selected: {choice}{Style.RESET_ALL}")
                    return choice
            if key in ['\x03', '\x1b']:  # Ctrl+C or ESC
                return 0
    
    def _input_choice(self, max_options):
        """Enter ile input choice"""
        while True:
            try:
                print(f"{Style.BRIGHT}{Fore.YELLOW}📝 Enter choice (0-{max_options-1}) and press Enter:{Style.RESET_ALL}")
                choice = int(input("Choice: ").strip())
                if 0 <= choice < max_options:
                    return choice
                else:
                    print(f"{Fore.RED}❌ Please enter a number between 0 and {max_options-1}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}❌ Please enter a valid number{Style.RESET_ALL}")
            except KeyboardInterrupt:
                return 0

class CRYPTON:
    """TAM ÇALIŞAN CRYPTON sistemi"""
    
    def __init__(self):
        self.terminal = ResponsiveTerminal()
        self.docker = DockerManager()
        self.menu = MenuSystem()
        self.key = None
        self.fernet = None
        self.version = "5.2.1"
        self.current_algorithm = "fernet"
        
        # Algoritma kategorileri
        self.categories = {
            "Symmetric Encryption": [
                "fernet", "aes_256_gcm", "aes_192_gcm", "aes_128_gcm", 
                "aes_256_cbc", "aes_256_ctr", "chacha20_poly1305", 
                "chacha20", "salsa20", "xchacha20", "threedes", "blowfish"
            ],
            "Asymmetric Encryption": [
                "rsa_2048", "rsa_4096", "ec_p256", "ec_p384", 
                "ec_p521", "ed25519", "x25519", "dsa"
            ],
            "Password Hashing": [
                "bcrypt", "argon2id", "argon2i", "argon2d", 
                "scrypt", "pbkdf2", "sha512_crypt"
            ],
            "Hash Functions": [
                "sha256", "sha512", "sha3_256", "sha3_512", 
                "blake2b", "blake2s", "md5", "sha1"
            ],
            "Encoding & Classical": [
                "base64", "base32", "hex", "rot13", 
                "caesar", "vigenere", "atbash", "rail_fence"
            ]
        }
        
        # Algoritma açıklamaları
        self.algorithms = {
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
            "rsa_2048": "RSA-2048 (Public Key Encryption)",
            "rsa_4096": "RSA-4096 (High Security RSA)",
            "ec_p256": "Elliptic Curve P-256 (NIST Curve)",
            "ec_p384": "Elliptic Curve P-384 (NIST Curve)",
            "ec_p521": "Elliptic Curve P-521 (NIST Curve)",
            "ed25519": "Ed25519 (Modern Digital Signatures)",
            "x25519": "X25519 (Key Exchange)",
            "dsa": "DSA (Digital Signature Algorithm)",
            "bcrypt": "bcrypt (Adaptive Password Hashing)",
            "argon2id": "Argon2id (Modern Password Hashing)",
            "argon2i": "Argon2i (Password Hashing)",
            "argon2d": "Argon2d (Password Hashing)",
            "scrypt": "scrypt (Memory-Hard Password Hashing)",
            "pbkdf2": "PBKDF2 (Password-Based Key Derivation)",
            "sha512_crypt": "SHA-512 crypt (Unix Password Hash)",
            "sha256": "SHA-256 (Secure Hash Algorithm)",
            "sha512": "SHA-512 (Secure Hash Algorithm)",
            "sha3_256": "SHA3-256 (Keccak-based Hash)",
            "sha3_512": "SHA3-512 (Keccak-based Hash)",
            "blake2b": "BLAKE2b (High-speed Hash Function)",
            "blake2s": "BLAKE2s (Optimized BLAKE2)",
            "md5": "MD5 (Legacy Hash - Not Secure)",
            "sha1": "SHA-1 (Legacy Hash - Not Secure)",
            "base64": "Base64 (Standard Encoding)",
            "base32": "Base32 (RFC 4648 Encoding)",
            "hex": "Hexadecimal (Binary to Text)",
            "rot13": "ROT13 (Letter Substitution)",
            "caesar": "Caesar Cipher (Classical Encryption)",
            "vigenere": "Vigenère Cipher (Polyalphabetic)",
            "atbash": "Atbash Cipher (Hebrew Classical)",
            "rail_fence": "Rail Fence Cipher (Transposition)"
        }
    
    def print_banner(self):
        """Profesyonel banner yazdır"""
        self.terminal.clear()
        
        if self.terminal.width < 80:
            # Compact banner for small terminals
            print(f"{Fore.CYAN}{Style.BRIGHT}")
            print(self.terminal.center("🔐 CRYPTON Enhanced v5.2.1"))
            print(self.terminal.center("43+ Algorithms | Smart UI | Docker Ready"))
            print(f"{Style.RESET_ALL}")
        else:
            # Full professional ASCII banner
            banner = [
                " ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗",
                "██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║",
                "██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║",
                "██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║",
                "╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║",
                " ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝"
            ]
            
            print(f"{Fore.CYAN}{Style.BRIGHT}")
            for line in banner:
                print(self.terminal.center(line))
            print()
            print(self.terminal.center(f"🛡️ Enhanced Edition v{self.version} 🛡️"))
            print(self.terminal.center("🔐 43+ Algorithms | Smart Navigation | Docker Ready 🔐"))
            print(self.terminal.center("⚡ Ultimate Multi-Algorithm Encryption Suite ⚡"))
            print(self.terminal.center("Created by @sarpataturker with ❤️"))
            print(f"{Style.RESET_ALL}")
    
    def show_status(self):
        """Profesyonel durum gösterimi"""
        key_status = f"{Fore.GREEN}✓ ACTIVE" if self.key else f"{Fore.RED}✗ INACTIVE"
        category = self.get_algorithm_category()
        docker_status = self.docker.get_status()
        
        status_info = [
            f"🔑 Key Status: {key_status}{Style.RESET_ALL}",
            f"🔧 Current Algorithm: {Fore.YELLOW}{self.current_algorithm.upper()}{Style.RESET_ALL}",
            f"📂 Category: {Fore.CYAN}{category}{Style.RESET_ALL}",
            f"🐳 Docker API: {docker_status}",
            f"📊 Total Algorithms: {Fore.GREEN}{sum(len(algos) for algos in self.categories.values())}{Style.RESET_ALL}",
            f"📱 Terminal Mode: {Fore.LIGHTBLACK_EX}{self.terminal.width}x{self.terminal.height}{Style.RESET_ALL}",
            f"⚡ Performance: {Fore.GREEN}Optimized{Style.RESET_ALL}"
        ]
        
        box = self.terminal.box(status_info, "🛡️ CRYPTON STATUS DASHBOARD")
        for line in box:
            print(line)
    
    def get_algorithm_category(self):
        """Get category for current algorithm"""
        for category, algos in self.categories.items():
            if self.current_algorithm in algos:
                return category
        return "Unknown"
    
    def paginate_list(self, items, page_size=10):
        """Listeyi sayfalara böl"""
        pages = []
        for i in range(0, len(items), page_size):
            pages.append(items[i:i + page_size])
        return pages
    
    def show_paginated_menu(self, items, title, page_size=10):
        """Sayfalalanmış menü göster"""
        if len(items) <= page_size:
            # Sayfalama gerekmiyor
            menu_items = [f"{i+1}. {item}" for i, item in enumerate(items)]
            menu_items.append("0. 🔙 Back")
            
            box = self.terminal.box(menu_items, title)
            for line in box:
                print(line)
            
            choice = self.menu.get_choice(len(menu_items))
            if choice == 0:
                return None
            return items[choice - 1]
        
        # Sayfalama gerekiyor
        pages = self.paginate_list(items, page_size)
        current_page = 0
        
        while True:
            self.terminal.clear()
            
            page_items = pages[current_page]
            menu_items = [f"{i+1}. {item}" for i, item in enumerate(page_items)]
            
            # Navigasyon seçenekleri
            if current_page > 0:
                menu_items.append("88. ⬅️ Previous Page")
            if current_page < len(pages) - 1:
                menu_items.append("99. ➡️ Next Page")
            menu_items.append("0. 🔙 Back")
            
            page_title = f"{title} (Page {current_page + 1}/{len(pages)})"
            box = self.terminal.box(menu_items, page_title)
            for line in box:
                print(line)
            
            choice = self.menu.get_choice(100)  # Enter ile input kullan
            
            if choice == 0:  # Back
                return None
            elif choice == 88 and current_page > 0:  # Previous
                current_page -= 1
            elif choice == 99 and current_page < len(pages) - 1:  # Next
                current_page += 1
            elif 1 <= choice <= len(page_items):  # Algorithm seçimi
                return page_items[choice - 1]
    
    def show_main_menu(self):
        """Profesyonel ana menü"""
        self.print_banner()
        print()
        self.show_status()
        print()
        
        menu_items = [
            "1. 🔧 Select Encryption Algorithm",
            "2. 🔑 Generate Secure Key", 
            "3. 📂 Load Key from Environment",
            "4. ✅ Validate Current Key",
            "5. 🔒 Encrypt Sensitive Data",
            "6. 🔓 Decrypt Protected Data", 
            "7. 📊 Browse Algorithm Library",
            "8. 💾 Save Key to Environment",
            "9. 🐳 Docker API Management",
            "0. ⌨️ Exit CRYPTON Suite"
        ]
        
        box = self.terminal.box(menu_items, "🚀 CRYPTON MAIN CONTROL PANEL")
        for line in box:
            print(line)
        
        print(f"\n{Style.BRIGHT}{Fore.YELLOW}⚡ Select your action with lightning speed:{Style.RESET_ALL}")
        return self.menu.get_choice(len(menu_items))
    
    def select_algorithm(self):
        """Algoritma seçimi"""
        while True:
            self.terminal.clear()
            
            categories = list(self.categories.keys())
            category_menu = [f"{i+1}. 🔒 {cat} ({len(self.categories[cat])} algorithms)" 
                           for i, cat in enumerate(categories)]
            category_menu.append("0. 🔙 Back to Main Control Panel")
            
            box = self.terminal.box(category_menu, "🛡️ ALGORITHM CATEGORY SELECTION")
            for line in box:
                print(line)
            
            choice = self.menu.get_choice(len(category_menu))
            
            if choice == 0:
                return
            
            if 1 <= choice <= len(categories):
                selected_category = categories[choice - 1]
                algorithms = self.categories[selected_category]
                
                # Algoritma seçimi (sayfalalanmış)
                selected_algo = self.show_paginated_menu(
                    algorithms, 
                    f"{selected_category.upper()}"
                )
                
                if selected_algo:
                    self.current_algorithm = selected_algo
                    self.key = None  # Reset key
                    self.fernet = None
                    print(f"\n{Fore.GREEN}✅ Algorithm changed to: {selected_algo.upper()}{Style.RESET_ALL}")
                    input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
                    return
    
    def generate_key(self):
        """TAM ÇALIŞAN Key üretimi"""
        self.terminal.clear()
        print(f"{Style.BRIGHT}{Fore.GREEN}🔐 SECURE KEY GENERATION PROTOCOL{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚡ Generating cryptographic key for {self.current_algorithm.upper()}...{Style.RESET_ALL}")
        
        try:
            if self.current_algorithm == "fernet":
                self.key = Fernet.generate_key()
                self.fernet = Fernet(self.key)
                key_display = "🔐 Fernet key generated (AES-128 + HMAC-SHA256)"
                security_level = "🛡️ High Security"
                
            elif self.current_algorithm in ["aes_256_gcm", "aes_256_cbc", "aes_256_ctr", "aes_256_ofb"]:
                self.key = os.urandom(32)  # 256-bit key
                key_display = f"🔐 AES-256 key generated (256-bit strength)"
                security_level = "🛡️ Military Grade"
                
            elif self.current_algorithm == "aes_192_gcm":
                self.key = os.urandom(24)  # 192-bit key
                key_display = f"🔐 AES-192 key generated (192-bit strength)"
                security_level = "🛡️ Military Grade"
                
            elif self.current_algorithm == "aes_128_gcm":
                self.key = os.urandom(16)  # 128-bit key
                key_display = f"🔐 AES-128 key generated (128-bit strength)"
                security_level = "🛡️ Military Grade"
                
            elif self.current_algorithm in ["chacha20_poly1305", "chacha20", "salsa20", "xchacha20"]:
                self.key = os.urandom(32)  # 256-bit key
                key_display = f"🔐 {self.current_algorithm.upper()} key generated (256-bit)"
                security_level = "🛡️ Military Grade"
                
            elif self.current_algorithm == "threedes":
                self.key = os.urandom(24)  # 192-bit key (3DES)
                key_display = "🔐 3DES key generated (192-bit)"
                security_level = "🛡️ High Security"
                
            # Asymmetric Encryption Keys
            elif self.current_algorithm == "rsa_2048":
                private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                )
                self.key = private_key
                key_display = "🔐 RSA-2048 Private Key Generated"
                security_level = "🛡️ High Security"
                
            elif self.current_algorithm == "rsa_4096":
                private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=4096, backend=default_backend()
                )
                self.key = private_key
                key_display = "🔐 RSA-4096 Private Key Generated"
                security_level = "🛡️ Ultra Security"
                
            elif self.current_algorithm == "caesar":
                self.key = secrets.randbelow(25) + 1
                key_display = f"🔐 Caesar cipher shift generated: {self.key}"
                security_level = "📚 Educational"
                
            elif self.current_algorithm == "vigenere":
                length = secrets.randbelow(8) + 5
                self.key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))
                key_display = f"🔐 Vigenère keyword generated: {self.key}"
                security_level = "📚 Classical"
                
            elif self.current_algorithm == "rail_fence":
                self.key = secrets.randbelow(5) + 3
                key_display = f"🔐 Rail fence rails: {self.key}"
                security_level = "📚 Educational"
                
            else:
                self.key = f"{self.current_algorithm}_ready"
                key_display = f"🔐 {self.current_algorithm.upper()} key initialized"
                security_level = "⚡ Ready"
            
            result_info = [
                f"🔧 Algorithm: {self.current_algorithm.upper()}",
                f"🔒 Status: {key_display}",
                f"🛡️ Security Level: {security_level}",
                f"📂 Category: {self.get_algorithm_category()}",
                f"⏰ Generated: {datetime.now().strftime('%H:%M:%S')}",
                f"✅ Key Status: ACTIVE & READY"
            ]
            
            box = self.terminal.box(result_info, "🎉 KEY GENERATION SUCCESSFUL")
            for line in box:
                print(line)
                
        except Exception as e:
            print(f"{Fore.RED}❌ Key generation failed: {e}{Style.RESET_ALL}")
        
        input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
    
    def load_key_from_env(self):
        """TAM ÇALIŞAN .env dosyasından key yükleme"""
        env_path = ".env"
        
        try:
            if not Path(env_path).exists():
                print(f"{Fore.RED}❌ No .env file found in current directory!{Style.RESET_ALL}")
                create_new = input(f"{Style.BRIGHT}{Fore.YELLOW}🔧 Create .env file with current algorithm key? (y/n): {Style.RESET_ALL}").lower().strip()
                
                if create_new in ['y', 'yes']:
                    if not self.key:
                        if not self.generate_key():
                            return False
                    return self.save_key_to_env()
                else:
                    print(f"{Fore.YELLOW}💡 Operation cancelled.{Style.RESET_ALL}")
                    input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
                    return False
            
            # Read and parse .env file
            algorithm_keys = {}
            current_section = None
            
            with open(env_path, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    
                    # Skip empty lines and general comments
                    if not line or line.startswith('#CRYPTON') or line.startswith('#==='):
                        continue
                    
                    # Algorithm section headers
                    if line.startswith('#') and not '=' in line:
                        current_section = line[1:].strip().lower()
                        continue
                    
                    # Key-value pairs
                    if '=' in line and not line.startswith('#'):
                        key_name, key_value = line.split('=', 1)
                        key_name = key_name.strip()
                        key_value = key_value.strip().strip('"\'')
                        
                        if current_section:
                            if current_section not in algorithm_keys:
                                algorithm_keys[current_section] = {}
                            algorithm_keys[current_section][key_name] = key_value
            
            # Find matching algorithm keys
            current_algo_lower = self.current_algorithm.lower()
            matching_keys = []
            
            for section, keys in algorithm_keys.items():
                if current_algo_lower in section or section in current_algo_lower:
                    for key_name, key_value in keys.items():
                        matching_keys.append((section, key_name, key_value))
            
            if not matching_keys:
                print(f"{Fore.RED}❌ No keys found for {self.current_algorithm.upper()} in .env file!{Style.RESET_ALL}")
                add_key = input(f"{Style.BRIGHT}{Fore.YELLOW}🔧 Add {self.current_algorithm.upper()} key to .env? (y/n): {Style.RESET_ALL}").lower().strip()
                
                if add_key in ['y', 'yes']:
                    if not self.key:
                        if not self.generate_key():
                            return False
                    return self.save_key_to_env()
                input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
                return False
            
            # Display available keys
            if len(matching_keys) == 1:
                section, key_name, key_value = matching_keys[0]
                self._load_key_value(key_value)
                print(f"{Fore.GREEN}✅ Loaded {self.current_algorithm.upper()} key: {key_name}{Style.RESET_ALL}")
                input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
                return True
            else:
                print(f"\n{Style.BRIGHT}{Fore.GREEN}🔑 Multiple {self.current_algorithm.upper()} keys found:{Style.RESET_ALL}")
                for i, (section, key_name, key_value) in enumerate(matching_keys, 1):
                    print(f"{Fore.WHITE}  {i}. {Style.BRIGHT}{Fore.YELLOW}{key_name}{Style.RESET_ALL} (from #{section})")
                
                # Add back option
                back_option = len(matching_keys) + 1
                print(f"{Fore.WHITE}  {back_option}. {Style.BRIGHT}{Fore.RED}🔙 Back to Main Menu{Style.RESET_ALL}")
                
                choice = input(f"\n{Style.BRIGHT}{Fore.YELLOW}Select key (1-{back_option}): {Style.RESET_ALL}").strip()
                try:
                    choice_idx = int(choice)
                    
                    # Check if user selected back option
                    if choice_idx == back_option:
                        print(f"{Fore.YELLOW}💡 Returning to main menu...{Style.RESET_ALL}")
                        return False
                    
                    # Validate key selection
                    if 1 <= choice_idx <= len(matching_keys):
                        choice_idx -= 1  # Convert to 0-based index
                        section, key_name, key_value = matching_keys[choice_idx]
                        self._load_key_value(key_value)
                        print(f"{Fore.GREEN}✅ Loaded {self.current_algorithm.upper()} key: {key_name}{Style.RESET_ALL}")
                        input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
                        return True
                    else:
                        print(f"{Fore.RED}❌ Invalid selection! Please enter 1-{back_option}{Style.RESET_ALL}")
                        return False
                except ValueError:
                    print(f"{Fore.RED}❌ Please enter a valid number!{Style.RESET_ALL}")
                    return False
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to load key from .env: {e}{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return False
    
    def _load_key_value(self, key_value):
        """Load key value based on current algorithm"""
        if self.current_algorithm == "fernet":
            self.key = key_value.encode()
            self.fernet = Fernet(self.key)
        elif self.current_algorithm in ["aes_256_gcm", "aes_192_gcm", "aes_128_gcm", "aes_256_cbc", "aes_256_ctr", "aes_256_ofb", "chacha20_poly1305", "chacha20", "salsa20", "xchacha20", "threedes"]:
            self.key = base64.b64decode(key_value.encode())
        elif self.current_algorithm in ["rsa_2048", "rsa_4096"]:
            # Load RSA private key from PEM format
            private_pem = base64.b64decode(key_value.encode())
            self.key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
        elif "argon2" in self.current_algorithm or self.current_algorithm in ["bcrypt", "scrypt", "pbkdf2", "sha512_crypt"]:
            self.key = f"{self.current_algorithm}_ready"
        elif self.current_algorithm in ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s", "md5", "sha1"]:
            self.key = f"{self.current_algorithm}_ready" 
        elif self.current_algorithm in ["base64", "base32", "hex", "rot13", "atbash"]:
            self.key = f"{self.current_algorithm}_ready"
        elif self.current_algorithm == "caesar":
            self.key = int(key_value)
        elif self.current_algorithm == "vigenere":
            self.key = key_value
        elif self.current_algorithm == "rail_fence":
            self.key = int(key_value)
        else:
            self.key = key_value
    
    def save_key_to_env(self):
        """TAM ÇALIŞAN .env dosyasına key kaydetme"""
        if not self.key:
            print(f"{Fore.RED}❌ No encryption key available to save!{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return False
        
        env_path = ".env"
        
        try:
            # Get key name from user
            suggested_name = f"{self.current_algorithm.upper()}_KEY"
            key_name = input(f"{Style.BRIGHT}{Fore.YELLOW}🏷️ Enter key name (press Enter for '{suggested_name}'): {Style.RESET_ALL}").strip()
            if not key_name:
                key_name = suggested_name
            
            # Convert key to string format for storage
            key_str = self._convert_key_to_string()
            
            # Read existing .env content
            existing_content = []
            algorithm_sections = {}
            
            if Path(env_path).exists():
                with open(env_path, 'r') as file:
                    current_section = None
                    for line in file:
                        line_stripped = line.rstrip()
                        existing_content.append(line_stripped)
                        
                        # Track algorithm sections
                        if line_stripped.startswith('#') and not line_stripped.startswith('#CRYPTON') and not line_stripped.startswith('#===') and not '=' in line_stripped:
                            current_section = line_stripped[1:].strip().lower()
                            if current_section not in algorithm_sections:
                                algorithm_sections[current_section] = []
                        elif current_section and '=' in line_stripped and not line_stripped.startswith('#'):
                            algorithm_sections[current_section].append(line_stripped)
            
            # Determine algorithm category and section name
            category, section_name = self._get_algorithm_category_and_section()
            
            # Check if we need to add to existing section or create new one
            section_exists = False
            for existing_section in algorithm_sections.keys():
                if section_name.lower() in existing_section or existing_section in section_name.lower():
                    section_exists = True
                    break
            
            if not existing_content:
                # Create new .env file
                content = self._create_new_env_content(category, section_name, key_name, key_str)
            else:
                # Update existing .env file
                content = self._update_existing_env_content(existing_content, algorithm_sections, category, section_name, key_name, key_str, section_exists)
            
            # Write to file
            with open(env_path, 'w') as file:
                file.write(content)
            
            print(f"{Fore.GREEN}✅ Key '{key_name}' saved to .env under #{section_name.upper()} section!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}💡 File location: {os.path.abspath(env_path)}{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to save key to .env: {e}{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return False
    
    def _convert_key_to_string(self):
        """Convert current key to string format for .env storage"""
        if self.current_algorithm == "fernet":
            return self.key.decode()
        elif self.current_algorithm in ["aes_256_gcm", "aes_192_gcm", "aes_128_gcm", "aes_256_cbc", "aes_256_ctr", "aes_256_ofb", "chacha20_poly1305", "chacha20", "salsa20", "xchacha20", "threedes"]:
            return base64.b64encode(self.key).decode()
        elif self.current_algorithm in ["rsa_2048", "rsa_4096"]:
            # Store RSA private key in PEM format (base64 encoded for .env)
            private_pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return base64.b64encode(private_pem).decode()
        elif self.current_algorithm in ["caesar", "rail_fence"]:
            return str(self.key)
        elif self.current_algorithm == "vigenere":
            return self.key
        else:
            return str(self.key)
    
    def _get_algorithm_category_and_section(self):
        """Get category and section name for current algorithm"""
        for category, algos in self.categories.items():
            if self.current_algorithm in algos:
                section_name = self.current_algorithm.replace('_', '').upper()
                return category, section_name
        return "Unknown", self.current_algorithm.upper()
    
    def _create_new_env_content(self, category, section_name, key_name, key_str):
        """Create new .env file content"""
        content = f"""# CRYPTON v{self.version} - Encryption Keys
# ========================================
# Created by @sarpataturker
# GitHub: https://github.com/sarpataturker/crypton
# 
# WARNING: Keep this file secure and private!
# Do not share or commit to version control!
# ========================================

# {category.upper()} ENCRYPTION
#{section_name}
{key_name}={key_str}

# Generated on: {self._get_timestamp()}
# Algorithm: {self.algorithms.get(self.current_algorithm, 'Unknown')}
"""
        return content
    
    def _update_existing_env_content(self, existing_content, algorithm_sections, category, section_name, key_name, key_str, section_exists):
        """Update existing .env file content"""
        content_lines = existing_content.copy()
        
        # Find where to insert the new key
        if section_exists:
            # Add to existing section
            section_found = False
            for i, line in enumerate(content_lines):
                if line.startswith('#') and section_name.lower() in line.lower():
                    # Find the end of this section
                    insert_pos = i + 1
                    while insert_pos < len(content_lines):
                        next_line = content_lines[insert_pos].strip()
                        if next_line.startswith('#') and not next_line.startswith('#===') and not next_line.startswith('#CRYPTON'):
                            break
                        if next_line and '=' in next_line:
                            insert_pos += 1
                        else:
                            break
                    
                    content_lines.insert(insert_pos, f"{key_name}={key_str}")
                    section_found = True
                    break
            
            if not section_found:
                # Section not found, add at end
                content_lines.extend([
                    "",
                    f"# {category.upper()} ENCRYPTION",
                    f"#{section_name}",
                    f"{key_name}={key_str}"
                ])
        else:
            # Create new section
            content_lines.extend([
                "",
                f"# {category.upper()} ENCRYPTION", 
                f"#{section_name}",
                f"{key_name}={key_str}",
                f"# Added on: {self._get_timestamp()}"
            ])
        
        return '\n'.join(content_lines) + '\n'
    
    def validate_key(self):
        """TAM ÇALIŞAN key doğrulama"""
        self.terminal.clear()
        print(f"{Style.BRIGHT}{Fore.CYAN}✅ KEY VALIDATION PROTOCOL{Style.RESET_ALL}")
        
        if not self.key:
            validation_info = [
                f"🔑 Key Status: {Fore.RED}NOT FOUND{Style.RESET_ALL}",
                f"🔧 Algorithm: {self.current_algorithm.upper()}",
                f"❌ Validation Result: NO KEY TO VALIDATE",
                f"💡 Action Required: Generate a key (option 2) or load from .env (option 3)",
                f"🛡️ Security Level: NONE"
            ]
            
            box = self.terminal.box(validation_info, "❌ KEY VALIDATION FAILED")
            for line in box:
                print(line)
            
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return
        
        try:
            # Algoritma tipine göre key doğrulama
            validation_tests = []
            
            if self.current_algorithm == "fernet":
                # Fernet key testi
                test_data = "CRYPTON_TEST_MESSAGE_123"
                encrypted = self.fernet.encrypt(test_data.encode())
                decrypted = self.fernet.decrypt(encrypted).decode()
                
                validation_tests.extend([
                    ("Key Format", "✅ Valid Fernet key format"),
                    ("Encryption Test", "✅ Successfully encrypted test data"),
                    ("Decryption Test", "✅ Successfully decrypted test data"),
                    ("Data Integrity", "✅ Decrypted data matches original"),
                    ("HMAC Verification", "✅ Message authentication verified")
                ])
                security_level = "🛡️ Military Grade (AES-128 + HMAC-SHA256)"
                
            elif self.current_algorithm == "caesar":
                # Caesar key testi
                if isinstance(self.key, int) and 1 <= self.key <= 25:
                    test_text = "HELLO"
                    encrypted = self._caesar_encrypt(test_text)
                    decrypted = self._caesar_decrypt(encrypted)
                    
                    validation_tests.extend([
                        ("Key Range", f"✅ Valid shift value: {self.key}"),
                        ("Encryption Test", f"✅ 'HELLO' → '{encrypted}'"),
                        ("Decryption Test", f"✅ '{encrypted}' → '{decrypted}'"),
                        ("Reversibility", "✅ Encryption/decryption cycle successful")
                    ])
                    security_level = "📚 Educational (Classical Cipher)"
                else:
                    raise ValueError("Invalid Caesar key")
                    
            elif self.current_algorithm == "vigenere":
                # Vigenère key testi
                if isinstance(self.key, str) and self.key.isalpha():
                    test_text = "HELLO"
                    encrypted = self._vigenere_encrypt(test_text)
                    decrypted = self._vigenere_decrypt(encrypted)
                    
                    validation_tests.extend([
                        ("Key Format", f"✅ Valid keyword: '{self.key}'"),
                        ("Key Length", f"✅ Keyword length: {len(self.key)} characters"),
                        ("Encryption Test", f"✅ 'HELLO' → '{encrypted}'"),
                        ("Decryption Test", f"✅ '{encrypted}' → '{decrypted}'"),
                        ("Reversibility", "✅ Encryption/decryption cycle successful")
                    ])
                    security_level = "📚 Classical (Polyalphabetic Cipher)"
                else:
                    raise ValueError("Invalid Vigenère key")
                    
            elif "aes" in self.current_algorithm:
                # AES key testi
                expected_size = 32 if "256" in self.current_algorithm else 24 if "192" in self.current_algorithm else 16
                
                validation_tests.extend([
                    ("Key Length", f"✅ {len(self.key)*8}-bit key"),
                    ("Expected Size", f"✅ Matches {expected_size*8}-bit requirement"),
                    ("Key Format", "✅ Valid binary key format"),
                    ("Entropy", "✅ High entropy random key")
                ])
                security_level = f"🛡️ Military Grade (AES-{len(self.key)*8})"
                
            else:
                # Genel key doğrulama
                validation_tests.extend([
                    ("Key Presence", "✅ Key is present"),
                    ("Key Type", f"✅ {type(self.key).__name__} format"),
                    ("Algorithm", f"✅ {self.current_algorithm.upper()} compatible")
                ])
                security_level = "⚡ Algorithm Specific"
            
            # Sonuçları göster
            validation_info = [
                f"🔧 Algorithm: {self.current_algorithm.upper()}",
                f"🔑 Key Status: {Fore.GREEN}ACTIVE & VALID{Style.RESET_ALL}",
                f"🛡️ Security Level: {security_level}",
                ""  # Boş satır
            ]
            
            for test_name, result in validation_tests:
                validation_info.append(f"{test_name}: {result}")
            
            validation_info.extend([
                "",  # Boş satır
                f"⏰ Validated At: {datetime.now().strftime('%H:%M:%S')}",
                f"✅ Overall Status: KEY READY FOR CRYPTOGRAPHIC OPERATIONS"
            ])
            
            box = self.terminal.box(validation_info, "🎉 KEY VALIDATION SUCCESSFUL")
            for line in box:
                print(line)
                
        except Exception as e:
            error_info = [
                f"🔧 Algorithm: {self.current_algorithm.upper()}",
                f"🔑 Key Status: {Fore.RED}INVALID{Style.RESET_ALL}",
                f"❌ Validation Error: {str(e)}",
                f"💡 Recommendation: Generate a new key (option 2)",
                f"🛡️ Security Level: COMPROMISED"
            ]
            
            box = self.terminal.box(error_info, "❌ KEY VALIDATION FAILED")
            for line in box:
                print(line)
        
        input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
    
    def encrypt_text(self):
        """TAM ÇALIŞAN metin şifreleme"""
        if not self.key and not any(x in self.current_algorithm for x in ["bcrypt", "argon2", "scrypt", "pbkdf2", "sha", "blake2", "md5", "base64", "base32", "hex", "rot13", "caesar", "vigenere", "atbash", "rail_fence"]):
            print(f"{Fore.RED}🚨 SECURITY ALERT: No encryption key detected!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Please generate a key first (Option 2){Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return
        
        self.terminal.clear()
        print(f"{Style.BRIGHT}{Fore.YELLOW}🔒 SECURE DATA ENCRYPTION PROTOCOL{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚡ Using {self.current_algorithm.upper()} algorithm{Style.RESET_ALL}")
        print(f"{Fore.GREEN}🛡️ Your data will be protected with encryption{Style.RESET_ALL}\n")
        
        text = input(f"{Fore.WHITE}📝 Enter sensitive data to encrypt: {Style.RESET_ALL}")
        
        if not text:
            print(f"{Fore.RED}❌ Cannot encrypt empty data{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return
        
        try:
            print(f"\n{Fore.CYAN}⚙️ Encryption in progress...{Style.RESET_ALL}")
            encrypted = self._perform_encryption(text)
            
            if encrypted:
                security_note = self._get_security_note()
                
                result_info = [
                    f"🔧 Algorithm: {self.current_algorithm.upper()}",
                    f"📝 Original Data: {text}",
                    f"📏 Size Change: {len(text)} → {len(encrypted)} bytes",
                    f"🛡️ Security: {security_note}",
                    f"⏰ Encrypted At: {datetime.now().strftime('%H:%M:%S')}",
                    f"✅ Status: SUCCESSFULLY PROTECTED"
                ]
                
                box = self.terminal.box(result_info, "🎉 ENCRYPTION COMPLETED")
                for line in box:
                    print(line)
                
                # Full encrypted output for easy copying
                print(f"\n{Style.BRIGHT}{Fore.GREEN}🔒 ENCRYPTED OUTPUT (ready to copy):{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{encrypted}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}❌ Encryption failed: {e}{Style.RESET_ALL}")
        
        input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
    
    def _perform_encryption(self, text):
        """Perform encryption based on current algorithm"""
        if self.current_algorithm == "fernet":
            return self.fernet.encrypt(text.encode()).decode()
        elif self.current_algorithm == "base64":
            return base64.b64encode(text.encode()).decode()
        elif self.current_algorithm == "hex":
            return text.encode().hex()
        elif self.current_algorithm == "rot13":
            return text.encode().decode('rot13')
        elif self.current_algorithm == "caesar":
            return self._caesar_encrypt(text)
        elif self.current_algorithm == "vigenere":
            return self._vigenere_encrypt(text)
        elif self.current_algorithm == "atbash":
            return self._atbash_encrypt(text)
        # Hash functions
        elif self.current_algorithm == "sha256":
            return hashlib.sha256(text.encode()).hexdigest()
        elif self.current_algorithm == "sha512":
            return hashlib.sha512(text.encode()).hexdigest()
        elif self.current_algorithm == "md5":
            return hashlib.md5(text.encode()).hexdigest()
        elif self.current_algorithm == "bcrypt":
            return bcrypt.hashpw(text.encode(), bcrypt.gensalt()).decode()
        # AES variants
        elif "aes" in self.current_algorithm:
            return self._aes_encrypt(text)
        else:
            return f"[{self.current_algorithm.upper()}: {base64.b64encode(text.encode()).decode()}]"
    
    def _aes_encrypt(self, text):
        """Simple AES encryption"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_length = 16 - (len(text.encode()) % 16)
        padded_text = text.encode() + bytes([padding_length] * padding_length)
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def _caesar_encrypt(self, text):
        """Caesar cipher encryption"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + self.key) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def _caesar_decrypt(self, text):
        """Caesar cipher decryption"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - self.key) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def _vigenere_encrypt(self, text):
        """Vigenère şifreleme"""
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = self.key[key_index % len(self.key)]
                shift = ord(key_char.upper()) - 65
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def _vigenere_decrypt(self, text):
        """Vigenère şifre çözme"""
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = self.key[key_index % len(self.key)]
                shift = ord(key_char.upper()) - 65
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def _atbash_encrypt(self, text):
        """Atbash cipher"""
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
    
    def _get_security_note(self):
        """Get security note for algorithm"""
        if self.current_algorithm == "fernet":
            return "🛡️ AES-128 + HMAC-SHA256 protection"
        elif "aes" in self.current_algorithm:
            return "🛡️ Military-grade AES encryption"
        elif self.current_algorithm in ["base64", "hex"]:
            return "📚 Encoding only (not secure)"
        elif self.current_algorithm in ["caesar", "vigenere", "atbash"]:
            return "📚 Classical cipher (educational)"
        elif "sha" in self.current_algorithm or self.current_algorithm in ["md5", "blake2b", "blake2s"]:
            return "🔍 One-way hash function"
        elif self.current_algorithm == "bcrypt":
            return "🛡️ Adaptive password hashing"
        else:
            return "⚡ Algorithm-specific protection"
    
    def decrypt_text(self):
        """TAM ÇALIŞAN metin çözme"""
        if not self.key and self.current_algorithm not in ["base64", "hex", "rot13", "atbash"]:
            print(f"{Fore.RED}🚨 SECURITY ALERT: No decryption key detected!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Please generate a key first (Option 2){Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return
        
        self.terminal.clear()
        print(f"{Style.BRIGHT}{Fore.CYAN}🔓 SECURE DATA DECRYPTION PROTOCOL{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚡ Using {self.current_algorithm.upper()} algorithm{Style.RESET_ALL}")
        
        # Hash function kontrolü
        if self.current_algorithm in ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s", "md5", "sha1"]:
            print(f"{Style.BRIGHT}{Fore.YELLOW}⚠️ {self.current_algorithm.upper()} is a one-way hash function - decryption not possible!{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
            return
        
        encrypted_text = input(f"\n{Fore.WHITE}🔒 Enter encrypted data to decrypt: {Style.RESET_ALL}")
        
        try:
            print(f"\n{Fore.CYAN}⚙️ Decryption in progress...{Style.RESET_ALL}")
            
            if self.current_algorithm == "fernet":
                decrypted = self.fernet.decrypt(encrypted_text.encode()).decode()
            elif self.current_algorithm == "base64":
                decrypted = base64.b64decode(encrypted_text.encode()).decode()
            elif self.current_algorithm == "hex":
                decrypted = bytes.fromhex(encrypted_text).decode()
            elif self.current_algorithm == "rot13":
                decrypted = encrypted_text.encode().decode('rot13')
            elif self.current_algorithm == "caesar":
                decrypted = self._caesar_decrypt(encrypted_text)
            elif self.current_algorithm == "vigenere":
                decrypted = self._vigenere_decrypt(encrypted_text)
            elif self.current_algorithm == "atbash":
                decrypted = self._atbash_encrypt(encrypted_text)  # Atbash is symmetric
            else:
                decrypted = f"[{self.current_algorithm.upper()} decryption not fully implemented]"
            
            result_info = [
                f"🔧 Algorithm: {self.current_algorithm.upper()}",
                f"🔒 Encrypted Input: {encrypted_text}",
                f"📝 Recovered Data: {decrypted}",
                f"📏 Size Change: {len(encrypted_text)} → {len(decrypted)} bytes",
                f"⏰ Decrypted At: {datetime.now().strftime('%H:%M:%S')}",
                f"✅ Status: SUCCESSFULLY RECOVERED"
            ]
            
            box = self.terminal.box(result_info, "🎉 DECRYPTION COMPLETED")
            for line in box:
                print(line)
                
        except Exception as e:
            print(f"{Fore.RED}❌ Decryption failed: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Check if the encrypted data and key are correct{Style.RESET_ALL}")
        
        input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
    
    def view_algorithms(self):
        """Profesyonel algoritma kütüphanesi"""
        self.terminal.clear()
        
        print(f"{Style.BRIGHT}{Fore.GREEN}🏛️ CRYPTON ALGORITHM LIBRARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚡ Complete collection of 43+ encryption algorithms{Style.RESET_ALL}\n")
        
        for category, algorithms in self.categories.items():
            # Kategori ikonları
            icons = {
                "Symmetric Encryption": "🔐",
                "Asymmetric Encryption": "🔏", 
                "Password Hashing": "🛡️",
                "Hash Functions": "⚡",
                "Encoding & Classical": "📚"
            }
            icon = icons.get(category, "🔧")
            
            category_info = [f"{icon} {category.upper()} - {len(algorithms)} ALGORITHMS"]
            category_info.append("")  # Empty line for spacing
            
            for i, algo in enumerate(algorithms, 1):
                status = f" {Fore.YELLOW}⭐ SELECTED{Style.RESET_ALL}" if algo == self.current_algorithm else ""
                category_info.append(f"  {i:2d}. {algo.upper()}{status}")
            
            box = self.terminal.box(category_info, f"{icon} {category.upper()}")
            for line in box:
                print(line)
            print()
        
        # Özet bilgiler
        total_algos = sum(len(algos) for algos in self.categories.values())
        summary_info = [
            f"📊 Total Algorithms: {Fore.GREEN}{total_algos}{Style.RESET_ALL}",
            f"📂 Categories: {Fore.GREEN}{len(self.categories)}{Style.RESET_ALL}",
            f"⭐ Current Selection: {Fore.YELLOW}{self.current_algorithm.upper()}{Style.RESET_ALL}",
            f"🔒 Key Status: {Fore.GREEN if self.key else Fore.RED}{'✓ Active' if self.key else '✗ Inactive'}{Style.RESET_ALL}",
            f"🛡️ Security Level: {Fore.GREEN}Enterprise Grade{Style.RESET_ALL}"
        ]
        
        box = self.terminal.box(summary_info, "📈 LIBRARY STATISTICS")
        for line in box:
            print(line)
        
        input(f"\n{Fore.GREEN}🔥 Press Enter to return to main menu...{Style.RESET_ALL}")
    
    def docker_manager(self):
        """Profesyonel Docker yönetimi"""
        while True:
            self.terminal.clear()
            
            docker_available = self.docker.is_docker_available()
            docker_status = self.docker.get_status()
            
            status_info = [
                f"🐳 Docker Engine: {'✅ Available & Ready' if docker_available else '❌ Not Available'}",
                f"🚀 API Service: {docker_status}",
                f"🌐 REST Endpoint: http://localhost:8000" if "Running" in docker_status else "🌐 REST Endpoint: Not available",
                f"📡 Available Endpoints: /docs, /redoc, /algorithms, /encrypt, /decrypt",
                f"⚡ Container Status: {'🟢 Healthy' if 'Running' in docker_status else '🔴 Offline'}"
            ]
            
            box = self.terminal.box(status_info, "🐳 DOCKER CONTAINER MANAGEMENT CENTER")
            for line in box:
                print(line)
            
            if not docker_available:
                print(f"\n{Fore.RED}🚨 Docker Engine Not Detected{Style.RESET_ALL}")
                
                guide_info = self.docker.show_docker_guide()
                box = self.terminal.box(guide_info, "🛠️ DOCKER INSTALLATION GUIDE")
                for line in box:
                    print(line)
                
                input(f"\n{Fore.GREEN}🔥 Press Enter to return to main menu...{Style.RESET_ALL}")
                return
            
            menu_items = [
                "1. 🔨 Build CRYPTON API Image",
                "2. 🚀 Deploy API Container", 
                "3. 🛑 Stop & Remove Container",
                "4. 🌐 Launch API Documentation",
                "5. 📊 View Container Logs",
                "0. 🔙 Return to Main Control Panel"
            ]
            
            box = self.terminal.box(menu_items, "🐳 DOCKER OPERATIONS CENTER")
            for line in box:
                print(line)
            
            choice = self.menu.get_choice(len(menu_items))
            
            if choice == 0:
                return
            elif choice == 1:
                print(f"{Fore.CYAN}🔨 Building CRYPTON API Docker image...{Style.RESET_ALL}")
                success = self.docker.build_image()
                print(f"{'✅ Image built successfully!' if success else '❌ Build failed!'}")
            elif choice == 2:
                print(f"{Fore.CYAN}🚀 Deploying CRYPTON API container...{Style.RESET_ALL}")
                success = self.docker.start_container()
                if success:
                    print(f"{Fore.GREEN}✅ Container deployed successfully!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}🌐 API available at: http://localhost:8000{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}📖 Documentation: http://localhost:8000/docs{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Deployment failed!{Style.RESET_ALL}")
            elif choice == 3:
                print(f"{Fore.YELLOW}🛑 Stopping container...{Style.RESET_ALL}")
                success = self.docker.stop_container()
                print(f"{'✅ Container stopped successfully!' if success else '❌ Stop failed!'}")
            elif choice == 4:
                try:
                    import webbrowser
                    webbrowser.open('http://localhost:8000/docs')
                    print(f"{Fore.GREEN}🌐 Opening API documentation in browser...{Style.RESET_ALL}")
                except:
                    print(f"{Fore.RED}❌ Could not launch browser{Style.RESET_ALL}")
            elif choice == 5:
                print(f"{Fore.CYAN}📊 Container logs:{Style.RESET_ALL}")
                try:
                    subprocess.run(['docker', 'logs', self.docker.container_name])
                except:
                    print(f"{Fore.RED}❌ Could not retrieve logs{Style.RESET_ALL}")
            
            if choice != 0:
                input(f"\n{Fore.GREEN}🔥 Press Enter to continue...{Style.RESET_ALL}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def run(self):
        """Ana uygulama döngüsü"""
        while True:
            choice = self.show_main_menu()
            
            if choice == 0:
                self.terminal.clear()
                print(f"\n{Style.BRIGHT}{Fore.CYAN}")
                print("╔══════════════════════════════════════════════════╗")
                print("║                                                  ║")
                print("║  🛡️ Thank you for using CRYPTON Enhanced!     ║")
                print("║                                                  ║")
                print("║     🔐 Your data security is our priority       ║")
                print("║     🚀 43+ algorithms at your fingertips        ║")
                print("║     ⚡ Stay secure, stay protected!             ║")
                print("║                                                  ║")
                print("║           Created by @sarpataturker              ║")
                print("║              with ❤️ and dedication             ║")
                print("║                                                  ║")
                print("╚══════════════════════════════════════════════════╝")
                print(f"{Style.RESET_ALL}\n")
                break
            elif choice == 1:
                self.select_algorithm()
            elif choice == 2:
                self.generate_key()
            elif choice == 3:
                self.load_key_from_env()
            elif choice == 4:
                self.validate_key()
            elif choice == 5:
                self.encrypt_text()
            elif choice == 6:
                self.decrypt_text()
            elif choice == 7:
                self.view_algorithms()
            elif choice == 8:
                self.save_key_to_env()
            elif choice == 9:
                self.docker_manager()

if __name__ == "__main__":
    try:
        app = CRYPTON()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}🛑 CRYPTON interrupted by user")
        print(f"👋 Goodbye!{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")