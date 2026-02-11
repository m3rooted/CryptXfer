# CryptXfer by Nguyen Duong Quang
# Secure File Transfer Tool
# www.m3rooted.com

"""
CryptXfer - Secure File Transfer Tool

A modern secure file transfer application with AES-256-CBC encryption,
HMAC-SHA256 integrity verification, and a beautiful GUI.

Features:
- AES-256-CBC encryption with random salt and IV
- HMAC-SHA256 for data integrity
- PBKDF2 key derivation (100,000 iterations)
- File size limits (1GB max)
- Modern, responsive GUI
- Input validation
"""

from gui import main

if __name__ == "__main__":
    main()

