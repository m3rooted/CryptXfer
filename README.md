# CryptXfer

## Secure File Transfer Tool

**CryptXfer**, a secure file transfer tool designed by Nguyen Duong Quang. This tool ensures your files are transferred safely and confidentially over the network using strong encryption methods.

### Features

- **AES-256-CBC Encryption**: Ensures that your files are encrypted with one of the strongest encryption standards.
- **PBKDF2-HMAC-SHA256 Key Derivation**: Uses a robust key derivation function with random salt (16 bytes) and 100,000 iterations to protect your password.
- **HMAC-SHA256 Integrity Verification**: Protects against tampering, bit-flipping attacks, and padding oracle attacks.
- **Random Salt & IV**: Each file transfer uses unique random salt and initialization vector for maximum security.
- **File Size Protection**: Built-in limits (1GB max) to prevent denial-of-service attacks.
- **User-Friendly Interface**: Simple and intuitive GUI built with Tkinter, with non-blocking operations.
- **Input Validation**: Enforces minimum password length (8 characters) and valid port ranges (1-65535).

### Why CryptXfer?

Unlike other online file sharing tools that might expose your files to security vulnerabilities or data breaches, **CryptXfer** ensures end-to-end encryption. Your files are encrypted locally on your machine before being sent over the network, ensuring that only the intended recipient can decrypt and access them. It also works on all platforms, weather its an windows machine, linux, mac, or an android phone.

### Requirements

To run CryptXfer, you need to have the following installed:

- Python 3.x
- Required Python libraries:
  - `tkinter`
  - `socket`
  - `cryptography`

### Installation

1. **Clone the Repository**:

    ```sh
    git clone https://github.com/m3rooted/CryptXfer.git
    cd CryptXfer
    ```

2. **Install the Required Libraries**:

    ```sh
    pip install cryptography
    ```

    Note: `socket`, `tkinter`, `threading`, and `logging` are built-in Python modules and don't need to be installed separately.

### Usage

1. **Run the Tool**:

    ```sh
    python CryptXfer.py
    ```

2. **Sending a File**:
    - Open **CryptXfer** and select "Send".
    - Enter the recipient's host address and port.
    - Choose the file you want to send.
    - Enter a secure password.
    - Click "Execute" to send the file.

3. **Receiving a File**:
    - Open **CryptXfer** and select "Receive".
    - Enter the port to listen on.
    - Enter the password that the sender will use.
    - Click "Execute" to start listening for incoming files.

### Example Usage

#### Sending a File

1. Start the **CryptXfer** tool.
2. Select "Send".
3. Enter the recipient's host (e.g., `192.168.1.4`).
4. Enter the port (e.g., `12345`).
5. Choose the file you want to send.
6. Enter a secure password (e.g., `mypassword`).
7. Click "Execute".

#### Receiving a File

1. Start the **CryptXfer** tool.
2. Select "Receive".
3. Enter the port (e.g., `12345`).
4. Enter the same password used by the sender (e.g., `mypassword`).
5. Click "Execute".

### Security

**CryptXfer** employs multiple layers of security mechanisms:

- **AES-256-CBC Encryption**: Industry-standard strong encryption to protect your files.
- **PBKDF2-HMAC-SHA256 Key Derivation**: 100,000 iterations with random 16-byte salt to secure password against brute-force and rainbow table attacks.
- **Random Salt Per File**: Each file transfer generates a unique random salt, preventing rainbow table attacks.
- **Random IV (Initialization Vector)**: Random 16-byte IV for each encryption session to ensure uniqueness.
- **HMAC-SHA256 Authentication**: Verifies data integrity and authenticity, protecting against:
  - Tampering and modification attacks
  - Bit-flipping attacks
  - Padding oracle attacks
- **File Size Limits**: Maximum 1GB file size to prevent denial-of-service attacks.
- **Input Validation**: Enforces password complexity and valid network parameters.

### Threat Model

**What CryptXfer Protects Against:**

- ✅ Network eavesdropping (passive monitoring)
- ✅ Password brute-force attacks (PBKDF2 with 100k iterations)
- ✅ Rainbow table attacks (random salt per transfer)
- ✅ Data tampering and modification (HMAC verification)
- ✅ Bit-flipping attacks (HMAC integrity check)
- ✅ Padding oracle attacks (HMAC-then-decrypt pattern)
- ✅ Replay attacks across sessions (random salt + IV)
- ✅ Basic DoS via large files (1GB limit)

**What CryptXfer Does NOT Protect Against:**

- ❌ Weak passwords (use strong passwords ≥ 8 chars)
- ❌ Compromised endpoints (malware on sender/receiver)
- ❌ Man-in-the-middle without additional authentication
- ❌ Traffic analysis (connection metadata visible)
- ❌ Advanced persistent threats or state-level adversaries

**Recommendations:**

- Use strong, unique passwords (minimum 8 characters, recommended 16+)
- Transfer files over trusted networks when possible
- Verify file integrity through a separate channel if needed
- Keep your system and Python dependencies updated

### Disclaimer

While **CryptXfer** provides strong encryption, it is essential to use a strong, unique password and ensure that the password is shared securely between sender and receiver. The security of the file transfer relies on the secrecy and complexity of the password used.

### Contact

For any issues, suggestions, or contributions, feel free to reach out or create an issue in the GitHub repository.

---

Thank you for using **CryptXfer**. Secure your file transfers with confidence!
