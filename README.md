#####Quantum-Secure Email Client Application#####

A Flask-based secure email system that uses Post-Quantum Cryptography (PQC) for key exchange and digital signatures, combined with AES-256-GCM for message encryption.

🚀 Overview

This project implements an end-to-end encrypted email-like communication platform that is resistant to quantum computer attacks.
It uses:

Post-Quantum KEM (Key Encapsulation) → for shared key agreement

Post-Quantum Signatures → for authentication

AES-256-GCM → for message confidentiality & integrity

Flask + SQLite → backend & database

Flask-Login → user authentication session management

Users can:
✔ Register & generate PQC keys
✔ Login securely
✔ Compose & send encrypted emails
✔ Verify sender signatures
✔ View inbox & sent messages
✔ Download their public keys

🔐 Security Architecture
1️⃣ Key Generation

For every new user:

PQC KEM key pair (public/private)

PQC Signature key pair (public/private)

These are stored Base64-encoded in the database.

2️⃣ Sending a Message

When a user sends a message:

Sender fetches the recipient’s KEM public key

Generates:

KEM ciphertext (encapsulation)

Shared secret

Shared secret → HKDF → AES-256-GCM key

Message plaintext → encrypted with AES-GCM

Sender signs:

KEM_ciphertext + nonce + ciphertext + tag


Message gets saved into database

3️⃣ Receiving a Message

Recipient decrypts using:

Their KEM private key

AES-256-GCM key derived via HKDF

Verifies the PQ signature

Messages that fail decryption are hidden automatically.

🛠️ Tech Stack

Python 3.11

Flask

SQLite

SQLAlchemy

Flask-Login

Post-Quantum Crypto Library (python-oqs or custom qcrypto)

AES-256-GCM

📂 Project Structure
app.py
templates/
    index.html
    login.html
    register.html
    home.html
    inbox.html
    sent.html
    compose.html
    message.html
    keys.html
static/
database.sqlite3 (auto-created)

▶️ How to Run the Application
1. Install Dependencies
pip install -r requirements.txt

2. Set up environment variables
FLASK_SECRET_KEY=your_secret_key

3. Run the Flask App
python app.py


The server runs on:

http://127.0.0.1:5000/

🧪 Features
Feature	Description
✔ PQC-Based Key Exchange	KEM (encaps/decaps) for secure key sharing
✔ PQC Signatures	Digital signatures for message authenticity
✔ AES-256-GCM Encryption	Confidentiality + integrity
✔ Secure Login	Password hashing + session management
✔ Inbox + Sent View	Fully encrypted email-like system
✔ Message Verification	Signature verification for every message
✔ Key Download	User can export public keys
