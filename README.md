📧 CSE_229 – Quantum-Secure Email Client Application

A secure email communication system that uses Post-Quantum Cryptography (PQC) and AES-256-GCM to protect messages against classical and quantum computer attacks. This system ensures end-to-end confidentiality, integrity, authentication, and future-proof security.

🎯 Objectives

Implement Post-Quantum key exchange using KEM

Implement Post-Quantum digital signatures for message authenticity

Provide encrypted email communication between users

Secure users’ data with AES-256-GCM symmetric encryption

Allow users to send, receive, view, decrypt, and verify messages

Display and export user public PQC keys

🛠️ Technologies Used
Category	Tools / Technologies
Programming Language	Python (Flask Framework)
Cryptography	PQC (KEM + Signatures), AES-256-GCM
Libraries	Flask, SQLAlchemy, Flask-Login, python-oqs / qcrypto
Database	SQLite
Templates	HTML, CSS (Jinja2)
IDE	VS Code / PyCharm
🔐 Security Algorithms Used

PQC KEM: Used for shared-secret generation

PQC Digital Signature: Used for message authenticity

Symmetric Encryption: AES-256-GCM

Key Derivation: HKDF-SHA256

Your system ensures security even against future quantum computers.

⚙️ How to Run the Project
1. Clone the repository
git clone https://github.com/<your-username>/CSE_229---Quantum-secure-email-client-application.git

2. Navigate to the project folder
cd CSE_229---Quantum-secure-email-client-application

3. Install required dependencies
pip install -r requirements.txt

4. Run the Flask application
python app.py

5. Open in browser
http://127.0.0.1:5000/

🌟 Features

🔐 User Registration & Login (with hashed passwords)

🔑 Automatic PQC Key Pair Generation

✉️ Encrypted Email Sending

📨 Inbox & Sent Items View

🔏 Digital Signature Verification

🔓 AES-GCM Decryption for authorized users

📄 Public Key Export (JSON)

🗑️ Delete Sent Messages

🧭 Simple UI for sending and receiving secure messages

🌟 Future Enhancements

Real-time message notification system

Multi-user group encrypted messaging

Admin panel for monitoring usage

Mobile-friendly UI

Zero-knowledge cloud backup for PQ keys

👩‍💻 Author

Name: Poola Dhathri ,Nikhitha S, Anke Mounika 
Department: CSE 
Batch: CSE_229
Project: Quantum-Secure Email Client Application
GitHub: https://github.com/Dhathri-Poola-22
