import os
import io
import json
import base64
from datetime import datetime

from dotenv import load_dotenv
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, send_file
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

from qcrypto.sym import aes_gcm_encrypt, aes_gcm_decrypt, hkdf_sha256
from qcrypto.pq import PQC

# -------- Flask setup --------
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "database.sqlite3")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------- Models --------
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    kem_public = db.Column(db.Text, nullable=False)
    kem_private = db.Column(db.Text, nullable=False)
    sig_public = db.Column(db.Text, nullable=False)
    sig_private = db.Column(db.Text, nullable=False)

    inbox = db.relationship('Message', back_populates='recipient', foreign_keys='Message.recipient_id')
    sent = db.relationship('Message', back_populates='sender', foreign_keys='Message.sender_id')


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)

    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    subject = db.Column(db.String(255), nullable=False)

    kem_ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


with app.app_context():
    db.create_all()

# -------- Login manager --------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------- Routes --------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'warning')
            return redirect(url_for('register'))

        kem_pub_b64, kem_priv_b64 = PQC.kem_generate()
        sig_pub_b64, sig_priv_b64 = PQC.sig_generate()

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            kem_public=kem_pub_b64,
            kem_private=kem_priv_b64,
            sig_public=sig_pub_b64,
            sig_private=sig_priv_b64
        )
        db.session.add(user)

        try:
            db.session.commit()
            flash('Account created. Please sign in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already registered.', 'warning')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/inbox')
@login_required
def inbox():
    all_msgs = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.created_at.desc()).all()
    visible_msgs = []

    for msg in all_msgs:
        try:
            # Attempt decryption to check validity
            shared_secret_b64 = PQC.kem_decapsulate(current_user.kem_private, msg.kem_ciphertext)
            shared_secret = base64.b64decode(shared_secret_b64)
            aes_key = hkdf_sha256(shared_secret, 32, info=b'PQ-Email-AES-GCM')
            _ = aes_gcm_decrypt(aes_key, msg.nonce, msg.ciphertext, msg.tag)
            visible_msgs.append(msg)
        except Exception:
            # Skip messages that cannot be decrypted
            continue

    return render_template('inbox.html', messages=visible_msgs)



@app.route('/sent')
@login_required
def sent():
    msgs = Message.query.filter_by(sender_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('sent.html', messages=msgs)


@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    if request.method == 'POST':
        recipient_id = request.form.get('recipient')
        subject = (request.form.get('subject') or '').strip()
        plaintext = request.form.get('message', '')

        if not recipient_id or not plaintext:
            flash("Recipient and message are required.", "danger")
            return redirect(url_for('compose'))

        recipient = User.query.get(int(recipient_id))
        if not recipient:
            flash("Recipient not found.", "danger")
            return redirect(url_for('compose'))

        if not subject:
            subject = "(no subject)"

        kem_ct_b64, shared_b64 = PQC.kem_encapsulate(recipient.kem_public)
        shared_secret = base64.b64decode(shared_b64)
        aes_key = hkdf_sha256(shared_secret, 32, info=b'PQ-Email-AES-GCM')

        enc = aes_gcm_encrypt(aes_key, plaintext.encode('utf-8'))

        signed_blob = (
            base64.b64decode(kem_ct_b64)
            + base64.b64decode(enc["nonce"])
            + base64.b64decode(enc["ciphertext"])
            + base64.b64decode(enc["tag"])
        )
        signature_b64 = PQC.sig_sign(current_user.sig_private, signed_blob)

        msg = Message(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            subject=subject,
            kem_ciphertext=kem_ct_b64,
            nonce=enc["nonce"],
            ciphertext=enc["ciphertext"],
            tag=enc["tag"],
            signature=signature_b64,
        )
        db.session.add(msg)
        db.session.commit()

        flash("Message sent successfully!", "success")
        return redirect(url_for('inbox'))

    users = User.query.filter(User.id != current_user.id).all()
    return render_template('compose.html', users=users)


@app.route('/message/<int:msg_id>')
@login_required
def message_view(msg_id):
    msg = Message.query.get(msg_id)
    if not msg or (msg.recipient_id != current_user.id and msg.sender_id != current_user.id):
        flash('Message not found.', 'warning')
        return redirect(url_for('inbox'))

    signed_blob = (
        base64.b64decode(msg.kem_ciphertext)
        + base64.b64decode(msg.nonce)
        + base64.b64decode(msg.ciphertext)
        + base64.b64decode(msg.tag)
    )
    ok = PQC.sig_verify(msg.sender.sig_public, signed_blob, msg.signature)
    
    decrypted = None
    error = None
    if msg.recipient_id == current_user.id:
        try:
            shared_secret_b64 = PQC.kem_decapsulate(current_user.kem_private, msg.kem_ciphertext)
            shared_secret = base64.b64decode(shared_secret_b64)
            aes_key = hkdf_sha256(shared_secret, 32, info=b'PQ-Email-AES-GCM')
            decrypted = aes_gcm_decrypt(aes_key, msg.nonce, msg.ciphertext, msg.tag).decode('utf-8')
        except Exception:
            decrypted = "[Cannot decrypt: message may be old or corrupted]"
            error = "Decryption failed"


    return render_template('message.html', m=msg, verified=ok, decrypted=decrypted, error=error)


@app.route('/keys')
@login_required
def keys():
    data = {
        'email': current_user.email,
        'name': current_user.name,
        'kem_public_base64': current_user.kem_public,
        'sig_public_base64': current_user.sig_public,
        'algorithms': {
            'kem': PQC.KEM_ALG,
            'signature': PQC.SIG_ALG,
            'symmetric': 'AES-256-GCM'
        }
    }
    return render_template('keys.html', data=json.dumps(data, indent=2))


@app.route('/keys/download')
@login_required
def keys_download():
    payload = {
        'email': current_user.email,
        'name': current_user.name,
        'kem_public_base64': current_user.kem_public,
        'sig_public_base64': current_user.sig_public,
        'algorithms': {
            'kem': PQC.KEM_ALG,
            'signature': PQC.SIG_ALG,
            'symmetric': 'AES-256-GCM'
        }
    }
    bio = io.BytesIO(json.dumps(payload, indent=2).encode())
    bio.seek(0)
    return send_file(bio, mimetype='application/json', as_attachment=True, download_name='pq_public_keys.json')


@app.route('/delete/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.sender_id != current_user.id:
        flash("You can only delete your own sent messages.", "danger")
        return redirect(url_for('sent'))

    db.session.delete(msg)
    db.session.commit()
    flash("Message deleted successfully.", "success")
    return redirect(url_for('sent'))


if __name__ == '__main__':
    app.run(debug=True)
