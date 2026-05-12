import base64
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "hospital.db")
KEY_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("HOSPITAL_SECRET_KEY", "dev-secret-change-me")
app.config["DATABASE"] = DB_PATH


SERVICE_BASE_PRICES = {
    "Appointment Booking": 500,
    "Lab Test Payment": 3500,
    "Surgery Payment": 25000,
    "Pharmacy Bill": 1200,
    "Admission Advance": 8000,
}

HOSPITAL_FEATURES = [
    {
        "title": "24/7 Emergency Care",
        "text": "Rapid emergency response, trauma support, and critical care assistance at any hour.",
        "icon": "🚑",
    },
    {
        "title": "Expert Specialists",
        "text": "Consult leading doctors across cardiology, orthopedics, pediatrics, and general medicine.",
        "icon": "🩺",
    },
    {
        "title": "Digital Billing",
        "text": "Pay securely for consultations, lab tests, pharmacy, and surgery using protected transactions.",
        "icon": "💳",
    },
    {
        "title": "Advanced Diagnostics",
        "text": "Access lab test requests, scan appointments, and structured medical service payments from one portal.",
        "icon": "🧪",
    },
]

PRIVATE_KEY = None
PUBLIC_KEY = None


def ensure_key_dir() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)


def load_crypto_keys():
    private = None
    public = None
    try:
        with open(PRIVATE_KEY_PATH, "rb") as private_file:
            private = serialization.load_pem_private_key(private_file.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as public_file:
            public = serialization.load_pem_public_key(public_file.read())
    except FileNotFoundError:
        pass
    return private, public


ensure_key_dir()
PRIVATE_KEY, PUBLIC_KEY = load_crypto_keys()


# -------------------------
# Database helpers
# -------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def bootstrap_app():
    init_db()


def ensure_column(db, table: str, column_name: str, column_def: str) -> None:
    existing = db.execute(f"PRAGMA table_info({table})").fetchall()
    if column_name not in {row['name'] for row in existing}:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_def}")
        db.commit()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            otp_hash TEXT,
            otp_expiry TEXT,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            age INTEGER,
            city TEXT,
            created_at TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_type TEXT NOT NULL,
            amount REAL NOT NULL,
            security_mode TEXT NOT NULL,
            security_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    ensure_column(db, "users", "full_name", "TEXT")
    ensure_column(db, "users", "email", "TEXT")
    ensure_column(db, "users", "phone", "TEXT")
    ensure_column(db, "users", "age", "INTEGER")
    ensure_column(db, "users", "city", "TEXT")
    ensure_column(db, "users", "created_at", "TEXT")

    count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if count == 0:
        db.execute(
            """
            INSERT INTO users (username, password_hash, balance, full_name, email, phone, age, city, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "demo",
                generate_password_hash("Test@123"),
                50000.0,
                "Demo Patient",
                "demo@hospital.com",
                "9876543210",
                24,
                "Visakhapatnam",
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()


# -------------------------
# Cryptography helpers
# -------------------------
def message_digest(data: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode("utf-8"))
    return digest.finalize().hex()


def sign_data(data: str) -> str:
    if PRIVATE_KEY is None:
        return "RSA private key not found. Run generate_keys.py first."

    signature = PRIVATE_KEY.sign(
        data.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(data: str, signature_b64: str) -> bool:
    if PUBLIC_KEY is None:
        return False
    try:
        PUBLIC_KEY.verify(
            base64.b64decode(signature_b64),
            data.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def aes_gcm_encrypt(plaintext: str) -> dict:
    if PUBLIC_KEY is None:
        return {"error": "RSA public key not found. Run generate_keys.py first."}

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)

    encrypted_key = PUBLIC_KEY.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def build_payment_payload(username: str, service_type: str, amount: float) -> str:
    payload = {
        "username": username,
        "service_type": service_type,
        "amount": round(amount, 2),
        "timestamp": datetime.utcnow().isoformat(),
    }
    return json.dumps(payload, sort_keys=True)


def build_security_bundle(username: str, service_type: str, amount: float):
    payload = build_payment_payload(username, service_type, amount)

    if amount <= 2000:
        return "SHA-256 Message Digest", json.dumps(
            {
                "payload": json.loads(payload),
                "digest": message_digest(payload),
            },
            indent=2,
        )

    if amount <= 5000:
        signature = sign_data(payload)
        return "RSA Digital Signature", json.dumps(
            {
                "payload": json.loads(payload),
                "signature": signature,
                "verified": verify_signature(payload, signature),
            },
            indent=2,
        )

    signature = sign_data(payload)
    encrypted_signature = aes_gcm_encrypt(signature)
    return "Digital Signature + AES-GCM Encryption", json.dumps(
        {
            "payload": json.loads(payload),
            "signature_encrypted": encrypted_signature,
        },
        indent=2,
    )


# -------------------------
# Auth / routes
# -------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id is None:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        db = get_db()
        user_exists = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_exists is None:
            session.clear()
            flash("Your session was reset. Please log in again.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def home():
    user = None
    if session.get("user_id"):
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if user is None:
            session.clear()
    return render_template("home.html", services=SERVICE_BASE_PRICES, features=HOSPITAL_FEATURES, user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        city = request.form.get("city", "").strip()
        age_raw = request.form.get("age", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        opening_balance_raw = request.form.get("opening_balance", "1000").strip()

        if len(username) < 3 or not username.replace("_", "").isalnum():
            flash("Username must be at least 3 characters and contain letters, numbers, or underscore.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Password and confirm password do not match.", "danger")
            return render_template("register.html")

        try:
            opening_balance = float(opening_balance_raw)
        except ValueError:
            flash("Opening balance must be a valid number.", "danger")
            return render_template("register.html")

        age = None
        if age_raw:
            try:
                age = int(age_raw)
            except ValueError:
                flash("Age must be a valid number.", "danger")
                return render_template("register.html")

        if opening_balance < 0:
            flash("Opening balance cannot be negative.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already exists.", "danger")
            return render_template("register.html")

        db.execute(
            """
            INSERT INTO users (username, password_hash, balance, full_name, email, phone, age, city, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                opening_balance,
                full_name or username.title(),
                email,
                phone,
                age,
                city,
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hash = message_digest(f"{username}:{otp}")
        otp_expiry = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

        db.execute(
            "UPDATE users SET otp_hash = ?, otp_expiry = ? WHERE id = ?",
            (otp_hash, otp_expiry, user["id"]),
        )
        db.commit()

        session.clear()
        session["pending_user_id"] = user["id"]
        session["otp_demo_code"] = otp

        flash("OTP generated successfully. Demo OTP is shown below for this academic project.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def verify_otp():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        provided_otp = request.form.get("otp", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        otp_expiry = user["otp_expiry"]
        if not otp_expiry or datetime.utcnow() > datetime.fromisoformat(otp_expiry):
            flash("OTP expired. Please log in again.", "danger")
            session.clear()
            return redirect(url_for("login"))

        expected_hash = user["otp_hash"]
        provided_hash = message_digest(f"{user['username']}:{provided_otp}")

        if expected_hash != provided_hash:
            flash("Invalid OTP. Please try again.", "danger")
            return render_template("verify_otp.html", demo_otp=session.get("otp_demo_code"))

        db.execute("UPDATE users SET otp_hash = NULL, otp_expiry = NULL WHERE id = ?", (user["id"],))
        db.commit()

        session["user_id"] = user["id"]
        session.pop("pending_user_id", None)
        session.pop("otp_demo_code", None)
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", demo_otp=session.get("otp_demo_code"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))
    recent_payments = db.execute(
        """
        SELECT id, service_type, amount, security_mode, created_at
        FROM payments
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "dashboard.html",
        user=user,
        services=SERVICE_BASE_PRICES,
        recent_payments=recent_payments,
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        city = request.form.get("city", "").strip()
        age_raw = request.form.get("age", "").strip()

        age = None
        if age_raw:
            try:
                age = int(age_raw)
            except ValueError:
                flash("Age must be a valid number.", "danger")
                return redirect(url_for("profile"))

        if not full_name:
            flash("Full name is required.", "danger")
            return redirect(url_for("profile"))

        db.execute(
            """
            UPDATE users
            SET full_name = ?, email = ?, phone = ?, city = ?, age = ?
            WHERE id = ?
            """,
            (full_name, email, phone, city, age, session["user_id"]),
        )
        db.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))
    payment_stats = db.execute(
        """
        SELECT COUNT(*) AS total_payments, COALESCE(SUM(amount), 0) AS total_spent
        FROM payments
        WHERE user_id = ?
        """,
        (session["user_id"],),
    ).fetchone()
    return render_template("profile.html", user=user, payment_stats=payment_stats)


@app.route("/add-money", methods=["POST"])
@login_required
def add_money():
    amount_text = request.form.get("amount", "").strip()
    try:
        amount = float(amount_text)
    except ValueError:
        flash("Enter a valid amount to add to balance.", "danger")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("Amount must be greater than zero.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, session["user_id"]))
    db.commit()
    flash(f"₹{amount:,.2f} added successfully to your balance.", "success")
    return redirect(url_for("dashboard"))


@app.route("/pay", methods=["POST"])
@login_required
def make_payment():
    service_type = request.form.get("service_type", "").strip()
    amount_text = request.form.get("amount", "").strip()

    if service_type not in SERVICE_BASE_PRICES:
        flash("Please choose a valid hospital service.", "danger")
        return redirect(url_for("dashboard"))

    try:
        amount = float(amount_text)
    except ValueError:
        flash("Please enter a valid amount.", "danger")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("Amount must be greater than zero.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))

    if user["balance"] < amount:
        flash("Insufficient balance.", "danger")
        return redirect(url_for("dashboard"))

    security_mode, security_data = build_security_bundle(user["username"], service_type, amount)

    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user["id"]))
    db.execute(
        """
        INSERT INTO payments (user_id, service_type, amount, security_mode, security_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user["id"], service_type, amount, security_mode, security_data, datetime.utcnow().isoformat()),
    )
    db.commit()

    flash(f"Payment of ₹{amount:,.2f} for {service_type} completed successfully.", "success")
    flash(f"Applied security mode: {security_mode}", "info")
    return redirect(url_for("history"))


@app.route("/history")
@login_required
def history():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))

    payments = db.execute(
        """
        SELECT * FROM payments
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    return render_template("history.html", payments=payments)


@app.route("/payment/<int:payment_id>")
@login_required
def payment_detail(payment_id: int):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))

    payment = db.execute(
        "SELECT * FROM payments WHERE id = ? AND user_id = ?",
        (payment_id, session["user_id"]),
    ).fetchone()
    if payment is None:
        flash("Payment record not found.", "warning")
        return redirect(url_for("history"))
    return render_template("payment_detail.html", payment=payment)


@app.route("/balance")
@login_required
def check_balance():
    db = get_db()
    user = db.execute("SELECT balance FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        flash("User profile not found. Please log in again.", "warning")
        return redirect(url_for("login"))
    flash(f"Current wallet balance: ₹{user['balance']:,.2f}", "info")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
