
"""
Know-Thyself — consolidated app.py
Features:
 - Local MongoDB (db name 'portal')
 - Student registration/login (Flask-Login)
 - Teacher fixed credentials inside file (can move to .env)
 - Jobs, applications, uploads (resume + photo)
 - Teacher assessment, per-application clear/delete
 - Brevo (SendinBlue) transactional email sending (with attachments)
 - CSV export for registered students and assessed students
 - /debug/db to quickly verify data
 - Server runs on port 10000 for local testing
"""

import os
import io
import csv
import zipfile
from flask import send_file
import base64
import io
import json
from csrf_debug import log_csrf_state
import logging
from functools import wraps
from datetime import datetime, timedelta, timezone as tz
from pathlib import Path
from flask_session import Session
import mailtrigger
# ===============================
# DECORATORS (MUST BE DEFINED FIRST)
# ===============================

from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def student_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "student":
            flash("Unauthorized — student only area.", "danger")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper
from forms import SelfAssessmentForm
from flask_wtf.csrf import generate_csrf
from flask_wtf import CSRFProtect
from flask import Flask
import os
from growth_data import get_questions_for_theme
from self_assessment_questions import generate_assessment_questions
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"
from bson import ObjectId

def mongo_objid_from_str(id_str):
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        return None
    
from flask import current_app
from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort,
    send_file, send_from_directory, jsonify, session
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from flask_wtf.csrf import CSRFProtect
from datetime import timezone

def ensure_utc(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
# --- SECURITY / PRODUCTION HELPERS ---
import threading
from werkzeug.exceptions import BadRequest
from bson.errors import InvalidId
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from bson.objectid import ObjectId
from dotenv import load_dotenv
import requests
import pandas as pd
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
# forms.py or inside app.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
# ---- Put this once near top of app.py ----
import threading
import requests
import base64
from datetime import datetime
from flask import Flask
import os

from flask_session import Session
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)
# 🔑 REQUIRED for CSRF
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

# ✅ Initialize CSRF AFTER app is created
BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"
BREVO_API_KEY = os.getenv("BREVO_API_KEY")  # ensure set in Render env
FROM_NAME = os.getenv("FROM_NAME", "Know-Thyself")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@example.com")

def _call_brevo(payload, headers):
    """Internal synchronous call to Brevo with logging."""
    try:
        resp = requests.post(BREVO_SEND_URL, headers=headers, json=payload, timeout=15)
        print(f"✅ [Brevo] {resp.status_code} | {resp.text[:300]}")
        logger.info("Brevo response: %s %s", resp.status_code, resp.text[:300])
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"❌ [Brevo] send failed: {e}")
        logger.exception("Brevo send failed: %s", e)
        return False

def send_brevo_email(
    to_email,
    to_name,
    subject,
    html_content,
    attachments=None,
    async_send=False,
):
    import threading
    import requests

    if not BREVO_API_KEY:
        logger.warning("Missing BREVO_API_KEY; attempted send to %s", to_email)
        return False

    payload = {
        "sender": {"name": FROM_NAME, "email": FROM_EMAIL},
        "to": [{"email": to_email, "name": to_name or ""}],
        "subject": subject,
        "htmlContent": html_content,
    }

    if attachments:
        payload["attachment"] = attachments

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }

    # ---------------- INTERNAL SEND ----------------
    def _send():
        try:
            resp = requests.post(
                BREVO_SEND_URL,
                headers=headers,
                json=payload,
                timeout=(4, 8)  # short + safe for async
            )

            if resp.status_code in (200, 201, 202):
                logger.info(
                    "Brevo email success | %s | %s",
                    resp.status_code,
                    resp.text[:200]
                )
                return True

            logger.warning(
                "Brevo non-200 response | %s | %s",
                resp.status_code,
                resp.text[:200]
            )
            return False

        except requests.exceptions.ReadTimeout:
            logger.warning("Brevo read timeout (async send, ignored)")
            return False

        except Exception as e:
            logger.info("Brevo async send timed out (safe to ignore)")
            return False

    # ---------------- DISPATCH ----------------
    if async_send:
        threading.Thread(target=_send, daemon=True).start()
        print("🟡 Sent mail asynchronously (background thread)")
        return True
    else:
        return _send()

def make_attachment_from_file_path(filepath):
    if not filepath or not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as fh:
        b = fh.read()
    return {"name": os.path.basename(filepath), "content": base64.b64encode(b).decode("utf-8")}
class LoginForm(FlaskForm):
    email_or_sid = StringField("Email or SID", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
class SimpleForm(FlaskForm):
    email_or_sid = StringField("Email or Student ID", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")



# --------------------- place near top of app.py (after imports) ---------------------
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))

def local_dt_now():
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)

def utc_to_ist(dt):
    """Convert a UTC-aware datetime -> IST-aware datetime."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(IST)

def ist_to_utc(dt):
    """Convert local IST (naive or aware) to UTC-aware datetime."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # assume dt is in IST if naive
        dt = dt.replace(tzinfo=IST)
    return dt.astimezone(UTC)

def make_attachment_from_file_path(filepath):
    """Return Brevo attachment dict from file path {name, content(base64)}"""
    import base64, os
    if not filepath or not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as fh:
        b = fh.read()
    content_b64 = base64.b64encode(b).decode("utf-8")
    return {"name": os.path.basename(filepath), "content": content_b64}
# -----------------------------------------------------------------------------------
# -------------------------
# Load .env (if exists)
# -------------------------
load_dotenv()

# -------------------------
# Basic config
# -------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_RESUME = {"pdf", "doc", "docx"}
ALLOWED_PHOTO = {"png", "jpg", "jpeg"}

# -------------------------
# App setup
# -------------------------

from datetime import datetime
app.jinja_env.globals['datetime'] = datetime
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
# limit uploads to e.g., 5 MB per file
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("know-thyself")

# -------------------------
# MongoDB connection
# -------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Digitaldoncodes:digitaldoncodesx@know-thyself.1m8vekk.mongodb.net")
client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000,  # wait up to 10s for primary
    connectTimeoutMS=10000,
    socketTimeoutMS=20000,
    retryWrites=True,
    retryReads=True,
)
db = client["portal"]  # your local DB (portal)
users_col = db["users"]
jobs_col = db["jobs"]
applications_col = db["applications"]
growth_col = db["growth_responses"]
self_assess_col = db["self_assessments"]
otp_col = db["otp_store"]

# Add these imports at top:
from gridfs import GridFS
from pymongo.errors import PyMongoError

# After db = client["portal"]
try:
    fs = GridFS(db)
    logger.info("GridFS initialized.")
except Exception as e:
    logger.exception("GridFS init failed: %s", e)
    fs = None
# -------------------------
# Brevo config (SendinBlue)
# -------------------------
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@example.com")
FROM_NAME = os.getenv("FROM_NAME", "Know-Thyself")

BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"  # transactional send endpoint

# require SECRET_KEY in production
if os.getenv("FLASK_ENV") == "production":
    if not os.getenv("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY must be set in production")
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
else:
    # keep development fallback but warn
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

# Secure cookie settings (override in prod via env if desired)
app.config.update(
    SESSION_COOKIE_SECURE=(os.getenv("FLASK_ENV") == "production"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
    REMEMBER_COOKIE_HTTPONLY=True
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# -------------------------
# Login manager
# -------------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------------
# Teachers (fixed local credentials)
# -------------------------
TEACHERS = [
    {
        "email": "gnanaprakash@kclas.ac.in",
        "password": "gpsir098",
        "name": "Prof. Gnanaprakash",
        "role": "teacher"
    },
    {
        "email": "dhatchinamoorthiai@gmail.com",
        "password": "DigitalDonDa@2005",
        "name": "Deeksha",
        "role": "teacher"
    }
]

# Wrap teacher credentials with hashed password for safer local checks
for t in TEACHERS:
    if not t.get("password_hash"):
        t["password_hash"] = generate_password_hash(t["password"])
        # Keep plaintext only if you need (not recommended). We'll use password_hash.

# -------------------------
# Helpers & utilities
# -------------------------
def allowed_file(filename, allowed_set):
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_set

def local_dt_now():
    """Return timezone-aware UTC now"""
    return datetime.now(tz=tz.utc)

def ist_to_utc(dt_ist):
    """Convert naive IST datetime (assumed) to UTC aware"""
    # dt_ist is naive local (IST) like datetime.strptime(...). Add IST offset -5.5 hours
    return (dt_ist - timedelta(hours=5, minutes=30)).replace(tzinfo=tz.utc)

def utc_to_ist_str(dt_utc):
    if dt_utc is None:
        return None
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=tz.utc)
    dt_ist = dt_utc.astimezone(tz=tz(timedelta(hours=5, minutes=30)))
    return dt_ist.strftime("%d %b %Y, %I:%M %p")

def objectid_to_str(doc):
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])
    return doc

def mongo_objid_from_str(s):
    try:
        return ObjectId(s)
    except Exception:
        return None

# -------------------------
# Brevo (Send email) wrapper
# -------------------------

def send_status_email_for_application(application, new_status, feedback=""):
    # application is the DB doc from applications_col
    # find student
    student = None
    if application.get("applicant_id"):
        try:
            student = users_col.find_one({"_id": application.get("applicant_id")})
        except Exception:
            pass
    if not student and application.get("student_id"):
        student = users_col.find_one({"student_id": application.get("student_id")})

    job = None
    if application.get("job_id"):
        try:
            job = jobs_col.find_one({"_id": application.get("job_id")})
        except Exception:
            pass

    if not student or not student.get("email"):
        logger.warning("No student email found for application %s", application.get("_id"))
        return False

    html = render_template(
        "email/student_status_update.html",
        student_name=student.get("name", "Student"),
        job_title=(job.get("title") if job else application.get("job_title", "Application")),
        status=new_status,
        feedback=feedback,
        now=datetime.now
    )

    # If corrections_needed, include a quick call-to-action in subject
    subject = f"Update on your application: {job.get('title') if job else ''} — {new_status.replace('_',' ').capitalize()}"

    # send in background to avoid blocking
    return send_brevo_email(student.get("email"), student.get("name"), subject, html, sync=False)

import os, base64, requests, logging
from dotenv import load_dotenv

# --- Email Config ---
load_dotenv()
BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
FROM_NAME = "Know-Thyself"
FROM_EMAIL = "psychologyresumemail@gmail.com"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- Helper: Convert file to Brevo attachment format ---
def make_attachment_from_file_path(filepath):
    """
    Return Brevo attachment dict {name, content(base64)} from a local file path.
    """
    if not filepath or not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        file_bytes = f.read()
        encoded = base64.b64encode(file_bytes).decode("utf-8")
        return {"name": os.path.basename(filepath), "content": encoded}


# --- Helper: Send Brevo Email ---
# -------------------------
# Users for Flask-Login
# -------------------------
class User(UserMixin):
    def __init__(self, data):
        # data can be dict from Mongo or teacher dict
        self._raw = data
        self.id = str(data.get("_id", data.get("email")))
        self.email = data.get("email")
        self.name = data.get("name")
        self.role = data.get("role", "student")

@login_manager.user_loader
def load_user(user_id):
    # first check teachers by email
    for t in TEACHERS:
        if user_id == t["email"]:
            return User(t)
    # then check users collection by _id (ObjectId) or email fallback
    try:
        # try as ObjectId
        u = users_col.find_one({"_id": ObjectId(user_id)})
        if u:
            return User(u)
    except Exception:
        # maybe it's an email stored as id
        u = users_col.find_one({"email": user_id})
        if u:
            return User(u)
    return None

def teacher_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "teacher":
            flash("Unauthorized — teacher only area.", "danger")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

@app.route("/debug/application/<app_id>")
def debug_application(app_id):
    """Inspect a specific application document (for debugging only)."""
    try:
        app_doc = applications_col.find_one({"_id": ObjectId(app_id)})
        if not app_doc:
            return jsonify({"ok": False, "error": "Application not found"}), 404

        # Convert ObjectId fields for JSON safety
        app_doc["_id"] = str(app_doc["_id"])
        if app_doc.get("applicant_id"):
            app_doc["applicant_id"] = str(app_doc["applicant_id"])
        if app_doc.get("job_id"):
            app_doc["job_id"] = str(app_doc["job_id"])

        # Attach student info
        student = users_col.find_one({"_id": mongo_objid_from_str(app_doc.get("applicant_id"))})
        if student:
            app_doc["student_name"] = student.get("name")
            app_doc["student_email"] = student.get("email")

        return jsonify({"ok": True, "application": app_doc}), 200
    except Exception as e:
        logger.exception("Debug route failed: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500
    
@app.route("/test-email")
def test_email():
    """Debug route to verify Brevo mail sending works."""
    from datetime import datetime

    print("🟡 [Render] Test email route hit at", datetime.now())

    html = render_template(
        "email/student_status_update.html",
        student_name="Test Student",
        job_title="Test Job",
        status="approved",
        feedback="Everything looks great!",
        now=datetime.now
    )

    ok = send_brevo_email(
        "dhatchinamoorthiat@gmail.com",  # change if needed
        "Test User",
        "✅ Know-Thyself | Mail Test",
        html,
        async_send=False   # ✅ FIXED (no sync argument)
    )

    print("🟢 [Render] Mail send result:", ok)
    logger.info("🟢 [Render] Mail send result: %s", ok)

    return f"<h3>Mail send result: {ok}</h3>"
# -------------------------
# Routes - General
# -------------------------
@app.route('/')
@app.route('/index')
def startpage():
    return render_template('startpage.html')

# -------------------------
# Auth: login/logout/register
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    form = SimpleForm()

    if request.method == "POST" and form.validate_on_submit():
        email_or_sid = form.email_or_sid.data.strip()
        password = form.password.data.strip()

        # 🔹 Teacher login
        teacher = next((t for t in TEACHERS if t.get("email") == email_or_sid), None)
        if teacher and check_password_hash(teacher["password_hash"], password):
            user = User(teacher)
            login_user(user)
            flash("Welcome, Teacher!", "success")
            return redirect(url_for("teacher_dashboard"))

        # 🔹 Student login
        student = users_col.find_one({"email": email_or_sid})
        if student:
            stored_hash = student.get("password_hash") or student.get("password")
            if stored_hash and check_password_hash(stored_hash, password):
                user = User(student)
                login_user(user)
                flash("Welcome, Student!", "success")
                return redirect(url_for("student_dashboard"))

        # ⚠️ Only runs if no teacher/student matched
        flash("Invalid credentials. Please try again.", "danger")

    # Always render template with form for GET or failed POST
    return render_template("login.html", form=form)        
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        sid = request.form.get("sid", "").strip() or None

        # Basic validation
        if not name or not email or not password or not phone:
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        existing = users_col.find_one({"email": email})
        if existing:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(password)

        new_user = {
            "name": name,
            "email": email,
            "phone": phone,
            "sid": sid,
            "password_hash": password_hash,
            "role": "student",
            "created_at": local_dt_now()
        }

        res = users_col.insert_one(new_user)
        new_user["_id"] = res.inserted_id

        login_user(User(new_user))
        flash("Registration successful — welcome!", "success")
        return redirect(url_for("student_dashboard"))

    return render_template("register.html")

# -------------------------
# Student dashboard & apply
# -------------------------
import random
from bson import ObjectId
@csrf.exempt
@app.route("/student/")
@login_required
@student_required
def student_dashboard():
    """Student Dashboard with active application + daily motivation."""

    # -----------------------------
    # 🔹 Motivation Quotes Pool
    # -----------------------------
    MOTIVATION_QUOTES = [
        "Small progress each day adds up to big results.",
        "Your growth matters more than your speed.",
        "Consistency beats motivation — show up anyway.",
        "You’re building a future version of yourself.",
        "Every effort you make today is an investment.",
        "Clarity comes from action, not overthinking.",
        "You don’t need to be perfect — just present.",
        "Learning about yourself is never a waste.",
        "Progress is personal. Don’t compare timelines.",
        "You are allowed to grow at your own pace."
    ]

    dashboard_quote = random.choice(MOTIVATION_QUOTES)

    # -----------------------------
    # 🔹 Student & Applications
    # -----------------------------
    student_id = str(current_user.id)
    try:
        student_oid = ObjectId(student_id)
    except Exception:
        student_oid = None

    query = {
        "$or": [
            {"applicant_id": student_oid},
            {"applicant_id": student_id},
            {"student_id": student_id},
            {"user_id": student_oid},
            {"user_id": student_id},
        ]
    }

    applications = list(
        applications_col.find(query).sort("application_time", -1)
    )

    # -----------------------------
    # 🔹 Enrich Applications
    # -----------------------------
    for a in applications:
        job = None
        job_id = a.get("job_id")
        if job_id:
            job = jobs_col.find_one({"_id": job_id})

        a["job_title"] = (
            job.get("title")
            if job else a.get("job_title", "Unknown Job")
        )

        if not a.get("application_time"):
            a["application_time"] = a.get("created_at") or local_dt_now()

        stages = [
            "submitted",
            "under_review",
            "corrections_needed",
            "approved",
            "rejected"
        ]
        a["status_index"] = (
            stages.index(a.get("status"))
            if a.get("status") in stages
            else 0
        )

        a["deadline_str"] = utc_to_ist_str(a.get("deadline"))
        a["resume_upload_ist"] = utc_to_ist_str(a.get("resume_upload_time"))

    # -----------------------------
    # 🔹 Active Application
    # -----------------------------
    active_app = next(
        (
            app for app in applications
            if app.get("status") in (
                "upload_required",
                "submitted",
                "under_review",
                "corrections_needed"
            )
        ),
        None
    )

    has_active = bool(active_app)

    # -----------------------------
    # 🔹 Dashboard Metrics (FINAL FIX)
    # -----------------------------
    total_applications = len(applications)

    under_review = sum(
        1 for app in applications
        if app.get("status") in ("submitted", "under_review")
    )

    corrections_needed = sum(
        1 for app in applications
        if app.get("status") == "corrections_needed"
    )

    # Simple, stable growth score
    progress_score = max(
        0,
        min(100, total_applications * 25 - corrections_needed * 10)
    )

    # -----------------------------
    # 🔹 Render Dashboard
    # -----------------------------
    return render_template(
    "student_dashboard.html",
    applications=applications,
    active_app=active_app,   # ✅ FIXED
    has_active=has_active,
    dashboard_quote=dashboard_quote,

    total_applications=total_applications,
    under_review=under_review,
    corrections_needed=corrections_needed,
    progress_score=progress_score,

    current_user=current_user,
    timedelta=timedelta
)
def has_active_application(student_id):
    try:
        student_oid = ObjectId(student_id)
    except Exception:
        student_oid = None

    return applications_col.find_one({
        "$or": [
            {"student_id": student_id},
            {"student_id": student_oid},
            {"applicant_id": student_id},
            {"applicant_id": student_oid},
            {"user_id": student_id},
            {"user_id": student_oid},
        ],
        "status": {
            "$in": [
                "upload_required",
                "submitted",
                "under_review",
                "corrections_needed"
            ]
        }
    }) is not None
class User(UserMixin):
    def __init__(self, data):
        self.id = str(data.get("_id", data.get("email")))
        self.email = data.get("email")
        self.name = data.get("name")
        self.role = data.get("role", "student")

    def has_applied(self, job):
        """Check if the current student has already applied for this job."""
        from bson import ObjectId
        from app import db  # use your MongoDB client directly
        application = db.applications.find_one({
            "applicant_id": ObjectId(self.id),
            "job_id": job["_id"]
        })
        return application is not None

from self_assessment_questions import QUESTION_BANK, generate_assessment_questions
from flask import session
from flask import session, redirect, url_for

from flask import session
@csrf.exempt
@app.route("/student/self-assessment/start")
@login_required
@student_required
def start_self_assessment():

    if "assessment_id" in session:
        return redirect(url_for("self_assessment_step", step=1))

    questions = generate_assessment_questions(questions_per_domain=1)

    assessment = {
        "student_id": ObjectId(current_user.id),
        "created_at": local_dt_now(),
        "questions": questions,
        "responses": []
    }

    res = self_assess_col.insert_one(assessment)
    session["assessment_id"] = str(res.inserted_id)

    return redirect(url_for("self_assessment_step", step=1))

DOMAINS_ORDER = [
    "emotional_awareness",
    "stress_coping",
    "self_confidence",
    "social_wellbeing",
    "growth_mindset"
]
LIKERT_MAP = {
    "Strongly Disagree": 1,
    "Disagree": 2,
    "Neutral": 3,
    "Agree": 4,
    "Strongly Agree": 5
}
def generate_assessment_questions(questions_per_domain=5):
    selected = {}

    for domain in DOMAINS_ORDER:
        questions = QUESTION_BANK.get(domain, [])

        if len(questions) < questions_per_domain:
            raise ValueError(
                f"Not enough questions in domain '{domain}'. "
                f"Required: {questions_per_domain}, Found: {len(questions)}"
            )

        selected[domain] = random.sample(questions, questions_per_domain)

    return selected

@app.route("/student/self-assessment")
@login_required
def student_self_assessment_intro():
    return render_template("self_assessment_intro.html")

@app.route("/student/self-assessment/step/<int:step>", methods=["GET", "POST"])
@login_required
@student_required
def self_assessment_step(step):
    log_csrf_state()
    assessment_id = session.get("assessment_id")
    if not assessment_id:
        return redirect(url_for("student_self_assessment_intro"))

    assessment = self_assess_col.find_one(
        {"_id": ObjectId(assessment_id)}
    )

    questions = assessment["questions"]
    responses = assessment.get("responses", [])

    # Flatten questions (order is fixed for this assessment)
    flat_questions = []
    for domain, qs in questions.items():
        for q in qs:
            flat_questions.append({
                "domain": domain,
                "question": q
            })

    total = len(flat_questions)

    if step > total:
        return redirect(url_for("student_self_assessment_finish"))

    current_q = flat_questions[step - 1]

    if request.method == "POST":

        answer = request.form.get("answer")
        if not answer:
            flash("Please select an option before continuing.", "warning")
            return redirect(url_for("self_assessment_step", step=step))

        answer = int(answer)

        # ✅ REMOVE previous answer for this question (prevents duplicates)
        responses = [
            r for r in responses
            if r["question"] != current_q["question"]
        ]

        responses.append({
            "domain": current_q["domain"],
            "question": current_q["question"],
            "answer": answer
        })

        self_assess_col.update_one(
            {"_id": ObjectId(assessment_id)},
            {"$set": {"responses": responses}}
        )

        return redirect(url_for("self_assessment_step", step=step + 1))

    progress_percent = int((step / total) * 100)

    return render_template(
        "self_assessment_step.html",
        question=current_q,
        step=step,
        total=total,
        progress_percent=progress_percent,
        likert_map=LIKERT_MAP
    )
def calculate_domain_scores(responses):
    from collections import defaultdict

    domain_map = defaultdict(list)

    for r in responses:
        domain_map[r["domain"]].append(r["answer"])

    domain_scores = {}

    for domain, scores in domain_map.items():
        avg = round(sum(scores) / len(scores), 2)

        if avg >= 4.2:
            label = "Strong"
            color = "success"
        elif avg >= 3.5:
            label = "Stable"
            color = "primary"
        elif avg >= 2.8:
            label = "Needs Attention"
            color = "warning"
        else:
            label = "Critical"
            color = "danger"

        domain_scores[domain] = {
            "average": avg,
            "label": label,
            "color": color
        }

    return domain_scores
def interpret_score(avg):
    if avg >= 4.2:
        return "High"
    elif avg >= 3.5:
        return "Moderate"
    elif avg >= 2.8:
        return "Low"
    else:
        return "Critical"
def generate_insight_summary(domain_scores):
    insights = {}

    for domain, data in domain_scores.items():
        avg = data["average"]   # ✅ extract numeric value

        level = interpret_score(avg)

        if level == "High":
            insights[domain] = "Strong strength 💪"
        elif level == "Moderate":
            insights[domain] = "Stable but improvable 👍"
        elif level == "Low":
            insights[domain] = "Needs focused attention ⚠️"
        else:
            insights[domain] = "Critical area 🚨"

    return insights
@csrf.exempt
@app.route("/student/self-assessment/finish")
@login_required
@student_required
def student_self_assessment_finish():
    return render_template("self_assessment_finish.html")


@csrf.exempt
@app.route("/growth-hub/submit", methods=["POST"])
@login_required
def growth_hub_submit():
    for key, value in request.form.items():
        if key.startswith("q_") and value.strip():
            question_id = int(key.split("_")[1])

            save_growth_response(
    user=current_user,
    theme=theme,
    question_id=question_id,
    answer=value
)

    flash("🌱 Reflections saved successfully!", "success")
    return redirect(url_for("student_growth_hub"))
@csrf.exempt
@app.route("/growth/<int:qid>", methods=["GET", "POST"])
@login_required
def growth_question(qid):
    activity = GROWTH_ACTIVITIES[qid]

    if request.method == "POST":
        answer = request.form["answer"]

        save_growth_response(
    user=current_user,
    theme=theme,
    question_id=question_id,
    answer=value
)

        flash("✅ Reflection submitted!", "success")
        return redirect(url_for("student_growth_hub"))

    return render_template(
        "growth_question.html",
        activity=activity,
        qid=qid
    )

def save_growth_response(user, theme, question_id, answer):
    db.growth_responses.insert_one({
        "student_id": ObjectId(user.id),   # MUST be ObjectId
        "module": theme,                   # MUST exist
        "question_id": question_id,
        "answer": answer,
        "updated_at": datetime.utcnow()
    })
@csrf.exempt
@app.route("/student/self-assessment/submit", methods=["POST"])
@login_required
@student_required
def submit_self_assessment():

    assessment_id = session.get("assessment_id")
    if not assessment_id:
        return redirect(url_for("student_self_assessment_intro"))

    assessment = self_assess_col.find_one(
        {"_id": ObjectId(assessment_id)}
    )

    responses = assessment.get("responses", [])

    # ✅ STEP B — calculate scores (SINGLE SOURCE OF TRUTH)
    raw_scores = calculate_domain_scores(responses)

    # ✅ STEP C — normalize / repair data
    domain_scores = {}
    for domain, data in raw_scores.items():
        if isinstance(data, dict):
            domain_scores[domain] = data
        else:
            # 🔥 Repair legacy float data safely
            domain_scores[domain] = {
                "average": float(data),
                "label": interpret_score(float(data)),
                "color": "secondary"
            }

    # ✅ STEP D — insights
    insight_summary = generate_insight_summary(domain_scores)

    # ✅ SAVE FINAL RESULT
    self_assess_col.update_one(
        {"_id": ObjectId(assessment_id)},
        {"$set": {
            "domain_scores": domain_scores,
            "insight_summary": insight_summary,
            "completed_at": datetime.utcnow()
        }}
    )

    # ✅ CLEANUP SESSION
    session.pop("assessment_id", None)

    return render_template(
        "self_assessment_result.html",
        domain_scores=domain_scores,
        insight_summary=insight_summary
    )

@app.route("/student/profile")
@login_required
@student_required
def student_profile():
    return render_template("student_profile.html", user=current_user)

# ===============================
# APPLICATION STATUS CONSTANTS
# ===============================
ACTIVE_STATUSES = [
    "applied",
    "under_review",
    "shortlisted",
    "resubmitted",
    "corrections_needed"
]

@app.route("/student/applications")
@login_required
@student_required
def student_applications():
    student_id = str(current_user.id)

    try:
        student_oid = ObjectId(student_id)
    except Exception:
        student_oid = None

    query = {
        "$or": [
            {"applicant_id": student_oid},
            {"applicant_id": student_id},
            {"student_id": student_oid},
            {"student_id": student_id},
            {"user_id": student_oid},
            {"user_id": student_id},
        ],
        "status": {"$in": ACTIVE_STATUSES}
    }

    applications = list(
        applications_col.find(query)
        .sort("application_time", -1)
    )

    has_active = bool(applications)

    return render_template(
        "student_applications.html",
        applications=applications,
        has_active=has_active
    )

@app.route("/student/jobs")
@login_required
@student_required
def student_jobs():
    jobs = list(jobs_col.find().sort("created_at", -1))
    jobs = [objectid_to_str(j) for j in jobs]
    return render_template("student_jobs.html", jobs=jobs)

@app.route("/job/<job_id>", methods=["GET", "POST"])
@login_required
@student_required
def view_job(job_id):
    job = jobs_col.find_one({"_id": ObjectId(job_id)})
    if not job:
        flash("⚠️ Job not found.", "danger")
        return redirect(url_for("student_dashboard"))

    # Check if the student has an existing application (any job)
    active_app = applications_col.find_one({
        "applicant_id": ObjectId(current_user.id),
        "status": {"$in": ["submitted", "under_review", "corrections_needed"]}
    })

    # Check if they applied for THIS specific job
    existing_app = applications_col.find_one({
        "applicant_id": ObjectId(current_user.id),
        "job_id": ObjectId(job_id)
    })

    has_applied = bool(existing_app)
    has_active = bool(active_app and str(active_app.get("job_id")) != str(job_id))

    return render_template(
        "job_detail.html",
        job=job,
        has_applied=has_applied,
        has_active=has_active,
        app=existing_app
    )
# -------------------------
# Google Drive-based File Viewer
# -------------------------
@app.route("/view/<file_type>/<app_id>")
@login_required
def view_from_drive(file_type, app_id):
    """
    Allows teachers/students to view resumes or photos stored as Google Drive links.
    Example:
        /view/resume/<app_id>
        /view/photo/<app_id>
    """
    app_doc = applications_col.find_one({"_id": mongo_objid_from_str(app_id)})
    if not app_doc:
        abort(404, "Application not found")

    if file_type == "resume":
        drive_link = app_doc.get("resume_drive_link")
        display_name = "Resume"
    elif file_type == "photo":
        drive_link = app_doc.get("photo_drive_link")
        display_name = "Photo"
    else:
        abort(400, "Invalid file type")

    if not drive_link:
        flash(f"⚠️ No {display_name} available for this student.", "warning")
        return redirect(request.referrer or url_for("teacher_dashboard"))

    # Convert to Google Drive preview link
    if "view" in drive_link:
        preview_link = drive_link.replace("view?usp=drive_link", "preview")
    else:
        preview_link = drive_link

    return render_template(
        "view_drive_file.html",
        preview_link=preview_link,
        display_name=display_name
    )
from self_assessment_logic import (
    calculate_domain_scores,
    generate_insight_summary
)

@csrf.exempt
@csrf.exempt
@app.route("/student/growth", methods=["GET"])
@login_required
def growth_hub_menu():
    activities = [
        {
            "title": "Self Awareness",
            "description": "Understand your thoughts, emotions, and behaviors.",
            "slug": "self_awareness"
        },
        {
            "title": "Mindfulness",
            "description": "Be present and aware in daily life.",
            "slug": "mindfulness"
        },
        {
            "title": "Career Growth",
            "description": "Reflect on your professional journey.",
            "slug": "career_growth"
        },
        {
            "title": "Relationships",
            "description": "Understand how you connect with others.",
            "slug": "relationships"
        },
        {
            "title": "Creativity",
            "description": "Explore your creative thinking.",
            "slug": "creativity"
        }
    ]

    return render_template("growth_hub_menu.html", activities=activities)
@app.route("/growth-hub")
@login_required
def growth_hub_redirect():
    return redirect(url_for("growth_hub_menu"))
@csrf.exempt
@app.route("/student/growth/<theme>", methods=["GET", "POST"])
@login_required
def student_growth_theme(theme):

    all_questions = get_questions_for_theme(theme)   # ← 500 questions

    # If no session set OR user clicked dice
    if "random_set" not in session or request.args.get("shuffle") == "1":
        session["random_set"] = random.sample(all_questions, 100)

    questions = session["random_set"]

    saved_answers = get_saved_answers(current_user.id, theme)

    if request.method == "POST":
        handle_growth_submission(request, theme)

    return render_template(
        "growth_hub.html",
        theme=theme,
        questions=questions,
        saved_answers=saved_answers
    )
def get_saved_answers(user_id, theme):
    """
    Temporary placeholder.
    Returns previously saved answers for a user & theme.
    """
    return {}
@csrf.exempt
@app.route("/student/growth/random")
@login_required
def student_growth_random():
    themes = [
        "self_awareness",
        "confidence",
        "emotional_intelligence",
        "goal_setting",
        "resilience",
        "mindfulness",
        "career_growth",
        "relationships",
        "creativity"
    ]

    chosen_theme = random.choice(themes)
    return redirect(url_for("student_growth_theme", theme=chosen_theme))

def handle_growth_submission(request, theme):
    """
    Handles partial save and final submit for Growth Hub.
    """

    is_partial = "save_partial" in request.form
    is_final = "submit_all" in request.form

    for key, value in request.form.items():
        if key.startswith("q") and value.strip():
            question_id = int(key.replace("q", ""))

            # 🔹 SAVE LOGIC (placeholder / DB)
            save_growth_answer(
                user_id=current_user.id,
                theme=theme,
                question_id=question_id,
                answer=value.strip()
            )

    if is_final:
        flash("✅ Growth Hub submitted successfully!", "success")
    else:
        flash("💾 Progress saved. You can continue later.", "info")

def save_growth_answer(user_id, theme, question_id, answer):
    """
    Temporary placeholder for saving answers.
    Replace with DB logic later.
    """
    pass

# ---------------------------------------------------------------------
# 📄 View Resume or Photo (from Drive or Local Upload)
# ---------------------------------------------------------------------
@app.route("/view/resume/<app_id>")
@login_required
def view_resume(app_id):
    """
    View a student's resume — either from Google Drive or local upload.
    """
    application = applications_col.find_one({"_id": mongo_objid_from_str(app_id)})
    if not application:
        flash("⚠️ Application not found.", "danger")
        return redirect(request.referrer or url_for("teacher_dashboard"))

    # ✅ Prefer Google Drive link if present
    drive_link = (
        application.get("resume_drive_link")
        or application.get("resume_url")
        or application.get("resume_link")
    )

    if drive_link:
        # Render HTML with iframe to view inline
        return render_template("view_drive_file.html", drive_url=drive_link, title="View Resume")

    # Fallback: Local upload
    filename = application.get("resume_filename")
    if filename:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(file_path):
            return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    
    flash("⚠️ Resume not found for this application.", "warning")
    return redirect(request.referrer or url_for("teacher_dashboard"))


@app.route("/view/photo/<app_id>")
@login_required
def view_photo(app_id):
    """
    View a student's photo — either from Google Drive or local upload.
    """
    application = applications_col.find_one({"_id": mongo_objid_from_str(app_id)})
    if not application:
        flash("⚠️ Application not found.", "danger")
        return redirect(request.referrer or url_for("teacher_dashboard"))

    # ✅ Prefer Google Drive link if present
    drive_link = (
        application.get("photo_drive_link")
        or application.get("photo_url")
        or application.get("photo_link")
    )

    if drive_link:
        return render_template("view_drive_file.html", drive_url=drive_link, title="View Photo")

    # Fallback: Local upload
    filename = application.get("photo_filename")
    if filename:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(file_path):
            return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    
    flash("⚠️ Photo not found for this application.", "warning")
    return redirect(request.referrer or url_for("teacher_dashboard"))

@app.route("/apply/<job_id>", methods=["POST"])
@login_required
def apply_job(job_id):
    job_oid = mongo_objid_from_str(job_id)
    if not job_oid:
        abort(404)

    job = jobs_col.find_one({"_id": job_oid})
    if not job:
        flash("⚠️ Job not found. Please refresh.", "danger")
        return redirect(url_for("student_dashboard"))

    if job.get("vacancies", 0) <= 0:
        flash("🚫 No vacancies left for this job.", "warning")
        return redirect(url_for("student_dashboard"))

    # 🔒 ONE-ACTIVE-APPLICATION RULE
    student_id = str(current_user.id)
    try:
        student_oid = ObjectId(student_id)
    except Exception:
        student_oid = None

    active_app = applications_col.find_one({
        "$or": [
            {"applicant_id": student_oid},
            {"applicant_id": student_id},
            {"student_id": student_oid},
            {"student_id": student_id},
            {"user_id": student_oid},
            {"user_id": student_id},
        ],
        "status": {"$in": ["upload_required", "submitted", "under_review", "corrections_needed"]}
    })

    if active_app:
        flash(
            "🚫 You already have an active application. "
            "You can apply for only one job at a time.",
            "warning"
        )
        return redirect(url_for("student_dashboard"))

    # Prevent duplicate application for same job
    existing = applications_col.find_one({
        "job_id": job_oid,
        "applicant_id": student_oid
    })
    if existing:
        flash("ℹ️ You already applied for this job.", "info")
        return redirect(url_for("student_dashboard"))

    # Create application
    now = local_dt_now()
    res = applications_col.insert_one({
        "job_id": job_oid,
        "job_title": job.get("title"),
        "applicant_id": student_oid,
        "status": "upload_required",
        "application_time": now,
        "deadline": job.get("deadline"),
    })

    jobs_col.update_one(
        {"_id": job_oid, "vacancies": {"$gt": 0}},
        {"$inc": {"vacancies": -1}}
    )

    flash(
        "✅ Application created successfully! "
        "Please upload your resume & photo within 48 hours.",
        "success"
    )
    return redirect(url_for("upload_files", app_id=str(res.inserted_id)))
from datetime import datetime, timedelta, timezone as tz

@app.route("/upload/<app_id>", methods=["GET", "POST"])
@login_required
@student_required
def upload_files(app_id):
    application = applications_col.find_one(
        {"_id": mongo_objid_from_str(app_id)}
    )
    if not application or str(application.get("applicant_id")) != str(current_user.id):
        flash("⚠️ Application not found.", "danger")
        abort(403)

    now = datetime.now(UTC)

    created_time = application.get("application_time") or now
    if created_time.tzinfo is None:
        created_time = created_time.replace(tzinfo=UTC)

    deadline = application.get("deadline")
    if deadline:
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        effective_deadline = deadline
    else:
        effective_deadline = created_time + timedelta(hours=48)

    status = application.get("status", "upload_required")

    # ---------------- EXPIRE CHECK ----------------
    if now > effective_deadline and status not in ("submitted", "corrections_needed"):
        applications_col.update_one(
            {"_id": application["_id"]},
            {"$set": {"status": "expired", "last_updated": now}}
        )
        flash("⏰ Deadline expired. Upload not allowed.", "danger")
        return render_template(
            "upload_blocked.html",
            app=objectid_to_str(application)
        )

    # ---------------- BLOCK DOUBLE SUBMIT ----------------
    if request.method == "POST" and status == "submitted":
        flash("ℹ️ Files already submitted. Await review.", "info")
        return redirect(url_for("student_applications"))

    # ===================== POST =====================
    if request.method == "POST":
        resume = request.files.get("resume")
        photo = request.files.get("photo")

        if not resume or not photo or resume.filename == "" or photo.filename == "":
            flash("⚠️ Please upload both resume and photo.", "warning")
            return redirect(request.url)

        updates = {}

        # ---------- SAVE FILES ----------
        if allowed_file(resume.filename, ALLOWED_RESUME):
            ext = resume.filename.rsplit(".", 1)[1].lower()
            resume_name = secure_filename(f"{app_id}_resume.{ext}")
            resume_path = os.path.join(app.config["UPLOAD_FOLDER"], resume_name)
            resume.save(resume_path)
            updates["resume_filename"] = resume_name
        else:
            resume_path = None

        if allowed_file(photo.filename, ALLOWED_PHOTO):
            ext = photo.filename.rsplit(".", 1)[1].lower()
            photo_name = secure_filename(f"{app_id}_photo.{ext}")
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], photo_name)
            photo.save(photo_path)
            updates["photo_filename"] = photo_name
        else:
            photo_path = None

        # ---------- UPDATE DB ----------
        if updates:
            previous_status = status

            if status in ("upload_required", "corrections_needed"):
                updates["status"] = "submitted"

            updates["last_updated"] = now

            applications_col.update_one(
                {"_id": application["_id"]},
                {"$set": updates}
            )

            # ---------- MAIL TRIGGER (FIRST SUBMISSION ONLY) ----------
            if previous_status == "upload_required":
                student_doc = users_col.find_one(
                    {"_id": ObjectId(current_user.id)}
                )
                student_name = student_doc.get("name", current_user.name)
                student_email = student_doc.get("email")

                job = jobs_col.find_one({"_id": application.get("job_id")})
                job_title = job.get(
                    "title",
                    application.get("job_title", "Application")
                )

                submitted_time = now.astimezone(IST).strftime(
                    "%d %b %Y, %I:%M %p IST"
                )

                mailtrigger.on_application_submitted(
                    student_name=student_name,
                    student_email=student_email,
                    job_title=job_title,
                    app_id=str(application["_id"]),
                    submitted_time=submitted_time,
                    resume_path=resume_path,
                    photo_path=photo_path,
                )

            flash("✅ Files uploaded successfully!", "success")
            return redirect(url_for("student_applications"))

        flash("⚠️ No valid files uploaded.", "warning")
        return redirect(request.url)

    # ===================== GET =====================
    app_for_template = objectid_to_str(application)
    app_for_template["_id_str"] = str(app_for_template["_id"])

    return render_template(
        "upload_files.html",
        app=app_for_template,
        deadline_iso=effective_deadline.isoformat()
    )
@app.route("/reupload/<app_id>", methods=["GET", "POST"])
@login_required
@student_required
def reupload_files(app_id):
    """Allow student to re-upload files after 'corrections_needed'."""

    app_oid = mongo_objid_from_str(app_id)
    if not app_oid:
        flash("Invalid Application ID.", "danger")
        return redirect(url_for("student_dashboard"))

    app_doc = applications_col.find_one({"_id": app_oid})
    if not app_doc:
        flash("Application not found.", "danger")
        return redirect(url_for("student_dashboard"))

    # 🔹 Resolve student safely
    applicant_id = (
        app_doc.get("applicant_id")
        or app_doc.get("student_id")
        or app_doc.get("user_id")
    )

    student = None
    if applicant_id:
        try:
            student = users_col.find_one({"_id": ObjectId(applicant_id)})
        except Exception:
            student = users_col.find_one({
                "$or": [
                    {"student_id": str(applicant_id)},
                    {"user_id": str(applicant_id)},
                    {"_id": str(applicant_id)},
                ]
            })

    if not student:
        flash("⚠️ Student record not found for this application.", "warning")
        return redirect(url_for("student_dashboard"))

    # ---------------- POST ----------------
    if request.method == "POST":
        resume = request.files.get("resume")
        photo = request.files.get("photo")

        if not resume or not photo or resume.filename == "" or photo.filename == "":
            flash("⚠️ Both Resume and Photo are required.", "warning")
            return redirect(request.url)

        updates = {}
        resume_path = None
        photo_path = None

        # --- Resume upload ---
        if allowed_file(resume.filename, ALLOWED_RESUME):
            ext = resume.filename.rsplit(".", 1)[1].lower()
            resume_name = secure_filename(f"{app_id}_resume.{ext}")
            resume_path = os.path.join(app.config["UPLOAD_FOLDER"], resume_name)
            resume.save(resume_path)
            updates["resume_filename"] = resume_name

        # --- Photo upload ---
        if allowed_file(photo.filename, ALLOWED_PHOTO):
            ext = photo.filename.rsplit(".", 1)[1].lower()
            photo_name = secure_filename(f"{app_id}_photo.{ext}")
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], photo_name)
            photo.save(photo_path)
            updates["photo_filename"] = photo_name

        # --- Update DB FIRST ---
        updates["status"] = "submitted"
        updates["last_updated"] = datetime.now(IST)
        applications_col.update_one(
            {"_id": app_oid},
            {"$set": updates}
        )

        # --- Prepare data for mail trigger ---
        job = jobs_col.find_one({"_id": app_doc.get("job_id")})
        job_title = job.get("title", "Application") if job else "Application"
        student_name = student.get("name", "Student")
        student_email = student.get("email")

        # --- Trigger centralized mail logic ---
        mailtrigger.on_files_reuploaded(
            student_name=student_name,
            student_email=student_email,
            job_title=job_title,
            app_id=app_id,
            resume_path=resume_path,
            photo_path=photo_path
        )

        flash("✅ Files re-uploaded and notifications sent!", "success")
        return redirect(url_for("student_dashboard"))

    # ---------------- GET ----------------
    return render_template("reupload_files.html", app=app_doc)
# -------------------------
# View files (resume/photo)
# -------------------------
@app.route("/uploads/<filename>")
@login_required
def view_file(filename):
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(path):
        abort(404)
    # Let browser handle (for pdf) or download
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# -------------------------
# Teacher dashboard & job management
# -------------------------
@app.route("/teacher/dashboard")
@login_required
@teacher_required
def teacher_dashboard():

    # ================= BASIC COUNTS =================
    total_students = users_col.count_documents({"role": "student"})
    total_applications = applications_col.count_documents({})

    pending_review = applications_col.count_documents({
        "status": {"$in": ["submitted", "under_review"]}
    })

    corrections_needed = applications_col.count_documents({
        "status": "corrections_needed"
    })

    # ================= CORRECTION METRICS =================
    reuploads_pending = applications_col.count_documents({
        "status": "corrections_needed",
        "resume_filename": {"$exists": False}
    })

    repeat_corrections = applications_col.count_documents({
        "status": "corrections_needed",
        "correction_count": {"$gte": 2}
    })

    # ================= AVG CORRECTION TURNAROUND =================
    pipeline = [
        {"$match": {
            "status": "corrections_needed",
            "last_updated": {"$exists": True},
            "application_time": {"$exists": True}
        }},
        {"$project": {
            "days": {
                "$divide": [
                    {"$subtract": ["$last_updated", "$application_time"]},
                    1000 * 60 * 60 * 24
                ]
            }
        }},
        {"$group": {
            "_id": None,
            "avg_days": {"$avg": "$days"}
        }}
    ]

    result = list(applications_col.aggregate(pipeline))
    avg_correction_days = round(result[0]["avg_days"], 1) if result else 0

    # ================= OLDEST CORRECTIONS =================
    oldest_apps = list(
        applications_col.find({"status": "corrections_needed"})
        .sort("last_updated", 1)
        .limit(5)
    )

    now_utc = datetime.now(UTC)
    oldest_corrections = []

    for app in oldest_apps:
        student = users_col.find_one({
            "$or": [
                {"_id": app.get("applicant_id")},
                {"student_id": str(app.get("applicant_id"))},
                {"user_id": str(app.get("applicant_id"))}
            ]
        })

        job = jobs_col.find_one({"_id": app.get("job_id")})

        last_updated = app.get("last_updated")
        if last_updated and last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=UTC)

        days_pending = (now_utc - last_updated).days if last_updated else 0

        oldest_corrections.append({
            "student_name": student.get("name", "Unknown") if student else "Unknown",
            "job_title": job.get("title", "Unknown") if job else "Unknown",
            "days_pending": days_pending
        })

    # ================= STATUS BREAKDOWN =================
    status_counts = {
        "approved": applications_col.count_documents({"status": "approved"}),
        "rejected": applications_col.count_documents({"status": "rejected"}),
        "pending": applications_col.count_documents({
            "status": {"$in": ["submitted", "under_review"]}
        }),
        "corrections": applications_col.count_documents({
            "status": "corrections_needed"
        })
    }

    # ================= CORRECTIONS TREND (LAST 7 DAYS) =================
    from datetime import timedelta

    trend_labels = []
    trend_values = []

    for i in range(6, -1, -1):
        day = datetime.now(UTC) - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)

        count = applications_col.count_documents({
            "status": "corrections_needed",
            "last_updated": {"$gte": start, "$lt": end}
        })

        trend_labels.append(start.strftime("%d %b"))
        trend_values.append(count)

    # ================= JOBS WITH MOST CORRECTIONS =================
    pipeline = [
        {"$match": {"status": "corrections_needed"}},
        {"$group": {"_id": "$job_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]

    job_stats = list(applications_col.aggregate(pipeline))

    job_labels = []
    job_values = []

    for row in job_stats:
        job = jobs_col.find_one({"_id": row["_id"]})
        job_labels.append(job.get("title", "Unknown") if job else "Unknown")
        job_values.append(row["count"])

    # ================= FINAL RENDER (ONLY ONCE) =================
    return render_template(
    "teacher_dashboard.html",

    # KPIs
    total_students=total_students,
    total_applications=total_applications,
    pending_review=pending_review,
    corrections_needed=corrections_needed,

    # Corrections metrics
    avg_correction_days=avg_correction_days,
    reuploads_pending=reuploads_pending,
    repeat_corrections=repeat_corrections,

    # Lists
    oldest_corrections=oldest_corrections,

    # Charts
    status_counts=status_counts,
    trend_labels=trend_labels,
    trend_values=trend_values,
    job_labels=job_labels,
    job_values=job_values
)
@app.route("/teacher/add_job", methods=["GET", "POST"])
@login_required
@teacher_required
def add_job():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        specifications = request.form.get("specifications", "").strip()
        vacancies = int(request.form.get("vacancies") or 1)
        deadline_str = request.form.get("deadline")  # expect "YYYY-MM-DDTHH:MM" from datetime-local input

        if deadline_str:
            try:
                dt_ist = datetime.strptime(deadline_str, "%Y-%m-%dT%H:%M")
                deadline_utc = ist_to_utc(dt_ist)
            except Exception:
                flash("Invalid deadline format.", "danger")
                return redirect(request.url)
        else:
            deadline_utc = None

        job_doc = {
            "title": title,
            "description": description,
            "specifications": specifications,
            "vacancies": vacancies,
            "deadline": deadline_utc,
            "created_by": current_user.id,
            "created_at": local_dt_now()
        }
        jobs_col.insert_one(job_doc)
        flash("✅ Job posted successfully.", "success")
        return redirect(url_for("teacher_dashboard"))
    return render_template("add_job.html")
app.jinja_env.globals.update(getenv=os.getenv)

# Ensure teacher password hashes exist and remove plaintext passwords from memory
for t in TEACHERS:
    # if teacher already has password_hash, keep it
    if not t.get("password_hash") and t.get("password"):
        t["password_hash"] = generate_password_hash(t["password"])
    # remove plaintext password to avoid accidental leakage
    if "password" in t:
        del t["password"]

def resolve_student(app):
    sid = app.get("applicant_id") or app.get("student_id") or app.get("user_id")
    if not sid:
        return None

    try:
        return users_col.find_one({"_id": ObjectId(sid)})
    except Exception:
        return users_col.find_one({
            "$or": [
                {"student_id": str(sid)},
                {"user_id": str(sid)}
            ]
        })

@app.route("/teacher/manage_jobs", methods=["GET", "POST"])
@login_required
@teacher_required
def manage_jobs():
    """
    Teacher job management page:
    - Lists all jobs with deadlines, application counts, and statuses.
    - Allows safe deletion only if no active applications exist.
    """
    IST = tz(timedelta(hours=5, minutes=30))

    # --- POST: Handle job deletion safely ---
    if request.method == "POST":
        job_id = request.form.get("job_id")
        action = request.form.get("action")

        if not job_id:
            flash("⚠️ Missing job ID.", "danger")
            return redirect(url_for("manage_jobs"))

        # ✅ Safe ObjectId conversion
        job_oid = mongo_objid_from_str(job_id)
        if not job_oid:
            flash("❌ Invalid Job ID.", "danger")
            return redirect(url_for("manage_jobs"))

        job = jobs_col.find_one({"_id": job_oid})
        if not job:
            flash("⚠️ Job not found.", "warning")
            return redirect(url_for("manage_jobs"))

        # 🔹 Handle deletion
        if action == "delete":
            active_apps = applications_col.count_documents({
                "job_id": job_oid,
                "status": {"$in": ["upload_required", "submitted", "under_review", "corrections_needed"]}
            })

            if active_apps > 0:
                flash("⚠️ Cannot delete job with active applications.", "warning")
                return redirect(url_for("manage_jobs"))

            jobs_col.delete_one({"_id": job_oid})
            flash(f"🗑️ Job '{job.get('title', 'Untitled Job')}' deleted successfully.", "success")
            return redirect(url_for("manage_jobs"))

    # --- GET: Display all jobs ---
    jobs = list(jobs_col.find().sort("deadline", 1))
    now_ist = datetime.now(IST)

    for j in jobs:
        job_id = j["_id"]

        # 🔹 Format deadline
        dl = j.get("deadline")
        if dl:
            if dl.tzinfo is None:
                dl = dl.replace(tzinfo=tz.utc)
            j["deadline_ist"] = dl.astimezone(IST).strftime("%d %b %Y, %I:%M %p")
        else:
            j["deadline_ist"] = "Not set"

        # 🔹 Application counts (consistent with ObjectId job_id)
        j["total_applications"] = applications_col.count_documents({"job_id": job_id})
        j["active_applications"] = applications_col.count_documents({
            "job_id": job_id,
            "status": {"$in": ["upload_required", "submitted", "corrections_needed"]}
        })
        j["approved_applications"] = applications_col.count_documents({
            "job_id": job_id,
            "status": "approved"
        })

        # 🔹 Prepare ID for Jinja templates
        j["job_id_str"] = str(job_id)

    return render_template("manage_jobs.html", jobs=jobs)

from random import randint
from datetime import datetime, timedelta

# temporary in-memory OTP store (you can later move this to Mongo)
otp_store = {}

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password_request():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        user = users_col.find_one({"email": email})

        if not user:
            flash("⚠️ No account found with this email.", "warning")
            return redirect(url_for("reset_password_request"))

        # generate a 6-digit OTP
        otp = str(randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=10)
        otp_store[email] = {"otp": otp, "expires": expiry}

        # send the OTP via email
        try:
            html = render_template("email/reset_otp.html", otp=otp, user=user)
            send_brevo_email(email, user.get("name", "User"), "🔐 Password Reset OTP", html)
            flash("✅ OTP sent to your registered email.", "success")
            return redirect(url_for("verify_otp"))
        except Exception as e:
            logger.exception("Failed to send OTP: %s", e)
            flash("⚠️ Could not send OTP. Please try again later.", "danger")
            return redirect(url_for("reset_password_request"))

    return render_template("reset_password_request.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        otp_input = request.form.get("otp").strip()
        new_pw = request.form.get("password").strip()

        record = otp_store.get(email)
        if not record:
            flash("❌ No OTP found for this email. Please request again.", "danger")
            return redirect(url_for("reset_password_request"))

        if datetime.now() > record["expires"]:
            flash("⚠️ OTP expired. Please request a new one.", "warning")
            otp_store.pop(email, None)
            return redirect(url_for("reset_password_request"))

        if otp_input != record["otp"]:
            flash("❌ Invalid OTP. Please try again.", "danger")
            return redirect(url_for("verify_otp"))

        # update password in database
        hashed = generate_password_hash(new_pw)
        users_col.update_one({"email": email}, {"$set": {"password_hash": hashed}})
        otp_store.pop(email, None)
        flash("✅ Password reset successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("verify_otp.html")

from flask_wtf.csrf import generate_csrf

@app.route("/debug-token")
def debug_token():
    return generate_csrf()

@app.route("/teacher/edit_job/<job_id>", methods=["GET", "POST"])
@login_required
@teacher_required
def edit_job(job_id):
    job = jobs_col.find_one({"_id": mongo_objid_from_str(job_id)})
    if not job:
        flash("Job not found.", "danger")
        return redirect(url_for("manage_jobs"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        specifications = request.form.get("specifications", "").strip()
        vacancies = int(request.form.get("vacancies") or job.get("vacancies", 1))
        deadline_str = request.form.get("deadline")
        if deadline_str:
            dt_ist = datetime.strptime(deadline_str, "%Y-%m-%dT%H:%M")
            deadline_utc = ist_to_utc(dt_ist)
        else:
            deadline_utc = None
        jobs_col.update_one({"_id": job["_id"]}, {"$set": {
            "title": title,
            "description": description,
            "specifications": specifications,
            "vacancies": vacancies,
            "deadline": deadline_utc
        }})
        flash("Job updated.", "success")
        return redirect(url_for("manage_jobs"))
    job = objectid_to_str(job)
    job["deadline_str"] = utc_to_ist_str(job.get("deadline"))
    return render_template("edit_job.html", job=job)

@app.route("/teacher/delete_job/<job_id>", methods=["POST"])
@login_required
@teacher_required
def delete_job(job_id):
    job = jobs_col.find_one({"_id": mongo_objid_from_str(job_id)})
    if not job:
        flash("Job not found.", "danger")
        return redirect(url_for("manage_jobs"))
    # Optionally delete related applications and files
    apps = list(applications_col.find({"job_id": job["_id"]}))
    for a in apps:
        # delete files referenced by application
        for key in ("resume_filename", "photo_filename"):
            fn = a.get(key)
            if fn:
                p = os.path.join(app.config["UPLOAD_FOLDER"], fn)
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except Exception:
                    logger.exception("Failed to remove %s", p)
        applications_col.delete_one({"_id": a["_id"]})
    jobs_col.delete_one({"_id": job["_id"]})
    flash("Job and its applications removed.", "success")
    return redirect(url_for("manage_jobs"))

# 🧠 Teacher — View Self Assessments
@app.route("/teacher/self-assessments", methods=["GET"])
@login_required
@teacher_required
def teacher_self_assessments():
    responses = list(self_assess_col.find().sort("submitted_at", -1))

    for r in responses:
        student = users_col.find_one({"_id": r.get("student_id")})
        r["student_name"] = student.get("name", "Unknown") if student else "Unknown"
        r["student_email"] = student.get("email", "N/A") if student else "N/A"
        r["_id_str"] = str(r["_id"])

    return render_template(
        "teacher_self_assessments.html",
        responses=responses
    )
@app.route("/teacher/self-assessment/<id>")
@login_required
@teacher_required
def view_self_assessment(id):
    response = self_assess_col.find_one({"_id": ObjectId(id)})

    if not response:
        abort(404)

    student = users_col.find_one({"_id": response.get("student_id")})

    response["student_name"] = student.get("name", "Unknown") if student else "Unknown"
    response["student_email"] = student.get("email", "N/A") if student else "N/A"

    return render_template(
        "view_self_assessment.html",
        response=response
    )
# --------------------------------------------------------------------------
# Teacher Growth Hub View
# --------------------------------------------------------------------------
@app.route("/teacher/growth-responses")
@login_required
def growthhub_table():
    if current_user.role != "teacher":

        abort(403)

    responses = list(db.growth_responses.find().sort("submitted_at", -1))

    return render_template(
        "growthhub_table.html",
        growth_responses=responses
    )
from bson import ObjectId
@app.route("/teacher/growth/delete/<response_id>", methods=["POST"])
@login_required
def delete_growth_response(response_id):
    if current_user.role != "teacher":
        abort(403)

    try:
        oid = ObjectId(response_id)
    except Exception:
        abort(400)

    growth_responses_col.delete_one({"_id": oid})

    flash("Growth response deleted.", "success")
    return redirect(url_for("growthhub_table"))

@app.route("/teacher/growth_hub")
@login_required
@teacher_required
def teacher_growth_hub():

    pipeline = [
        {
            "$group": {
                "_id": {
                    "student_id": "$student_id",
                    "module": {"$ifNull": ["$module", "General"]}
                },
                "answers": {"$sum": 1},
                "updated_at": {"$max": "$updated_at"}
            }
        }
    ]

    rows = list(db.growth_responses.aggregate(pipeline))
    growth_data = []

    for r in rows:
        student = None
        sid = r["_id"].get("student_id")

        try:
            if isinstance(sid, str):
                sid = ObjectId(sid)
            student = users_col.find_one({"_id": sid})
        except Exception:
            student = None

        growth_data.append({
            "student_name": student.get("name") if student else "Unknown",
            "student_email": student.get("email") if student else "N/A",
            "module": r["_id"].get("module", "General"),
            "completion": min(100, r.get("answers", 0)),
            "updated_at": r.get("updated_at")
        })

    return render_template(
        "teacher_growth_hub.html",
        growth_data=growth_data
    )
@app.route("/teacher/export", methods=["GET"])
@login_required
@teacher_required
def export_hub():
    return render_template("export_hub.html")
def export_applications(file_format):
    applications = list(applications_col.find())

    if file_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Student", "Job", "Status"])

        for a in applications:
            writer.writerow([
                a.get("student_name"),
                a.get("job_title"),
                a.get("status")
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=applications.csv"}
        )

def export_students(fmt):
    students = list(users_col.find({"role": "student"}))

    if fmt == "csv":
        return export_students_csv(students)

    if fmt == "pdf":
        return export_students_pdf(students)

        
        
@app.route("/teacher/export/preview")
@login_required
@teacher_required
def export_preview():
    preview = {
        "students": users_col.count_documents({"role": "student"}),

        "applications": applications_col.count_documents({}),

        "corrections": applications_col.count_documents({
            "status": "corrections_needed"
        }),

        "reuploads": applications_col.count_documents({
            "status": "resubmitted"
        }),
    }

    return jsonify(preview)
@app.route("/teacher/export/zip", methods=["POST"])
@login_required
@teacher_required
def export_zip():
    datasets = request.form.getlist("datasets")
    fmt = request.form.get("format")

    if not datasets or not fmt:
        flash("⚠️ Select datasets and format.", "warning")
        return redirect(url_for("export_hub"))

    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:

        if "students" in datasets:
            content, filename = generate_students_file(fmt)
            zf.writestr(filename, content)

        if "applications" in datasets:
            content, filename = generate_applications_file(fmt)
            zf.writestr(filename, content)

        if "corrections" in datasets:
            content, filename = generate_corrections_file(fmt)
            zf.writestr(filename, content)

        if "reuploads" in datasets:
            content, filename = generate_reuploads_file(fmt)
            zf.writestr(filename, content)

    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name="know_thyself_export.zip",
        mimetype="application/zip"
    )
def generate_students_file(fmt):
    students = list(users_col.find({"role": "student"}))

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Email", "Department"])

        for s in students:
            writer.writerow([
                s.get("name"),
                s.get("email"),
                s.get("department")
            ])

        return output.getvalue(), "students.csv"

    if fmt == "pdf":
        return generate_students_pdf(students), "students.pdf"
@app.route("/teacher/assess/<job_id>", methods=["GET", "POST"])
@login_required
@teacher_required
def assess_students_for_job(job_id):
    """Teacher view to assess and update student job applications."""

    job_oid = mongo_objid_from_str(job_id)
    if not job_oid:
        flash("❌ Invalid Job ID.", "danger")
        return redirect(url_for("manage_jobs"))

    # ========================== POST ==========================
    if request.method == "POST":
        app_id = request.form.get("app_id")
        new_status = request.form.get("status")
        feedback = request.form.get("feedback", "").strip()

        application = applications_col.find_one({"_id": ObjectId(app_id)})
        if not application:
            flash("⚠️ Application not found.", "danger")
            return redirect(url_for("assess_students_for_job", job_id=job_id))

        previous_status = application.get("status")

        # ---- Update application status FIRST ----
        applications_col.update_one(
            {"_id": ObjectId(app_id)},
            {"$set": {
                "status": new_status,
                "teacher_feedback": feedback,
                "last_updated": datetime.now(IST)
            }}
        )

        # ---- Resolve student safely ----
        applicant_id = (
            application.get("applicant_id")
            or application.get("student_id")
            or application.get("user_id")
        )

        student = None
        if applicant_id:
            try:
                student = users_col.find_one({"_id": ObjectId(applicant_id)})
            except Exception:
                student = users_col.find_one({
                    "$or": [
                        {"student_id": str(applicant_id)},
                        {"user_id": str(applicant_id)}
                    ]
                })

        student_name = student.get("name", "Student") if student else "Student"
        student_email = student.get("email") if student else None

        job = jobs_col.find_one({"_id": application.get("job_id")})
        job_title = job.get("title", "Application") if job else "Application"

        # ================= Vacancy Management =================
        if job:
            vacancies = job.get("vacancies", 0)

            if new_status == "rejected" and previous_status != "rejected":
                vacancies += 1

            elif new_status == "submitted" and previous_status != "submitted":
                vacancies = max(0, vacancies - 1)

            jobs_col.update_one(
                {"_id": job["_id"]},
                {"$set": {"vacancies": vacancies}}
            )

        # ================= Mail Triggers =================
        if new_status == "corrections_needed":
            mailtrigger.on_corrections_requested(
                student_name=student_name,
                student_email=student_email,
                job_title=job_title,
                app_id=app_id
            )

        elif new_status in ["approved", "rejected", "under_review", "cleared"]:
            mailtrigger.on_status_updated(
                student_name=student_name,
                student_email=student_email,
                job_title=job_title,
                new_status=new_status,
                feedback=feedback
            )

        flash("✅ Application updated successfully.", "success")
        return redirect(url_for("assess_students_for_job", job_id=job_id))

    # ========================== GET ==========================
    job = jobs_col.find_one({"_id": job_oid})
    if not job:
        flash("⚠️ Job not found.", "danger")
        return redirect(url_for("manage_jobs"))

    applications = list(
        applications_col.find({"job_id": job_oid}).sort("application_time", -1)
    )

    for application_entry in applications:
        applicant_id = (
            application_entry.get("applicant_id")
            or application_entry.get("user_id")
        )

        student = None
        if applicant_id:
            try:
                student = users_col.find_one({"_id": ObjectId(applicant_id)})
            except Exception:
                student = users_col.find_one({
                    "$or": [
                        {"student_id": str(applicant_id)},
                        {"user_id": str(applicant_id)}
                    ]
                })

        application_entry["student_name"] = (
            student.get("name", "Unknown") if student else "Unknown"
        )
        application_entry["student_email"] = (
            student.get("email", "N/A") if student else "N/A"
        )
        application_entry["job_title"] = job.get("title", "Unknown")
        application_entry["app_id_str"] = str(application_entry["_id"])

        application_entry["photo_drive_link"] = (
            application_entry.get("photo_drive_link")
            or application_entry.get("photo_url")
            or application_entry.get("photo_link")
        )
        application_entry["resume_drive_link"] = (
            application_entry.get("resume_drive_link")
            or application_entry.get("resume_url")
            or application_entry.get("resume_link")
        )

    return render_template(
        "assess_students.html",
        applications=applications,
        job=job
    )
from flask import Response, send_file
from bson import ObjectId
import mimetypes
import os

@app.route("/get_file/<file_id>")
@login_required
def get_file(file_id):
    """
    Serve files inline (not downloaded).
    Supports both GridFS (database) and fallback to local uploads.
    """
    try:
        # Try fetching from GridFS first
        file = fs.get(ObjectId(file_id))
        content_type = file.content_type or "application/octet-stream"
        filename = file.filename
        data = file.read()

        # Force inline viewing
        response = Response(data, mimetype=content_type)
        response.headers["Content-Disposition"] = f"inline; filename={filename}"
        return response

    except Exception:
        # If not found in GridFS, try from local /uploads folder
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_id)
        if os.path.exists(file_path):
            # Guess MIME type (pdf, image, etc)
            mime_type, _ = mimetypes.guess_type(file_path)
            mime_type = mime_type or "application/octet-stream"
            return send_file(file_path, mimetype=mime_type, as_attachment=False)
        abort(404)

@app.route("/view_drive_file/<app_id>/<file_type>")
@login_required
def view_drive_file(app_id, file_type):
    """
    Allows teachers or students to view a file directly from Google Drive.
    file_type: 'photo' or 'resume'
    """
    app_doc = applications_col.find_one({"_id": ObjectId(app_id)})
    if not app_doc:
        flash("⚠️ Application not found.", "danger")
        return redirect(url_for("teacher_dashboard"))

    # Match correct field
    drive_link = None
    if file_type == "photo":
        drive_link = (
            app_doc.get("photo_drive_link")
            or app_doc.get("photo_url")
            or app_doc.get("photo_link")
        )
    elif file_type == "resume":
        drive_link = (
            app_doc.get("resume_drive_link")
            or app_doc.get("resume_url")
            or app_doc.get("resume_link")
        )

    if not drive_link:
        flash("⚠️ File not available.", "warning")
        return redirect(url_for("assess_students_for_job", job_id=str(app_doc.get("job_id"))))

    # Redirect directly to the Drive view link
    return redirect(drive_link)

@app.route("/teacher/clear_applications", methods=["GET", "POST"])
@login_required
@teacher_required
def clear_applications():

    # ---------------- GET ALL APPLICATIONS ----------------
    try:
        applications = list(
            applications_col.find().sort("application_time", -1)
        )
    except Exception as e:
        flash("⚠️ Database temporarily unavailable.", "danger")
        return redirect(url_for("teacher_dashboard"))

    # ---------------- POST: CLEAR APPLICATION ----------------
    if request.method == "POST":
        app_id = request.form.get("app_id")

        if not app_id:
            flash("⚠️ Missing application ID.", "danger")
            return redirect(url_for("clear_applications"))

        app_oid = mongo_objid_from_str(app_id)
        if not app_oid:
            flash("❌ Invalid application ID.", "danger")
            return redirect(url_for("clear_applications"))

        application = applications_col.find_one({"_id": app_oid})
        if not application:
            flash("❌ Application not found.", "danger")
            return redirect(url_for("clear_applications"))

        # 🔹 Delete uploaded files safely
        for key in ("resume_filename", "photo_filename"):
            filename = application.get(key)
            if filename:
                path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass  # never block deletion due to file issues

        # 🔹 Restore job vacancy
        job = jobs_col.find_one({"_id": application.get("job_id")})
        if job:
            jobs_col.update_one(
                {"_id": job["_id"]},
                {"$inc": {"vacancies": 1}}
            )

        # 🔹 Remove application from DB
        applications_col.delete_one({"_id": app_oid})

        flash("✅ Application permanently cleared.", "success")
        return redirect(url_for("clear_applications"))

    # ---------------- BUILD TABLE DATA ----------------
    applications_with_details = []

    for app_entry in applications:

        applicant_id = (
            app_entry.get("applicant_id")
            or app_entry.get("user_id")
            or app_entry.get("student_id")
        )

        student = None
        if applicant_id:
            try:
                student = users_col.find_one({"_id": ObjectId(applicant_id)})
            except Exception:
                student = users_col.find_one({
                    "$or": [
                        {"student_id": str(applicant_id)},
                        {"user_id": str(applicant_id)},
                        {"email": str(applicant_id)}
                    ]
                })

        job = jobs_col.find_one({"_id": app_entry.get("job_id")})

        applications_with_details.append({
            "app_id_str": str(app_entry["_id"]),
            "student_name": student.get("name") if student else "Unknown",
            "student_email": student.get("email") if student else "N/A",
            "job_title": (
                job.get("title")
                if job else app_entry.get("job_title", "Unknown")
            ),
            "status": app_entry.get("status", "unknown")
        })

    return render_template(
        "clear_application.html",
        applications=applications_with_details
    )
@app.route("/teacher/clear-application/<app_id>", methods=["POST"])
@login_required
@teacher_required
def clear_application(app_id):
    # Find the application
    application = applications_col.find_one({"_id": mongo_objid_from_str(app_id)})
    if not application:
        flash("⚠️ Application not found.", "danger")
        return redirect(url_for("assess_students"))

    # --- Handle vacancy restoration ---
    job = jobs_col.find_one({"_id": application.get("job_id")})
    if job:
        new_vacancies = job.get("vacancies", 0) + 1
        jobs_col.update_one({"_id": job["_id"]}, {"$set": {"vacancies": new_vacancies}})
        logger.info(f"Vacancy restored for job '{job.get('title', 'Unknown')}'. Now: {new_vacancies}")

    # --- Delete uploaded files (resume & photo) safely ---
    for key in ("resume_filename", "photo_filename"):
        filename = application.get(key)
        if filename:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted file: {file_path}")
            except Exception as e:
                logger.exception(f"Failed to remove {file_path}: {e}")

    # --- Remove the application from database ---
    applications_col.delete_one({"_id": application["_id"]})

    flash("🗑️ Application cleared and vacancy restored.", "success")
    return redirect(url_for("assess_students"))

# -------------------------
# Exports (CSV)
# -------------------------
# --------------------------------------------------------------------------
# Teacher: Export Dashboard Data (Registered & Assessed Students)
# --------------------------------------------------------------------------
from flask import make_response
import pandas as pd
from io import BytesIO

@app.route("/teacher/export", methods=["GET"])
@login_required
@teacher_required
def export_dashboard_data():
    """
    Exports two Excel sheets:
    1. Registered Students
    2. Assessed Applications
    """
    # Fetch Registered Students
    students = list(db.users.find({"role": "student"}))
    for s in students:
        s["_id"] = str(s["_id"])

    # Fetch Applications with Student & Job info
    applications = list(db.applications.find())
    for a in applications:
        user = db.users.find_one({"_id": a.get("applicant_id")})
        job = db.jobs.find_one({"_id": a.get("job_id")})
        a["student_name"] = user.get("name") if user else "Unknown"
        a["student_email"] = user.get("email") if user else "N/A"
        a["job_title"] = job.get("title") if job else "N/A"
        a["_id"] = str(a["_id"])
        if a.get("application_time"):
            a["application_time"] = a["application_time"].strftime("%Y-%m-%d %H:%M:%S")

    # Create DataFrames
    df_students = pd.DataFrame(students)
    df_apps = pd.DataFrame(applications)

    # Excel in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df_students.to_excel(writer, sheet_name="Registered Students", index=False)
        df_apps.to_excel(writer, sheet_name="Assessed Applications", index=False)

    # Build response
    output.seek(0)
    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=TeacherDashboardData.xlsx"
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return response

@app.route("/teacher/export/registered")
@login_required
def export_registered_students():
    from io import BytesIO
    import pandas as pd
    from flask import send_file

    students = list(db.users.find({"role": "student"}))
    if not students:
        flash("No registered students to export.", "warning")
        return redirect(url_for("registered_students"))

    # Convert MongoDB data to DataFrame
    df = pd.DataFrame(students)
    df = df[["name", "email"]]  # Keep relevant columns only

    # Convert to Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Registered Students")

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="registered_students.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# --------------------------------------------------------------------------
# Teacher: View Registered Students
# --------------------------------------------------------------------------
@app.route("/teacher/registered_students")
@login_required
@teacher_required
def registered_students():
    """
    Displays a list of all registered students from the database.
    """
    students = list(db.users.find({"role": "student"}))
    for s in students:
        s["_id"] = str(s["_id"])
        s["app_count"] = db.applications.count_documents({"applicant_id": s["_id"]})
        s["growth_progress"] = 0  # placeholder — replace if growth tracking exists

    return render_template("registered_students.html", students=students)

@app.route("/teacher/export/assessed_students")
@login_required
@teacher_required
def export_assessed_students():
    cursor = applications_col.find({"status": {"$in": ["approved", "rejected", "corrections_needed", "resubmitted"]}})
    rows = []
    for a in cursor:
        applicant = users_col.find_one({"_id": a.get("applicant_id")})
        rows.append({
            "application_id": str(a.get("_id")),
            "student_name": applicant.get("name") if applicant else "",
            "student_email": applicant.get("email") if applicant else "",
            "job_title": a.get("job_title"),
            "status": a.get("status"),
            "application_time": a.get("application_time").isoformat() if a.get("application_time") else "",
            "teacher_feedback": a.get("teacher_feedback", "")
        })
    df = pd.DataFrame(rows)
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="assessed_students.csv", mimetype="text/csv")

# -------------------------
# Debug route (DB counts)
# -------------------------
@app.route("/debug/db")
def debug_db():
    try:
        info = {
            "users": users_col.count_documents({}),
            "jobs": jobs_col.count_documents({}),
            "applications": applications_col.count_documents({}),
            "growth_responses": growth_col.count_documents({}),
            "self_assessments": self_assess_col.count_documents({})
        }
        sample_users = list(users_col.find().limit(5))
        # convert ObjectId to str for JSON
        for u in sample_users:
            u["_id"] = str(u["_id"])
            if "created_at" in u and hasattr(u["created_at"], "isoformat"):
                u["created_at"] = u["created_at"].isoformat()
        return jsonify({"ok": True, "info": info, "sample_users": sample_users})
    except Exception as e:
        logger.exception("Debug DB failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Error handlers
# -------------------------
@app.errorhandler(403)
def forbidden(e):
    try:
        return render_template("403.html"), 403
    except Exception:
        return "403 Forbidden", 403

@app.errorhandler(404)
def not_found(e):
    try:
        return render_template("404.html"), 404
    except Exception:
        return "404 Not Found", 404

@app.errorhandler(500)
def server_error(e):
    try:
        return render_template("500.html", error=str(e)), 500
    except Exception:
        return f"500 Server Error: {e}", 500

# -------------------------
# Helper: ensure templates present (warn)
# -------------------------
def check_templates_exist():
    # We'll scan common templates referenced above
    templates = [
        "startpage.html", "login.html", "register.html", "student_dashboard.html",
        "teacher_dashboard.html", "upload_files.html", "upload_blocked.html",
        "add_job.html", "manage_jobs.html", "edit_job.html", "job_detail.html",
        "assess_students.html", "403.html", "404.html", "500.html"
    ]
    missing = []
    for t in templates:
        p = BASE_DIR / "templates" / t
        if not p.exists():
            missing.append(t)
    if missing:
        logger.warning("Missing templates detected: %s", missing)

# Run check at startup
check_templates_exist()

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/resources")
def resources():
    return render_template("resources.html")

@app.route("/advice")
def advice():
    return render_template("advice.html")

@app.route("/creator")
def creator():
    return render_template("creator.html")

import random

@app.route("/student/motivation")
@login_required
@student_required
def motivation_hub():
    quotes = [
        {"quote": "Knowing yourself is the beginning of all wisdom.", "author": "Aristotle"},
        {"quote": "What we achieve inwardly will change outer reality.", "author": "Plutarch"},
        {"quote": "Growth begins at the edge of comfort.", "author": "Anonymous"},
        {"quote": "You don’t have to be perfect to be powerful.", "author": "Psychology Insight"},
        {"quote": "Self-awareness is the most powerful change tool.", "author": "Clinical Psychology"},
        {"quote": "Your mind is not your enemy. It is your instrument.", "author": "Cognitive Science"},
        {"quote": "Small progress is still progress.", "author": "Student Psychology"},
        {"quote": "Your thoughts shape your future.", "author": "Cognitive Theory"},
        {"quote": "Healing is not linear, and that’s okay.", "author": "Mental Health Studies"},
        {"quote": "Discipline is self-respect in action.", "author": "Behavioral Science"},
        {"quote": "Consistency builds confidence.", "author": "Academic Psychology"},
        {"quote": "Your effort matters more than your talent.", "author": "Educational Psychology"},
        {"quote": "Emotional intelligence is real intelligence.", "author": "Psychology Today"},
        {"quote": "Every struggle rewires your strength.", "author": "Neuropsychology"},
        {"quote": "Your mind learns what you repeatedly tell it.", "author": "Cognitive Science"},
        {"quote": "You grow when you challenge your comfort zone.", "author": "Behavioral Therapy"},
        {"quote": "Focus creates clarity.", "author": "Mental Performance"},
        {"quote": "Your habits shape your identity.", "author": "Behavioral Psychology"},
        {"quote": "Learning is self-transformation.", "author": "Educational Science"},
        {"quote": "The brain grows through effort.", "author": "Neuroscience"},
        {"quote": "Self-discipline is self-love.", "author": "Mental Wellness"},
        {"quote": "Failure is feedback, not defeat.", "author": "Growth Psychology"},
        {"quote": "Your mindset determines your direction.", "author": "Positive Psychology"},
        {"quote": "Progress beats perfection.", "author": "Student Mindset"},
        {"quote": "Resilience is built, not born.", "author": "Clinical Studies"},
        {"quote": "Your focus defines your reality.", "author": "Cognitive Focus"},
        {"quote": "Strong minds create strong futures.", "author": "Mental Health Academy"},
        {"quote": "Self-control is a superpower.", "author": "Behavioral Science"},
        {"quote": "Awareness creates change.", "author": "Psychological Research"},
        {"quote": "Your effort is never wasted.", "author": "Academic Growth"},
        {"quote": "Calm minds learn better.", "author": "Neuroeducation"},
        {"quote": "Belief drives behavior.", "author": "Cognitive Theory"},
        {"quote": "Mental strength grows with challenge.", "author": "Neuroscience"},
        {"quote": "You are becoming, not stuck.", "author": "Student Psychology"},
        {"quote": "Self-belief fuels success.", "author": "Positive Psychology"},
        {"quote": "Focus is mental discipline.", "author": "Cognitive Training"},
        {"quote": "Your brain adapts to what you practice.", "author": "Neuroplasticity"},
        {"quote": "Learning builds inner power.", "author": "Psychology Academy"},
        {"quote": "Your mind is trainable.", "author": "Cognitive Science"},
        {"quote": "Patience strengthens intelligence.", "author": "Behavioral Studies"},
        {"quote": "Mental growth requires discomfort.", "author": "Developmental Psychology"},
        {"quote": "Effort builds excellence.", "author": "Educational Psychology"},
        {"quote": "Your emotions are data, not commands.", "author": "Emotional Psychology"},
        {"quote": "Self-regulation creates freedom.", "author": "Clinical Psychology"},
        {"quote": "Thoughts become behaviors.", "author": "Cognitive Behavioral Therapy"},
        {"quote": "Your discipline defines your destiny.", "author": "Behavioral Science"},
        {"quote": "Learning is mental empowerment.", "author": "Academic Psychology"},
        {"quote": "Focus builds mastery.", "author": "Performance Psychology"},
        {"quote": "Self-control creates success.", "author": "Mental Training"},
        {"quote": "The mind grows with intention.", "author": "Cognitive Growth"},
        {"quote": "Resilience is psychological strength.", "author": "Clinical Psychology"},
        {"quote": "Your attitude trains your brain.", "author": "Neuroscience"},
        {"quote": "Mental clarity creates progress.", "author": "Psychological Wellness"},
        {"quote": "Growth starts with self-belief.", "author": "Positive Psychology"},
        {"quote": "Your mind is your greatest asset.", "author": "Cognitive Science"},
        {"quote": "Consistency builds success.", "author": "Behavioral Psychology"},
        {"quote": "Your brain rewards discipline.", "author": "Neurobehavioral Science"},
        {"quote": "Inner strength creates outer success.", "author": "Mental Health Studies"},
        {"quote": "Psychological growth is real growth.", "author": "Clinical Psychology"},
        {"quote": "Your focus fuels achievement.", "author": "Mental Performance"},
        {"quote": "Your mindset shapes your learning.", "author": "Educational Psychology"},
        {"quote": "Mental habits define outcomes.", "author": "Behavioral Science"},
        {"quote": "Learning is brain training.", "author": "Neuroscience"},
        {"quote": "Effort strengthens the mind.", "author": "Cognitive Development"},
        {"quote": "Discipline trains the brain.", "author": "Neuropsychology"},
        {"quote": "Your thoughts guide your actions.", "author": "Cognitive Therapy"},
        {"quote": "Self-growth is self-respect.", "author": "Mental Wellness"},
        {"quote": "Strong focus creates strong minds.", "author": "Cognitive Training"},
        {"quote": "Learning builds mental resilience.", "author": "Psychological Science"},
        {"quote": "Your brain evolves with effort.", "author": "Neuroplasticity"},
        {"quote": "Self-discipline builds confidence.", "author": "Behavioral Studies"},
        {"quote": "Your mindset builds your future.", "author": "Positive Psychology"},
        {"quote": "Mental training builds success.", "author": "Performance Psychology"},
        {"quote": "Awareness builds wisdom.", "author": "Psychological Insight"},
        {"quote": "Consistency rewires the brain.", "author": "Neuroscience"},
        {"quote": "Growth is a daily decision.", "author": "Student Psychology"},
        {"quote": "Your thoughts train your mind.", "author": "Cognitive Science"},
        {"quote": "Effort creates intelligence.", "author": "Educational Psychology"},
        {"quote": "Mental discipline builds freedom.", "author": "Behavioral Psychology"},
        {"quote": "Learning strengthens the brain.", "author": "Neuroscience"},
        {"quote": "Your inner world shapes your outer world.", "author": "Psychology Insight"},
        {"quote": "Psychological strength builds life strength.", "author": "Clinical Psychology"},
        {"quote": "Mindset is mental architecture.", "author": "Cognitive Science"},
        {"quote": "Your brain becomes what you train it to be.", "author": "Neuroplasticity"},
        {"quote": "Growth is a mental skill.", "author": "Psychological Training"},
        {"quote": "Your focus defines your future.", "author": "Mental Performance"},
        {"quote": "Mental resilience builds success.", "author": "Clinical Studies"}
    ]

    today_quote = random.choice(quotes)

    return render_template(
        "motivation_hub.html",
        quote=today_quote
    )

from flask_wtf.csrf import generate_csrf
app.config.update(
    SESSION_TYPE="filesystem",   # simple & stable
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_FILE_DIR="./flask_sessions",
)
Session(app)
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)
print(app.url_map)
from pymongo.read_preferences import ReadPreference
db = db.with_options(read_preference=ReadPreference.PRIMARY_PREFERRED)
# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    # Local dev: port 10000
    port = int(os.getenv("PORT", 10000))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info("Starting Know-Thyself local server on %s:%s", host, port)
    app.run(host=host, port=port, debug=True)