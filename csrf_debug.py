# csrf_debug.py
from flask import request, session, current_app
from flask_wtf.csrf import validate_csrf, CSRFError
import logging

def log_csrf_state():
    print("\n================ CSRF DEBUG =================")
    print("REQUEST PATH:", request.path)
    print("REQUEST METHOD:", request.method)

    print("\n--- FORM DATA ---")
    print(dict(request.form))

    print("\n--- HEADERS ---")
    print({k: v for k, v in request.headers.items() if "csrf" in k.lower()})

    print("\n--- SESSION ---")
    print(dict(session))

    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")

    print("\n--- CSRF TOKEN ---")
    print("Token received:", token)

    try:
        validate_csrf(token)
        print("✅ CSRF TOKEN IS VALID")
    except Exception as e:
        print("❌ CSRF VALIDATION FAILED:", repr(e))

    print("============================================\n")