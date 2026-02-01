# app_audit.py
from flask import Flask

def create_app():
    app = Flask(__name__)

    # Import ONLY route files (no mail, no DB triggers)
    import routes
    import auth_routes
    import student_routes
    import teacher_routes
    import admin_routes

    return app