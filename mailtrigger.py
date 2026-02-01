# mailtrigger.py
from flask import render_template, url_for
from datetime import datetime
import os


# --------------------------------------------------
# Internal helper (lazy import to avoid circular deps)
# --------------------------------------------------
def _get_mail_utils():
    """
    Lazy import to prevent circular imports with app.py
    """
    from app import send_brevo_email, make_attachment_from_file_path, IST
    return send_brevo_email, make_attachment_from_file_path, IST


# --------------------------------------------------
# 1. Application Submitted (after upload)
# --------------------------------------------------
def on_application_submitted(
    *,
    student_name,
    student_email,
    job_title,
    app_id,
    submitted_time,
    resume_path=None,
    photo_path=None
):
    """Triggered when student uploads resume + photo"""

    send_brevo_email, make_attachment_from_file_path, _ = _get_mail_utils()

    teacher_email = os.getenv("TEACHER_INBOX", "psychologyresumemail@gmail.com")

    # ---------- Attachments ----------
    attachments = []
    if resume_path:
        att = make_attachment_from_file_path(resume_path)
        if att:
            attachments.append(att)

    if photo_path:
        att = make_attachment_from_file_path(photo_path)
        if att:
            attachments.append(att)

    # ---------- Teacher mail ----------
    teacher_html = render_template(
        "email/email_admin_notification.html",
        app={
            "name": student_name,
            "email": student_email,
            "job_title": job_title,
            "submitted_at": submitted_time,
        }
    )

    send_brevo_email(
        teacher_email,
        "Teacher",
        f"📥 New Application from {student_name}",
        teacher_html,
        attachments=attachments,
        async_send=True
    )

    # ---------- Student confirmation ----------
    student_html = render_template(
        "email/email_student_confirmation.html",
        app={
            "name": student_name,
            "job_title": job_title,
            "submitted_at": submitted_time,
        }
    )

    send_brevo_email(
        student_email,
        student_name,
        f"✅ Application received for {job_title}",
        student_html,
        async_send=True
    )


# --------------------------------------------------
# 2. Corrections Requested
# --------------------------------------------------
def on_corrections_requested(
    *,
    student_name,
    student_email,
    job_title,
    app_id
):
    """Triggered when teacher requests corrections"""

    send_brevo_email, _, _ = _get_mail_utils()

    upload_link = url_for("upload_files", app_id=app_id, _external=True)

    html = render_template(
        "email/email_status_update.html",
        name=student_name,
        job_title=job_title,
        status="corrections_needed",
        upload_link=upload_link
    )

    send_brevo_email(
        student_email,
        student_name,
        f"⚙️ Corrections requested – {job_title}",
        html,
        async_send=True
    )


# --------------------------------------------------
# 3. Re-upload Completed
# --------------------------------------------------
def on_files_reuploaded(
    *,
    student_name,
    student_email,
    job_title,
    app_id,
    resume_path=None,
    photo_path=None
):
    """Triggered after student re-uploads files"""

    send_brevo_email, make_attachment_from_file_path, IST = _get_mail_utils()

    teacher_email = os.getenv("TEACHER_INBOX", "psychologyresumemail@gmail.com")

    attachments = []
    if resume_path:
        att = make_attachment_from_file_path(resume_path)
        if att:
            attachments.append(att)

    if photo_path:
        att = make_attachment_from_file_path(photo_path)
        if att:
            attachments.append(att)

    # ---------- Student mail ----------
    send_brevo_email(
        student_email,
        student_name,
        f"✅ Files re-uploaded for {job_title}",
        render_template(
            "email/email_status_update.html",
            name=student_name,
            job_title=job_title,
            status="resubmitted"
        ),
        async_send=True
    )

    # ---------- Teacher mail ----------
    send_brevo_email(
        teacher_email,
        "Teacher",
        f"📥 Updated files from {student_name}",
        render_template(
            "email/email_admin_notification.html",
            app={
                "name": student_name,
                "email": student_email,
                "job_title": job_title,
                "submitted_at": datetime.now(IST).strftime(
                    "%d %b %Y, %I:%M %p IST"
                ),
            }
        ),
        attachments=attachments,
        async_send=True
    )


# --------------------------------------------------
# 4. Status Updated (approved / rejected / etc.)
# --------------------------------------------------
def on_status_updated(
    *,
    student_name,
    student_email,
    job_title,
    new_status,
    feedback=""
):
    """Triggered when teacher updates application status"""

    send_brevo_email, _, _ = _get_mail_utils()

    html = render_template(
        "email/email_status_update.html",
        name=student_name,
        job_title=job_title,
        status=new_status,
        feedback=feedback
    )

    send_brevo_email(
        student_email,
        student_name,
        f"📢 Application Update – {job_title}",
        html,
        async_send=True
    )