import os
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.firefox import GeckoDriverManager

BASE_URL = "http://127.0.0.1:5000"
OUTPUT_ROOT = "auto_screenshots"

# ============================
# ROUTES (FROM YOUR AUDIT)
# ============================

PUBLIC_ROUTES = {
    "index": "/",
    "about": "/about",
    "contact": "/contact",
    "support": "/support",
    "resources": "/resources",
    "advice": "/advice",
    "creator": "/creator"
}

STUDENT_ROUTES = {
    "dashboard": "/student/",
    "applications": "/student/applications",
    "jobs": "/student/jobs",
    "profile": "/student/profile",
    "growth_menu": "/student/growth",
    "growth_random": "/student/growth/random",
    "motivation": "/student/motivation",
    "self_assessment_intro": "/student/self-assessment",
    "self_assessment_start": "/student/self-assessment/start",
    "self_assessment_finish": "/student/self-assessment/finish"
}

TEACHER_ROUTES = {
    "dashboard": "/teacher/dashboard",
    "registered_students": "/teacher/registered_students",
    "manage_jobs": "/teacher/manage_jobs",
    "add_job": "/teacher/add_job",
    "self_assessments": "/teacher/self-assessments",
    "growth_responses": "/teacher/growth-responses",
    "growth_hub": "/teacher/growth_hub",
    "export": "/teacher/export",
    "export_preview": "/teacher/export/preview"
}

CREDENTIALS = {
    "student": {
        "email": "dhatchinamoorthi.23bpy@kclas.ac.in",
        "password": "password1234"
    },
    "teacher": {
        "email": "gnanaprakash@kclas.ac.in",
        "password": "gpsir098"
    }
}


# ============================
# BROWSER SETUP
# ============================

def start_browser():
    options = Options()
    options.headless = True

    driver = webdriver.Firefox(
        service=Service(GeckoDriverManager().install()),
        options=options
    )
    driver.set_window_size(1440, 2200)
    return driver


# ============================
# LOGIN
# ============================

def login(driver, role):
    print(f"🔐 Logging in as {role.upper()}")
    driver.get(BASE_URL + "/login")

    wait = WebDriverWait(driver, 15)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "input")))

    inputs = driver.find_elements(By.TAG_NAME, "input")
    email_input = next(i for i in inputs if i.get_attribute("type") in ["email", "text"])
    password_input = next(i for i in inputs if i.get_attribute("type") == "password")

    email_input.send_keys(CREDENTIALS[role]["email"])
    password_input.send_keys(CREDENTIALS[role]["password"])
    password_input.send_keys(Keys.RETURN)

    time.sleep(4)


# ============================
# SCREENSHOT ROUTES
# ============================

def capture_routes(driver, role, routes):
    folder = os.path.join(OUTPUT_ROOT, role)
    os.makedirs(folder, exist_ok=True)

    print(f"\n📸 Capturing {role.upper()} routes")

    for name, route in routes.items():
        url = BASE_URL + route
        print(" →", url)

        driver.get(url)
        time.sleep(2)

        filepath = os.path.join(folder, f"{name}.png")
        driver.save_screenshot(filepath)
        print("   ✅ Saved:", filepath)


# ============================
# MAIN
# ============================

def main():
    os.makedirs(OUTPUT_ROOT, exist_ok=True)

    # ---------- PUBLIC ----------
    print("\n🌐 Capturing PUBLIC pages")
    driver = start_browser()
    for name, route in PUBLIC_ROUTES.items():
        driver.get(BASE_URL + route)
        time.sleep(2)

        path = os.path.join(OUTPUT_ROOT, "public")
        os.makedirs(path, exist_ok=True)
        driver.save_screenshot(os.path.join(path, f"{name}.png"))
    driver.quit()

    # ---------- STUDENT ----------
    driver = start_browser()
    login(driver, "student")
    capture_routes(driver, "student", STUDENT_ROUTES)
    driver.quit()

    # ---------- TEACHER ----------
    driver = start_browser()
    login(driver, "teacher")
    capture_routes(driver, "teacher", TEACHER_ROUTES)
    driver.quit()

    print("\n🎉 ALL SCREENSHOTS CAPTURED SUCCESSFULLY")


if __name__ == "__main__":
    main()