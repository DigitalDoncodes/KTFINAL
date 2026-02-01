# open_teacher_pages.py
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.firefox import GeckoDriverManager

BASE_URL = "http://127.0.0.1:5000"

# ===============================
# TEACHER CREDENTIALS (TEMP)
# ===============================
TEACHER_EMAIL = "gnanaprakash@kclas.ac.in"
TEACHER_PASSWORD = "gpsir098"

# ===============================
# TEACHER ROUTES TO CHECK
# ===============================
TEACHER_PAGES = [
    "/teacher/dashboard",
    "/teacher/add_job",
    "/teacher/manage_jobs",
    "/teacher/self-assessments",
    "/teacher/growth_hub",
    "/teacher/growth-responses",
    "/teacher/export",
    "/teacher/export/preview",
    "/teacher/registered_students",
]

def login_and_open_teacher_pages():
    print("🦊 Launching Firefox (Teacher Check)…")

    options = Options()
    options.headless = False

    driver = webdriver.Firefox(
        service=Service(GeckoDriverManager().install()),
        options=options
    )
    driver.maximize_window()

    wait = WebDriverWait(driver, 15)

    # -------------------------------
    # LOGIN AS TEACHER
    # -------------------------------
    print("👨‍🏫 Logging in as TEACHER")
    driver.get(BASE_URL + "/login")

    # wait until login form loads
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "input")))
    inputs = driver.find_elements(By.TAG_NAME, "input")

    email_input = None
    password_input = None

    for inp in inputs:
        t = inp.get_attribute("type")
        if t in ["email", "text"] and email_input is None:
            email_input = inp
        if t == "password":
            password_input = inp

    if not email_input or not password_input:
        print("❌ Could not locate login fields on login page")
        driver.quit()
        return

    email_input.clear()
    email_input.send_keys(TEACHER_EMAIL)

    password_input.clear()
    password_input.send_keys(TEACHER_PASSWORD)
    password_input.send_keys(Keys.RETURN)

    print("⏳ Waiting for teacher dashboard…")
    time.sleep(4)

    # -------------------------------
    # OPEN TEACHER PAGES
    # -------------------------------
    print("📄 Opening teacher pages:\n")

    for path in TEACHER_PAGES:
        url = BASE_URL + path
        print("🔗", url)
        driver.execute_script(f"window.open('{url}', '_blank');")
        time.sleep(1.2)

    print("\n✅ All teacher pages opened")
    print("👀 Visually inspect layouts, tables, empty states")

if __name__ == "__main__":
    login_and_open_teacher_pages()