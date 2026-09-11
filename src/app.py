"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi import Cookie, FastAPI, HTTPException, Response
from pydantic import BaseModel
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

TEACHERS_FILE = current_dir / "teachers.json"
SESSION_COOKIE = "teacher_session"
SESSION_MAX_AGE = 8 * 60 * 60
SESSION_SECRET = os.getenv("SESSION_SECRET", "development-only-change-me").encode()

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


def load_teachers():
    with TEACHERS_FILE.open(encoding="utf-8") as teachers_file:
        return json.load(teachers_file)


def verify_password(password, stored_password):
    salt, expected_hash = stored_password.split("$", 1)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 120_000
    ).hex()
    return hmac.compare_digest(password_hash, expected_hash)


def create_session(username):
    expires_at = int(time.time()) + SESSION_MAX_AGE
    payload = f"{username}|{expires_at}".encode()
    signature = hmac.new(SESSION_SECRET, payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + signature


def get_authenticated_teacher(session):
    if not session or "." not in session:
        return None

    encoded_payload, signature = session.split(".", 1)
    try:
        payload = base64.urlsafe_b64decode(encoded_payload + "===")
        username, expires_at = payload.decode().split("|", 1)
    except (ValueError, UnicodeDecodeError):
        return None

    expected_signature = hmac.new(
        SESSION_SECRET, payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    if int(expires_at) < time.time():
        return None
    if username not in load_teachers():
        return None
    return username


def require_teacher(session):
    username = get_authenticated_teacher(session)
    if not username:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.get("/auth/me")
def get_current_teacher(teacher_session: str | None = Cookie(default=None)):
    username = get_authenticated_teacher(teacher_session)
    return {"authenticated": bool(username), "username": username}


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response):
    stored_password = load_teachers().get(credentials.username)
    if not stored_password or not verify_password(credentials.password, stored_password):
        raise HTTPException(status_code=401, detail="Invalid teacher credentials")

    response.set_cookie(
        SESSION_COOKIE,
        create_session(credentials.username),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return {"message": "Teacher login successful", "username": credentials.username}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"message": "Teacher logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    teacher_session: str | None = Cookie(default=None),
):
    """Sign up a student for an activity"""
    require_teacher(teacher_session)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    teacher_session: str | None = Cookie(default=None),
):
    """Unregister a student from an activity"""
    require_teacher(teacher_session)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
