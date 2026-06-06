import base64
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

APP_NAME = "Casebook AD CTF Service"
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "casebook.sqlite3"
SHARE_SALT = os.getenv("SHARE_SALT", "winter-audit")

app = FastAPI(title=APP_NAME, version="1.0.0")


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                public_summary TEXT NOT NULL,
                secret_note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def extract_bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def current_user(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
    token = extract_bearer(authorization)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="bad token")
    return row


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=6, max_length=80)


class LoginRequest(BaseModel):
    username: str
    password: str


class CaseRequest(BaseModel):
    title: str = Field(min_length=3, max_length=100)
    category: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_-]+$")
    public_summary: str = Field(min_length=1, max_length=500)
    secret_note: str = Field(min_length=1, max_length=200)


def make_share_code(case_id: int) -> str:
    # Intentional CTF bug: the code is deterministic and based only on a public, sequential id.
    digest = hashlib.md5(f"{case_id}:{SHARE_SALT}".encode()).hexdigest()[:10]
    raw = f"{case_id}:{digest}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_share_code(code: str) -> tuple[int, str]:
    try:
        padded = code + "=" * (-len(code) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        case_id_s, digest = raw.split(":", 1)
        return int(case_id_s), digest
    except Exception as exc:
        raise HTTPException(status_code=404, detail="bad share code") from exc


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "casebook"}


@app.post("/api/users/register")
def register(req: RegisterRequest) -> dict:
    token = secrets.token_urlsafe(24)
    with db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users(username, password_hash, token, created_at) VALUES (?, ?, ?, ?)",
                (req.username, password_hash(req.password), token, now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="username already exists")
    return {"user_id": cur.lastrowid, "username": req.username, "token": token}


@app.post("/api/sessions/login")
def login(req: LoginRequest) -> dict:
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, token FROM users WHERE username = ? AND password_hash = ?",
            (req.username, password_hash(req.password)),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="bad credentials")
    return {"user_id": row["id"], "username": row["username"], "token": row["token"]}


@app.post("/api/cases")
def create_case(req: CaseRequest, user: sqlite3.Row = Depends(current_user)) -> dict:
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO cases(owner_id, title, category, public_summary, secret_note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user["id"], req.title, req.category, req.public_summary, req.secret_note, now_iso()),
        )
        conn.commit()
    case_id = cur.lastrowid
    return {"case_id": case_id, "share_code": make_share_code(case_id)}


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, user: sqlite3.Row = Depends(current_user)) -> dict:
    with db() as conn:
        row = conn.execute(
            "SELECT id, title, category, public_summary, secret_note, created_at FROM cases WHERE id = ? AND owner_id = ?",
            (case_id, user["id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="case not found")
    return dict(row)


@app.get("/api/cases")
def list_my_cases(user: sqlite3.Row = Depends(current_user)) -> dict:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, title, category, public_summary, created_at FROM cases WHERE owner_id = ? ORDER BY id DESC LIMIT 20",
            (user["id"],),
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/api/cases/{case_id}/share")
def create_share(case_id: int, user: sqlite3.Row = Depends(current_user)) -> dict:
    with db() as conn:
        row = conn.execute("SELECT id FROM cases WHERE id = ? AND owner_id = ?", (case_id, user["id"])).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="case not found")
    return {"share_code": make_share_code(case_id)}


@app.get("/api/shared/{code}")
def shared_case(code: str) -> dict:
    case_id, digest = parse_share_code(code)
    expected = hashlib.md5(f"{case_id}:{SHARE_SALT}".encode()).hexdigest()[:10]
    if not secrets.compare_digest(digest, expected):
        raise HTTPException(status_code=404, detail="bad share code")
    with db() as conn:
        row = conn.execute(
            "SELECT id, title, category, public_summary, secret_note, created_at FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="case not found")
    return dict(row)


@app.get("/api/audit/search")
def audit_search(
    category: str = Query(default="network", max_length=80),
    needle: str = Query(default="", max_length=120),
    user: sqlite3.Row = Depends(current_user),
) -> dict:
    # Intentional CTF bug: unsafe SQL string formatting in a diagnostic endpoint.
    # It leaks secret_note because internal audit preview was never trimmed for production.
    sql = (
        "SELECT id, title, category, public_summary, secret_note AS debug_preview "
        f"FROM cases WHERE category = '{category}' AND title LIKE '%{needle}%' "
        "ORDER BY id DESC LIMIT 25"
    )
    try:
        with db() as conn:
            rows = conn.execute(sql).fetchall()
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="bad audit query")
    return {"items": [dict(r) for r in rows]}
