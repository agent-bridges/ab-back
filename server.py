#!/usr/bin/env python3
"""
Agent Bridge (AB) - Main Backend
Serves frontend and proxies PTY requests to ab-pty
"""

import asyncio
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import httpx
import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from pydantic import BaseModel
import uvicorn
import websockets

app = FastAPI(title="Agent Bridge")


# Auth middleware will be added after models are defined


# === Database Setup ===
def require_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


DB_PATH = Path(require_env("AB_BACK_DB_PATH"))
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(100), nullable=False)
    jwt_key = Column(Text, nullable=True)
    is_local = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LockedProcess(Base):
    __tablename__ = "locked_processes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pty_id = Column(String(100), nullable=False)  # PTY process ID
    agent_id = Column(Integer, nullable=False, default=1)  # Agent ID
    claude_session_id = Column(String(100), nullable=True)  # Claude session ID for recreate
    project_hash = Column(String(100), nullable=True)  # Project directory hash
    project_path = Column(String(500), nullable=True)  # Full project path
    project_name = Column(String(200), nullable=True)  # Project display name
    label = Column(String(200), nullable=True)  # User-defined label
    proc_type = Column(String(20), default='claude')  # 'claude' or 'bash'
    created_at = Column(DateTime, default=datetime.utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    username = Column(String(100), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ProjectLabel(Base):
    __tablename__ = "project_labels"

    agent_id = Column(Integer, primary_key=True)
    project_hash = Column(String(200), primary_key=True)
    label = Column(String(200), nullable=False, default="")


Base.metadata.create_all(engine)


# === JWT Auth ===
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30
SESSION_EXPIRE_DAYS = 30
PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 310000
PASSWORD_SALT_BYTES = 16
DEFAULT_USERNAME = require_env("AB_DEFAULT_USERNAME")
DEFAULT_PASSWORD = require_env("AB_DEFAULT_PASSWORD")
SESSION_COOKIE_NAME = "ab_session"


def get_setting_row(db, key: str) -> Optional[Setting]:
    return db.query(Setting).filter(Setting.key == key).first()


def get_setting_value(key: str) -> Optional[str]:
    db = SessionLocal()
    try:
        setting = get_setting_row(db, key)
        return setting.value if setting else None
    finally:
        db.close()


def upsert_setting(db, key: str, value: str) -> Setting:
    setting = get_setting_row(db, key)
    if not setting:
        setting = Setting(key=key, value=value)
        db.add(setting)
    else:
        setting.value = value
    return setting


def get_jwt_secret() -> str:
    """Get or create JWT secret"""
    db = SessionLocal()
    try:
        setting = get_setting_row(db, "jwt_secret")
        if not setting:
            setting = upsert_setting(db, "jwt_secret", secrets.token_hex(32))
            db.commit()
        return setting.value
    finally:
        db.close()


def get_password_hash() -> Optional[str]:
    """Get stored password hash"""
    return get_setting_value("password_hash")


def get_username() -> str:
    """Get stored username"""
    username = get_setting_value("username")
    if not username:
        raise RuntimeError("Missing required setting: username")
    return username


def hash_session_token(token: str) -> str:
    """Hash a session token before storing it."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_session_token(username: str) -> str:
    """Create and persist a browser session token."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_EXPIRE_DAYS)
    db = SessionLocal()
    try:
        session = AuthSession(
            token_hash=hash_session_token(token),
            username=username,
            expires_at=expires_at,
        )
        db.add(session)
        db.commit()
    finally:
        db.close()
    return token


def verify_session_token(token: str) -> Optional[str]:
    """Verify a browser session token and return its username."""
    if not token:
        return None

    db = SessionLocal()
    try:
        session = db.query(AuthSession).filter(
            AuthSession.token_hash == hash_session_token(token)
        ).first()
        if not session:
            return None
        if session.expires_at <= datetime.utcnow():
            db.delete(session)
            db.commit()
            return None
        return session.username
    finally:
        db.close()


def revoke_session_token(token: Optional[str]) -> None:
    """Delete a persisted browser session token."""
    if not token:
        return

    db = SessionLocal()
    try:
        session = db.query(AuthSession).filter(
            AuthSession.token_hash == hash_session_token(token)
        ).first()
        if session:
            db.delete(session)
            db.commit()
    finally:
        db.close()


def revoke_all_sessions(username: Optional[str] = None) -> None:
    """Delete all persisted browser sessions, optionally scoped to a username."""
    db = SessionLocal()
    try:
        query = db.query(AuthSession)
        if username:
            query = query.filter(AuthSession.username == username)
        query.delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def get_cookie_secure_flag(request: Request) -> bool:
    """Decide whether auth cookies should be marked Secure."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto:
        return forwarded_proto.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def set_auth_cookie(response: Response, request: Request, token: str) -> None:
    """Attach the browser auth session cookie to a response."""
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=get_cookie_secure_flag(request),
        samesite="lax",
        max_age=SESSION_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
    )


def clear_auth_cookies(response: Response, request: Request) -> None:
    """Clear browser auth cookies from a response."""
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=get_cookie_secure_flag(request),
        samesite="lax",
    )


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-SHA256."""
    salt = os.urandom(PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_HASH_ITERATIONS)
    return f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against the current PBKDF2 hash format."""
    if not stored_hash:
        return False

    prefix = f"{PASSWORD_HASH_SCHEME}$"
    if not stored_hash.startswith(prefix):
        return False

    try:
        _, iterations_str, salt_hex, digest_hex = stored_hash.split("$", 3)
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_jwt_token(username: str, jwt_secret: Optional[str] = None) -> str:
    """Create JWT token"""
    expire = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, jwt_secret or get_jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Optional[str]:
    """Verify JWT token, return username or None"""
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def get_http_auth_user(request: Request) -> Optional[str]:
    """Get authenticated username from the browser session cookie."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    username = verify_session_token(session_token) if session_token else None
    return username if username else None


def get_ws_auth_user(ws: WebSocket) -> Optional[str]:
    """Get authenticated username for a WebSocket request."""
    cookie_header = ws.headers.get("cookie", "")
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        session_cookie = cookie.get(SESSION_COOKIE_NAME)
        if session_cookie and session_cookie.value:
            username = verify_session_token(session_cookie.value)
            if username:
                return username
    return None


async def ensure_ws_authenticated(ws: WebSocket) -> bool:
    """Validate backend JWT before accepting WebSocket connection."""
    username = get_ws_auth_user(ws)
    if username:
        return True

    await ws.close(code=4401, reason="Not authenticated")
    return False


async def get_current_user(request: Request) -> str:
    """Dependency to get current user from the session cookie."""
    username = get_http_auth_user(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return username


# === Auth Middleware ===
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    # Public endpoints - no auth required
    if (path.startswith("/api/auth/") or
        not path.startswith("/api/") or
        path.startswith("/ws")):
        return await call_next(request)

    username = get_http_auth_user(request)
    if not username:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    return await call_next(request)


# Run migrations
def run_migrations():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Add agent_id to locked_processes if missing
    cursor.execute("PRAGMA table_info(locked_processes)")
    columns = [row[1] for row in cursor.fetchall()]
    if "agent_id" not in columns:
        cursor.execute("ALTER TABLE locked_processes ADD COLUMN agent_id INTEGER DEFAULT 1")
        conn.commit()
        print("Added agent_id column to locked_processes")

    # Ensure mandatory auth credentials exist in every mode.
    cursor.execute("SELECT value FROM settings WHERE key = 'username'")
    username_row = cursor.fetchone()
    if not username_row:
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("username", DEFAULT_USERNAME))
        conn.commit()
        print(f"Initialized default username: {DEFAULT_USERNAME}")

    cursor.execute("SELECT value FROM settings WHERE key = 'password_hash'")
    password_row = cursor.fetchone()
    if not password_row:
        cursor.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("password_hash", hash_password(DEFAULT_PASSWORD)),
        )
        conn.commit()
        print(f"Initialized default password hash for user: {DEFAULT_USERNAME}")

    conn.close()

run_migrations()


# Pydantic models for API
class AgentCreate(BaseModel):
    name: str
    ip: str
    jwt_key: Optional[str] = None


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    ip: Optional[str] = None
    jwt_key: Optional[str] = None


class LockedProcessCreate(BaseModel):
    pty_id: str
    agent_id: int = 1
    claude_session_id: Optional[str] = None
    project_hash: Optional[str] = None
    project_path: Optional[str] = None
    project_name: Optional[str] = None
    label: Optional[str] = None
    proc_type: str = 'claude'


# Default PTY server URL (for local agent)
DEFAULT_PTY_SERVER = require_env("AB_BACK_PTY_URL")
DEFAULT_PTY_WS_URL = require_env("AB_BACK_PTY_WS_URL")


def get_agent_pty_urls(agent_id: int) -> tuple[str, str, str]:
    """Get PTY server URLs for an agent. Returns (http_url, ws_url, jwt_token)"""
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return None, None, None

        # JWT is required for all agents
        if not agent.jwt_key:
            return None, None, None

        if agent.is_local:
            return DEFAULT_PTY_SERVER, DEFAULT_PTY_WS_URL, agent.jwt_key

        # For remote agents, construct URL from IP
        ip = agent.ip
        if not ip.startswith("http"):
            ip = f"http://{ip}"
        ip = ip.rstrip("/")
        if ":" not in ip.split("//")[-1]:
            ip = f"{ip}:8421"

        http_url = ip
        ws_url = ip.replace("http://", "ws://").replace("https://", "wss://")

        return http_url, ws_url, agent.jwt_key
    finally:
        db.close()


async def has_agent_canvas_access(agent_id: int) -> bool:
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url or not jwt:
        return False

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            health = await client.get(f"{pty_url}/health")
            if health.status_code != 200:
                return False

            probe = await client.get(f"{pty_url}/api/pty", headers=get_auth_headers(jwt))
            return probe.status_code == 200
    except Exception:
        return False


def diagnose_agent_pty_create_failure(agent_id: int, project_path: str | None) -> dict:
    """Remote create failures are forwarded as-is from the agent daemon."""
    return {}


def get_auth_headers(jwt_secret: str) -> dict:
    """Get auth headers for PTY requests.

    Supports two persisted agent auth formats:
    - raw shared secret: sign a short-lived JWT per request
    - pre-issued bearer JWT: forward it as-is
    """
    if jwt_secret:
        if jwt_secret.count(".") == 2:
            return {"Authorization": f"Bearer {jwt_secret}"}
        token = jwt.encode(
            {"sub": "ab-back", "exp": datetime.utcnow() + timedelta(minutes=5)},
            jwt_secret,
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}"}
    return {}

# Claude projects directory
CLAUDE_PROJECTS_DIR = Path.home() / ".claude" / "projects"
CLAUDE_HISTORY_FILE = Path.home() / ".claude" / "history.jsonl"


def get_project_paths_from_history() -> dict[str, str]:
    """Build mapping of dir_name -> project_path from history.jsonl"""
    mapping = {}
    if not CLAUDE_HISTORY_FILE.exists():
        return mapping

    try:
        with open(CLAUDE_HISTORY_FILE, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    project_path = data.get("project")
                    if project_path:
                        # Claude encodes /foo/bar as -foo-bar
                        dir_name = "-" + project_path[1:].replace("/", "-") if project_path.startswith("/") else project_path
                        mapping[dir_name] = project_path
                except:
                    pass
    except:
        pass

    return mapping


def get_project_hash(path: str) -> str:
    """Get Claude's project hash for a path"""
    return hashlib.sha256(path.encode()).hexdigest()[:16]


async def get_live_ptys() -> list[str]:
    """Get list of live PTY session IDs from ab-pty"""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{DEFAULT_PTY_SERVER}/api/pty", timeout=2.0)
            if resp.status_code == 200:
                return [s["id"] for s in resp.json() if s.get("alive")]
    except:
        pass
    return []


async def get_live_ptys_by_path() -> dict[str, list[dict]]:
    """Get mapping of project_path -> [{pty_id, claude_session_id}]"""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{DEFAULT_PTY_SERVER}/api/pty", timeout=2.0)
            if resp.status_code == 200:
                result = {}
                for s in resp.json():
                    if s.get("alive"):
                        path = s.get("project_path", "")
                        if path not in result:
                            result[path] = []
                        result[path].append({
                            "pty_id": s["id"],
                            "claude_session_id": s.get("meta", {}).get("claude_session_id")
                        })
                return result
    except:
        pass
    return {}


def get_claude_projects_fast(live_ptys_by_path: dict[str, list[str]] = None) -> list[dict]:
    """Fast scan - only counts session files, no content reading"""
    projects = []

    if not CLAUDE_PROJECTS_DIR.exists():
        return projects

    if live_ptys_by_path is None:
        live_ptys_by_path = {}

    path_mapping = get_project_paths_from_history()

    for project_dir in CLAUDE_PROJECTS_DIR.iterdir():
        if not project_dir.is_dir():
            continue

        # Just count .jsonl files (fast, no content check)
        session_count = 0
        latest_mtime = 0
        for session_file in project_dir.glob("*.jsonl"):
            if session_file.name.startswith("agent-"):
                continue
            stat = session_file.stat()
            if stat.st_size < 50:
                continue
            session_count += 1
            if stat.st_mtime > latest_mtime:
                latest_mtime = stat.st_mtime

        if session_count == 0:
            continue

        dir_name = project_dir.name
        project_path = path_mapping.get(dir_name, dir_name)

        live_pty_info = live_ptys_by_path.get(project_path, [])

        projects.append({
            "hash": project_dir.name,
            "path": project_path,
            "name": os.path.basename(project_path) or project_path,
            "session_count": session_count,
            "latest": datetime.fromtimestamp(latest_mtime).isoformat() if latest_mtime else None,
            "live_ptys": [p["pty_id"] for p in live_pty_info],
        })

    projects.sort(key=lambda p: p.get("latest") or "", reverse=True)
    return projects


def get_project_sessions(project_hash: str) -> list[dict]:
    """Get sessions for a specific project (with content check)"""
    project_dir = CLAUDE_PROJECTS_DIR / project_hash
    if not project_dir.exists():
        return []

    session_files = []
    for session_file in project_dir.glob("*.jsonl"):
        if session_file.name.startswith("agent-"):
            continue
        stat = session_file.stat()
        if stat.st_size < 50:
            continue

        # Check for actual content
        has_content = False
        try:
            with open(session_file, 'r') as f:
                for line in f:
                    if '"type":"user"' in line or '"type":"assistant"' in line or '"type":"summary"' in line:
                        has_content = True
                        break
        except:
            pass

        if not has_content:
            continue

        session_files.append({
            "id": session_file.stem,
            "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "size": stat.st_size
        })

    session_files.sort(key=lambda s: s["created"], reverse=True)
    return session_files


def get_claude_projects(live_ptys_by_path: dict[str, list[str]] = None) -> list[dict]:
    """Scan ~/.claude/projects/ and return project info (fast, uses history.jsonl for paths)"""
    projects = []

    if not CLAUDE_PROJECTS_DIR.exists():
        return projects

    if live_ptys_by_path is None:
        live_ptys_by_path = {}

    # Get path mapping from history.jsonl (fast)
    path_mapping = get_project_paths_from_history()

    for project_dir in CLAUDE_PROJECTS_DIR.iterdir():
        if not project_dir.is_dir():
            continue

        # Get session files (filter out empty/useless ones)
        session_files = []
        for session_file in project_dir.glob("*.jsonl"):
            if session_file.name.startswith("agent-"):
                continue
            stat = session_file.stat()
            # Skip empty or too small files (no useful content)
            if stat.st_size < 50:
                continue

            # Quick check: must have at least one user or assistant message
            has_content = False
            try:
                with open(session_file, 'r') as f:
                    for line in f:
                        if '"type":"user"' in line or '"type":"assistant"' in line or '"type":"summary"' in line:
                            has_content = True
                            break
            except:
                pass

            if not has_content:
                continue

            session_files.append({
                "id": session_file.stem,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "size": stat.st_size
            })

        if not session_files:
            continue

        # Sort by date descending
        session_files.sort(key=lambda s: s["created"], reverse=True)

        # Get project path from mapping (built from history.jsonl)
        dir_name = project_dir.name
        project_path = path_mapping.get(dir_name, dir_name)

        # Get live PTYs for this project and extract active session IDs
        live_pty_info = live_ptys_by_path.get(project_path, [])
        live_session_ids = set(
            p["claude_session_id"] for p in live_pty_info
            if p.get("claude_session_id")
        )

        projects.append({
            "hash": project_dir.name,
            "path": project_path,
            "name": os.path.basename(project_path) or project_path,
            "sessions": session_files,
            "session_count": len(session_files),
            "live_ptys": [p["pty_id"] for p in live_pty_info],
            "live_session_ids": list(live_session_ids)
        })

    projects.sort(key=lambda p: p["sessions"][0]["created"], reverse=True)
    return projects


def get_session_details(project_hash: str, session_id: str) -> dict:
    """Get detailed session info (reads file)"""
    session_file = CLAUDE_PROJECTS_DIR / project_hash / f"{session_id}.jsonl"
    if not session_file.exists():
        return {"error": "Session not found"}

    summary = None
    has_user_message = False

    try:
        with open(session_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                if data.get("type") == "summary":
                    summary = data.get("summary", "")
                if data.get("type") == "user":
                    has_user_message = True
                    break  # Found user message, can stop
    except:
        pass

    # Compacted = can't continue = no user messages
    is_compacted = not has_user_message
    if is_compacted and not summary:
        summary = "(empty session)"

    stat = session_file.stat()
    return {
        "id": session_id,
        "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "size": stat.st_size,
        "compacted": is_compacted,
        "summary": summary
    }


# === Agents API ===

# Local agent is no longer auto-created - must be added manually with JWT key


# === Auth API ===
class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Check if auth is required and current status"""
    authenticated = get_http_auth_user(request) is not None
    return {
        "auth_required": True,
        "authenticated": authenticated,
        "username": get_username(),
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request):
    """Login and create an HttpOnly browser session."""
    stored_hash = get_password_hash()
    if not stored_hash or get_username() != req.username or not verify_password(req.password, stored_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session_token = create_session_token(req.username)
    response = JSONResponse({"ok": True, "username": req.username})
    set_auth_cookie(response, request, session_token)
    return response


@app.post("/api/auth/logout")
async def logout(request: Request):
    """Logout current browser session."""
    revoke_session_token(request.cookies.get(SESSION_COOKIE_NAME))
    response = JSONResponse({"success": True})
    clear_auth_cookies(response, request)
    return response


@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordRequest, request: Request, user: str = Depends(get_current_user)):
    """Change password"""
    stored_hash = get_password_hash()
    if stored_hash and not verify_password(req.current_password, stored_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_jwt_secret = secrets.token_hex(32)
    db = SessionLocal()
    try:
        upsert_setting(db, "password_hash", hash_password(req.new_password))
        # Rotate backend JWT secret so previously issued tokens are invalidated.
        upsert_setting(db, "jwt_secret", new_jwt_secret)
        db.commit()
    finally:
        db.close()

    revoke_all_sessions(user)
    session_token = create_session_token(user)
    response = JSONResponse({"success": True, "username": user})
    set_auth_cookie(response, request, session_token)
    return response


@app.get("/api/agents")
async def list_agents():
    """List all agents with PTY info (parallel fetch)"""
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        agent_list = []
        for a in agents:
            agent_list.append({
                "id": str(a.id),
                "name": a.name,
                "ip": a.ip,
                "is_local": a.is_local,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "pty_info": None,
                "_pty_url": f"{DEFAULT_PTY_SERVER}/info" if a.is_local else f"http://{a.ip if ':' in (a.ip or '') else f'{a.ip}:8421'}/info",
            })

        async def fetch_pty_info(agent_data):
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(agent_data["_pty_url"])
                    if resp.status_code == 200:
                        agent_data["pty_info"] = resp.json()
            except:
                pass

        await asyncio.gather(*(fetch_pty_info(a) for a in agent_list))

        for a in agent_list:
            a.pop("_pty_url", None)
        return agent_list
    finally:
        db.close()


@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: int):
    """Get single agent"""
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return JSONResponse({"error": "Agent not found"}, status_code=404)

        result = {
            "id": str(agent.id),
            "name": agent.name,
            "ip": agent.ip,
            "jwt_key": agent.jwt_key or "",
            "is_local": agent.is_local,
            "pty_info": None,
        }

        # Fetch PTY info (use DEFAULT_PTY_SERVER for local agent)
        try:
            if agent.is_local:
                pty_url = f"{DEFAULT_PTY_SERVER}/info"
            else:
                ip = agent.ip if ":" in agent.ip else f"{agent.ip}:8421"
                pty_url = f"http://{ip}/info"
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(pty_url)
                if resp.status_code == 200:
                    result["pty_info"] = resp.json()
        except:
            pass

        return result
    finally:
        db.close()


@app.get("/api/pty-daemon/check")
async def check_agent_reachable(ip: str, port: int = 8421, jwt: str = None):
    """Check if PTY daemon is reachable at ip:port and JWT is valid"""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # First check if daemon is reachable
            res = await client.get(f"http://{ip}:{port}/health")
            if res.status_code != 200:
                return {"ok": False, "message": f"Daemon status {res.status_code}"}

            # If JWT provided, verify it works
            if jwt:
                res = await client.get(f"http://{ip}:{port}/api/pty", headers=get_auth_headers(jwt))
                if res.status_code == 401:
                    return {"ok": False, "message": "Invalid JWT token"}
                elif res.status_code != 200:
                    return {"ok": False, "message": f"Auth failed: {res.status_code}"}
                return {"ok": True, "message": "Connected & authenticated"}
            else:
                return {"ok": True, "message": "Daemon reachable (no JWT)"}
    except httpx.ConnectError:
        return {"ok": False, "message": "Connection refused"}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Connection timeout"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


async def verify_pty_daemon_access(ip: str, port: int, jwt: str) -> tuple[bool, str]:
    """Verify that a PTY daemon is reachable and accepts the provided JWT."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(f"http://{ip}:{port}/health")
            if res.status_code != 200:
                return False, f"Daemon status {res.status_code}"

            res = await client.get(
                f"http://{ip}:{port}/api/pty",
                headers=get_auth_headers(jwt),
            )
            if res.status_code == 401:
                return False, "Stored JWT token is invalid"
            if res.status_code != 200:
                return False, f"Auth failed: {res.status_code}"
            return True, "Connected & authenticated"
    except httpx.ConnectError:
        return False, "Connection refused"
    except httpx.TimeoutException:
        return False, "Connection timeout"
    except Exception as e:
        return False, str(e)


@app.post("/api/agents")
async def create_agent(data: AgentCreate):
    """Create new agent"""
    if not data.jwt_key:
        return JSONResponse({"error": "jwt_key is required"}, status_code=400)

    db = SessionLocal()
    try:
        agent = Agent(name=data.name, ip=data.ip, jwt_key=data.jwt_key)
        db.add(agent)
        db.commit()
        db.refresh(agent)
        return {"id": str(agent.id), "name": agent.name, "ip": agent.ip, "ok": True}
    finally:
        db.close()


@app.put("/api/agents/{agent_id}")
async def update_agent(agent_id: int, data: AgentUpdate):
    """Update agent"""
    # Don't allow clearing jwt_key
    if data.jwt_key is not None and not data.jwt_key:
        return JSONResponse({"error": "jwt_key cannot be empty"}, status_code=400)

    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return JSONResponse({"error": "Agent not found"}, status_code=404)

        if data.name is not None:
            agent.name = data.name
        if data.ip is not None:
            agent.ip = data.ip
        if data.jwt_key is not None:
            agent.jwt_key = data.jwt_key

        db.commit()
        return {"ok": True, "id": str(agent.id)}
    finally:
        db.close()


@app.delete("/api/agents/{agent_id}")
async def delete_agent(agent_id: int):
    """Delete agent"""
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return JSONResponse({"error": "Agent not found"}, status_code=404)
        if agent.is_local:
            return JSONResponse({"error": "Cannot delete local agent"}, status_code=400)

        db.delete(agent)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


# === Locked Processes API ===

@app.get("/api/locked")
async def list_locked_processes():
    """List all locked processes from all agents"""
    db = SessionLocal()
    try:
        # Get all agents
        agents = db.query(Agent).all()

        locked_procs = []
        async with httpx.AsyncClient() as client:
            for agent in agents:
                pty_url, _, jwt = get_agent_pty_urls(agent.id)
                if not pty_url:
                    continue
                try:
                    resp = await client.get(f"{pty_url}/api/pty", headers=get_auth_headers(jwt), timeout=3.0)
                    if resp.status_code == 200:
                        sessions = resp.json()
                        for s in sessions:
                            if s.get("locked"):
                                project_path = s.get("project_path") or ""
                                project_hash = project_path.replace("/", "-") if project_path else None
                                locked_procs.append({
                                    "id": f"{agent.id}_{s.get('id')}",
                                    "pty_id": s.get("id"),
                                    "agent_id": agent.id,
                                    "agent_name": agent.name,
                                    "claude_session_id": s.get("claude_session_id"),
                                    "project_hash": project_hash,
                                    "project_path": project_path,
                                    "project_name": s.get("meta", {}).get("project_name") or s.get("name"),
                                    "name": s.get("name"),  # PTY process name for display
                                    "label": s.get("label"),
                                    "proc_type": s.get("type", "claude"),
                                    "created_at": s.get("created_at"),
                                    "alive": s.get("alive", False),
                                })
                except Exception as e:
                    print(f"Error fetching sessions from agent {agent.id}: {e}")

        # Sort by created_at descending
        locked_procs.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        return locked_procs
    finally:
        db.close()


@app.post("/api/locked")
async def create_locked_process(data: LockedProcessCreate):
    """Add process to locked list"""
    db = SessionLocal()
    try:
        # Check if already locked
        existing = db.query(LockedProcess).filter(
            LockedProcess.pty_id == data.pty_id
        ).first()
        if existing:
            return {"id": existing.id, "already_locked": True}

        proc = LockedProcess(
            pty_id=data.pty_id,
            agent_id=data.agent_id,
            claude_session_id=data.claude_session_id,
            project_hash=data.project_hash,
            project_path=data.project_path,
            project_name=data.project_name,
            label=data.label,
            proc_type=data.proc_type,
        )
        db.add(proc)
        db.commit()
        db.refresh(proc)
        return {"id": proc.id, "ok": True}
    finally:
        db.close()


@app.delete("/api/locked/{locked_id}")
async def delete_locked_process(locked_id: int):
    """Remove process from locked list"""
    db = SessionLocal()
    try:
        proc = db.query(LockedProcess).filter(LockedProcess.id == locked_id).first()
        if not proc:
            return JSONResponse({"error": "Locked process not found"}, status_code=404)

        db.delete(proc)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@app.delete("/api/locked/by-pty/{pty_id}")
async def unlock_by_pty(pty_id: str):
    """Unlock process by PTY ID"""
    db = SessionLocal()
    try:
        proc = db.query(LockedProcess).filter(
            LockedProcess.pty_id == pty_id
        ).first()
        if not proc:
            return {"ok": True, "was_locked": False}

        db.delete(proc)
        db.commit()
        return {"ok": True, "was_locked": True}
    finally:
        db.close()


# === Projects API ===

@app.get("/api/projects")
async def list_projects():
    """List all Claude projects (fast, no session content reading)"""
    live_ptys = await get_live_ptys_by_path()
    return get_claude_projects_fast(live_ptys)


@app.get("/api/projects/{project_hash}")
async def get_project(project_hash: str):
    """Get single project info"""
    live_ptys = await get_live_ptys_by_path()
    projects = get_claude_projects_fast(live_ptys)
    for p in projects:
        if p["hash"] == project_hash:
            return p
    return {"error": "Project not found"}


@app.get("/api/projects/{project_hash}/sessions")
async def get_project_sessions_api(project_hash: str):
    """Get sessions for a specific project (lazy load)"""
    return get_project_sessions(project_hash)


@app.get("/api/sessions/{project_hash}/{session_id}/details")
async def get_session_info(project_hash: str, session_id: str):
    """Get session details (compacted status, summary)"""
    return get_session_details(project_hash, session_id)


@app.get("/api/check-path")
async def check_path(path: str):
    """Check if a path exists"""
    expanded = os.path.expanduser(path)
    return {"exists": os.path.isdir(expanded), "path": expanded}


@app.post("/api/create-path")
async def create_path(data: dict):
    """Create a directory"""
    path = data.get("path", "")
    expanded = os.path.expanduser(path)
    try:
        os.makedirs(expanded, exist_ok=True)
        return {"ok": True, "path": expanded}
    except Exception as e:
        return {"error": str(e)}


@app.delete("/api/sessions/{project_hash}/{session_id}")
async def delete_claude_session(project_hash: str, session_id: str):
    """Delete a saved Claude session (jsonl file)"""
    session_file = CLAUDE_PROJECTS_DIR / project_hash / f"{session_id}.jsonl"
    if not session_file.exists():
        return {"error": "Session not found"}

    try:
        session_file.unlink()
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/sessions/{project_hash}/{session_id}/content")
async def get_session_content(project_hash: str, session_id: str):
    """Get session content (messages from jsonl)"""
    session_file = CLAUDE_PROJECTS_DIR / project_hash / f"{session_id}.jsonl"
    if not session_file.exists():
        return {"error": "Session not found"}

    messages = []
    has_user_message = False

    try:
        with open(session_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    msg_type = data.get("type", "")
                    if msg_type in ("user", "assistant", "summary"):
                        messages.append(data)
                        if msg_type == "user":
                            has_user_message = True
                except:
                    pass
    except Exception as e:
        return {"error": str(e)}

    # Session is compacted (can't continue) only if no user messages
    return {"messages": messages, "compacted": not has_user_message}


# === Canvas / Board Proxy API ===

def parse_canvas_agent_id(agent_id: str | None) -> int | None:
    if agent_id is None or agent_id == "":
        return None
    try:
        return int(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid agent id") from exc


async def get_canvas_proxy_target(agent_id: str | None) -> tuple[str | None, str | None, str | None, int | None]:
    agent_id_int = parse_canvas_agent_id(agent_id)
    if agent_id_int is None:
        return None, None, None, None

    if not await has_agent_canvas_access(agent_id_int):
        return None, None, None, agent_id_int

    pty_url, _, jwt = get_agent_pty_urls(agent_id_int)
    if not pty_url or not jwt:
        return None, None, None, agent_id_int

    return pty_url, jwt, agent_id, agent_id_int


def normalize_canvas_board_items(items: list[dict], agent_id: str | None) -> list[dict]:
    normalized: list[dict] = []
    for item in items:
        normalized.append({
            "id": item.get("id"),
            "type": item.get("type"),
            "x": item.get("x", 0),
            "y": item.get("y", 0),
            "label": item.get("label", ""),
            "ptyId": item.get("ptyId"),
            "agentId": agent_id,
            "noteContent": item.get("noteContent"),
            "currentPath": item.get("currentPath"),
            "window": item.get("window"),
        })
    return normalized


def normalize_canvas_layout_summary(layouts: list[dict], agent_id: str | None) -> list[dict]:
    normalized: list[dict] = []
    for layout in layouts:
        normalized.append({
            "name": layout.get("name"),
            "agentId": agent_id,
            "savedAt": layout.get("savedAt"),
            "snapshot": layout.get("snapshot"),
        })
    return normalized


@app.get("/api/canvas")
async def list_canvas_items(agent_id: str | None = None):
    pty_url, jwt, scoped_agent_id, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        return []

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/board/items", headers=get_auth_headers(jwt), timeout=5.0)
            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
            items = resp.json()
            return normalize_canvas_board_items(items, scoped_agent_id)
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.get("/api/canvas/layouts")
async def list_canvas_layouts(agent_id: str | None = None):
    pty_url, jwt, scoped_agent_id, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        return []

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/board/layouts", headers=get_auth_headers(jwt), timeout=5.0)
            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
            layouts = resp.json()
            return normalize_canvas_layout_summary(layouts, scoped_agent_id)
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.get("/api/canvas/layouts/{layout_name}")
async def get_canvas_layout(layout_name: str, agent_id: str | None = None):
    pty_url, jwt, scoped_agent_id, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        raise HTTPException(status_code=404, detail="Layout not found")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{pty_url}/api/board/layouts/{quote(layout_name, safe='')}",
                headers=get_auth_headers(jwt),
                timeout=5.0,
            )
            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
            layout = resp.json()
            layout["agentId"] = scoped_agent_id
            return layout
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.put("/api/canvas/layouts/{layout_name}")
async def put_canvas_layout(layout_name: str, request: Request):
    payload = await request.json()
    if not layout_name.strip():
        raise HTTPException(status_code=400, detail="Layout name is required")

    agent_id = payload.get("agentId")
    snapshot = payload.get("snapshot")
    if not isinstance(snapshot, dict):
        raise HTTPException(status_code=400, detail="snapshot must be an object")

    pty_url, jwt, _, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        return {"ok": False, "skipped": True}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{pty_url}/api/board/layouts/{quote(layout_name, safe='')}",
                json={"snapshot": snapshot},
                headers=get_auth_headers(jwt),
                timeout=10.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/canvas/layouts/{layout_name}")
async def delete_canvas_layout(layout_name: str, agent_id: str | None = None):
    pty_url, jwt, _, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        return {"ok": False, "skipped": True}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{pty_url}/api/board/layouts/{quote(layout_name, safe='')}",
                headers=get_auth_headers(jwt),
                timeout=5.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.put("/api/canvas/{item_id}")
async def upsert_canvas_item(item_id: str, request: Request):
    data = await request.json()
    if data.get("type") == "terminal":
        return {"ok": True, "skipped": True}

    pty_url, jwt, _, _ = await get_canvas_proxy_target(data.get("agentId"))
    if not pty_url or not jwt:
        return {"ok": False, "skipped": True}

    payload = {
        "type": data.get("type"),
        "label": data.get("label", ""),
        "ptyId": data.get("ptyId"),
        "noteContent": data.get("noteContent"),
        "currentPath": data.get("currentPath"),
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{pty_url}/api/board/items/{quote(item_id, safe='')}",
                json=payload,
                headers=get_auth_headers(jwt),
                timeout=10.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/canvas/{item_id}")
async def delete_canvas_item(item_id: str, agent_id: str | None = None):
    pty_url, jwt, _, _ = await get_canvas_proxy_target(agent_id)
    if not pty_url or not jwt:
        return {"ok": False, "skipped": True}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{pty_url}/api/board/items/{quote(item_id, safe='')}",
                headers=get_auth_headers(jwt),
                timeout=5.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/canvas/sync")
async def sync_canvas_items(request: Request):
    """Bulk sync non-terminal canvas items to the selected agent daemon."""
    data = await request.json()
    items = data if isinstance(data, list) else data.get("items", [])
    scoped_agent_id = None if isinstance(data, list) else data.get("agentId")

    if not scoped_agent_id:
        return {"ok": False, "skipped": True, "count": 0}

    pty_url, jwt, _, _ = await get_canvas_proxy_target(scoped_agent_id)
    if not pty_url or not jwt:
        return {"ok": False, "skipped": True, "count": 0}

    payload = {
        "items": [
            {
                "id": item.get("id"),
                "type": item.get("type"),
                "label": item.get("label", ""),
                "ptyId": item.get("ptyId"),
                "noteContent": item.get("noteContent"),
                "currentPath": item.get("currentPath"),
            }
            for item in items
            if item.get("type") != "terminal"
        ]
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{pty_url}/api/board/items/sync",
                json=payload,
                headers=get_auth_headers(jwt),
                timeout=10.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


# === Agent-based PTY API ===

async def restore_locked_processes(agent_id: int, pty_url: str, jwt: str | None, live_pty_ids: set[str]):
    """Restore locked processes that are not alive"""
    db = SessionLocal()
    try:
        locked = db.query(LockedProcess).filter(LockedProcess.agent_id == agent_id).all()
        if not locked:
            return

        async with httpx.AsyncClient() as client:
            for proc in locked:
                if proc.pty_id in live_pty_ids:
                    continue  # Already alive

                # Restore: create new PTY with same params
                body = {
                    "path": proc.project_path,
                    "name": proc.project_name,
                    "shell_only": proc.proc_type == "bash",
                }
                if proc.claude_session_id:
                    body["claude_session_id"] = proc.claude_session_id

                try:
                    resp = await client.post(f"{pty_url}/api/pty", json=body, headers=get_auth_headers(jwt), timeout=10.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        new_pty_id = data.get("session_id")
                        if new_pty_id:
                            # Update pty_id in DB and lock the new session
                            proc.pty_id = new_pty_id
                            db.commit()
                            # Lock the new PTY session
                            await client.post(f"{pty_url}/api/pty/{new_pty_id}/lock", headers=get_auth_headers(jwt), timeout=5.0)
                            print(f"Restored locked process: {proc.proc_type} -> {new_pty_id}")
                except Exception as e:
                    print(f"Failed to restore {proc.pty_id}: {e}")
    finally:
        db.close()


@app.get("/api/agents/{agent_id}/pty")
async def agent_list_pty(agent_id: int):
    """List PTY sessions for an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/pty", headers=get_auth_headers(jwt), timeout=5.0)
            if resp.status_code == 200:
                sessions = resp.json()
                live_pty_ids = {s["id"] for s in sessions}
                # Restore locked processes that are not alive
                await restore_locked_processes(agent_id, pty_url, jwt, live_pty_ids)
                # Re-fetch after restore
                resp = await client.get(f"{pty_url}/api/pty", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/pty")
async def agent_create_pty(agent_id: int, request: Request):
    """Create new PTY session on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{pty_url}/api/pty", json=body, headers=get_auth_headers(jwt), timeout=10.0)

            # If daemon returned a generic 5xx, enrich with actionable diagnostics.
            if resp.status_code >= 500:
                try:
                    payload = resp.json()
                except Exception:
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}

                if not payload.get("details") or not payload.get("error_type"):
                    diagnostics = diagnose_agent_pty_create_failure(agent_id, body.get("project_path"))
                    if diagnostics:
                        payload["details"] = payload.get("details") or diagnostics.get("details")
                        payload["error_type"] = payload.get("error_type") or diagnostics.get("error_type")
                if payload:
                    payload["ok"] = False
                    payload["error"] = payload.get("error") or "Failed to create PTY session"
                    return JSONResponse(payload, status_code=resp.status_code)

            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/agents/{agent_id}/pty/{session_id}")
async def agent_kill_pty(agent_id: int, session_id: str):
    """Kill PTY session on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(f"{pty_url}/api/pty/{session_id}", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/pty/{session_id}/lock")
async def agent_lock_pty(agent_id: int, session_id: str):
    """Lock PTY session on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{pty_url}/api/pty/{session_id}/lock", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/agents/{agent_id}/pty/{session_id}/lock")
async def agent_unlock_pty(agent_id: int, session_id: str):
    """Unlock PTY session on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(f"{pty_url}/api/pty/{session_id}/lock", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.patch("/api/agents/{agent_id}/pty/{session_id}/meta")
async def agent_update_pty_meta(agent_id: int, session_id: str, request: Request):
    """Update PTY session metadata on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.patch(f"{pty_url}/api/pty/{session_id}/meta", json=body, headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


# === Agent-based Projects API ===

@app.get("/api/agents/{agent_id}/projects")
async def agent_list_projects(agent_id: int):
    """List projects for an agent, merge labels from coordinator DB"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/projects", headers=get_auth_headers(jwt), timeout=5.0)
            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
            projects = resp.json()
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)

    # Merge labels from coordinator DB
    db = SessionLocal()
    try:
        labels = db.query(ProjectLabel).filter(ProjectLabel.agent_id == agent_id).all()
        label_map = {pl.project_hash: pl.label for pl in labels}
        for p in projects:
            p["label"] = label_map.get(p.get("hash", ""), "")
    finally:
        db.close()
    return projects


@app.patch("/api/agents/{agent_id}/projects/{project_hash}")
async def agent_update_project_label(agent_id: int, project_hash: str, request: Request):
    """Update project label in coordinator DB"""
    body = await request.json()
    label = body.get("label", "")
    db = SessionLocal()
    try:
        db.merge(ProjectLabel(agent_id=agent_id, project_hash=project_hash, label=label))
        db.commit()
    finally:
        db.close()
    return {"ok": True, "label": label}


@app.get("/api/agents/{agent_id}/projects/{project_hash}")
async def agent_get_project(agent_id: int, project_hash: str):
    """Get project info for an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/projects/{project_hash}", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.get("/api/agents/{agent_id}/projects/{project_hash}/sessions")
async def agent_get_project_sessions(agent_id: int, project_hash: str):
    """Get project sessions for an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/projects/{project_hash}/sessions", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/agents/{agent_id}/projects/{project_hash}/sessions/{session_id}")
async def agent_delete_session(agent_id: int, project_hash: str, session_id: str):
    """Delete a Claude session on an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(f"{pty_url}/api/sessions/{project_hash}/{session_id}", headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/mkdir")
async def agent_mkdir(agent_id: int, request: Request):
    """Create directory on remote agent via PTY daemon"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        body = await request.json()
        path = body.get("path", "")
        if not path or ".." in path:
            return JSONResponse({"error": "Invalid path"}, status_code=400)

        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{pty_url}/api/mkdir", json={"path": path}, headers=get_auth_headers(jwt), timeout=10.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.delete("/api/agents/{agent_id}/projects/{project_hash}")
async def agent_delete_project(agent_id: int, project_hash: str):
    """Delete project from agent's PTY daemon"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(f"{pty_url}/api/projects/{project_hash}", headers=get_auth_headers(jwt), timeout=10.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/agents/{agent_id}/fs")
async def agent_browse_filesystem(agent_id: int, path: str = "~", content: str = ""):
    """Browse filesystem on agent, or get file content if content=true"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        params = {"path": path}
        if content.lower() == "true":
            params["content"] = "true"
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/fs", params=params, headers=get_auth_headers(jwt), timeout=10.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/fs")
async def agent_create_fs(agent_id: int, request: Request):
    """Create file or folder on agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{pty_url}/api/fs", json=body, headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.put("/api/agents/{agent_id}/fs")
async def agent_write_fs(agent_id: int, request: Request):
    """Write file content on agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.put(f"{pty_url}/api/fs", json=body, headers=get_auth_headers(jwt), timeout=10.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.delete("/api/agents/{agent_id}/fs")
async def agent_delete_fs(agent_id: int, path: str):
    """Delete file or folder on agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(f"{pty_url}/api/fs", params={"path": path}, headers=get_auth_headers(jwt), timeout=5.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.get("/api/agents/{agent_id}/fs/download")
async def agent_download_file(agent_id: int, path: str):
    """Download file from agent as binary"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/fs/download", params={"path": path}, headers=get_auth_headers(jwt), timeout=30.0)
            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
            # Forward binary content with original headers
            headers = {}
            if "content-disposition" in resp.headers:
                headers["content-disposition"] = resp.headers["content-disposition"]
            return Response(
                content=resp.content,
                status_code=200,
                media_type=resp.headers.get("content-type", "application/octet-stream"),
                headers=headers,
            )
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/fs/upload")
async def agent_upload_file(agent_id: int, request: Request):
    """Upload file to agent via multipart"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        # Forward multipart body as-is
        body = await request.body()
        content_type = request.headers.get("content-type", "")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{pty_url}/api/fs/upload",
                content=body,
                headers={**get_auth_headers(jwt), "content-type": content_type},
                timeout=60.0,
            )
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.get("/api/agents/{agent_id}/sessions/{project_hash}/{session_id}/content")
async def agent_get_session_content(agent_id: int, project_hash: str, session_id: str):
    """Get session content for an agent"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{pty_url}/api/sessions/{project_hash}/{session_id}/content", headers=get_auth_headers(jwt), timeout=10.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


@app.post("/api/agents/{agent_id}/paste-image")
async def agent_paste_image(agent_id: int, request: Request):
    """Paste image from clipboard - saves to /tmp and returns path"""
    pty_url, _, jwt = get_agent_pty_urls(agent_id)
    if not pty_url:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{pty_url}/api/paste-image", json=body, headers=get_auth_headers(jwt), timeout=30.0)
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return JSONResponse({"error": "PTY server unavailable", "details": str(e)}, status_code=503)


# === Agent-based WebSocket Proxy ===

@app.websocket("/ws/agents/{agent_id}")
async def agent_websocket_proxy(client_ws: WebSocket, agent_id: int):
    """Proxy WebSocket to specific agent's PTY server"""
    if not await ensure_ws_authenticated(client_ws):
        return

    _, pty_ws_url, jwt = get_agent_pty_urls(agent_id)
    if not pty_ws_url:
        await client_ws.close(code=4004, reason="Agent not found")
        return

    await client_ws.accept()
    pty_ws = None

    try:
        ws_url = f"{pty_ws_url}/ws"
        headers = get_auth_headers(jwt)
        pty_ws = await websockets.connect(
            ws_url,
            max_size=50 * 1024 * 1024,
            additional_headers=headers if headers else None,
        )

        async def client_to_pty():
            try:
                while True:
                    data = await client_ws.receive_text()
                    await pty_ws.send(data)
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        async def pty_to_client():
            try:
                async for message in pty_ws:
                    await client_ws.send_text(message)
            except Exception:
                pass

        # Use FIRST_COMPLETED so when either direction dies,
        # we cancel the other immediately (prevents proxy deadlock)
        _tasks = [
            asyncio.create_task(client_to_pty()),
            asyncio.create_task(pty_to_client()),
        ]
        _, _pending = await asyncio.wait(_tasks, return_when=asyncio.FIRST_COMPLETED)
        for _t in _pending:
            _t.cancel()
            try:
                await _t
            except asyncio.CancelledError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"Agent WebSocket proxy error: {e}")
        try:
            await client_ws.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        if pty_ws:
            try:
                await pty_ws.close()
            except:
                pass
        try:
            await client_ws.close()
        except:
            pass


@app.websocket("/ws/agents/{agent_id}/pty-state")
async def agent_pty_state_proxy(client_ws: WebSocket, agent_id: int):
    """Proxy PTY state WebSocket to specific agent's PTY server"""
    if not await ensure_ws_authenticated(client_ws):
        return

    _, pty_ws_url, jwt = get_agent_pty_urls(agent_id)
    if not pty_ws_url:
        await client_ws.close(code=4004, reason="Agent not found")
        return

    await client_ws.accept()
    pty_ws = None

    try:
        ws_url = f"{pty_ws_url}/ws/pty-state"
        headers = get_auth_headers(jwt)
        pty_ws = await websockets.connect(
            ws_url,
            additional_headers=headers if headers else None,
        )

        async def client_to_pty():
            try:
                while True:
                    data = await client_ws.receive_text()
                    await pty_ws.send(data)
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        async def pty_to_client():
            try:
                async for message in pty_ws:
                    await client_ws.send_text(message)
            except Exception:
                pass

        # Use FIRST_COMPLETED so when either direction dies,
        # we cancel the other immediately (prevents proxy deadlock)
        _tasks = [
            asyncio.create_task(client_to_pty()),
            asyncio.create_task(pty_to_client()),
        ]
        _, _pending = await asyncio.wait(_tasks, return_when=asyncio.FIRST_COMPLETED)
        for _t in _pending:
            _t.cancel()
            try:
                await _t
            except asyncio.CancelledError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"Agent PTY state proxy error: {e}")
    finally:
        if pty_ws:
            try:
                await pty_ws.close()
            except:
                pass
        try:
            await client_ws.close()
        except:
            pass


# === WebSocket Proxy ===

@app.websocket("/ws")
async def websocket_proxy(client_ws: WebSocket):
    """Proxy WebSocket to ab-pty"""
    if not await ensure_ws_authenticated(client_ws):
        return

    await client_ws.accept()
    pty_ws = None

    try:
        pty_ws = await websockets.connect(f"{DEFAULT_PTY_WS_URL}/ws", max_size=50 * 1024 * 1024)

        async def client_to_pty():
            try:
                while True:
                    data = await client_ws.receive_text()
                    await pty_ws.send(data)
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        async def pty_to_client():
            try:
                async for message in pty_ws:
                    await client_ws.send_text(message)
            except Exception:
                pass

        # Use FIRST_COMPLETED so when either direction dies,
        # we cancel the other immediately (prevents proxy deadlock)
        _tasks = [
            asyncio.create_task(client_to_pty()),
            asyncio.create_task(pty_to_client()),
        ]
        _, _pending = await asyncio.wait(_tasks, return_when=asyncio.FIRST_COMPLETED)
        for _t in _pending:
            _t.cancel()
            try:
                await _t
            except asyncio.CancelledError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"WebSocket proxy error: {e}")
        try:
            await client_ws.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        if pty_ws:
            try:
                await pty_ws.close()
            except:
                pass
        try:
            await client_ws.close()
        except:
            pass


@app.websocket("/ws/pty-state")
async def pty_state_proxy(client_ws: WebSocket):
    """Proxy PTY state WebSocket to ab-pty"""
    if not await ensure_ws_authenticated(client_ws):
        return

    await client_ws.accept()
    pty_ws = None

    try:
        pty_ws = await websockets.connect(f"{DEFAULT_PTY_WS_URL}/ws/pty-state")

        async def client_to_pty():
            try:
                while True:
                    data = await client_ws.receive_text()
                    await pty_ws.send(data)
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        async def pty_to_client():
            try:
                async for message in pty_ws:
                    await client_ws.send_text(message)
            except Exception:
                pass

        # Use FIRST_COMPLETED so when either direction dies,
        # we cancel the other immediately (prevents proxy deadlock)
        _tasks = [
            asyncio.create_task(client_to_pty()),
            asyncio.create_task(pty_to_client()),
        ]
        _, _pending = await asyncio.wait(_tasks, return_when=asyncio.FIRST_COMPLETED)
        for _t in _pending:
            _t.cancel()
            try:
                await _t
            except asyncio.CancelledError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"PTY state proxy error: {e}")
    finally:
        if pty_ws:
            try:
                await pty_ws.close()
            except:
                pass
        try:
            await client_ws.close()
        except:
            pass


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "ok"}


# Serve frontend (built static or proxy to Vite dev)
VITE_DEV_URL = os.environ.get("VITE_DEV_URL")
VITE_DEV_WS_URL = None
if VITE_DEV_URL:
    VITE_DEV_WS_URL = VITE_DEV_URL.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")

if VITE_DEV_URL:
    # Dev/preview mode: proxy non-API requests to Vite server
    @app.middleware("http")
    async def vite_proxy_middleware(request: Request, call_next):
        path = request.url.path
        # Let API, WS requests and WebSocket upgrades through to FastAPI
        if path.startswith("/api/") or path.startswith("/ws/") or request.headers.get("upgrade") == "websocket":
            return await call_next(request)

        # Proxy everything else to Vite
        async with httpx.AsyncClient() as client:
            try:
                url = f"{VITE_DEV_URL}{path}"
                if request.url.query:
                    url += f"?{request.url.query}"
                resp = await client.get(url, headers=dict(request.headers), timeout=30.0)
                # Filter out conflicting headers
                headers = {k: v for k, v in resp.headers.items()
                          if k.lower() not in ('transfer-encoding', 'content-encoding', 'content-length')}
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=headers
                )
            except Exception as e:
                return JSONResponse({"error": str(e)}, status_code=502)

    @app.websocket("/")
    async def vite_hmr_ws_proxy(client_ws: WebSocket):
        """Proxy Vite HMR WebSocket (root path) when backend fronts dev server."""
        if not VITE_DEV_WS_URL:
            await client_ws.close(code=4404, reason="Vite dev proxy is disabled")
            return

        # Vite client uses `vite-hmr` subprotocol; browsers expect it echoed back.
        requested = client_ws.headers.get("sec-websocket-protocol", "")
        requested_protocols = [p.strip() for p in requested.split(",") if p.strip()]
        selected_protocol = requested_protocols[0] if requested_protocols else None

        await client_ws.accept(subprotocol=selected_protocol)
        vite_ws = None

        try:
            ws_url = f"{VITE_DEV_WS_URL}/"
            if client_ws.url.query:
                ws_url += f"?{client_ws.url.query}"

            vite_ws = await websockets.connect(
                ws_url,
                subprotocols=[selected_protocol] if selected_protocol else None,
            )

            async def client_to_vite():
                try:
                    while True:
                        msg = await client_ws.receive()
                        if msg["type"] == "websocket.disconnect":
                            break
                        if "text" in msg and msg["text"] is not None:
                            await vite_ws.send(msg["text"])
                        elif "bytes" in msg and msg["bytes"] is not None:
                            await vite_ws.send(msg["bytes"])
                except Exception:
                    pass

            async def vite_to_client():
                try:
                    async for message in vite_ws:
                        if isinstance(message, bytes):
                            await client_ws.send_bytes(message)
                        else:
                            await client_ws.send_text(message)
                except Exception:
                    pass

            await asyncio.gather(client_to_vite(), vite_to_client())
        except Exception as e:
            print(f"Vite HMR WebSocket proxy error: {e}")
        finally:
            if vite_ws:
                try:
                    await vite_ws.close()
                except Exception:
                    pass
            try:
                await client_ws.close()
            except Exception:
                pass
else:
    # Production: serve built static files
    static_dir = Path(__file__).parent / "frontend" / "build"
    if not static_dir.exists():
        static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")


if __name__ == "__main__":
    port = int(require_env("AB_BACK_PORT"))
    uvicorn.run(app, host="0.0.0.0", port=port)
