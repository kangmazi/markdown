from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "markdown_app.db"
SESSION_SECONDS = 60 * 60 * 24 * 14


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.executescript(
            """
            create table if not exists users (
              id integer primary key autoincrement,
              username text not null unique,
              password_hash text not null,
              created_at text not null default current_timestamp
            );

            create table if not exists sessions (
              token text primary key,
              user_id integer not null references users(id) on delete cascade,
              expires_at integer not null
            );

            create table if not exists articles (
              id integer primary key autoincrement,
              user_id integer not null references users(id) on delete cascade,
              title text not null,
              content text not null default '',
              created_at text not null default current_timestamp,
              updated_at text not null default current_timestamp
            );
            """
        )


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000)
    return f"pbkdf2_sha256$150000${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def public_user(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {"id": row["id"], "username": row["username"]}


def public_article(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "content": row["content"],
        "updatedAt": row["updated_at"],
    }


class AppHandler(SimpleHTTPRequestHandler):
    server_version = "MarkdownLocal/1.0"

    def translate_path(self, path: str) -> str:
        parsed = urlparse(path)
        safe = parsed.path.lstrip("/") or "index.html"
        target = (ROOT / safe).resolve()
        if target != ROOT and not str(target).startswith(str(ROOT) + os.sep):
            return str(ROOT / "index.html")
        return str(target)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_json(self, status: int, payload: object, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def current_user(self) -> sqlite3.Row | None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("session")
        if not morsel:
            return None
        token = morsel.value
        now = int(time.time())
        with connect_db() as conn:
            conn.execute("delete from sessions where expires_at < ?", (now,))
            row = conn.execute(
                """
                select users.id, users.username
                from sessions
                join users on users.id = sessions.user_id
                where sessions.token = ? and sessions.expires_at >= ?
                """,
                (token, now),
            ).fetchone()
            return row

    def require_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "请先登录"})
            return None
        return user

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/me":
            self.send_json(200, {"user": public_user(self.current_user())})
            return
        if path == "/api/articles":
            user = self.require_user()
            if not user:
                return
            with connect_db() as conn:
                rows = conn.execute(
                    """
                    select id, title, content, updated_at
                    from articles
                    where user_id = ?
                    order by updated_at desc, id desc
                    """,
                    (user["id"],),
                ).fetchall()
            self.send_json(200, [public_article(row) for row in rows])
            return
        return super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            data = self.read_json()
        except json.JSONDecodeError:
            self.send_json(400, {"error": "JSON 格式错误"})
            return

        if path == "/api/register":
            self.handle_register(data)
            return
        if path == "/api/login":
            self.handle_login(data)
            return
        if path == "/api/logout":
            self.handle_logout()
            return
        if path == "/api/articles":
            self.handle_create_article(data)
            return
        self.send_json(404, {"error": "接口不存在"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/articles/"):
            self.send_json(404, {"error": "接口不存在"})
            return
        try:
            data = self.read_json()
            article_id = int(path.rsplit("/", 1)[-1])
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "请求参数错误"})
            return
        self.handle_update_article(article_id, data)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/articles/"):
            self.send_json(404, {"error": "接口不存在"})
            return
        try:
            article_id = int(path.rsplit("/", 1)[-1])
        except ValueError:
            self.send_json(400, {"error": "文章 ID 错误"})
            return
        user = self.require_user()
        if not user:
            return
        with connect_db() as conn:
            conn.execute("delete from articles where id = ? and user_id = ?", (article_id, user["id"]))
        self.send_json(200, {"ok": True})

    def create_session(self, user_id: int) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + SESSION_SECONDS
        with connect_db() as conn:
            conn.execute(
                "insert into sessions(token, user_id, expires_at) values (?, ?, ?)",
                (token, user_id, expires_at),
            )
        return token, expires_at

    def session_cookie(self, token: str, max_age: int = SESSION_SECONDS) -> str:
        return f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"

    def handle_register(self, data: dict) -> None:
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if len(username) < 2 or len(username) > 32:
            self.send_json(400, {"error": "用户名长度需要在 2 到 32 个字符之间"})
            return
        if len(password) < 6:
            self.send_json(400, {"error": "密码至少需要 6 位"})
            return
        try:
            with connect_db() as conn:
                cur = conn.execute(
                    "insert into users(username, password_hash) values (?, ?)",
                    (username, hash_password(password)),
                )
                user_id = cur.lastrowid
                user = conn.execute("select id, username from users where id = ?", (user_id,)).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "用户名已存在"})
            return
        token, _ = self.create_session(user_id)
        self.send_json(200, {"user": public_user(user)}, {"Set-Cookie": self.session_cookie(token)})

    def handle_login(self, data: dict) -> None:
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        with connect_db() as conn:
            user = conn.execute("select id, username, password_hash from users where username = ?", (username,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            self.send_json(401, {"error": "用户名或密码错误"})
            return
        token, _ = self.create_session(user["id"])
        self.send_json(200, {"user": public_user(user)}, {"Set-Cookie": self.session_cookie(token)})

    def handle_logout(self) -> None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("session")
        if morsel:
            with connect_db() as conn:
                conn.execute("delete from sessions where token = ?", (morsel.value,))
        self.send_json(200, {"ok": True}, {"Set-Cookie": self.session_cookie("", 0)})

    def handle_create_article(self, data: dict) -> None:
        user = self.require_user()
        if not user:
            return
        title = str(data.get("title") or "未命名文章").strip()[:120]
        content = str(data.get("content") or "")
        with connect_db() as conn:
            cur = conn.execute(
                """
                insert into articles(user_id, title, content, updated_at)
                values (?, ?, ?, current_timestamp)
                """,
                (user["id"], title, content),
            )
            row = conn.execute(
                "select id, title, content, updated_at from articles where id = ?",
                (cur.lastrowid,),
            ).fetchone()
        self.send_json(200, public_article(row))

    def handle_update_article(self, article_id: int, data: dict) -> None:
        user = self.require_user()
        if not user:
            return
        title = str(data.get("title") or "未命名文章").strip()[:120]
        content = str(data.get("content") or "")
        with connect_db() as conn:
            conn.execute(
                """
                update articles
                set title = ?, content = ?, updated_at = current_timestamp
                where id = ? and user_id = ?
                """,
                (title, content, article_id, user["id"]),
            )
            row = conn.execute(
                """
                select id, title, content, updated_at
                from articles
                where id = ? and user_id = ?
                """,
                (article_id, user["id"]),
            ).fetchone()
        if not row:
            self.send_json(404, {"error": "文章不存在"})
            return
        self.send_json(200, public_article(row))


def main() -> None:
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    env_port = os.environ.get("PORT")
    if env_port:
        preferred_ports = [int(env_port)]
        host = "0.0.0.0"
    else:
        preferred_ports = [8000, 8765, 3000, 5173, 0]
    server = None
    last_error = None
    for port in preferred_ports:
        try:
            server = ThreadingHTTPServer((host, port), AppHandler)
            break
        except OSError as exc:
            last_error = exc
    if server is None:
        raise RuntimeError(f"无法启动本地服务：{last_error}") from last_error
    actual_port = server.server_address[1]
    print(f"本地服务已启动：http://{host}:{actual_port}/")
    print(f"数据库位置：{DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
