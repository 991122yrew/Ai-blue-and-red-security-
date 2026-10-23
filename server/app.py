"""RedBlue Sentinel API.

Standard library only (Python 3.9+). SQLite storage, scrypt password hashes,
HMAC-signed bearer tokens, role-based access control and a SHA-256 hash-chained,
append-only audit log.

Run:  python server/app.py        (http://127.0.0.1:8000, serves the front end too)
Test: python -m unittest discover -s server -v
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import analyzer

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
STATIC_ROOT = ROOT.parent

GENESIS = "0" * 64
ROLES = ("red", "blue", "admin")
SESSION_TTL_MIN = 10
MAX_BODY = 64 * 1024
LOGIN_LIMIT = 5          # failed logins per email in the window before lockout
LOGIN_WINDOW_MIN = 5


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return salt.hex(), digest.hex()


def check_password(password, salt_hex, hash_hex):
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, title TEXT,
  role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rules(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, pattern_type TEXT NOT NULL, pattern TEXT NOT NULL,
  action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, note TEXT, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, session_id TEXT, user_id TEXT, actor TEXT, test_id TEXT, category TEXT,
  decision TEXT, matched_rule_id TEXT, risk_score INTEGER, risk_label TEXT, latency_ms INTEGER,
  ts_utc TEXT, response_preview TEXT, reasoning TEXT);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, ts_utc TEXT NOT NULL,
  actor_id TEXT, role TEXT, action TEXT, resource TEXT, test_id TEXT, result TEXT, ip TEXT,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, kind TEXT, subject TEXT, severity TEXT, status TEXT, reason TEXT, ts_utc TEXT,
  locked INTEGER NOT NULL DEFAULT 0);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class Store:
    def __init__(self, db_path, secret, demo_password=None):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.secret = secret.encode() if isinstance(secret, str) else secret
        with self.lock:
            self.db.executescript(SCHEMA)
            self._seed(demo_password)

    # ---- seeding ---------------------------------------------------------
    def _seed(self, demo_password):
        if self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0:
            for r in json.loads((DATA_DIR / "rules.json").read_text(encoding="utf-8")):
                self.db.execute(
                    "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?)",
                    (r["id"], r["name"], r["pattern_type"], r["pattern"], r["action"],
                     int(r["enabled"]), r["note"], r["created_by"], iso(now())))
        if demo_password and self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            for uid, email, name, role, title in [
                ("usr_red", "red@demo.io", "Riya Nair", "red", "Red Team Operator"),
                ("usr_blue", "blue@demo.io", "Dev Malhotra", "blue", "Blue Team Analyst"),
                ("usr_admin", "admin@demo.io", "A. Auditor", "admin", "Admin / Auditor"),
            ]:
                salt, digest = hash_password(demo_password)
                self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,?,?)",
                                (uid, email, name, title, role, salt, digest, iso(now())))
        self.db.commit()

    # ---- tokens ----------------------------------------------------------
    def make_token(self, user, ttl_min):
        payload = b64(json.dumps({"sub": user["id"], "exp": int(time.time()) + ttl_min * 60}).encode())
        sig = b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        return payload + "." + sig

    def read_token(self, token):
        try:
            payload, sig = token.split(".")
            good = b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, good):
                return None
            data = json.loads(unb64(payload))
            if data["exp"] < time.time():
                return None
            row = self.db.execute("SELECT * FROM users WHERE id=? AND active=1", (data["sub"],)).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    # ---- audit chain -----------------------------------------------------
    @staticmethod
    def _entry_hash(prev_hash, e):
        body = json.dumps(
            {k: e[k] for k in ("id", "ts_utc", "actor_id", "role", "action", "resource", "test_id", "result", "ip")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((prev_hash + body).encode()).hexdigest()

    def audit(self, actor, role, action, resource="", result="OK", test_id="", ip=""):
        with self.lock:
            last = self.db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            seq = (last["seq"] if last else 0) + 1
            e = {"id": "EVT-%04d" % seq, "ts_utc": iso(now()), "actor_id": actor, "role": role,
                 "action": action, "resource": resource, "test_id": test_id, "result": result, "ip": ip}
            h = self._entry_hash(prev, e)
            self.db.execute(
                "INSERT INTO audit(id,ts_utc,actor_id,role,action,resource,test_id,result,ip,prev_hash,hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (e["id"], e["ts_utc"], actor, role, action, resource, test_id, result, ip, prev, h))
            self.db.commit()
            return {**e, "prev_hash": prev, "hash": h}

    def verify_chain(self):
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        prev = GENESIS
        for r in rows:
            e = dict(r)
            if e["prev_hash"] != prev or self._entry_hash(prev, e) != e["hash"]:
                return {"valid": False, "checked": len(rows), "broken_at": e["id"], "head": prev}
            prev = e["hash"]
        return {"valid": True, "checked": len(rows), "broken_at": None, "head": prev}

    # ---- anomaly detection ----------------------------------------------
    def _count(self, sql, args):
        return self.db.execute(sql, args).fetchone()[0]

    def _raise(self, kind, subject, severity, reason):
        cutoff = iso(now() - timedelta(minutes=10))
        if self._count("SELECT COUNT(*) FROM alerts WHERE kind=? AND subject=? AND ts_utc>=?",
                       (kind, subject, cutoff)):
            return
        n = self._count("SELECT COUNT(*) FROM alerts", ()) + 1
        alert_id = "ALR-%03d" % n
        self.db.execute("INSERT INTO alerts(id,kind,subject,severity,status,reason,ts_utc) VALUES(?,?,?,?,?,?,?)",
                        (alert_id, kind, subject, severity, "open", reason, iso(now())))
        self.db.commit()
        self.audit("system", "system", "ALERT_RAISED", "/alerts/" + alert_id, "OK")

    def detect(self, subject):
        """Run the rule-based detectors for one actor (email)."""
        with self.lock:
            t = now()
            ago = lambda m: iso(t - timedelta(minutes=m))
            n = self._count("SELECT COUNT(*) FROM runs WHERE actor=? AND ts_utc>=?", (subject, ago(2)))
            if n >= 8:
                self._raise("burst_activity", subject, "High", "%d test runs within 2 minutes by %s (threshold: 8)" % (n, subject))
            row = self.db.execute(
                "SELECT category, COUNT(*) c FROM runs WHERE actor=? AND ts_utc>=? GROUP BY category ORDER BY c DESC LIMIT 1",
                (subject, ago(5))).fetchone()
            if row and row["c"] >= 5:
                self._raise("category_hammering", subject, "Medium",
                            "%d %s runs within 5 minutes by %s (threshold: 5)" % (row["c"], row["category"], subject))
            row = self.db.execute(
                "SELECT test_id, COUNT(*) c FROM runs WHERE actor=? AND decision='MISSED' AND ts_utc>=? "
                "GROUP BY test_id ORDER BY c DESC LIMIT 1", (subject, ago(30))).fetchone()
            if row and row["c"] >= 3:
                self._raise("repeated_misses", subject, "Medium",
                            "%s missed %d times in 30 minutes by %s (threshold: 3)" % (row["test_id"], row["c"], subject))
            n = self._count("SELECT COUNT(*) FROM audit WHERE actor_id=? AND action='ACCESS_DENIED' AND ts_utc>=?",
                            (subject, ago(10)))
            if n >= 3:
                self._raise("forbidden_access", subject, "High",
                            "%d ACCESS_DENIED events in 10 minutes by %s (threshold: 3)" % (n, subject))
            n = self._count("SELECT COUNT(*) FROM audit WHERE actor_id=? AND action='LOGIN_FAILED' AND ts_utc>=?",
                            (subject, ago(LOGIN_WINDOW_MIN)))
            if n >= 4:
                self._raise("failed_logins", subject, "Medium",
                            "%d failed logins in %d minutes for %s (threshold: 4)" % (n, LOGIN_WINDOW_MIN, subject))

    # ---- auth ------------------------------------------------------------
    def login(self, email, password, ip):
        email = (email or "").strip().lower()
        with self.lock:
            cutoff = iso(now() - timedelta(minutes=LOGIN_WINDOW_MIN))
            fails = self._count("SELECT COUNT(*) FROM audit WHERE actor_id=? AND action='LOGIN_FAILED' AND ts_utc>=?",
                                (email, cutoff))
            if fails >= LOGIN_LIMIT:
                self.audit(email, "unknown", "LOGIN_LOCKED", "/api/auth/login", "DENIED", ip=ip)
                raise ApiError(429, "Too many failed attempts. Try again in a few minutes.")
            row = self.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row:
                ok = check_password(password or "", row["pw_salt"], row["pw_hash"]) and row["active"]
            else:
                check_password(password or "", "00" * 16, "00" * 32)   # equalise timing
                ok = False
            if not ok:
                self.audit(email or "unknown", row["role"] if row else "unknown", "LOGIN_FAILED",
                           "/api/auth/login", "FAIL", ip=ip)
                self.detect(email)
                raise ApiError(401, "Invalid email or password.")
            user = dict(row)
            self.audit(email, user["role"], "LOGIN_SUCCESS", "/api/auth/login", "OK", ip=ip)
            return user

    # ---- domain ----------------------------------------------------------
    def tests(self):
        return json.loads((DATA_DIR / "tests.json").read_text(encoding="utf-8"))

    def rules(self):
        return [dict(r, enabled=bool(r["enabled"])) for r in self.db.execute("SELECT * FROM rules ORDER BY id")]

    def run_test(self, user, test_id, ip):
        test = next((t for t in self.tests() if t["id"] == test_id), None)
        if not test:
            raise ApiError(404, "Unknown test case.")
        with self.lock:
            res = analyzer.analyze(test, self.rules())
            risk = analyzer.risk_score(test, res["decision"])
            n = self._count("SELECT COUNT(*) FROM runs", ()) + 1
            run = {"id": "RUN-%04d" % n, "session_id": "sess_" + secrets.token_hex(3),
                   "user_id": user["id"], "actor": user["email"], "test_id": test["id"],
                   "category": test["category"], "decision": res["decision"],
                   "matched_rule_id": res["matched_rule_id"], "risk_score": risk["score"],
                   "risk_label": risk["label"], "latency_ms": res["latency_ms"], "ts_utc": iso(now()),
                   "response_preview": res["response_preview"], "reasoning": json.dumps(res["reasoning"])}
            self.db.execute("INSERT INTO runs VALUES(:id,:session_id,:user_id,:actor,:test_id,:category,:decision,"
                            ":matched_rule_id,:risk_score,:risk_label,:latency_ms,:ts_utc,:response_preview,:reasoning)", run)
            self.db.commit()
            self.audit(user["email"], user["role"], "RUN_TEST", "/api/runs/" + run["id"],
                       res["decision"], test_id=test["id"], ip=ip)
            self.detect(user["email"])
        return self.present_run(run, user["role"])

    @staticmethod
    def present_run(run, role):
        run = dict(run)
        steps = json.loads(run["reasoning"]) if isinstance(run["reasoning"], str) else run["reasoning"]
        if role == "red":     # red never sees rule names, ids or counts
            run.pop("matched_rule_id", None)
            for s in steps:
                if s["key"] == "input_scan":
                    s["detail"] = "Prompt scanned against the active defense policy"
                    s["outcome"] = s["outcome"].split(" — ")[0]
        run["reasoning"] = steps
        run["session_ttl_min"] = SESSION_TTL_MIN
        return run

    def runs(self, user):
        sql, args = "SELECT * FROM runs", ()
        if user["role"] == "red":
            sql, args = "SELECT * FROM runs WHERE user_id=?", (user["id"],)
        rows = self.db.execute(sql + " ORDER BY ts_utc DESC LIMIT 200", args).fetchall()
        return [self.present_run(r, user["role"]) for r in rows]

    def metrics(self, user):
        where, args = ("WHERE user_id=?", (user["id"],)) if user["role"] == "red" else ("", ())
        rows = [dict(r) for r in self.db.execute("SELECT * FROM runs " + where, args)]
        total = len(rows)
        by = lambda key: {k: sum(1 for r in rows if r[key] == k) for k in {r[key] for r in rows}}
        dec = by("decision")
        out = {
            "total": total,
            "blocked": dec.get("BLOCKED", 0), "flagged": dec.get("FLAGGED", 0), "missed": dec.get("MISSED", 0),
            "detection_rate": round(100 * (dec.get("BLOCKED", 0) + dec.get("FLAGGED", 0)) / total, 1) if total else 0,
            "by_category": by("category"), "risk": by("risk_label"),
            "avg_latency_ms": round(sum(r["latency_ms"] for r in rows) / total) if total else 0,
        }
        t = now().replace(minute=0, second=0, microsecond=0)
        series = []
        for h in range(23, -1, -1):
            lo, hi = iso(t - timedelta(hours=h)), iso(t - timedelta(hours=h - 1))
            bucket = [r for r in rows if lo <= r["ts_utc"] < hi]
            series.append({"hour": lo, "total": len(bucket),
                           "blocked": sum(r["decision"] == "BLOCKED" for r in bucket),
                           "flagged": sum(r["decision"] == "FLAGGED" for r in bucket),
                           "missed": sum(r["decision"] == "MISSED" for r in bucket)})
        out["series_24h"] = series
        if user["role"] != "red":
            out["open_alerts"] = self._count("SELECT COUNT(*) FROM alerts WHERE status='open'", ())
            out["audit_entries"] = self._count("SELECT COUNT(*) FROM audit", ())
        return out

    def audit_page(self, user, q):
        where, args = [], []
        if user["role"] == "blue":
            where.append("role != 'admin'")
        for col, key in (("action", "action"), ("actor_id", "actor"), ("result", "result")):
            if q.get(key):
                where.append(col + "=?")
                args.append(q[key][0])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        limit = max(1, min(int(q.get("limit", ["100"])[0]), 500))
        offset = max(0, int(q.get("offset", ["0"])[0]))
        total = self._count("SELECT COUNT(*) FROM audit" + clause, args)
        rows = self.db.execute("SELECT * FROM audit" + clause + " ORDER BY seq DESC LIMIT ? OFFSET ?",
                               args + [limit, offset]).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}


# --------------------------------------------------------------------------
RULE_TYPES = ("keyword", "regex", "encoding", "locale")


def validate_rule(body, partial=False):
    out = {}
    if "name" in body or not partial:
        name = str(body.get("name", "")).strip()
        if not 1 <= len(name) <= 80:
            raise ApiError(400, "name must be 1-80 characters")
        out["name"] = name
    if "pattern_type" in body or not partial:
        if body.get("pattern_type") not in RULE_TYPES:
            raise ApiError(400, "pattern_type must be one of " + ", ".join(RULE_TYPES))
        out["pattern_type"] = body["pattern_type"]
    if "pattern" in body or not partial:
        pattern = str(body.get("pattern", ""))
        if not 1 <= len(pattern) <= 200:
            raise ApiError(400, "pattern must be 1-200 characters")
        out["pattern"] = pattern
    if "action" in body or not partial:
        if body.get("action") not in ("BLOCK", "FLAG"):
            raise ApiError(400, "action must be BLOCK or FLAG")
        out["action"] = body["action"]
    if "enabled" in body:
        out["enabled"] = int(bool(body["enabled"]))
    if "note" in body:
        out["note"] = str(body["note"])[:300]
    ptype = out.get("pattern_type")
    if ptype and ptype != "keyword" and "pattern" in out:
        try:
            re.compile(out["pattern"])
        except re.error as e:
            raise ApiError(400, "invalid regex: %s" % e)
    return out


def csv_safe(value):
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class Handler(BaseHTTPRequestHandler):
    server_version = "RedBlueSentinel/1.0"
    store = None
    cors_origin = "*"

    def log_message(self, fmt, *args):
        if os.environ.get("SENTINEL_LOG"):
            super().log_message(fmt, *args)

    # ---- plumbing --------------------------------------------------------
    def _headers(self, status, ctype, length):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", self.cors_origin)
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.end_headers()

    def send_json(self, status, obj):
        raw = json.dumps(obj).encode()
        self._headers(status, "application/json; charset=utf-8", len(raw))
        self.wfile.write(raw)

    def ip(self):
        return self.client_address[0]

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(413, "Request body too large.")
        if not n:
            return {}
        try:
            data = json.loads(self.rfile.read(n))
        except ValueError:
            raise ApiError(400, "Body must be valid JSON.")
        if not isinstance(data, dict):
            raise ApiError(400, "Body must be a JSON object.")
        return data

    def do_OPTIONS(self):
        self._headers(204, "text/plain", 0)

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PATCH(self):
        self.dispatch("PATCH")

    def dispatch(self, method):
        url = urlparse(self.path)
        try:
            if url.path.startswith("/api/"):
                self.api(method, url.path, parse_qs(url.query))
            elif method == "GET":
                self.static(url.path)
            else:
                raise ApiError(405, "Method not allowed.")
        except ApiError as e:
            self.send_json(e.status, {"error": e.message})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send_json(500, {"error": "Internal server error."})
            if os.environ.get("SENTINEL_LOG"):
                raise

    def static(self, path):
        pages = {"/": "index.html", "/index.html": "index.html", "/live.html": "live.html"}
        if path not in pages:
            raise ApiError(404, "Not found.")
        f = STATIC_ROOT / pages[path]
        raw = f.read_bytes()
        self._headers(200, "text/html; charset=utf-8", len(raw))
        self.wfile.write(raw)

    # ---- auth helpers ----------------------------------------------------
    def authed(self):
        header = self.headers.get("Authorization", "")
        user = self.store.read_token(header[7:]) if header.startswith("Bearer ") else None
        if not user:
            raise ApiError(401, "Authentication required.")
        return user

    def require(self, user, *roles, resource=""):
        if user["role"] not in roles:
            self.store.audit(user["email"], user["role"], "ACCESS_DENIED", resource or self.path, "DENIED", ip=self.ip())
            self.store.detect(user["email"])
            raise ApiError(403, "Access denied for your role. This attempt was logged.")

    # ---- routes ----------------------------------------------------------
    def api(self, method, path, q):
        s = self.store
        if (method, path) == ("GET", "/api/health"):
            return self.send_json(200, {"status": "ok", "audit_entries": s._count("SELECT COUNT(*) FROM audit", ())})
        if (method, path) == ("POST", "/api/auth/login"):
            b = self.body()
            user = s.login(b.get("email"), b.get("password"), self.ip())
            return self.send_json(200, {
                "token": s.make_token(user, int(os.environ.get("TOKEN_TTL_MIN", "60"))),
                "user": {k: user[k] for k in ("id", "email", "name", "role", "title")}})

        user = self.authed()
        res = path
        if (method, path) == ("GET", "/api/me"):
            return self.send_json(200, {k: user[k] for k in ("id", "email", "name", "role", "title")})

        if (method, path) == ("POST", "/api/events/denied"):
            # the UI reports a screen the user's role cannot open; recorded against the caller
            resource = str(self.body().get("resource", ""))[:200]
            if not resource.startswith("/"):
                raise ApiError(400, "resource must be a path.")
            s.audit(user["email"], user["role"], "ACCESS_DENIED", "/api/v1" + resource, "DENIED", ip=self.ip())
            s.detect(user["email"])
            return self.send_json(201, {"logged": True})

        if (method, path) == ("GET", "/api/directory"):
            self.require(user, "blue", "admin", resource=res)
            rows = s.db.execute("SELECT id,email,name,title,role,active,created_at FROM users").fetchall()
            return self.send_json(200, {"items": [dict(r, active=bool(r["active"])) for r in rows]})

        if (method, path) == ("GET", "/api/tests"):
            tests = s.tests()
            if user["role"] == "red":
                keep = ("id", "title", "category", "severity", "prompt_text", "expected_behavior")
                tests = [{k: t[k] for k in keep} for t in tests]
            else:
                tests = [{k: v for k, v in t.items() if k != "seedWeight"} for t in tests]
            return self.send_json(200, {"items": tests})

        if (method, path) == ("POST", "/api/runs"):
            self.require(user, "red", "admin", resource=res)
            test_id = self.body().get("test_id")
            return self.send_json(201, s.run_test(user, str(test_id), self.ip()))
        if (method, path) == ("GET", "/api/runs"):
            return self.send_json(200, {"items": s.runs(user)})
        if (method, path) == ("GET", "/api/metrics"):
            return self.send_json(200, s.metrics(user))

        if (method, path) == ("GET", "/api/rules"):
            self.require(user, "blue", "admin", resource=res)
            return self.send_json(200, {"items": s.rules()})
        if (method, path) == ("POST", "/api/rules"):
            self.require(user, "blue", "admin", resource=res)
            r = validate_rule(self.body())
            with s.lock:
                rid = "RULE-%03d" % (s._count("SELECT COUNT(*) FROM rules", ()) + 1)
                s.db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?)",
                             (rid, r["name"], r["pattern_type"], r["pattern"], r["action"],
                              r.get("enabled", 1), r.get("note", ""), user["email"], iso(now())))
                s.db.commit()
                s.audit(user["email"], user["role"], "RULE_CREATED", "/api/rules/" + rid, "OK", ip=self.ip())
            return self.send_json(201, {"id": rid})
        m = re.fullmatch(r"/api/rules/(RULE-\d+)", path)
        if m and method == "PATCH":
            self.require(user, "blue", "admin", resource=res)
            r = validate_rule(self.body(), partial=True)
            if not r:
                raise ApiError(400, "Nothing to update.")
            with s.lock:
                if not s.db.execute("SELECT 1 FROM rules WHERE id=?", (m.group(1),)).fetchone():
                    raise ApiError(404, "Unknown rule.")
                s.db.execute("UPDATE rules SET " + ",".join(k + "=?" for k in r) + " WHERE id=?",
                             list(r.values()) + [m.group(1)])
                s.db.commit()
                s.audit(user["email"], user["role"], "RULE_UPDATED", path, "OK", ip=self.ip())
            return self.send_json(200, {"id": m.group(1), "updated": list(r)})

        if (method, path) == ("GET", "/api/audit/mine"):
            rows = s.db.execute("SELECT * FROM audit WHERE actor_id=? ORDER BY seq DESC LIMIT 20",
                                (user["email"],)).fetchall()
            return self.send_json(200, {"items": [dict(r) for r in rows]})
        if (method, path) == ("GET", "/api/audit"):
            self.require(user, "blue", "admin", resource=res)
            try:
                page = s.audit_page(user, q)
            except ValueError:
                raise ApiError(400, "limit and offset must be integers.")
            return self.send_json(200, page)
        if (method, path) == ("GET", "/api/audit/verify"):
            self.require(user, "blue", "admin", resource=res)
            return self.send_json(200, s.verify_chain())
        if (method, path) == ("GET", "/api/audit/export.csv"):
            self.require(user, "admin", resource=res)
            rows = s.audit_page(user, {"limit": ["500"]})["items"]
            cols = ["ts_utc", "id", "actor_id", "role", "action", "resource", "test_id", "result", "ip", "prev_hash", "hash"]
            buf = io.StringIO()
            w = csv.writer(buf, quoting=csv.QUOTE_ALL)
            w.writerow(cols)
            for r in reversed(rows):
                w.writerow([csv_safe(r[c]) for c in cols])
            s.audit(user["email"], user["role"], "LOG_EXPORT", res, "OK", ip=self.ip())
            raw = buf.getvalue().encode()
            self._headers(200, "text/csv; charset=utf-8", len(raw))
            return self.wfile.write(raw)

        if (method, path) == ("GET", "/api/alerts"):
            self.require(user, "blue", "admin", resource=res)
            rows = s.db.execute("SELECT * FROM alerts ORDER BY ts_utc DESC").fetchall()
            return self.send_json(200, {"items": [dict(r) for r in rows]})
        m = re.fullmatch(r"/api/alerts/(ALR-\d+)/ack", path)
        if m and method == "POST":
            self.require(user, "blue", "admin", resource=res)
            with s.lock:
                cur = s.db.execute("UPDATE alerts SET status='acknowledged' WHERE id=?", (m.group(1),))
                s.db.commit()
                if not cur.rowcount:
                    raise ApiError(404, "Unknown alert.")
                s.audit(user["email"], user["role"], "ALERT_ACK", "/api/alerts/" + m.group(1), "OK", ip=self.ip())
            return self.send_json(200, {"id": m.group(1), "status": "acknowledged"})

        m = re.fullmatch(r"/api/alerts/(ALR-\d+)/lock-session", path)
        if m and method == "POST":
            self.require(user, "admin", resource=res)
            with s.lock:
                cur = s.db.execute("UPDATE alerts SET status='acknowledged', locked=1 WHERE id=?", (m.group(1),))
                s.db.commit()
                if not cur.rowcount:
                    raise ApiError(404, "Unknown alert.")
                s.audit(user["email"], user["role"], "SESSION_LOCKED", path, "OK", ip=self.ip())
            return self.send_json(200, {"id": m.group(1), "locked": True})

        if (method, path) == ("GET", "/api/users"):
            self.require(user, "admin", resource=res)
            rows = s.db.execute("SELECT id,email,name,title,role,active,created_at FROM users").fetchall()
            return self.send_json(200, {"items": [dict(r, active=bool(r["active"])) for r in rows]})
        m = re.fullmatch(r"/api/users/([\w-]+)", path)
        if m and method == "PATCH":
            self.require(user, "admin", resource=res)
            b = self.body()
            upd = {}
            if "role" in b:
                if b["role"] not in ROLES:
                    raise ApiError(400, "role must be red, blue or admin")
                upd["role"] = b["role"]
            if "active" in b:
                upd["active"] = int(bool(b["active"]))
            if not upd:
                raise ApiError(400, "Nothing to update.")
            if m.group(1) == user["id"]:
                raise ApiError(400, "You cannot change your own role or status.")
            with s.lock:
                cur = s.db.execute("UPDATE users SET " + ",".join(k + "=?" for k in upd) + " WHERE id=?",
                                   list(upd.values()) + [m.group(1)])
                s.db.commit()
                if not cur.rowcount:
                    raise ApiError(404, "Unknown user.")
                s.audit(user["email"], user["role"], "ROLE_CHANGED" if "role" in upd else "USER_STATUS",
                        "/api/v1/admin/users/" + m.group(1), "OK", ip=self.ip())
            return self.send_json(200, {"id": m.group(1), "updated": list(upd)})

        raise ApiError(404, "Not found.")


def load_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    f = DATA_DIR / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
    return f.read_text().strip()


def make_server(host, port, db_path, secret, demo_password="demo1234"):
    Handler.store = Store(db_path, secret, demo_password)
    Handler.cors_origin = os.environ.get("CORS_ORIGIN", "*")
    return ThreadingHTTPServer((host, port), Handler)


def main():
    demo = os.environ.get("DEMO_PASSWORD", "demo1234") if os.environ.get("SEED_DEMO", "1") == "1" else None
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    db_path = os.environ.get("DB_PATH", str(DATA_DIR / "sentinel.db"))
    srv = make_server(host, port, db_path, load_secret(), demo)
    print("RedBlue Sentinel API on http://%s:%d  (db: %s)" % (host, port, db_path))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
