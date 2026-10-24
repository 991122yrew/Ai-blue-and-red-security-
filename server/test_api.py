import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402

PW = "demo1234"


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "t.db")
        self.srv = app.make_server("127.0.0.1", 0, self.db_path, "test-secret", PW)
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        app.Handler.store.db.close()
        self.tmp.cleanup()

    # ---- helpers ----
    def call(self, method, path, body=None, token=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers["Content-Type"].startswith("application/json") else raw.decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def login(self, who):
        status, data = self.call("POST", "/api/auth/login", {"email": who + "@demo.io", "password": PW})
        self.assertEqual(status, 200)
        return data["token"]

    def audit_actions(self, token):
        return [e["action"] for e in self.call("GET", "/api/audit?limit=500", token=token)[1]["items"]]

    # ---- auth ----
    def test_login_and_me(self):
        t = self.login("red")
        status, me = self.call("GET", "/api/me", token=t)
        self.assertEqual((status, me["role"]), (200, "red"))
        self.assertNotIn("pw_hash", me)

    def test_bad_login_and_no_token(self):
        self.assertEqual(self.call("POST", "/api/auth/login", {"email": "red@demo.io", "password": "nope"})[0], 401)
        self.assertEqual(self.call("GET", "/api/me")[0], 401)
        self.assertEqual(self.call("GET", "/api/me", token="garbage.token")[0], 401)

    def test_tampered_token_rejected(self):
        t = self.login("red")
        payload, sig = t.split(".")
        self.assertEqual(self.call("GET", "/api/me", token=payload + "." + sig[::-1])[0], 401)

    def test_login_lockout(self):
        for _ in range(5):
            self.assertEqual(self.call("POST", "/api/auth/login", {"email": "blue@demo.io", "password": "x"})[0], 401)
        self.assertEqual(self.call("POST", "/api/auth/login", {"email": "blue@demo.io", "password": PW})[0], 429)

    # ---- RBAC / separation ----
    def test_red_blocked_from_rules_and_audit_and_denial_logged(self):
        red, admin = self.login("red"), self.login("admin")
        self.assertEqual(self.call("GET", "/api/rules", token=red)[0], 403)
        self.assertEqual(self.call("GET", "/api/audit", token=red)[0], 403)
        self.assertEqual(self.call("GET", "/api/alerts", token=red)[0], 403)
        self.assertGreaterEqual(self.audit_actions(admin).count("ACCESS_DENIED"), 3)

    def test_red_never_sees_rule_details(self):
        red = self.login("red")
        status, run = self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        self.assertEqual(status, 201)
        self.assertNotIn("matched_rule_id", run)
        blob = json.dumps(run)
        self.assertNotIn("Instruction override guard", blob)
        self.assertNotIn("RULE-", blob)
        tests = self.call("GET", "/api/tests", token=red)[1]["items"]
        self.assertNotIn("response", tests[0])
        self.assertNotIn("suggest", tests[0])

    def test_blue_sees_rules_and_cannot_run_or_export(self):
        blue = self.login("blue")
        self.assertEqual(len(self.call("GET", "/api/rules", token=blue)[1]["items"]), 8)
        self.assertEqual(self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=blue)[0], 403)
        self.assertEqual(self.call("GET", "/api/audit/export.csv", token=blue)[0], 403)

    def test_blue_audit_view_hides_admin_entries(self):
        self.login("admin")
        blue = self.login("blue")
        roles = {e["role"] for e in self.call("GET", "/api/audit", token=blue)[1]["items"]}
        self.assertNotIn("admin", roles)

    # ---- analyzer through the API ----
    def test_decisions(self):
        red = self.login("red")
        decisions = {}
        for t in self.call("GET", "/api/tests", token=red)[1]["items"]:
            decisions[t["id"]] = self.call("POST", "/api/runs", {"test_id": t["id"]}, token=red)[1]["decision"]
        self.assertEqual(decisions["T-PI-001"], "BLOCKED")
        self.assertEqual(set(decisions.values()), {"BLOCKED", "FLAGGED", "MISSED"})
        self.assertEqual(self.call("POST", "/api/runs", {"test_id": "NOPE"}, token=red)[0], 404)

    def test_red_runs_are_scoped_to_red(self):
        red, admin = self.login("red"), self.login("admin")
        self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        self.call("POST", "/api/runs", {"test_id": "T-PI-002"}, token=admin)
        self.assertEqual(len(self.call("GET", "/api/runs", token=red)[1]["items"]), 1)
        self.assertEqual(len(self.call("GET", "/api/runs", token=admin)[1]["items"]), 2)
        m = self.call("GET", "/api/metrics", token=red)[1]
        self.assertEqual(m["total"], 1)
        self.assertNotIn("open_alerts", m)

    # ---- rules management ----
    def test_rule_create_update_validation(self):
        blue = self.login("blue")
        status, r = self.call("POST", "/api/rules", {"name": "n", "pattern_type": "regex", "pattern": "(", "action": "BLOCK"}, token=blue)
        self.assertEqual(status, 400)
        status, r = self.call("POST", "/api/rules", {"name": "Custom", "pattern_type": "keyword", "pattern": "unrestricted", "action": "BLOCK"}, token=blue)
        self.assertEqual(status, 201)
        self.assertEqual(self.call("PATCH", "/api/rules/" + r["id"], {"enabled": False}, token=blue)[0], 200)
        self.assertEqual(self.call("PATCH", "/api/rules/RULE-999", {"enabled": False}, token=blue)[0], 404)
        self.assertIn("RULE_CREATED", self.audit_actions(blue))

    # ---- audit chain ----
    def test_chain_verifies_and_persists_across_restart(self):
        red, blue = self.login("red"), self.login("blue")
        self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        v = self.call("GET", "/api/audit/verify", token=blue)[1]
        self.assertTrue(v["valid"])
        before = v["checked"]
        store2 = app.Store(self.db_path, "test-secret", None)
        self.assertEqual(store2.verify_chain()["checked"], before)
        store2.db.close()

    def test_audit_is_append_only(self):
        self.login("red")
        db = app.Handler.store.db
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("UPDATE audit SET result='OK' WHERE seq=1")
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("DELETE FROM audit WHERE seq=1")

    def test_tampering_is_detected(self):
        red, blue = self.login("red"), self.login("blue")
        self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        db = app.Handler.store.db
        db.execute("DROP TRIGGER audit_no_update")          # an attacker with raw DB access
        changed = db.execute("UPDATE audit SET result='OK' WHERE action='RUN_TEST'").rowcount
        db.commit()
        self.assertEqual(changed, 1)
        v = self.call("GET", "/api/audit/verify", token=blue)[1]
        self.assertFalse(v["valid"])
        self.assertTrue(v["broken_at"].startswith("EVT-"))

    # ---- anomalies ----
    def test_burst_raises_alert(self):
        red, blue = self.login("red"), self.login("blue")
        for _ in range(8):
            self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        alerts = self.call("GET", "/api/alerts", token=blue)[1]["items"]
        self.assertIn("burst_activity", {a["kind"] for a in alerts})
        aid = alerts[0]["id"]
        self.assertEqual(self.call("POST", "/api/alerts/%s/ack" % aid, token=blue)[1]["status"], "acknowledged")
        self.assertIn("ALERT_RAISED", self.audit_actions(blue))

    # ---- admin ----
    def test_admin_csv_and_user_management(self):
        admin = self.login("admin")
        status, text = self.call("GET", "/api/audit/export.csv", token=admin)
        self.assertEqual(status, 200)
        self.assertTrue(text.startswith('"ts_utc","id"'))
        self.assertEqual(self.call("PATCH", "/api/users/usr_red", {"active": False}, token=admin)[0], 200)
        self.assertEqual(self.call("POST", "/api/auth/login", {"email": "red@demo.io", "password": PW})[0], 401)
        self.assertEqual(self.call("PATCH", "/api/users/usr_admin", {"role": "red"}, token=admin)[0], 400)

    def test_deactivated_user_token_stops_working(self):
        red, admin = self.login("red"), self.login("admin")
        self.call("PATCH", "/api/users/usr_red", {"active": False}, token=admin)
        self.assertEqual(self.call("GET", "/api/me", token=red)[0], 401)

    def test_front_end_contract(self):
        """Endpoints and names the main site (index.html) relies on."""
        red, blue, admin = self.login("red"), self.login("blue"), self.login("admin")
        # UI-reported denial is logged against the caller and counted
        self.assertEqual(self.call("POST", "/api/events/denied", {"resource": "/app/admin"}, token=red)[0], 201)
        self.assertEqual(self.call("POST", "/api/events/denied", {"resource": "no-slash"}, token=red)[0], 400)
        mine = self.call("GET", "/api/audit/mine", token=red)[1]["items"]
        self.assertIn("ACCESS_DENIED", [e["action"] for e in mine])
        self.assertTrue(all(e["actor_id"] == "red@demo.io" for e in mine))
        # directory is Blue/Admin only
        self.assertEqual(self.call("GET", "/api/directory", token=red)[0], 403)
        self.assertEqual(len(self.call("GET", "/api/directory", token=blue)[1]["items"]), 3)
        # action names match the UI's labels
        self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        self.call("POST", "/api/auth/login", {"email": "red@demo.io", "password": "bad"})
        actions = set(self.audit_actions(blue))
        self.assertTrue({"RUN_TEST", "LOGIN_FAILED", "ACCESS_DENIED", "LOGIN_SUCCESS"} <= actions)
        # em-dash outcomes: red sees only the generic outcome
        run = self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)[1]
        self.assertEqual(run["reasoning"][0]["outcome"], "Blocking rule hit")
        blue_run = self.call("GET", "/api/runs", token=blue)[1]["items"][0]
        self.assertIn("—", blue_run["reasoning"][0]["outcome"])

    def test_lock_session_and_user_audit_names(self):
        red, blue, admin = self.login("red"), self.login("blue"), self.login("admin")
        for _ in range(8):
            self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        aid = self.call("GET", "/api/alerts", token=blue)[1]["items"][0]["id"]
        self.assertEqual(self.call("POST", "/api/alerts/%s/lock-session" % aid, token=blue)[0], 403)
        self.assertEqual(self.call("POST", "/api/alerts/%s/lock-session" % aid, token=admin)[0], 200)
        alert = next(a for a in self.call("GET", "/api/alerts", token=admin)[1]["items"] if a["id"] == aid)
        self.assertEqual((alert["status"], alert["locked"]), ("acknowledged", 1))
        self.call("PATCH", "/api/users/usr_blue", {"role": "red"}, token=admin)
        self.call("PATCH", "/api/users/usr_blue", {"active": True}, token=admin)
        actions = self.audit_actions(admin)
        self.assertTrue({"SESSION_LOCKED", "ROLE_CHANGED", "USER_STATUS"} <= set(actions))

    def test_run_rate_limit(self):
        red, blue = self.login("red"), self.login("blue")
        old, app.RUN_LIMIT_PER_MIN = app.RUN_LIMIT_PER_MIN, 4
        try:
            codes = [self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)[0] for _ in range(6)]
        finally:
            app.RUN_LIMIT_PER_MIN = old
        self.assertEqual(codes, [201, 201, 201, 201, 429, 429])
        self.assertIn("RATE_LIMITED", self.audit_actions(blue))

    def test_simulated_tamper_never_modifies_the_log(self):
        red, blue = self.login("red"), self.login("blue")
        self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        sim = self.call("GET", "/api/audit/verify?simulate_tamper=auto", token=blue)[1]
        self.assertFalse(sim["valid"])
        self.assertTrue(sim["simulated"])
        self.assertEqual(sim["broken_at"], sim["tampered"])
        real = self.call("GET", "/api/audit/verify", token=blue)[1]
        self.assertTrue(real["valid"])
        self.assertEqual(self.call("GET", "/api/audit/verify?simulate_tamper=EVT-9999", token=blue)[0], 404)
        self.assertEqual(self.call("GET", "/api/audit/verify?simulate_tamper=auto", token=red)[0], 403)

    # ---- real accounts ----
    GOOD = "correct horse battery"

    def register(self, email="new@user.io", name="New User", password=GOOD):
        return self.call("POST", "/api/auth/register", {"email": email, "name": name, "password": password})

    def login_as(self, email, password):
        return self.call("POST", "/api/auth/login", {"email": email, "password": password})

    def test_signup_creates_least_privilege_account(self):
        status, d = self.register()
        self.assertEqual((status, d["user"]["role"]), (201, "red"))
        self.assertNotIn("password", json.dumps(d))
        status, d = self.login_as("new@user.io", self.GOOD)
        self.assertEqual((status, d["user"]["role"]), (200, "red"))
        self.assertEqual(self.call("GET", "/api/rules", token=d["token"])[0], 403)

    def test_signup_validation_and_duplicates(self):
        self.assertEqual(self.register(password="short")[0], 400)
        self.assertEqual(self.register(password="aaaaaaaaaaaa")[0], 400)
        self.assertEqual(self.register(email="not-an-email")[0], 400)
        self.assertEqual(self.register(name="")[0], 400)
        self.assertEqual(self.register()[0], 201)
        self.assertEqual(self.register(email="NEW@user.io")[0], 409)
        self.assertEqual(self.register(email="red@demo.io")[0], 409)

    def test_signup_rate_limit_and_switch(self):
        old, app.SIGNUPS_PER_HOUR = app.SIGNUPS_PER_HOUR, 2
        try:
            codes = [self.register(email="u%d@user.io" % i)[0] for i in range(3)]
        finally:
            app.SIGNUPS_PER_HOUR = old
        self.assertEqual(codes, [201, 201, 429])
        os.environ["ALLOW_SIGNUP"] = "0"
        try:
            self.assertEqual(self.register(email="late@user.io")[0], 403)
            self.assertFalse(self.call("GET", "/api/health")[1]["signup"])
        finally:
            del os.environ["ALLOW_SIGNUP"]
        self.assertTrue(self.call("GET", "/api/health")[1]["signup"])
        self.assertTrue(self.call("GET", "/api/health")[1]["demo"])

    def test_change_password_flow(self):
        self.register()
        old = self.login_as("new@user.io", self.GOOD)[1]["token"]
        blue = self.login("blue")
        body = {"current_password": "wrong password!", "new_password": "a brand new passphrase"}
        self.assertEqual(self.call("POST", "/api/auth/change-password", body, token=old)[0], 400)
        body["current_password"] = self.GOOD
        self.assertEqual(self.call("POST", "/api/auth/change-password", dict(body, new_password="short"), token=old)[0], 400)
        self.assertEqual(self.call("POST", "/api/auth/change-password", dict(body, new_password=self.GOOD), token=old)[0], 400)
        status, d = self.call("POST", "/api/auth/change-password", body, token=old)
        self.assertEqual(status, 200)
        self.assertEqual(self.call("GET", "/api/me", token=old)[0], 401)          # other sessions are signed out
        self.assertEqual(self.call("GET", "/api/me", token=d["token"])[0], 200)    # the fresh token works
        self.assertEqual(self.login_as("new@user.io", self.GOOD)[0], 401)
        self.assertEqual(self.login_as("new@user.io", "a brand new passphrase")[0], 200)
        actions = self.audit_actions(blue)
        self.assertTrue({"PASSWORD_CHANGED", "PASSWORD_CHANGE_FAILED", "USER_REGISTERED"} <= set(actions))

    def test_change_password_lockout(self):
        self.register()
        t = self.login_as("new@user.io", self.GOOD)[1]["token"]
        bad = {"current_password": "nope nope nope", "new_password": "another good passphrase"}
        codes = [self.call("POST", "/api/auth/change-password", bad, token=t)[0] for _ in range(6)]
        self.assertEqual(codes, [400] * 5 + [429])

    def test_admin_creates_users(self):
        admin, red = self.login("admin"), self.login("red")
        new = {"email": "analyst@corp.io", "name": "Ana Lyst", "role": "blue", "password": self.GOOD}
        self.assertEqual(self.call("POST", "/api/users", new, token=red)[0], 403)
        status, d = self.call("POST", "/api/users", new, token=admin)
        self.assertEqual((status, d["user"]["role"]), (201, "blue"))
        self.assertEqual(self.call("POST", "/api/users", new, token=admin)[0], 409)
        self.assertEqual(self.call("POST", "/api/users", dict(new, email="x@corp.io", role="root"), token=admin)[0], 400)
        self.assertEqual(self.login_as("analyst@corp.io", self.GOOD)[1]["user"]["role"], "blue")
        self.assertIn("USER_CREATED", self.audit_actions(admin))

    def test_bootstrap_admin_without_demo_accounts(self):
        path = os.path.join(self.tmp.name, "boot.db")
        store = app.Store(path, "s", None, ("Boss@Corp.io", self.GOOD))
        try:
            self.assertFalse(store.demo)
            self.assertEqual(store.login("boss@corp.io", self.GOOD, "")["role"], "admin")
            self.assertEqual(store.db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        finally:
            store.db.close()

    def test_old_database_is_migrated(self):
        path = os.path.join(self.tmp.name, "old.db")
        db = sqlite3.connect(path)
        db.executescript("CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, title TEXT,"
                         " role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, pw_salt TEXT NOT NULL,"
                         " pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);")
        db.commit()
        db.close()
        store = app.Store(path, "s", "demo1234")
        try:
            cols = [r["name"] for r in store.db.execute("PRAGMA table_info(users)")]
            self.assertIn("pw_changed_at", cols)
            self.assertEqual(store.login("red@demo.io", "demo1234", "")["role"], "red")
        finally:
            store.db.close()

    def test_proxy_header_sets_client_ip_only_when_trusted(self):
        def login_ip(header):
            req = urllib.request.Request(self.base + "/api/auth/login", method="POST",
                                         data=json.dumps({"email": "red@demo.io", "password": PW}).encode(),
                                         headers={"Content-Type": "application/json", "X-Forwarded-For": header})
            urllib.request.urlopen(req).read()
            blue = self.login("blue")
            return next(e["ip"] for e in self.call("GET", "/api/audit", token=blue)[1]["items"]
                        if e["action"] == "LOGIN_SUCCESS" and e["actor_id"] == "red@demo.io")
        self.assertEqual(login_ip("203.0.113.7, 10.0.0.1"), "127.0.0.1")
        os.environ["TRUST_PROXY"] = "1"
        try:
            self.assertEqual(login_ip("203.0.113.7, 10.0.0.1"), "203.0.113.7")
        finally:
            del os.environ["TRUST_PROXY"]

    def test_csv_formula_injection_neutralised(self):
        self.assertEqual(app.csv_safe("=1+1"), "'=1+1")
        self.assertEqual(app.csv_safe("ok"), "ok")

    def test_bad_input(self):
        red = self.login("red")
        req = urllib.request.Request(self.base + "/api/runs", data=b"{not json", method="POST",
                                     headers={"Authorization": "Bearer " + red})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(self.call("GET", "/api/nope", token=red)[0], 404)

    def test_serves_front_end(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn(b"RedBlue Sentinel", r.read(4000))
        with urllib.request.urlopen(self.base + "/config.js") as r:
            self.assertTrue(r.headers["Content-Type"].startswith("application/javascript"))


if __name__ == "__main__":
    unittest.main()
