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
        db.execute("UPDATE audit SET result='OK' WHERE action='TEST_EXECUTED'")
        db.commit()
        v = self.call("GET", "/api/audit/verify", token=blue)[1]
        self.assertFalse(v["valid"])
        self.assertTrue(v["broken_at"].startswith("EVT-"))

    # ---- anomalies ----
    def test_burst_raises_alert(self):
        red, blue = self.login("red"), self.login("blue")
        for _ in range(8):
            self.call("POST", "/api/runs", {"test_id": "T-PI-001"}, token=red)
        alerts = self.call("GET", "/api/alerts", token=blue)[1]["items"]
        self.assertIn("burst", {a["kind"] for a in alerts})
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


if __name__ == "__main__":
    unittest.main()
