import unittest

from guardrails import AuditLog, Guard, Session, ToolPolicy, tainted_escalation


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def guard(**policies) -> Guard:
    return Guard(policies, clock=FakeClock())


class UrlChecks(unittest.TestCase):
    def setUp(self):
        self.g = guard(http_get=ToolPolicy(risk="low", allowed_domains=["example.com"]))
        self.s = Session()

    def action(self, url):
        return self.g.check(self.s, "http_get", {"url": url}).action

    def test_allowlisted_subdomain(self):
        self.assertEqual(self.action("https://api.example.com/v1"), "allow")

    def test_lookalike_domain_denied(self):
        self.assertEqual(self.action("https://example.com.attacker.net/"), "deny")
        self.assertEqual(self.action("https://notexample.com/"), "deny")

    def test_ssrf_targets_denied(self):
        for u in ("https://169.254.169.254/", "https://127.0.0.1/", "https://10.0.0.5/",
                  "https://[::1]/", "https://localhost/", "https://0.0.0.0/"):
            with self.subTest(url=u):
                self.assertEqual(self.action(u), "deny")

    def test_userinfo_trick_denied(self):
        self.assertEqual(self.action("https://example.com@attacker.net/"), "deny")

    def test_non_https_denied(self):
        self.assertEqual(self.action("file:///etc/passwd"), "deny")


class PathChecks(unittest.TestCase):
    def setUp(self):
        self.g = guard(read_file=ToolPolicy(sandbox_root="/workspace"))
        self.s = Session()

    def action(self, p):
        return self.g.check(self.s, "read_file", {"path": p}).action

    def test_inside(self):
        self.assertEqual(self.action("docs/a.md"), "allow")

    def test_traversal_variants(self):
        for p in ("../etc/passwd", "docs/../../etc/passwd", "/etc/passwd", "..\\..\\windows\\win.ini",
                  "/workspace/../workspace2/x", "a\x00.md"):
            with self.subTest(path=p):
                self.assertEqual(self.action(p), "deny")


class Decisions(unittest.TestCase):
    def test_default_deny(self):
        self.assertEqual(guard().check(Session(), "anything", {}).action, "deny")

    def test_high_risk_needs_approval(self):
        g = guard(send_email=ToolPolicy(risk="high", allowed_recipients=["*@corp.example"]))
        self.assertEqual(g.check(Session(), "send_email", {"to": "bob@corp.example"}).action, "approve")
        self.assertEqual(g.check(Session(), "send_email", {"to": ["bob@corp.example", "x@evil.example"]}).action,
                         "deny")

    def test_taint_escalation(self):
        g = guard(write_note=ToolPolicy(risk="low"), read_note=ToolPolicy(risk="low"))
        s = Session()
        self.assertEqual(tainted_escalation(g, s, "write_note", {}).action, "allow")
        s.ingest_untrusted("email:inbox/123")
        self.assertEqual(tainted_escalation(g, s, "write_note", {}).action, "approve")
        self.assertEqual(tainted_escalation(g, s, "read_note", {}).action, "allow")

    def test_rate_limit_window(self):
        clock = FakeClock()
        g = Guard({"t": ToolPolicy(max_calls_per_minute=2)}, clock=clock)
        s = Session()
        self.assertEqual([g.check(s, "t", {}).action for _ in range(3)], ["allow", "allow", "deny"])
        clock.t = 61
        self.assertEqual(g.check(s, "t", {}).action, "allow")

    def test_deny_args_case_insensitive(self):
        g = guard(run_shell=ToolPolicy(risk="high", deny_args={"cmd": ["rm -rf"]}))
        self.assertEqual(g.check(Session(), "run_shell", {"cmd": "RM -RF /"}).action, "deny")


class Audit(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(b"k")
        for i in range(5):
            self.log.append({"i": i})

    def test_intact(self):
        self.assertIsNone(self.log.verify())

    def test_edit_detected(self):
        self.log.records[2]["event"]["i"] = 99
        self.assertEqual(self.log.verify(), 2)

    def test_deletion_detected(self):
        del self.log.records[1]
        self.assertEqual(self.log.verify(), 1)

    def test_forgery_without_key_detected(self):
        forged = AuditLog(b"wrong-key")
        forged.records = [dict(r) for r in self.log.records]
        forged.records[4] = {**forged.records[4], "event": {"i": "x"}}
        forged.records[4]["mac"] = forged._mac({k: forged.records[4][k] for k in ("seq", "ts", "prev", "event")})
        self.log.records = forged.records
        self.assertEqual(self.log.verify(), 4)


if __name__ == "__main__":
    unittest.main()
